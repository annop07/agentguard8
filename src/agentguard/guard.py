"""เครื่องยนต์บังคับใช้ — ``Guard`` ถือกฎ ``Session`` ถือบริบทของ agent run หนึ่งครั้ง

แยกกันเพราะอายุการใช้งานต่างกันคนละระดับ: policy ประกาศครั้งเดียวตอน startup แล้วไม่เปลี่ยนอีก
ส่วน taint ledger, ตัวนับ, และ context ของ user เกิดและตายพร้อม request

ลำดับการตรวจใน :meth:`Session.check` เรียงจาก **ถูกที่สุดไปแพงที่สุด** — การตรวจ scope
คือการค้น set ส่วนการตรวจ provenance ต้องไล่เทียบข้อความทุก span ที่ลงทะเบียนไว้
tool call ที่ไม่มีสิทธิ์ตั้งแต่ต้นจึงไม่ควรเดินไปไกลกว่าขั้นแรก
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import replace
from types import TracebackType
from typing import Any, Literal
from uuid import uuid4

from pydantic import ValidationError

from agentguard.audit import AuditEvent, AuditSink
from agentguard.decisions import Action, Decision, Reason
from agentguard.errors import PolicyConfigError
from agentguard.policy import ToolPolicy
from agentguard.taint import TaintLedger, TaintMatch, spans_of

Mode = Literal["enforce", "observe"]


def _normalise_default_action(value: Action | str) -> Action:
    if isinstance(value, Action):
        return value
    lowered = value.lower()
    if lowered == "block":
        return Action.BLOCK
    if lowered in {"warn", "allow"}:
        return Action.ALLOW
    raise PolicyConfigError(f"default_action ต้องเป็น 'block' หรือ 'warn' ไม่ใช่ {value!r}")


class Guard:
    """ชุด policy ที่ไม่เปลี่ยนแปลง — สร้างครั้งเดียวตอน startup แล้วใช้ร่วมกันทุก request

    :param mode:
        ``"enforce"`` บังคับใช้จริง · ``"observe"`` ตัดสินครบทุกชั้นและบันทึก audit ครบ
        แต่คืน ``ALLOW`` เสมอ

        โหมด observe มีไว้สำหรับขั้นแรกของการติดตั้งในระบบที่ทำงานอยู่แล้ว — ไม่มีทีมไหน
        เปิดชั้นบังคับใช้แบบ fail closed ในวันแรกได้ เพราะยังไม่มีใครรู้ว่า agent เรียกอะไรบ้าง
        รันโหมดนี้สักสัปดาห์แล้วอ่าน audit log จะได้ policy ที่ตรงกับความจริง แทนที่จะเดา
    """

    def __init__(
        self,
        policies: Sequence[ToolPolicy] = (),
        *,
        default_action: Action | str = "block",
        mode: Mode = "enforce",
        audit_sink: AuditSink | None = None,
        min_match_chars: int = 4,
        ngram_k: int = 3,
    ) -> None:
        if mode not in ("enforce", "observe"):
            raise PolicyConfigError(f"mode ต้องเป็น 'enforce' หรือ 'observe' ไม่ใช่ {mode!r}")
        if min_match_chars < 1 or ngram_k < 1:
            raise PolicyConfigError("min_match_chars และ ngram_k ต้องเป็นจำนวนเต็มบวก")

        self.policies: dict[str, ToolPolicy] = {}
        for policy in policies:
            if policy.name in self.policies:
                raise PolicyConfigError(f"มี policy ซ้ำสำหรับ tool {policy.name!r}")
            self.policies[policy.name] = policy

        self.default_action = _normalise_default_action(default_action)
        self.mode: Mode = mode
        self.audit_sink = audit_sink
        self.min_match_chars = min_match_chars
        self.ngram_k = ngram_k

    def session(
        self,
        *,
        context: Mapping[str, Any] | None = None,
        allowed_tools: Sequence[str] | None = None,
        forbidden_tools: Sequence[str] | None = None,
        session_id: str | None = None,
    ) -> Session:
        return Session(
            self,
            context=context,
            allowed_tools=allowed_tools,
            forbidden_tools=forbidden_tools,
            session_id=session_id,
        )

    def close(self) -> None:
        if self.audit_sink is not None:
            self.audit_sink.close()


class Session:
    """บริบทของ agent run หนึ่งครั้ง

    :param allowed_tools:
        allowlist ระดับ session — ตอบคำถามที่ policy ตอบไม่ได้ว่า "**run นี้** แตะ tool ไหนได้"
        agent ตัวเดียวกันที่ทำงานในบริบทต่างกัน (ยืนยันตัวตนแล้ว/ยังไม่ยืนยัน) ควรมีสิทธิ์ต่างกัน
        โดยไม่ต้องแยก ``Guard`` หรือแก้ policy
    :param forbidden_tools:
        denylist — ชนะ allowlist เสมอ
    """

    def __init__(
        self,
        guard: Guard,
        *,
        context: Mapping[str, Any] | None = None,
        allowed_tools: Sequence[str] | None = None,
        forbidden_tools: Sequence[str] | None = None,
        session_id: str | None = None,
    ) -> None:
        self.guard = guard
        self.context: dict[str, Any] = dict(context or {})
        self.allowed_tools: set[str] | None = (
            set(allowed_tools) if allowed_tools is not None else None
        )
        self.forbidden_tools: set[str] = set(forbidden_tools or ())
        self.session_id = session_id or uuid4().hex[:12]

        self._events: list[AuditEvent] = []
        self._counts: Counter[str] = Counter()
        self._ledger = TaintLedger(
            min_match_chars=guard.min_match_chars, ngram_k=guard.ngram_k
        )

    # ── provenance ────────────────────────────────────────────────────────

    def taint(self, text: str, *, source: str, label: str = "untrusted") -> None:
        """ลงทะเบียนข้อความที่มาจากแหล่งควบคุมไม่ได้ — อีเมล, OCR, หน้าเว็บ, ไฟล์ที่ user อัป

        เรียกก่อนส่งข้อความเข้า prompt เสมอ ตัวชี้ ``source`` จะไปโผล่ใน audit log
        ตอนที่มี tool call ถูกบล็อก จึงควรชี้กลับไปยังต้นทางได้จริง เช่น ``"email:4821"``
        """
        self._ledger.add(text, source=source, label=label)

    def attach(self, value: object) -> int:
        """ดูด span ที่ติดมากับ :class:`~agentguard.taint.TaintedStr` เข้า ledger

        คืนจำนวน span ที่เพิ่ม — ``0`` แปลว่าค่านั้นเป็น ``str`` ธรรมดา ซึ่งมักหมายความว่า
        เครื่องหมายหายไประหว่างทาง (f-string เป็นสาเหตุที่พบบ่อยที่สุด)
        """
        return self._ledger.add_spans(spans_of(value))

    def trust(self, value: object) -> None:
        """ประกาศว่าค่านี้ปลอดภัยเสมอ แม้จะไปโผล่ในข้อความที่ taint ไว้"""
        self._ledger.trust(value)

    @property
    def ledger(self) -> TaintLedger:
        return self._ledger

    # ── enforcement ───────────────────────────────────────────────────────

    def check(self, tool: str, args: Mapping[str, Any] | None = None) -> Decision:
        """ตรวจ tool call หนึ่งครั้ง — **ไม่รัน tool**

        มี side effect โดยตั้งใจ: เขียน audit และเดินตัวนับโควตา จึงต้องเรียกครั้งเดียว
        ต่อหนึ่ง tool call ที่กำลังจะเกิดขึ้นจริง ไม่ใช่เรียกซ้ำเพื่อดูผล
        """
        raw = dict(args or {})
        return self._finalise(self._evaluate(tool, raw), raw)

    def _evaluate(self, tool: str, args: dict[str, Any]) -> Decision:
        # 1 ── capability scoping
        if tool in self.forbidden_tools:
            return Decision(
                action=Action.BLOCK,
                tool=tool,
                code=Reason.UNAUTHORIZED_TOOL,
                rule="scope.forbidden_tools",
                reason=f"{tool!r} is on this session's denylist",
            )
        if self.allowed_tools is not None and tool not in self.allowed_tools:
            return Decision(
                action=Action.BLOCK,
                tool=tool,
                code=Reason.UNAUTHORIZED_TOOL,
                rule="scope.allowed_tools",
                reason=f"{tool!r} is not in this session's allowlist",
            )

        # 2 ── policy lookup (fail closed)
        policy = self.guard.policies.get(tool)
        if policy is None:
            blocked = self.guard.default_action is Action.BLOCK
            return Decision(
                action=Action.BLOCK if blocked else Action.ALLOW,
                tool=tool,
                code=Reason.UNAUTHORIZED_TOOL,
                rule="guard.default_action",
                reason=(
                    f"no policy is declared for {tool!r}"
                    if blocked
                    else f"no policy is declared for {tool!r} (allowed by default_action='warn')"
                ),
            )

        # 3 ── schema — ทำก่อนกฎอื่นเพราะกฎที่เหลือทำงานบนค่าที่ผ่าน coercion แล้ว
        validated = args
        if policy.args_model is not None:
            try:
                validated = policy.args_model.model_validate(args).model_dump()
            except ValidationError as exc:
                errors = exc.errors()
                return Decision(
                    action=Action.BLOCK,
                    tool=tool,
                    code=Reason.INVALID_ARGUMENTS,
                    rule="schema",
                    reason=_summarise_validation_errors(errors),
                    # เก็บแค่ตำแหน่งกับชนิดของ error ไม่เก็บค่าที่ส่งมา — evidence ไหลลง
                    # audit log ที่มีอายุเก็บยาว ค่าดิบไม่ควรไปอยู่ตรงนั้น
                    evidence={
                        "errors": [
                            {"loc": ".".join(str(p) for p in e["loc"]), "type": e["type"]}
                            for e in errors
                        ]
                    },
                )

        # 4 ── budget
        limit = policy.max_calls_per_session
        if limit is not None and self._counts[tool] >= limit:
            return Decision(
                action=Action.BLOCK,
                tool=tool,
                code=Reason.BUDGET_EXCEEDED,
                rule="budget.max_calls_per_session",
                reason=f"{tool!r} may be called at most {limit}x per session",
                evidence={"limit": limit, "used": self._counts[tool]},
            )

        # 5 ── argument invariants
        for rule in policy.require:
            failure = rule.check(validated, self.context)
            if failure is not None:
                return Decision(
                    action=Action.BLOCK,
                    tool=tool,
                    code=Reason.INVARIANT_BREACH,
                    rule=f"require.{rule.name}",
                    reason=failure,
                )

        # 6 ── taint / provenance matching
        taint_hit: tuple[str, TaintMatch] | None = None
        if policy.taint_enabled:
            hits = self._ledger.scan(validated, policy.taint_targets(validated))
            if hits:
                taint_hit = next(iter(hits.items()))
                field, match = taint_hit
                if policy.taint_action is Action.BLOCK:
                    return Decision(
                        action=Action.BLOCK,
                        tool=tool,
                        code=Reason.TAINTED_ARGUMENT,
                        rule=f"taint.{field}",
                        reason=(
                            f"{field} was derived from untrusted content ({match.source}). "
                            f"Tools at {policy.risk.value.upper()} risk cannot use "
                            "attacker-controllable values."
                        ),
                        evidence=match.as_evidence(),
                    )

        # 7 ── human approval
        if policy.requires_approval:
            return Decision(
                action=Action.ESCALATE,
                tool=tool,
                code=Reason.APPROVAL_REQUIRED,
                rule="policy.requires_approval",
                reason=f"{tool!r} requires human approval before it runs",
                evidence=taint_hit[1].as_evidence() if taint_hit else {},
                validated_args=validated,
            )

        if taint_hit is not None:
            # taint_action=ALLOW คือ "เตือน" — ปล่อยผ่านแต่ไม่เงียบ audit ยังได้เหตุผลครบ
            field, match = taint_hit
            return Decision(
                action=Action.ALLOW,
                tool=tool,
                code=Reason.TAINTED_ARGUMENT,
                rule=f"taint.{field}",
                reason=f"{field} was derived from untrusted content ({match.source})",
                evidence=match.as_evidence(),
                validated_args=validated,
            )

        return Decision(action=Action.ALLOW, tool=tool, validated_args=validated)

    def _finalise(self, intended: Decision, raw_args: dict[str, Any]) -> Decision:
        decision = intended
        if self.guard.mode == "observe" and intended.action is not Action.ALLOW:
            decision = replace(intended, action=Action.ALLOW, observed_action=intended.action)

        event = AuditEvent.from_decision(decision, session_id=self.session_id, args=raw_args)
        self._events.append(event)
        if self.guard.audit_sink is not None:
            self.guard.audit_sink.emit(event)

        # นับจาก decision ที่ *ตั้งใจ* ไม่ใช่ decision ที่บังคับใช้ — call ที่ถูกบล็อก
        # ไม่ควรกินโควตา และโหมด observe ต้องรายงานตรงกับสิ่งที่ enforce จะทำ
        # ถ้านับตามผลที่บังคับใช้ call ที่ observe ปล่อยผ่านจะไปกินโควตาของ call ถัดไป
        # แล้วรายงานเป็น budget_exceeded ทั้งที่ enforce จะบล็อกด้วยเหตุผลอื่นตั้งแต่แรก
        if intended.action is Action.ALLOW:
            self._counts[decision.tool] += 1

        return decision

    # ── introspection ─────────────────────────────────────────────────────

    @property
    def audit(self) -> list[AuditEvent]:
        return list(self._events)

    @property
    def calls(self) -> dict[str, int]:
        """จำนวนครั้งที่แต่ละ tool ผ่านทุกชั้นตรวจ

        ในโหมด observe ตัวเลขนี้ยังเป็นจำนวนตาม *policy* ไม่ใช่จำนวนที่ทำงานจริง —
        เพราะโหมดนั้นตั้งใจรายงานสิ่งที่ enforce จะทำ
        """
        return dict(self._counts)

    @property
    def stats(self) -> dict[str, int]:
        stats = {"allowed": 0, "blocked": 0, "escalated": 0, "suppressed": 0}
        for event in self._events:
            effective = event.observed_action or event.action
            stats[{
                Action.ALLOW: "allowed",
                Action.BLOCK: "blocked",
                Action.ESCALATE: "escalated",
            }[effective]] += 1
            if event.observed_action is not None:
                stats["suppressed"] += 1
        return stats

    def __enter__(self) -> Session:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        return None


def _summarise_validation_errors(errors: list[Any]) -> str:
    if not errors:  # pragma: no cover - pydantic ไม่เคยคืน list ว่าง
        return "argument validation failed"
    first = errors[0]
    loc = ".".join(str(p) for p in first["loc"]) or "(root)"
    extra = f" (+{len(errors) - 1} more)" if len(errors) > 1 else ""
    return f"{loc}: {first['msg']}{extra}"
