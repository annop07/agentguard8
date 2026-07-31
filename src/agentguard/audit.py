"""Audit log.

บันทึก **ทุก** decision รวมถึง ``ALLOW`` — เพราะ log ที่มีแต่เหตุการณ์ที่ถูกบล็อก
แยกไม่ออกระหว่าง "ระบบทำงานแล้วไม่มีอะไรผิดปกติ" กับ "ระบบไม่ได้ทำงานเลย"
ซึ่งเป็นสองสถานะที่ต่างกันมากตอนต้องพิสูจน์ว่ามีการควบคุมอยู่จริง

argument ไม่ถูกเก็บเป็นค่าดิบ เก็บเป็น digest — audit log ของระบบ AI มักถูกส่งต่อไป SIEM
และมีอายุเก็บยาว การใส่ค่าดิบลงไปเท่ากับสร้างที่เก็บ PII แห่งที่สองโดยไม่ตั้งใจ
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Protocol

from agentguard.decisions import Action, Decision


def args_digest(args: dict[str, Any]) -> str:
    """digest ที่เสถียร — argument ชุดเดียวกันได้ค่าเดิมเสมอ ใช้จับ tool call ซ้ำใน log ได้"""
    blob = json.dumps(args, sort_keys=True, ensure_ascii=False, default=str)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()[:16]


@dataclass(frozen=True)
class AuditEvent:
    ts: str
    session_id: str
    tool: str
    action: Action
    code: str | None
    rule: str | None
    reason: str
    evidence: dict[str, Any]
    args_digest: str
    observed_action: Action | None = None

    @classmethod
    def from_decision(
        cls, decision: Decision, *, session_id: str, args: dict[str, Any]
    ) -> AuditEvent:
        return cls(
            ts=datetime.now(timezone.utc).isoformat(),
            session_id=session_id,
            tool=decision.tool,
            action=decision.action,
            code=decision.code.value if decision.code else None,
            rule=decision.rule,
            reason=decision.reason,
            evidence=dict(decision.evidence),
            args_digest=args_digest(args),
            observed_action=decision.observed_action,
        )

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "ts": self.ts,
            "session_id": self.session_id,
            "tool": self.tool,
            "action": self.action.value,
            "code": self.code,
            "rule": self.rule,
            "reason": self.reason,
            "evidence": self.evidence,
            "args_digest": self.args_digest,
        }
        if self.observed_action is not None:
            data["observed_action"] = self.observed_action.value
        return data

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, sort_keys=True)


class AuditSink(Protocol):
    """ปลายทางของ audit event"""

    def emit(self, event: AuditEvent) -> None: ...

    def close(self) -> None: ...


class MemorySink:
    """เก็บไว้ในหน่วยความจำ — default, ใช้ในเทสต์และตอน dry run"""

    def __init__(self) -> None:
        self.events: list[AuditEvent] = []

    def emit(self, event: AuditEvent) -> None:
        self.events.append(event)

    def close(self) -> None:
        return None


class JsonlSink:
    """เขียนต่อท้ายไฟล์ JSONL — บรรทัดละ event ป้อนเข้า SIEM ได้ตรงๆ"""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._fh = self.path.open("a", encoding="utf-8")

    def emit(self, event: AuditEvent) -> None:
        self._fh.write(event.to_json() + "\n")
        self._fh.flush()

    def close(self) -> None:
        if not self._fh.closed:
            self._fh.close()


class CallableSink:
    """ส่งต่อให้ฟังก์ชันที่ผู้ใช้กำหนดเอง — logger, queue, webhook"""

    def __init__(self, fn: Callable[[AuditEvent], None]) -> None:
        self._fn = fn

    def emit(self, event: AuditEvent) -> None:
        self._fn(event)

    def close(self) -> None:
        return None
