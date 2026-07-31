"""โหมด observe — ขั้นแรกของการติดตั้งในระบบที่ทำงานอยู่แล้ว

ตัดสินครบทุกชั้น เขียน audit ครบ แต่ไม่หยุดอะไรเลย เพื่อให้ทีมเห็นว่า agent เรียกอะไรบ้างจริงๆ
ก่อนตัดสินใจว่าจะบล็อกอะไร
"""

from __future__ import annotations

import pytest

from agentguard import Action, Guard, PolicyConfigError, Reason, ToolPolicy


def test_blocked_call_is_allowed_through_but_recorded(
    policies: list[ToolPolicy], context: dict
) -> None:
    guard = Guard(policies=policies, mode="observe")
    decision = guard.session(context=context).check(
        "transfer_money", {"to_account": "999-9", "amount": 100}
    )

    assert decision.allowed is True  # ไม่หยุดการทำงาน
    assert decision.observed_action is Action.BLOCK  # แต่บอกว่าจะบล็อกถ้า enforce
    assert decision.suppressed is True
    assert decision.code is Reason.INVARIANT_BREACH  # เหตุผลยังครบเหมือนเดิม
    assert decision.rule == "require.In(to_account)"


def test_escalation_is_suppressed_too(policies: list[ToolPolicy], context: dict) -> None:
    guard = Guard(policies=policies, mode="observe")
    decision = guard.session(context=context).check(
        "transfer_money", {"to_account": "111-1", "amount": 100}
    )
    assert decision.allowed is True
    assert decision.observed_action is Action.ESCALATE


def test_clean_calls_are_untouched(policies: list[ToolPolicy]) -> None:
    guard = Guard(policies=policies, mode="observe")
    decision = guard.session().check("get_invoice", {"id": 1})
    assert decision.allowed is True
    assert decision.observed_action is None
    assert decision.suppressed is False


def test_audit_records_what_would_have_happened(policies: list[ToolPolicy], context: dict) -> None:
    guard = Guard(policies=policies, mode="observe")
    s = guard.session(context=context)
    s.check("get_invoice", {})
    s.check("transfer_money", {"to_account": "999-9", "amount": 100})

    assert s.stats == {"allowed": 1, "blocked": 1, "escalated": 0, "suppressed": 1}
    assert s.audit[1].to_dict()["observed_action"] == "block"


def test_enforce_mode_stats_have_no_suppressions(policies: list[ToolPolicy], context: dict) -> None:
    s = Guard(policies=policies).session(context=context)
    s.check("get_invoice", {})
    s.check("transfer_money", {"to_account": "999-9", "amount": 100})
    assert s.stats == {"allowed": 1, "blocked": 1, "escalated": 0, "suppressed": 0}


def test_invalid_mode_rejected() -> None:
    with pytest.raises(PolicyConfigError):
        Guard(mode="dry-run")  # type: ignore[arg-type]


# ลำดับที่ออกแบบให้ชนโควตา: ถ้า call ที่ถูกบล็อกไปกินโควตา call ถัดๆ ไปจะรายงานผิดหมด
_SEQUENCE = [
    ("get_invoice", {"id": 1}),
    ("drop_database", {}),
    ("transfer_money", {"to_account": "999-9", "amount": 100}),
    ("transfer_money", {"to_account": "111-1", "amount": 9_000}),
    ("transfer_money", {"to_account": "111-1", "amount": -5}),
    ("transfer_money", {"to_account": "111-1", "amount": 100}),
]


def test_observe_reports_exactly_what_enforce_would_do(
    policies: list[ToolPolicy], context: dict
) -> None:
    """เหตุผลเดียวที่โหมด observe มีอยู่ — ถ้ารายงานไม่ตรง คนอ่าน log ไปเขียน policy ผิด

    จุดที่พลาดง่ายคือตัวนับโควตา: call ที่ observe ปล่อยผ่านต้องไม่กินโควตาของ call ถัดไป
    เพราะใน enforce mode มันถูกบล็อกไปแล้วตั้งแต่ชั้นก่อนหน้า
    """
    enforced = Guard(policies=policies).session(context=context)
    observed = Guard(policies=policies, mode="observe").session(context=context)

    for tool, args in _SEQUENCE:
        a = enforced.check(tool, args)
        b = observed.check(tool, args)
        intended = b.observed_action or b.action
        assert (intended, b.code, b.rule) == (a.action, a.code, a.rule), f"ต่างกันที่ {tool}"

    assert enforced.calls == observed.calls
    enforced_stats = enforced.stats
    assert observed.stats == {
        **enforced_stats,
        "suppressed": enforced_stats["blocked"] + enforced_stats["escalated"],
    }
