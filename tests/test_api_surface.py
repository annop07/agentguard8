"""ส่วนที่เหลือของพื้นผิว API — helper, การแปลงค่า, และการเตรียมทางให้ชั้น taint"""

from __future__ import annotations

from pathlib import Path

from taintguard import (
    Action,
    ApprovalRequired,
    Guard,
    JsonlSink,
    RiskClass,
    ToolPolicy,
)
from taintguard.policy import TAINT_ALL


class TestDecisionRepr:
    def test_allow_reads_cleanly(self, guard: Guard) -> None:
        line = str(guard.session().check("get_invoice", {}))
        assert line.split() == ["ALLOW", "get_invoice", "—"]

    def test_block_names_the_code_and_reason(self, guard: Guard) -> None:
        line = str(guard.session().check("drop_database", {}))
        assert line.startswith("BLOCK")
        assert "unauthorized_tool" in line


class TestApprovalHandle:
    def test_deny_and_tool_args_are_carried(self, guard: Guard, context: dict) -> None:
        decision = guard.session(context=context).check(
            "transfer_money", {"to_account": "111-1", "amount": 100}
        )
        try:
            decision.raise_for_action({"to_account": "111-1", "amount": 100})
        except ApprovalRequired as exc:
            exc.deny()
            assert exc.approved is False
            assert exc.tool_args["to_account"] == "111-1"
            assert exc.args == (f"transfer_money: {decision.reason}",)  # ของ Python ยังปกติ
        else:  # pragma: no cover
            raise AssertionError("ควร escalate")


class TestTaintTargets:
    """ยังไม่มีชั้น taint แต่ policy ต้องบอกได้แล้วว่าจะตรวจ field ไหน (ดู SPEC.md §5.5)"""

    def test_read_tools_have_no_targets(self) -> None:
        assert ToolPolicy("t", risk=RiskClass.READ).taint_targets({"q": "x"}) == []

    def test_unspecified_fields_means_every_field(self) -> None:
        policy = ToolPolicy("t", risk=RiskClass.CRITICAL)
        assert policy.taint_fields == TAINT_ALL
        assert sorted(policy.taint_targets({"a": 1, "b": 2})) == ["a", "b"]

    def test_explicit_fields_are_used_verbatim(self) -> None:
        policy = ToolPolicy("t", risk=RiskClass.CRITICAL, taint_fields=["to_account"])
        assert policy.taint_targets({"a": 1, "to_account": "x"}) == ["to_account"]

    def test_explicit_taint_action_overrides_the_risk_default(self) -> None:
        policy = ToolPolicy("t", risk=RiskClass.READ, taint_action=Action.BLOCK)
        assert policy.taint_enabled is True  # READ ปกติไม่ตรวจ แต่สั่งให้ตรวจได้

    def test_taint_is_switched_off_with_an_empty_field_list(self) -> None:
        """ต้องประกาศออกมาให้เห็น — taint_action=None แปลว่า 'ใช้ค่า default' ไม่ใช่ 'ปิด'"""
        assert ToolPolicy("t", risk=RiskClass.CRITICAL, taint_fields=[]).taint_enabled is False
        assert ToolPolicy("t", risk=RiskClass.CRITICAL, taint_action=None).taint_enabled is True


class TestGuardConstruction:
    def test_default_action_accepts_an_action_enum(self, policies: list[ToolPolicy]) -> None:
        guard = Guard(policies=policies, default_action=Action.ALLOW)
        assert guard.session().check("unknown_tool", {}).allowed

    def test_empty_guard_blocks_everything(self) -> None:
        assert Guard().session().check("anything", {}).action is Action.BLOCK

    def test_close_without_a_sink_is_a_no_op(self) -> None:
        Guard().close()


class TestSessionLifecycle:
    def test_context_manager_yields_the_session(self, guard: Guard) -> None:
        with guard.session() as s:
            s.check("get_invoice", {})
        assert len(s.audit) == 1

    def test_explicit_session_id_is_kept(self, guard: Guard) -> None:
        assert guard.session(session_id="run-42").session_id == "run-42"

    def test_sessions_do_not_share_counters(self, guard: Guard) -> None:
        a, b = guard.session(), guard.session()
        a.check("send_email", {})
        a.check("send_email", {})
        assert a.check("send_email", {}).allowed is False  # a หมดโควตา
        assert b.check("send_email", {}).allowed is True  # b ยังเต็ม


def test_jsonl_sink_close_is_idempotent(tmp_path: Path) -> None:
    sink = JsonlSink(tmp_path / "a.jsonl")
    sink.close()
    sink.close()
