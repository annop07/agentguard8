"""pipeline การบังคับใช้ — ลำดับของชั้นตรวจสำคัญพอๆ กับตัวชั้นเอง"""

from __future__ import annotations

import pytest

from taintguard import (
    Action,
    ApprovalRequired,
    Blocked,
    Guard,
    Max,
    PolicyConfigError,
    Reason,
    RiskClass,
    ToolPolicy,
)


class TestScoping:
    def test_read_tool_is_allowed(self, guard: Guard, context: dict) -> None:
        s = guard.session(context=context)
        assert s.check("get_invoice", {"id": 1}).allowed

    def test_tool_outside_allowlist_is_blocked(self, guard: Guard) -> None:
        s = guard.session(allowed_tools=["get_invoice"])
        decision = s.check("search_docs", {"q": "x"})
        assert decision.action is Action.BLOCK
        assert decision.code is Reason.UNAUTHORIZED_TOOL
        assert decision.rule == "scope.allowed_tools"

    def test_denylist_beats_allowlist(self, guard: Guard) -> None:
        s = guard.session(allowed_tools=["get_invoice"], forbidden_tools=["get_invoice"])
        assert s.check("get_invoice", {}).rule == "scope.forbidden_tools"

    def test_no_allowlist_means_policy_decides(self, guard: Guard) -> None:
        assert guard.session().check("get_invoice", {}).allowed


class TestUnknownTool:
    def test_fails_closed_by_default(self, guard: Guard) -> None:
        decision = guard.session().check("drop_database", {})
        assert decision.action is Action.BLOCK
        assert decision.code is Reason.UNAUTHORIZED_TOOL
        assert decision.rule == "guard.default_action"

    def test_warn_mode_allows_but_still_records_why(self, policies: list[ToolPolicy]) -> None:
        s = Guard(policies=policies, default_action="warn").session()
        decision = s.check("drop_database", {})
        assert decision.allowed
        assert decision.code is Reason.UNAUTHORIZED_TOOL  # อนุญาต แต่ไม่เงียบ
        assert s.audit[0].code == "unauthorized_tool"

    def test_invalid_default_action(self, policies: list[ToolPolicy]) -> None:
        with pytest.raises(PolicyConfigError):
            Guard(policies=policies, default_action="maybe")


class TestSchema:
    def test_bad_arguments_are_blocked(self, guard: Guard, context: dict) -> None:
        s = guard.session(context=context)
        decision = s.check("transfer_money", {"to_account": "111-1", "amount": -5})
        assert decision.action is Action.BLOCK
        assert decision.code is Reason.INVALID_ARGUMENTS
        assert decision.retryable is True

    def test_evidence_never_carries_raw_values(self, guard: Guard, context: dict) -> None:
        """evidence ไหลลง audit ที่เก็บยาว — ค่าที่ user ส่งมาต้องไม่ไปอยู่ตรงนั้น"""
        s = guard.session(context=context)
        decision = s.check("transfer_money", {"to_account": "SECRET-ACC", "amount": -5})
        assert "SECRET-ACC" not in str(decision.evidence)
        assert decision.evidence["errors"][0]["loc"] == "amount"

    def test_validated_args_are_coerced(self, guard: Guard, context: dict) -> None:
        s = guard.session(context=context)
        decision = s.check("transfer_money", {"to_account": "111-1", "amount": "4999"})
        assert decision.validated_args is not None
        assert decision.validated_args["amount"] == 4999.0

    def test_rules_run_against_coerced_values(self, guard: Guard, context: dict) -> None:
        """amount ที่มาเป็น string ต้องยังโดน Max ตรวจ ไม่ใช่หลุดเพราะเทียบคนละชนิด"""
        s = guard.session(context=context)
        decision = s.check("transfer_money", {"to_account": "111-1", "amount": "49000"})
        assert decision.code is Reason.INVARIANT_BREACH


class TestInvariants:
    def test_account_outside_the_user_allowlist_is_blocked(
        self, guard: Guard, context: dict
    ) -> None:
        s = guard.session(context=context)
        decision = s.check("transfer_money", {"to_account": "999-9", "amount": 100})
        assert decision.action is Action.BLOCK
        assert decision.code is Reason.INVARIANT_BREACH
        assert decision.rule == "require.In(to_account)"

    def test_amount_over_cap_is_blocked_and_retryable(self, guard: Guard, context: dict) -> None:
        s = guard.session(context=context)
        decision = s.check("transfer_money", {"to_account": "111-1", "amount": 9_000})
        assert decision.rule == "require.Max(amount)"
        assert decision.retryable is True  # ลดยอดแล้วลองใหม่ได้

    def test_first_failing_rule_wins(self, guard: Guard, context: dict) -> None:
        s = guard.session(context=context)
        decision = s.check("transfer_money", {"to_account": "999-9", "amount": 9_000})
        assert decision.rule == "require.In(to_account)"


class TestBudget:
    def test_limit_counts_only_allowed_calls(self, guard: Guard) -> None:
        s = guard.session()
        assert s.check("send_email", {"to": "a@b.com"}).allowed
        assert s.check("send_email", {"to": "c@d.com"}).allowed
        third = s.check("send_email", {"to": "e@f.com"})
        assert third.code is Reason.BUDGET_EXCEEDED
        assert third.retryable is False

    def test_blocked_calls_do_not_consume_quota(self, guard: Guard, context: dict) -> None:
        s = guard.session(context=context)
        s.check("transfer_money", {"to_account": "999-9", "amount": 100})  # โดนบล็อก
        s.check("transfer_money", {"to_account": "999-9", "amount": 100})  # โดนบล็อก
        assert s.calls.get("transfer_money", 0) == 0

    def test_negative_limit_is_a_config_error(self) -> None:
        with pytest.raises(PolicyConfigError):
            ToolPolicy("x", max_calls_per_session=-1)


class TestApproval:
    def test_critical_tools_escalate_by_default(self, guard: Guard, context: dict) -> None:
        s = guard.session(context=context)
        decision = s.check("transfer_money", {"to_account": "111-1", "amount": 100})
        assert decision.action is Action.ESCALATE
        assert decision.code is Reason.APPROVAL_REQUIRED
        assert decision.allowed is False

    def test_approval_can_be_switched_off_explicitly(self, context: dict) -> None:
        guard = Guard(
            policies=[
                ToolPolicy("transfer_money", risk=RiskClass.CRITICAL, requires_approval=False)
            ]
        )
        assert guard.session(context=context).check("transfer_money", {}).allowed


class TestPolicyDefaults:
    @pytest.mark.parametrize(
        ("risk", "approval"),
        [
            (RiskClass.READ, False),
            (RiskClass.WRITE, False),
            (RiskClass.EXTERNAL, False),
            (RiskClass.CRITICAL, True),
        ],
    )
    def test_approval_default_follows_risk(self, risk: RiskClass, approval: bool) -> None:
        assert ToolPolicy("t", risk=risk).requires_approval is approval

    def test_read_tools_skip_taint_entirely(self) -> None:
        """เงื่อนไขที่ทำให้ชั้น taint อยู่รอดในระบบจริง — ดู policy.py"""
        assert ToolPolicy("t", risk=RiskClass.READ).taint_enabled is False
        assert ToolPolicy("t", risk=RiskClass.CRITICAL).taint_enabled is True

    def test_write_taint_defaults_to_warn(self) -> None:
        assert ToolPolicy("t", risk=RiskClass.WRITE).taint_action is Action.ALLOW

    def test_duplicate_policy_names_rejected(self) -> None:
        with pytest.raises(PolicyConfigError):
            Guard(policies=[ToolPolicy("a"), ToolPolicy("a")])

    def test_unnamed_policy_rejected(self) -> None:
        with pytest.raises(PolicyConfigError):
            ToolPolicy("")


class TestRaiseForAction:
    def test_block_raises(self, guard: Guard) -> None:
        decision = guard.session().check("drop_database", {})
        with pytest.raises(Blocked) as exc:
            decision.raise_for_action()
        assert exc.value.decision is decision

    def test_escalate_raises_and_defaults_to_not_approved(
        self, guard: Guard, context: dict
    ) -> None:
        decision = guard.session(context=context).check(
            "transfer_money", {"to_account": "111-1", "amount": 100}
        )
        with pytest.raises(ApprovalRequired) as exc:
            decision.raise_for_action({"to_account": "111-1"})
        assert exc.value.approved is False  # ยังไม่ตัดสิน = ยังไม่อนุมัติ
        exc.value.approve()
        assert exc.value.approved is True

    def test_allow_does_not_raise(self, guard: Guard) -> None:
        guard.session().check("get_invoice", {}).raise_for_action()


class TestToolError:
    def test_shape_is_stable(self, guard: Guard, context: dict) -> None:
        decision = guard.session(context=context).check(
            "transfer_money", {"to_account": "999-9", "amount": 100}
        )
        assert decision.as_tool_error() == {
            "error": "blocked_by_policy",
            "code": "invariant_breach",
            "tool": "transfer_money",
            "reason": decision.reason,
            "retryable": True,
        }

    def test_ordering_cheapest_check_first(self, context: dict) -> None:
        """scope ต้องตัดก่อน schema — tool ที่ไม่มีสิทธิ์ไม่ควรเดินไปถึงชั้นที่แพงกว่า"""
        guard = Guard(policies=[ToolPolicy("t", risk=RiskClass.WRITE, require=[Max("amount", 1)])])
        s = guard.session(forbidden_tools=["t"], context=context)
        assert s.check("t", {"amount": 999}).rule == "scope.forbidden_tools"
