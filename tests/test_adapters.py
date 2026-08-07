"""Adapters — เส้นทางเข้าสู่ core ที่ไม่ใช่ ``session.check()`` ตรงๆ

สิ่งที่คุมไว้ตรงนี้คือ **พฤติกรรมตอนถูกบล็อกต่างกันตามเส้นทาง** (§7.5) ซึ่งเป็นการ
ตัดสินใจเชิงออกแบบ ไม่ใช่รายละเอียดการทำงาน: loop ต้องได้ error dict ไปให้ LLM แก้เอง
ส่วนการเรียกฟังก์ชันตรงๆ ต้องหยุดจริง
"""

from __future__ import annotations

import asyncio
import json
from types import SimpleNamespace

import pytest
from pydantic import BaseModel, Field

from taintguard import (
    ApprovalRequired,
    Blocked,
    Guard,
    In,
    Max,
    PolicyConfigError,
    RiskClass,
    ToolPolicy,
)
from taintguard.adapters import guarded_tool_result, parse_tool_call, wrap_dispatcher
from taintguard.guard import current_session


class TransferArgs(BaseModel):
    to_account: str
    amount: float = Field(gt=0)


def build_guard(**kwargs: object) -> Guard:
    return Guard(
        policies=[
            ToolPolicy("get_invoice", risk=RiskClass.READ),
            ToolPolicy(
                "transfer_money",
                risk=RiskClass.CRITICAL,
                # CRITICAL escalate โดย default — เส้นทาง escalate เทสต์แยกไว้ข้างล่าง
                requires_approval=False,
                args_model=TransferArgs,
                require=[In("to_account", ctx="own_accounts"), Max("amount", 5_000)],
            ),
        ],
        **kwargs,  # type: ignore[arg-type]
    )


def dispatch(tool: str, args: object) -> dict[str, object]:
    return {"ok": tool, "args": args}


CONTEXT = {"own_accounts": ["111-1"]}


# --- contextvar -----------------------------------------------------------


def test_the_session_is_discoverable_from_inside_the_with_block():
    guard = build_guard()
    assert current_session() is None
    with guard.session(context=CONTEXT) as s:
        assert current_session() is s
    assert current_session() is None


def test_nested_sessions_restore_the_outer_one_rather_than_clearing_it():
    """reset ด้วย token ไม่ใช่ set(None) — ไม่งั้น decorator ชั้นนอกพังหลังชั้นในจบ"""
    guard = build_guard()
    with guard.session(context=CONTEXT) as outer:
        with guard.session(context=CONTEXT) as inner:
            assert current_session() is inner
        assert current_session() is outer


# --- wrap_dispatcher ------------------------------------------------------


def test_an_allowed_call_reaches_the_real_dispatcher():
    guard = build_guard()
    with guard.session(context=CONTEXT) as s:
        guarded = wrap_dispatcher(dispatch, session=s)
        assert guarded("get_invoice", {"id": 7}) == {"ok": "get_invoice", "args": {"id": 7}}


def test_a_blocked_call_returns_an_error_dict_instead_of_raising():
    """raise ที่นี่จะพังทั้ง agent loop ทั้งที่ LLM แก้เองได้ในรอบถัดไป"""
    guard = build_guard()
    with guard.session(context=CONTEXT) as s:
        guarded = wrap_dispatcher(dispatch, session=s)
        result = guarded("transfer_money", {"to_account": "999-9", "amount": 100})

    assert result["error"] == "blocked_by_policy"
    assert result["code"] == "invariant_breach"
    assert result["tool"] == "transfer_money"


def test_on_block_raise_turns_the_same_call_into_an_exception():
    guard = build_guard()
    with guard.session(context=CONTEXT) as s:
        guarded = wrap_dispatcher(dispatch, session=s, on_block="raise")
        with pytest.raises(Blocked):
            guarded("transfer_money", {"to_account": "999-9", "amount": 100})


def test_escalation_raises_even_when_blocks_are_set_to_return():
    """ยังไม่มีคำตอบให้คืนจนกว่าคนจะตัดสิน — error dict จะทำให้ LLM คิดว่าเรื่องจบแล้ว"""
    guard = Guard(
        policies=[ToolPolicy("wire", risk=RiskClass.WRITE, requires_approval=True)],
    )
    with guard.session() as s:
        guarded = wrap_dispatcher(dispatch, session=s, on_block="return")
        with pytest.raises(ApprovalRequired):
            guarded("wire", {"amount": 1})


def test_the_dispatcher_receives_validated_arguments():
    """กฎตรวจค่าหลัง coercion — ส่งค่าดิบต่อไปคือให้ tool เห็นคนละค่ากับที่ตรวจ"""
    guard = build_guard()
    with guard.session(context=CONTEXT) as s:
        guarded = wrap_dispatcher(dispatch, session=s)
        result = guarded("transfer_money", {"to_account": "111-1", "amount": "1000"})

    assert result["args"]["amount"] == 1000.0
    assert isinstance(result["args"]["amount"], float)


def test_the_session_can_come_from_the_context_instead_of_the_call():
    guard = build_guard()
    guarded = wrap_dispatcher(dispatch)  # ครอบครั้งเดียวตอน startup
    with guard.session(context=CONTEXT):
        assert guarded("get_invoice", {"id": 1})["ok"] == "get_invoice"


def test_calling_without_any_session_is_an_error_not_a_silent_pass():
    guarded = wrap_dispatcher(dispatch)
    with pytest.raises(PolicyConfigError, match="session"):
        guarded("get_invoice", {"id": 1})


# --- @guard.protect -------------------------------------------------------


def test_the_decorator_raises_because_the_caller_is_expecting_a_real_value():
    guard = Guard()

    @guard.protect(risk=RiskClass.CRITICAL, requires_approval=False, require=[Max("amount", 5_000)])
    def transfer(to_account: str, amount: float) -> str:
        return f"sent {amount} to {to_account}"

    with guard.session() as s:  # noqa: F841
        assert transfer("111-1", 100) == "sent 100 to 111-1"
        with pytest.raises(Blocked):
            transfer("999-9", 49_000)


def test_the_decorator_can_return_an_error_dict_when_asked_to():
    guard = Guard()

    @guard.protect(
        on_block="return",
        risk=RiskClass.CRITICAL,
        requires_approval=False,
        require=[Max("amount", 10)],
    )
    def transfer(amount: float) -> str:
        return "sent"

    with guard.session():
        assert transfer(99)["code"] == "invariant_breach"


def test_the_decorator_reuses_a_policy_that_was_already_declared():
    guard = build_guard()

    @guard.protect(name="transfer_money")
    def send(to_account: str, amount: float) -> str:
        return "sent"

    with guard.session(context=CONTEXT):
        assert send("111-1", 100) == "sent"
        with pytest.raises(Blocked):
            send("999-9", 100)


def test_declaring_a_second_policy_for_the_same_tool_is_rejected():
    """policy สองอันสำหรับ tool เดียวกันแปลว่าอันหนึ่งไม่ถูกใช้ และไม่มีทางรู้ว่าอันไหน"""
    guard = build_guard()
    with pytest.raises(PolicyConfigError, match="ซ้ำ"):

        @guard.protect(name="transfer_money", risk=RiskClass.READ)
        def send(amount: float) -> str:
            return "sent"


def test_a_protected_function_called_outside_a_session_refuses_to_run():
    guard = Guard()

    @guard.protect(risk=RiskClass.CRITICAL, requires_approval=False)
    def transfer(amount: float) -> str:
        return "sent"

    with pytest.raises(PolicyConfigError, match="session"):
        transfer(1)


def test_defaults_are_checked_even_when_the_caller_omits_them():
    guard = Guard()

    @guard.protect(risk=RiskClass.CRITICAL, requires_approval=False, require=[Max("amount", 10)])
    def transfer(amount: float = 99) -> str:
        return "sent"

    with guard.session(), pytest.raises(Blocked):
        transfer()


def test_the_decorator_works_on_async_functions():
    """asyncio.run แทน pytest-asyncio — เทสต์เดียวไม่คุ้มกับ dependency เพิ่มหนึ่งตัว"""
    guard = Guard()

    @guard.protect(risk=RiskClass.CRITICAL, requires_approval=False, require=[Max("amount", 10)])
    async def transfer(amount: float) -> str:
        return "sent"

    async def scenario() -> None:
        with guard.session():
            assert await transfer(5) == "sent"
            with pytest.raises(Blocked):
                await transfer(99)

    asyncio.run(scenario())


def test_bare_decorator_form_works_too():
    guard = Guard(policies=[ToolPolicy("ping", risk=RiskClass.READ)])

    @guard.protect
    def ping() -> str:
        return "pong"

    with guard.session():
        assert ping() == "pong"


# --- OpenAI helper --------------------------------------------------------


def make_tool_call(name: str, arguments: str, call_id: str = "call_1") -> SimpleNamespace:
    return SimpleNamespace(id=call_id, function=SimpleNamespace(name=name, arguments=arguments))


def test_an_allowed_tool_call_becomes_a_tool_message():
    guard = build_guard()
    with guard.session(context=CONTEXT) as s:
        message = guarded_tool_result(
            make_tool_call("get_invoice", '{"id": 7}'), dispatch=dispatch, session=s
        )

    assert message["role"] == "tool"
    assert message["tool_call_id"] == "call_1"
    assert json.loads(message["content"])["ok"] == "get_invoice"


def test_a_blocked_tool_call_comes_back_in_the_same_message_shape():
    """shape เดียวตลอด loop — โมเดลเรียนรู้จากตัวอย่างเดียวว่าต้องแก้อะไร"""
    guard = build_guard()
    with guard.session(context=CONTEXT) as s:
        message = guarded_tool_result(
            make_tool_call("transfer_money", '{"to_account": "999-9", "amount": 100}'),
            dispatch=dispatch,
            session=s,
        )

    assert message["role"] == "tool"
    assert json.loads(message["content"])["error"] == "blocked_by_policy"


def test_arguments_that_are_not_valid_json_do_not_kill_the_loop():
    """โมเดลคาย JSON พังได้จริง และควรได้โอกาสแก้ ไม่ใช่ทำให้ทั้งรอบตาย"""
    guard = build_guard()
    with guard.session(context=CONTEXT) as s:
        message = guarded_tool_result(
            make_tool_call("get_invoice", "{not json"), dispatch=dispatch, session=s
        )

    content = json.loads(message["content"])
    assert content["error"] == "invalid_tool_arguments"
    assert content["retryable"] is True


def test_json_that_is_valid_but_not_an_object_is_rejected_the_same_way():
    guard = build_guard()
    with guard.session(context=CONTEXT) as s:
        message = guarded_tool_result(
            make_tool_call("get_invoice", "[1, 2]"), dispatch=dispatch, session=s
        )
    assert json.loads(message["content"])["error"] == "invalid_tool_arguments"


def test_missing_arguments_are_treated_as_an_empty_object():
    guard = build_guard()
    with guard.session(context=CONTEXT) as s:
        message = guarded_tool_result(
            make_tool_call("get_invoice", ""), dispatch=dispatch, session=s
        )
    assert json.loads(message["content"])["ok"] == "get_invoice"


def test_an_object_that_is_not_shaped_like_a_tool_call_says_so():
    guard = build_guard()
    with (
        guard.session(context=CONTEXT) as s,
        pytest.raises(PolicyConfigError, match=r"function\.name"),
    ):
        guarded_tool_result(SimpleNamespace(id="x"), dispatch=dispatch, session=s)


def test_parse_tool_call_reports_the_pieces_it_found():
    call_id, tool, args = parse_tool_call(make_tool_call("t", '{"a": 1}', "call_9"))
    assert (call_id, tool, args) == ("call_9", "t", {"a": 1})


def test_the_openai_helper_also_finds_the_session_from_context():
    guard = build_guard()
    with guard.session(context=CONTEXT):
        message = guarded_tool_result(make_tool_call("get_invoice", "{}"), dispatch=dispatch)
    assert message["role"] == "tool"


def test_the_openai_helper_without_a_session_is_an_error():
    with pytest.raises(PolicyConfigError, match="session"):
        guarded_tool_result(make_tool_call("get_invoice", "{}"), dispatch=dispatch)


def test_escalation_from_the_openai_helper_raises():
    guard = Guard(policies=[ToolPolicy("wire", risk=RiskClass.WRITE, requires_approval=True)])
    with guard.session() as s, pytest.raises(ApprovalRequired):
        guarded_tool_result(make_tool_call("wire", "{}"), dispatch=dispatch, session=s)


def test_a_protected_tool_without_an_args_model_still_runs():
    """ไม่มี args_model = ไม่มีค่าที่ผ่าน coercion ให้ใช้แทน — ต้องเรียกด้วยค่าที่ caller ส่งมา"""
    guard = Guard(policies=[ToolPolicy("lookup", risk=RiskClass.READ)])

    @guard.protect(name="lookup")
    def lookup(term: str) -> str:
        return term.upper()

    with guard.session():
        assert lookup("abc") == "ABC"


def test_an_async_protected_function_can_return_an_error_dict_too():
    guard = Guard()

    @guard.protect(
        on_block="return",
        risk=RiskClass.CRITICAL,
        requires_approval=False,
        require=[Max("amount", 10)],
    )
    async def transfer(amount: float) -> str:
        return "sent"

    async def scenario() -> None:
        with guard.session():
            assert await transfer(5) == "sent"
            assert (await transfer(99))["code"] == "invariant_breach"

    asyncio.run(scenario())


def test_leaving_a_session_that_was_never_entered_is_harmless():
    """``guard.session()`` ที่ไม่ได้ใช้เป็น context manager ไม่ควรทำให้ contextvar เพี้ยน"""
    guard = build_guard()
    session = guard.session(context=CONTEXT)
    session.__exit__(None, None, None)
    assert current_session() is None


def test_observe_mode_lets_a_protected_call_through_without_validated_args():
    """โหมด observe เปลี่ยน BLOCK เป็น ALLOW ได้ตั้งแต่ชั้นแรกๆ ซึ่งยังไม่มีค่าที่ผ่าน
    ``args_model`` ให้ใช้ — ตัว decorator ต้องเรียก tool ด้วยค่าที่ caller ส่งมาแทน"""
    guard = Guard(mode="observe")  # ไม่มี policy เลย → enforce จะบล็อกทุกอย่าง

    @guard.protect
    def lookup(term: str) -> str:
        return term.upper()

    with guard.session() as s:
        assert lookup("abc") == "ABC"
        assert s.stats["suppressed"] == 1
