"""ครอบ dispatcher ที่มีอยู่แล้วให้ตรวจ policy ก่อนเรียก tool จริง"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import Any

from taintguard.decisions import Action
from taintguard.errors import PolicyConfigError
from taintguard.guard import OnBlock, Session, current_session

Dispatcher = Callable[[str, Mapping[str, Any]], Any]


def wrap_dispatcher(
    dispatch: Dispatcher,
    *,
    session: Session | None = None,
    on_block: OnBlock = "return",
) -> Dispatcher:
    """คืน dispatcher ที่ signature เหมือนเดิม แต่ตรวจ policy ก่อนเรียกของจริง

    เส้นทางนี้ **คืน error dict** เป็นค่า default ต่างจาก ``@guard.protect`` ที่ raise —
    เพราะมันอยู่ใน agent loop การ raise จะทำให้ทั้งรอบพัง ทั้งที่สิ่งที่ควรเกิดคือ LLM
    ได้ error กลับไปแล้วแก้เองในรอบถัดไป ตั้ง ``on_block="raise"`` เมื่อต้องการหยุดจริง

    ``ESCALATE`` raise เสมอไม่ว่าตั้ง ``on_block`` เป็นอะไร เพราะยังไม่มีคำตอบให้คืน
    จนกว่าคนจะตัดสิน การคืน error dict จะทำให้ LLM คิดว่าเรื่องจบแล้ว

    ไม่ส่ง ``session`` มาก็ได้ — จะไปหยิบจาก ``contextvars`` ตอนถูกเรียก ซึ่งทำให้ครอบ
    dispatcher ครั้งเดียวตอน startup แล้วใช้ได้กับทุก session ที่ตามมา
    """

    def guarded(tool: str, args: Mapping[str, Any]) -> Any:
        active = session or current_session()
        if active is None:
            raise PolicyConfigError(
                f"wrap_dispatcher ถูกเรียกสำหรับ {tool!r} โดยไม่มี session — "
                "ส่ง session=... ตอนครอบ หรือเรียกภายใน with guard.session(...)"
            )

        decision = active.check(tool, args)
        if not decision.allowed:
            # ESCALATE raise เสมอ แม้ on_block="return" — ยังไม่มีคำตอบให้คืนจนกว่าคนจะตัดสิน
            # และ error dict จะทำให้ LLM เข้าใจว่าเรื่องจบแล้ว
            if on_block == "raise" or decision.action is Action.ESCALATE:
                decision.raise_for_action(dict(args))
            return decision.as_tool_error()

        return dispatch(tool, decision.validated_args or dict(args))

    return guarded
