"""ตัวช่วยสำหรับ tool-calling loop แบบ OpenAI

ไม่ import ``openai`` — รับ object อะไรก็ได้ที่มี ``.id`` และ ``.function.name`` /
``.function.arguments`` ตาม shape ของ chat completions ทำให้ใช้ได้กับ SDK ตัวจริง
กับ endpoint ที่ compatible และกับ object จำลองในเทสต์ โดยไม่ต้องเพิ่ม dependency
ให้แพ็กเกจที่ตอนนี้พึ่งแค่ pydantic
"""

from __future__ import annotations

import json
from collections.abc import Callable, Mapping
from typing import Any

from agentguard.decisions import Action
from agentguard.errors import PolicyConfigError
from agentguard.guard import Session, current_session

Dispatcher = Callable[[str, Mapping[str, Any]], Any]


def parse_tool_call(tool_call: Any) -> tuple[str, str, dict[str, Any] | None]:
    """แกะ ``(call_id, tool_name, args)`` ออกจาก tool_call

    ``args`` เป็น ``None`` เมื่อ JSON ที่โมเดลคายออกมาพัง ซึ่งเกิดจริงและไม่ใช่เรื่อง
    ผิดปกติ — ผู้เรียกควรส่ง error กลับไปให้โมเดลแก้ ไม่ใช่ปล่อยให้ loop ตาย
    """
    function = getattr(tool_call, "function", None)
    if function is None or not hasattr(function, "name"):
        raise PolicyConfigError(
            "tool_call ต้องมี .function.name และ .function.arguments ตาม shape ของ "
            f"OpenAI chat completions — ได้ {type(tool_call).__name__} มาแทน"
        )

    call_id = str(getattr(tool_call, "id", "") or "")
    raw = getattr(function, "arguments", "") or "{}"
    try:
        parsed = json.loads(raw)
    except (TypeError, json.JSONDecodeError):
        return call_id, str(function.name), None

    # โมเดลคาย JSON ที่ถูกต้องแต่ไม่ใช่ object ได้ เช่น "[]" — ซึ่งเป็น argument ที่ใช้ไม่ได้
    return call_id, str(function.name), parsed if isinstance(parsed, dict) else None


def guarded_tool_result(
    tool_call: Any,
    *,
    dispatch: Dispatcher,
    session: Session | None = None,
) -> dict[str, Any]:
    """ตรวจ policy แล้วคืน message สำหรับ ``role: "tool"`` ที่ต่อท้าย ``messages`` ได้เลย

    ทั้งผลลัพธ์จริงและ error จาก policy ออกมาเป็น shape เดียวกัน โมเดลจึงเห็นรูปแบบ
    เดียวตลอด loop และเรียนรู้ได้จากตัวอย่างเดียวว่าต้องแก้อะไร

    ``ESCALATE`` raise ``ApprovalRequired`` — loop เดินต่อไม่ได้จนกว่าคนจะตัดสิน
    """
    active = session or current_session()
    if active is None:
        raise PolicyConfigError(
            "guarded_tool_result ต้องมี session — ส่ง session=... หรือเรียกภายใน with guard.session(...)"
        )

    call_id, tool, args = parse_tool_call(tool_call)

    if args is None:
        return _message(
            call_id,
            {
                "error": "invalid_tool_arguments",
                "tool": tool,
                "reason": "arguments were not a JSON object",
                "retryable": True,
            },
        )

    decision = active.check(tool, args)
    if decision.action is Action.ESCALATE:
        decision.raise_for_action(args)
    if not decision.allowed:
        return _message(call_id, decision.as_tool_error())

    return _message(call_id, dispatch(tool, decision.validated_args or args))


def _message(call_id: str, content: Any) -> dict[str, Any]:
    return {
        "role": "tool",
        "tool_call_id": call_id,
        "content": content
        if isinstance(content, str)
        else json.dumps(content, ensure_ascii=False, default=str),
    }
