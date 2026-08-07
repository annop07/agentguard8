"""tool-calling loop แบบ OpenAI ที่มี TaintGuard คั่นอยู่ — รันได้เลย ไม่ต้องมี API key::

    python examples/openai_loop.py

เดโมนี้ต่างจาก ``injection_demo.py`` ตรงที่นั่นแสดง *ว่าทำไมต้องมีชั้นบังคับใช้*
ส่วนอันนี้แสดง *ว่าเสียบเข้า loop ที่มีอยู่แล้วยังไง* — โครงสร้าง loop ไม่ต้องแก้เลย
เปลี่ยนแค่บรรทัดที่เรียก tool ให้ผ่าน ``guarded_tool_result``

``client.chat.completions.create`` ถูกแทนด้วย stub เพราะสิ่งที่พิสูจน์คือทางเดินของข้อมูล
ไม่ใช่ความสามารถของโมเดล ตัว ``tool_call`` เป็น object ธรรมดาที่มี ``.id`` และ
``.function.name`` / ``.function.arguments`` เหมือน SDK จริงทุกประการ
"""

from __future__ import annotations

import json
from types import SimpleNamespace
from typing import Any

from taintguard import Guard, In, Max, RiskClass, ToolPolicy
from taintguard.adapters import guarded_tool_result

LEDGER = {"111-1": 120_000.0}


def get_balance(account: str) -> dict[str, Any]:
    return {"account": account, "balance": LEDGER.get(account, 0.0)}


def transfer_money(to_account: str, amount: float) -> dict[str, Any]:
    LEDGER["111-1"] -= amount
    return {"transferred": amount, "to": to_account}


TOOLS = {"get_balance": get_balance, "transfer_money": transfer_money}


def dispatch(tool: str, args: Any) -> dict[str, Any]:
    return TOOLS[tool](**args)


def tool_call(call_id: str, name: str, **args: Any) -> SimpleNamespace:
    """object รูปร่างเดียวกับที่ OpenAI SDK คืนมา"""
    return SimpleNamespace(
        id=call_id,
        function=SimpleNamespace(name=name, arguments=json.dumps(args)),
    )


def stub_llm(turn: int) -> list[SimpleNamespace]:
    """รอบแรกขอยอดคงเหลือ รอบสองพยายามโอนออกนอกบัญชีตัวเอง รอบสามยอมแพ้"""
    if turn == 0:
        return [tool_call("call_1", "get_balance", account="111-1")]
    if turn == 1:
        return [tool_call("call_2", "transfer_money", to_account="988-7712", amount=49_000)]
    return []


def main() -> None:
    guard = Guard(
        policies=[
            ToolPolicy("get_balance", risk=RiskClass.READ),
            ToolPolicy(
                "transfer_money",
                risk=RiskClass.CRITICAL,
                requires_approval=False,
                require=[In("to_account", ctx="own_accounts"), Max("amount", 5_000)],
            ),
        ],
    )

    messages: list[dict[str, Any]] = [{"role": "user", "content": "จ่ายใบแจ้งหนี้ให้หน่อย"}]

    with guard.session(context={"own_accounts": list(LEDGER)}) as session:
        for turn in range(3):
            calls = stub_llm(turn)
            if not calls:
                break

            for call in calls:
                # นี่คือบรรทัดเดียวที่ต่างจาก loop ที่ไม่มี TaintGuard
                message = guarded_tool_result(call, dispatch=dispatch, session=session)
                messages.append(message)

                content = json.loads(message["content"])
                verdict = content.get("error", "ok")
                print(f"  {call.function.name:<16} → {verdict}")
                if "reason" in content:
                    print(f"  {'':<16}   {content['reason']}")

    print()
    print(f"  ยอดคงเหลือ: {LEDGER['111-1']:,.2f}")
    print(f"  message ที่ส่งกลับให้โมเดล: {len(messages) - 1} รายการ shape เดียวกันทั้งหมด")
    print()
    for event in session.audit:
        print(f"  audit  {event.action.value:<8} {event.tool}")


if __name__ == "__main__":
    main()
