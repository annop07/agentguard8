"""ผลการตัดสินหนึ่งครั้ง.

``Decision`` เป็นสิ่งเดียวที่ ``Session.check()`` คืนออกมา — ทุกเส้นทางในระบบจบที่ object นี้
จึงตั้งใจให้มันตอบได้ครบสามคำถามในตัวเดียว: **เกิดอะไรขึ้น** (``action``)
**เพราะกฎประเภทไหน** (``code``) และ **กฎข้อไหนเป๊ะๆ** (``rule``)

``code`` กับ ``rule`` แยกกันโดยตั้งใจ: ``code`` เป็น enum ที่จะไม่เปลี่ยนข้ามเวอร์ชัน
ทีม security เอาไปตั้ง alert ใน SIEM ได้ ส่วน ``rule`` ละเอียดพอจะบอกได้ว่าต้องไปแก้ policy บรรทัดไหน
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from agentguard.errors import ApprovalRequired, Blocked


class Action(str, Enum):
    """ผลที่บังคับใช้จริงกับ tool call หนึ่งครั้ง

    มีแค่สามค่าโดยตั้งใจ ไม่มี ``WARN`` แยก — การเตือนคือ ``ALLOW`` ที่มี ``code`` ติดมาด้วย
    ซึ่งบันทึกลง audit ครบเหมือนกันทุกประการ ต่างกันแค่ไม่หยุดการทำงาน
    """

    ALLOW = "allow"
    BLOCK = "block"
    ESCALATE = "escalate"


class Reason(str, Enum):
    """หมวดของเหตุผล — เสถียรพอจะ aggregate ใน log ได้"""

    UNAUTHORIZED_TOOL = "unauthorized_tool"
    INVALID_ARGUMENTS = "invalid_arguments"
    INVARIANT_BREACH = "invariant_breach"
    TAINTED_ARGUMENT = "tainted_argument"
    BUDGET_EXCEEDED = "budget_exceeded"
    APPROVAL_REQUIRED = "approval_required"


# LLM ที่โดนบล็อกจะพยายามลองใหม่เสมอ — ถ้าไม่บอกว่าลองไปก็ไม่ผ่าน มันจะวนจนหมด iteration
# แล้วตอบ user ด้วยข้อมูลที่ไม่ครบ สู้บอกไปตรงๆ ตั้งแต่รอบแรกดีกว่า
_RETRYABLE: dict[Reason, bool] = {
    Reason.INVALID_ARGUMENTS: True,  # แก้รูปแบบ argument แล้วผ่านได้
    Reason.INVARIANT_BREACH: True,  # ลดจำนวน/เปลี่ยนค่าแล้วผ่านได้
    Reason.UNAUTHORIZED_TOOL: False,  # ไม่มีสิทธิ์ ลองกี่ครั้งก็ไม่มี
    Reason.TAINTED_ARGUMENT: False,  # ค่ามาจากแหล่งที่ห้ามใช้ เปลี่ยนรูปแบบไม่ช่วย
    Reason.BUDGET_EXCEEDED: False,  # โควตาหมดแล้ว
    Reason.APPROVAL_REQUIRED: False,  # ต้องรอคน ไม่ใช่เรื่องที่ LLM แก้เองได้
}


@dataclass(frozen=True)
class Decision:
    """ผลการตรวจ tool call หนึ่งครั้ง"""

    action: Action
    tool: str
    code: Reason | None = None
    rule: str | None = None
    reason: str = ""
    evidence: dict[str, Any] = field(default_factory=dict)
    observed_action: Action | None = None
    """โหมด observe: สิ่งที่ *จะ* เกิดถ้าอยู่ในโหมด enforce (ปกติเป็น ``None``)"""

    validated_args: dict[str, Any] | None = None
    """argument หลังผ่าน ``args_model`` แล้ว — มีค่าเมื่อ decision อนุญาตให้ทำงานต่อ

    ควรใช้ค่านี้เรียก tool แทน argument ดิบ ไม่งั้นกฎจะตรวจค่าที่ผ่าน coercion แล้ว
    แต่ tool ได้รับค่าดิบ ซึ่งเป็นคนละค่ากันได้ (เช่น ``"49000"`` กับ ``49000.0``)
    """

    @property
    def allowed(self) -> bool:
        return self.action is Action.ALLOW

    @property
    def suppressed(self) -> bool:
        """True เมื่อโหมด observe กลืนการบังคับใช้ไว้ — ใช้แยก log ตอนทำ dry run"""
        return self.observed_action is not None

    @property
    def retryable(self) -> bool:
        return _RETRYABLE.get(self.code, False) if self.code else False

    def as_tool_error(self) -> dict[str, Any]:
        """payload ที่ส่งกลับให้ LLM ในฐานะผลลัพธ์ของ tool

        รูปแบบคงที่ข้ามทุก tool และทุกเหตุผล เพื่อให้โมเดลจับ pattern ได้จากตัวอย่างเดียว
        """
        return {
            "error": "blocked_by_policy",
            "code": self.code.value if self.code else None,
            "tool": self.tool,
            "reason": self.reason,
            "retryable": self.retryable,
        }

    def raise_for_action(self, args: dict[str, Any] | None = None) -> None:
        """แปลง decision เป็น exception — ใช้ในเส้นทางที่เรียกฟังก์ชันตรงๆ"""
        if self.action is Action.BLOCK:
            raise Blocked(self)
        if self.action is Action.ESCALATE:
            raise ApprovalRequired(self, self.tool, args or {})

    def __str__(self) -> str:
        head = f"{self.action.value.upper():8} {self.tool}"
        if self.code is None:
            return f"{head}  —"
        return f"{head}  {self.code.value}" + (f" · {self.reason}" if self.reason else "")
