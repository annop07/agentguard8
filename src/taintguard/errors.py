"""Exceptions.

การบล็อกมีสองเส้นทางโดยตั้งใจ:

* ``session.check()`` และ ``wrap_dispatcher()`` **คืน** ``Decision`` เพราะอยู่ใน agent loop —
  ถ้า raise ตรงนั้น loop จะพังทั้งรอบ ทั้งที่สิ่งที่ควรเกิดคือ LLM ได้ error กลับไปแก้เอง
* decorator ``@guard.protect`` **raise** เพราะเป็นการเรียกฟังก์ชันตรงๆ การคืน error dict
  ให้ caller ที่คาดหวังค่าจริงคือการซ่อนความล้มเหลว

``ESCALATE`` raise เสมอทั้งสองเส้นทาง เพราะไม่มีคำตอบให้คืนจนกว่าคนจะตัดสิน
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:  # pragma: no cover - typing only
    from taintguard.decisions import Decision


class TaintGuardError(Exception):
    """ฐานของ error ทุกตัวในแพ็กเกจ — จับตัวเดียวได้ทั้งหมด"""


class PolicyConfigError(TaintGuardError):
    """policy เขียนผิดตั้งแต่ตอนประกาศ (คนละเรื่องกับ tool call ที่ผิดกฎ)"""


class Blocked(TaintGuardError):
    """tool call ถูกบล็อกโดย policy"""

    def __init__(self, decision: Decision) -> None:
        self.decision = decision
        super().__init__(f"{decision.tool}: {decision.reason}")


class ApprovalRequired(TaintGuardError):
    """tool call ต้องให้คนอนุมัติก่อน

    ผู้เรียกตัดสินใจแล้วเรียก ``approve()`` หรือ ``deny()`` — ตัว exception ถือสถานะไว้
    เพื่อให้ flow ที่ส่งต่อไป Slack/คิวอนุมัติ เอา object นี้ไปทั้งก้อนได้
    """

    def __init__(self, decision: Decision, tool: str, tool_args: dict[str, object]) -> None:
        self.decision = decision
        self.tool = tool
        # ตั้งชื่อ tool_args ไม่ใช่ args เพราะ BaseException.args เป็นของ Python เอง
        # การทับมันทำให้ pickle และ repr ของ exception เพี้ยน
        self.tool_args = tool_args
        self.resolved: bool | None = None
        super().__init__(f"{tool}: {decision.reason}")

    def approve(self) -> None:
        self.resolved = True

    def deny(self) -> None:
        self.resolved = False

    @property
    def approved(self) -> bool:
        """ยังไม่ตัดสิน = ยังไม่อนุมัติ (fail closed)"""
        return self.resolved is True
