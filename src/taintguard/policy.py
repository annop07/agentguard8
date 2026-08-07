"""Policy — กฎประจำ tool หนึ่งตัว

``RiskClass`` ไม่ใช่ป้ายประดับ มันคือสิ่งที่ทำให้ระบบใช้งานได้จริง: ถ้าตรวจ taint กับทุก tool
เท่ากันหมด ระบบจะเต็มไปด้วย false positive จนคนปิดทิ้ง — user ค้นหาข้อความที่บังเอิญ
มาจากเอกสารที่ taint ไว้ก็จะโดนบล็อกทั้งที่แค่อ่านข้อมูล

การให้ ``READ`` ข้าม taint check จึงไม่ใช่ช่องโหว่ แต่เป็นเงื่อนไขที่ทำให้ชั้นบังคับใช้
อยู่รอดในระบบจริงได้
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from pydantic import BaseModel

from taintguard.decisions import Action
from taintguard.errors import PolicyConfigError
from taintguard.rules import Rule

TAINT_ALL = "*"


class RiskClass(str, Enum):
    """ความเสียหายถ้า tool ตัวนี้ถูกเรียกผิด"""

    READ = "read"
    """อ่านอย่างเดียว ไม่มี side effect"""

    WRITE = "write"
    """เปลี่ยน state แต่ย้อนกลับได้"""

    EXTERNAL = "external"
    """ส่งข้อมูลออกนอก trust boundary — อีเมล, HTTP, webhook"""

    CRITICAL = "critical"
    """ย้อนกลับไม่ได้ — โอนเงิน, ลบข้อมูล, เปลี่ยนสิทธิ์"""

    @property
    def default_taint_action(self) -> Action | None:
        """``None`` = ไม่ตรวจ taint · ``ALLOW`` = ตรวจแล้วบันทึกไว้แต่ไม่หยุด (warn)"""
        return {
            RiskClass.READ: None,
            RiskClass.WRITE: Action.ALLOW,
            RiskClass.EXTERNAL: Action.BLOCK,
            RiskClass.CRITICAL: Action.BLOCK,
        }[self]

    @property
    def default_requires_approval(self) -> bool:
        return self is RiskClass.CRITICAL


@dataclass
class ToolPolicy:
    """กฎทั้งหมดของ tool หนึ่งตัว

    ค่าที่ปล่อยเป็น ``None`` จะถูกเติมจาก ``risk`` ให้อัตโนมัติ — ประกาศ ``risk`` อย่างเดียว
    ก็ได้พฤติกรรมที่ปลอดภัยตามชั้นความเสี่ยงแล้ว ระบุเองเมื่อต้องการแย้งค่า default เท่านั้น
    """

    name: str
    risk: RiskClass = RiskClass.WRITE
    args_model: type[BaseModel] | None = None
    require: Sequence[Rule] = field(default_factory=tuple)
    taint_fields: Sequence[str] | str | None = None
    taint_action: Action | None = None
    requires_approval: bool | None = None
    max_calls_per_session: int | None = None
    description: str = ""

    def __post_init__(self) -> None:
        if not self.name:
            raise PolicyConfigError("ToolPolicy ต้องมี name")
        if self.max_calls_per_session is not None and self.max_calls_per_session < 0:
            raise PolicyConfigError(f"{self.name}: max_calls_per_session ต้องไม่ติดลบ")

        if self.taint_action is None:
            self.taint_action = self.risk.default_taint_action
        if self.requires_approval is None:
            self.requires_approval = self.risk.default_requires_approval

        # ไม่ระบุ field = ตรวจทุก field (fail closed) ยกเว้น READ ที่ไม่ตรวจเลย
        if self.taint_fields is None and self.taint_action is not None:
            self.taint_fields = TAINT_ALL

    @property
    def taint_enabled(self) -> bool:
        """``taint_fields=[]`` คือวิธีปิด taint บน tool ที่ความเสี่ยงสูง

        ``taint_action=None`` ปิดไม่ได้ เพราะ ``None`` แปลว่า "ใช้ค่าตามชั้นความเสี่ยง"
        การปิดจึงต้องประกาศออกมาให้เห็นว่า "ตรวจ field เหล่านี้: ไม่มีเลย" ซึ่งอ่านแล้วรู้ว่า
        เป็นการตัดสินใจ ไม่ใช่ลืมตั้งค่า
        """
        return (
            self.taint_action is not None
            and self.taint_fields is not None
            and len(self.taint_fields) > 0
        )

    def taint_targets(self, args: dict[str, Any]) -> list[str]:
        """field ที่ต้องเอาไปตรวจ provenance สำหรับ argument ชุดนี้"""
        if not self.taint_enabled:
            return []
        if self.taint_fields == TAINT_ALL:
            return list(args)
        assert self.taint_fields is not None
        return [f for f in self.taint_fields if f != TAINT_ALL]
