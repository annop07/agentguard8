"""Argument invariants — กฎที่บังคับว่า tool call ต้องถูกต้องเทียบกับข้อมูลจริง ไม่ใช่แค่ถูกรูปแบบ

schema validation ตอบได้แค่ว่า ``amount`` เป็นตัวเลข กฎพวกนี้ตอบว่า ``amount`` ไม่เกินเพดาน
และ ``to_account`` เป็นบัญชีของ user คนนี้จริง — ซึ่งเป็นคนละคำถามกันโดยสิ้นเชิง

ทุกกฎเป็น pure function ``(args, context) -> str | None`` (``None`` = ผ่าน) จึงเทสต์ได้ตรงๆ
ไม่ต้อง mock อะไรเลย นั่นคือเหตุผลที่ core ของแพ็กเกจนี้ไม่มีโมเดลอยู่ในนั้น

**field ที่ไม่มีในargs** ปฏิบัติต่างกันตามความหมายของกฎ:

* ``Max``/``Min``/``Matches`` เป็นกฎ *ขอบเขต* — ไม่มีค่า = ไม่มีอะไรให้เกินขอบ → ผ่าน
* ``In``/``Present`` เป็นกฎ *ต้องมีและต้องอยู่ในชุดที่อนุญาต* — ไม่มีค่า = ไม่ผ่าน (fail closed)

การบังคับว่า field ไหน required เป็นหน้าที่ของ ``args_model`` ซึ่งทำงานก่อนกฎพวกนี้เสมอ

**ข้อความของกฎต้องไม่ echo ค่าที่ถูกส่งเข้ามา** — บอกได้แค่ชื่อ field กับค่าที่มาจากฝั่ง policy
(เพดาน, จำนวนรายการใน allowlist, pattern) เพราะข้อความนี้ไหลลง audit log ที่มีอายุเก็บยาว
และมักถูกส่งต่อไป SIEM การใส่ค่าดิบลงไปเท่ากับสร้างที่เก็บ PII แห่งที่สองโดยไม่ตั้งใจ

ข้อจำกัดนี้ไม่ทำให้ LLM แก้ตัวเองได้แย่ลง เพราะ LLM เป็นคนสร้าง argument นั้นมาเองเมื่อครู่
สิ่งที่มันยังไม่รู้คือ *ขอบเขต* ซึ่งยังบอกอยู่ครบ
"""

from __future__ import annotations

import re
from abc import ABC, abstractmethod
from collections.abc import Callable, Collection, Mapping
from dataclasses import dataclass, field
from typing import Any

from taintguard._walk import MISSING, lookup_path
from taintguard.errors import PolicyConfigError


def _as_number(value: Any) -> float | None:
    """LLM ชอบคืนตัวเลขมาเป็น string — ยอมรับได้ แต่สิ่งที่แปลงไม่ได้ต้องไม่เงียบ"""
    if isinstance(value, bool):
        return None  # bool เป็น subclass ของ int ใน Python — ไม่ใช่ตัวเลขที่เราหมายถึง
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value.strip().replace(",", ""))
        except ValueError:
            return None
    return None


class Rule(ABC):
    """กฎหนึ่งข้อ"""

    @property
    @abstractmethod
    def name(self) -> str:
        """ชื่อที่ขึ้นใน audit log — ต้องชี้ได้ว่าไปแก้ policy ตรงไหน"""

    @abstractmethod
    def check(self, args: Mapping[str, Any], context: Mapping[str, Any]) -> str | None:
        """คืน ``None`` ถ้าผ่าน หรือข้อความอธิบายว่าทำไมไม่ผ่าน"""


@dataclass(frozen=True)
class Max(Rule):
    """ค่าตัวเลขต้องไม่เกินเพดาน"""

    field: str
    limit: float

    @property
    def name(self) -> str:
        return f"Max({self.field})"

    def check(self, args: Mapping[str, Any], context: Mapping[str, Any]) -> str | None:
        value = lookup_path(args, self.field)
        if value is MISSING:
            return None
        number = _as_number(value)
        if number is None:
            return f"{self.field} is not a number"
        if number > self.limit:
            return f"{self.field} exceeds the maximum of {self.limit:g}"
        return None


@dataclass(frozen=True)
class Min(Rule):
    """ค่าตัวเลขต้องไม่ต่ำกว่าขั้นต่ำ"""

    field: str
    limit: float

    @property
    def name(self) -> str:
        return f"Min({self.field})"

    def check(self, args: Mapping[str, Any], context: Mapping[str, Any]) -> str | None:
        value = lookup_path(args, self.field)
        if value is MISSING:
            return None
        number = _as_number(value)
        if number is None:
            return f"{self.field} is not a number"
        if number < self.limit:
            return f"{self.field} is below the minimum of {self.limit:g}"
        return None


@dataclass(frozen=True)
class In(Rule):
    """ค่าต้องอยู่ในชุดที่อนุญาต

    ชุดที่อนุญาตมาได้สองทาง: ระบุตรงๆ ด้วย ``values`` หรือดึงจาก session context ด้วย ``ctx``
    แบบหลังคือกฎที่สำคัญที่สุดสำหรับระบบที่แตะข้อมูลจริง เพราะมันผูก tool call
    เข้ากับข้อมูลของ user คนนั้นตอน runtime::

        In("to_account", ctx="own_accounts")
    """

    field: str
    values: Collection[Any] | None = None
    ctx: str | None = None

    def __post_init__(self) -> None:
        if (self.values is None) == (self.ctx is None):
            raise PolicyConfigError(
                f"In({self.field!r}) ต้องระบุ values หรือ ctx อย่างใดอย่างหนึ่ง (ไม่ใช่ทั้งคู่)"
            )

    @property
    def name(self) -> str:
        return f"In({self.field})"

    def check(self, args: Mapping[str, Any], context: Mapping[str, Any]) -> str | None:
        if self.ctx is not None:
            if self.ctx not in context:
                # policy อ้าง context ที่ session ไม่ได้ส่งมา — เป็นความผิดพลาดของคนเขียนโค้ด
                # ไม่ใช่การโจมตี แต่ยังต้อง fail closed ไม่งั้นกฎจะหายไปเงียบๆ
                return f"context key {self.ctx!r} was not provided to the session"
            allowed: Collection[Any] = context[self.ctx]
        else:
            assert self.values is not None
            allowed = self.values

        value = lookup_path(args, self.field)
        if value is MISSING:
            return f"{self.field} is missing and cannot be checked against the allowlist"

        if value in allowed:
            return None
        # LLM คืนทุกอย่างมาเป็น string เสมอ เทียบแบบ string อีกรอบก่อนตัดสินว่าไม่ผ่าน
        if str(value) in {str(item) for item in allowed}:
            return None
        return f"{self.field} is not in the allowed set ({len(list(allowed))} entries)"


@dataclass(frozen=True)
class Matches(Rule):
    """ค่า string ต้องเข้ากับ regex"""

    field: str
    pattern: str

    def __post_init__(self) -> None:
        try:
            re.compile(self.pattern)
        except re.error as exc:
            raise PolicyConfigError(f"Matches({self.field!r}): regex ไม่ถูกต้อง — {exc}") from exc

    @property
    def name(self) -> str:
        return f"Matches({self.field})"

    def check(self, args: Mapping[str, Any], context: Mapping[str, Any]) -> str | None:
        value = lookup_path(args, self.field)
        if value is MISSING:
            return None
        if not isinstance(value, str):
            return f"{self.field} is not a string"
        if re.search(self.pattern, value) is None:
            return f"{self.field} does not match the required pattern {self.pattern!r}"
        return None


@dataclass(frozen=True)
class Present(Rule):
    """field ต้องมีอยู่และต้องไม่ว่าง"""

    field: str

    @property
    def name(self) -> str:
        return f"Present({self.field})"

    def check(self, args: Mapping[str, Any], context: Mapping[str, Any]) -> str | None:
        value = lookup_path(args, self.field)
        if value is MISSING or value is None or value == "":
            return f"{self.field} is required but missing"
        return None


@dataclass(frozen=True)
class Predicate(Rule):
    """escape hatch สำหรับกฎที่ประกาศแบบอื่นไม่ได้

    ฟังก์ชันต้อง deterministic — ถ้าไปเรียก network หรือโมเดล จะทำให้ทั้งแพ็กเกจ
    เสียคุณสมบัติที่เป็นจุดขาย และเทสต์จะไม่บอกความจริงอีกต่อไป
    """

    fn: Callable[[Mapping[str, Any], Mapping[str, Any]], bool]
    label: str = "Predicate"
    message: str = field(default="")

    @property
    def name(self) -> str:
        return self.label if self.label.startswith("Predicate") else f"Predicate({self.label})"

    def check(self, args: Mapping[str, Any], context: Mapping[str, Any]) -> str | None:
        try:
            ok = self.fn(args, context)
        except Exception as exc:
            return f"predicate {self.label!r} raised {type(exc).__name__}"
        if ok:
            return None
        return self.message or f"predicate {self.label!r} was not satisfied"
