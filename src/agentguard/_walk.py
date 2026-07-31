"""การเดินเข้าไปใน argument — ใช้ร่วมกันระหว่างชั้นกฎกับชั้น taint

argument ที่ LLM ส่งมาไม่ได้แบนเสมอไป ทั้งกฎและ provenance matching จึงต้องเข้าถึง
ค่าที่ซ้อนอยู่ในชั้นลึกได้เหมือนกัน
"""

from __future__ import annotations

from collections.abc import Iterator, Mapping
from typing import Any

MISSING = object()


def lookup_path(args: Mapping[str, Any], path: str) -> Any:
    """อ่านค่าจาก args รองรับ path แบบจุด (``payment.amount``)"""
    current: Any = args
    for part in path.split("."):
        if not isinstance(current, Mapping) or part not in current:
            return MISSING
        current = current[part]
    return current


def iter_scalars(value: Any) -> Iterator[str | int | float]:
    """ไล่เก็บค่าเดี่ยวทุกตัวที่ซ่อนอยู่ใน dict/list

    ข้าม ``bool`` และ ``None`` โดยตั้งใจ — สองอย่างนี้ไม่ได้พาข้อมูลที่ attacker
    กำหนดได้มาด้วย และ ``True`` ที่กลายเป็น ``"true"`` มีโอกาสไปชนข้อความจริงโดยบังเอิญสูง
    """
    if isinstance(value, bool) or value is None:
        return
    if isinstance(value, (str, int, float)):
        yield value
    elif isinstance(value, Mapping):
        for item in value.values():
            yield from iter_scalars(item)
    elif isinstance(value, (list, tuple, set, frozenset)):
        for item in value:
            yield from iter_scalars(item)


def text_of(value: str | int | float) -> str:
    """ข้อความมาตรฐานสำหรับเทียบ

    ``float`` ที่เป็นจำนวนเต็มต้องตัด ``.0`` ทิ้งก่อน ไม่งั้น ``49000.0`` จะกลายเป็น
    ``"490000"`` หลัง normalize แล้วเทียบกับ ``"49000"`` ในข้อความต้นทางไม่ติด
    """
    if isinstance(value, float) and value.is_integer():
        return str(int(value))
    return str(value)
