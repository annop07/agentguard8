"""Provenance tracking — หัวใจของแพ็กเกจ

**ข้อสังเกตที่เป็นแกนของดีไซน์นี้:** taint แบบผูกกับตัวแปร Python (``TaintedStr`` ที่ไหลตาม
การต่อสตริง) **ใช้บังคับกับ agent ไม่ได้** เพราะข้อมูลเดินทางผ่าน LLM — untrusted text
เข้าไปอยู่ใน prompt แล้ว LLM คาย argument ออกมาเป็น string ใหม่คนละ object จาก API response
ไม่มี taint ที่ผูกกับ object อันไหนข้ามช่องว่างตรงนั้นไปได้

เราจึงกลับด้าน: จำ span ที่ไม่น่าเชื่อถือไว้ใน ledger แล้วถามว่า argument ที่ LLM คายออกมา
**สืบสายมาจาก** span ไหนหรือเปล่า — เป็นการเทียบข้อความล้วนๆ deterministic 100%

``TaintedStr`` ยังมีอยู่ (ดูท้ายไฟล์) แต่บทบาทของมันคือ *ตัวช่วยลงทะเบียน* ไม่ใช่ตัวบังคับ

**สิ่งที่วิธีนี้จับไม่ได้:** argument ที่ attacker ไม่ได้ป้อนค่าตรงๆ เช่นสั่งว่า
"โอนเงินทั้งหมดที่มี" แล้ว LLM ไปคำนวณยอดจาก tool ที่เชื่อถือได้ — เคสนั้นเป็นหน้าที่ของ
``Max()`` invariant กับ ``requires_approval`` ป้องกันซ้อนอีกชั้น
"""

from __future__ import annotations

import unicodedata
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any, Literal, SupportsIndex

from taintguard._walk import MISSING, iter_scalars, lookup_path, text_of


def _keep(char: str) -> bool:
    """ตัวอักษรนี้เป็นเนื้อความ (ไม่ใช่เครื่องหมายวรรคตอน) หรือเปล่า

    ใช้ ``unicodedata`` แทน ``\\w`` ของ ``re`` เพราะ ``\\w`` ตัดสินจาก ``isalnum()``
    ซึ่ง **วรรณยุกต์และสระไทยไม่ผ่าน** (เป็น Unicode category ``Mn`` — combining mark
    ที่ไม่ใช่ตัวอักษรในตัวเอง) ผลคือ ``"ค่ากาแฟ"`` จะถูกกลืนเหลือ ``"คากาแฟ"``

    เรื่องนี้ไม่ได้ทำให้ attacker หลุด (span กับ argument ผ่านฟังก์ชันเดียวกัน) แต่ทำให้
    ข้อความไทยสองอันที่ต่างกันจริงกลายเป็นอันเดียวกัน — false positive เพิ่มโดยไม่มีเหตุผล
    และเป็นข้อบกพร่องที่น่าอายสำหรับแพ็กเกจที่บอกว่ารองรับภาษาไทย
    """
    return char.isalnum() or char == "_" or unicodedata.category(char).startswith("M")


def normalize(text: str) -> str:
    """ปรับข้อความให้เทียบกันได้ — พิมพ์เล็ก, ตัดเครื่องหมายวรรคตอน, ยุบช่องว่าง

    รองรับทุกระบบเขียน ตัวกรองแบบ ASCII-only จะล้างข้อความไทยจนเหลือค่าว่าง
    แล้วทุกการเทียบจะหลุดหมดโดยไม่มีใครรู้

    เครื่องหมายถูก *ลบ* ไม่ใช่แทนที่ด้วยช่องว่าง เพื่อให้ ``"999-9"`` กับ ``"9999"``
    และ ``"49,000"`` กับ ``49000`` เทียบกันติด ซึ่งเป็นรูปแบบที่ LLM สลับไปมาตลอด

    ฟังก์ชันนี้ idempotent — เรียกซ้ำได้ผลเดิม
    """
    kept: list[str] = []
    for char in text.lower():
        if _keep(char):
            kept.append(char)
        elif char.isspace():
            kept.append(" ")
        # เครื่องหมายวรรคตอนถูกลบทิ้งเฉยๆ ไม่แทนที่ด้วยช่องว่าง
    return " ".join("".join(kept).split())


def _ngrams(tokens: list[str], k: int) -> set[str]:
    return {" ".join(tokens[i : i + k]) for i in range(len(tokens) - k + 1)}


@dataclass(frozen=True)
class TaintSpan:
    """ข้อความหนึ่งก้อนที่มาจากแหล่งไม่น่าเชื่อถือ"""

    text: str
    source: str
    label: str = "untrusted"


@dataclass(frozen=True)
class TaintMatch:
    """หลักฐานว่า argument สืบสายมาจาก span ไหน"""

    source: str
    label: str
    kind: Literal["contains", "ngram"]
    """``contains`` = ค่าไปโผล่ในข้อความต้นทางตรงๆ · ``ngram`` = มีท่อนต่อเนื่องตรงกัน"""

    def as_evidence(self) -> dict[str, str]:
        return {"source": self.source, "label": self.label, "match": self.kind}


@dataclass(frozen=True)
class _Registered:
    normalized: str
    ngrams: frozenset[str]
    source: str
    label: str


class TaintLedger:
    """ทะเบียนข้อความที่ไม่น่าเชื่อถือของ session หนึ่ง

    :param min_match_chars:
        ค่าที่สั้นกว่านี้ (หลัง normalize) ถือว่าสะอาดเสมอ — ``"5"`` หรือ ``"ปี"``
        ไปโผล่ในข้อความไหนก็ได้ ถ้าไม่ตัดทิ้งจะได้ false positive จนใช้งานไม่ได้
    :param ngram_k:
        จำนวน token ต่อเนื่องที่ถือว่า "คัดลอกมา" — จับกรณีที่ LLM เรียบเรียงใหม่
        แต่ยังยกข้อความบางท่อนมาทั้งดุ้น และจับได้สองทิศ ทั้ง argument ที่เป็นชิ้นส่วน
        ของข้อความต้นทาง และ argument ที่กลืนข้อความต้นทางเข้าไปทั้งก้อน
    """

    def __init__(self, *, min_match_chars: int = 4, ngram_k: int = 3) -> None:
        self.min_match_chars = min_match_chars
        self.ngram_k = ngram_k
        self._spans: list[_Registered] = []
        self._trusted: set[str] = set()

    def __len__(self) -> int:
        return len(self._spans)

    def add(self, text: str, *, source: str, label: str = "untrusted") -> None:
        normalized = normalize(text)
        if not normalized:
            return
        self._spans.append(
            _Registered(
                normalized=normalized,
                ngrams=frozenset(_ngrams(normalized.split(" "), self.ngram_k)),
                source=source,
                label=label,
            )
        )

    def add_spans(self, spans: Iterable[TaintSpan]) -> int:
        before = len(self._spans)
        for span in spans:
            self.add(span.text, source=span.source, label=span.label)
        return len(self._spans) - before

    def trust(self, value: object) -> None:
        """ประกาศว่าค่านี้ปลอดภัยเสมอ แม้จะไปโผล่ในข้อความที่ taint ไว้

        เป็นเครื่องมือหลักในการคุม false positive — เลขบัญชีของ user เอง โดเมนบริษัท
        หรือรหัสสินค้าที่ปรากฏทั้งในอีเมลของ attacker และในข้อมูลจริง
        """
        normalized = normalize(text_of(value))  # type: ignore[arg-type]
        if normalized:
            self._trusted.add(normalized)

    def match(self, value: object) -> TaintMatch | None:
        """ค่านี้สืบสายมาจาก span ที่ลงทะเบียนไว้หรือเปล่า"""
        if isinstance(value, bool) or value is None:
            return None
        if not isinstance(value, (str, int, float)):
            return None

        text = normalize(text_of(value))
        if not text or text in self._trusted or len(text) < self.min_match_chars:
            return None

        for span in self._spans:
            if text in span.normalized:
                return TaintMatch(span.source, span.label, "contains")

        tokens = text.split(" ")
        if len(tokens) >= self.ngram_k:
            grams = _ngrams(tokens, self.ngram_k)
            for span in self._spans:
                if grams & span.ngrams:
                    return TaintMatch(span.source, span.label, "ngram")
        return None

    def scan(self, args: Mapping[str, Any], fields: Iterable[str]) -> dict[str, TaintMatch]:
        """ตรวจทุก field ที่ระบุ คืนเฉพาะ field ที่พบว่าสืบสายมาจากแหล่งไม่น่าเชื่อถือ"""
        found: dict[str, TaintMatch] = {}
        for field in fields:
            value = lookup_path(args, field)
            if value is MISSING:
                continue
            for scalar in iter_scalars(value):
                hit = self.match(scalar)
                if hit is not None:
                    found[field] = hit
                    break
        return found


# ── ตัวช่วยฝั่งก่อนถึง LLM ────────────────────────────────────────────────────


def spans_of(value: object) -> tuple[TaintSpan, ...]:
    return value.spans if isinstance(value, TaintedStr) else ()


class TaintedStr(str):
    """``str`` ที่จำได้ว่าตัวเองมาจากไหน

    ใช้ตอนประกอบ prompt เพื่อให้ไม่ต้องไล่เรียก :meth:`Session.taint` เองทุกจุด::

        body = tainted(email.body, source="email:4821")
        prompt = "สรุปอีเมลนี้:\\n" + body
        session.attach(prompt)          # ดูด span ที่ปนอยู่เข้า ledger

    **f-string ทำให้เครื่องหมายหาย** — ``f"{body}"`` ให้ ``str`` ธรรมดาเสมอ เพราะ CPython
    ประกอบผลลัพธ์ขึ้นใหม่ในระดับ C ไม่มี subclass ไหนแทรกได้ ใช้ ``+`` ``%`` หรือ
    ``"".join()`` แทน หรือเรียก :meth:`Session.taint` ตรงๆ ซึ่งได้ผลเท่ากันและไม่มีข้อยกเว้น

    ข้อจำกัดนี้ไม่กระทบความปลอดภัย เพราะตัวที่บังคับใช้จริงคือ :class:`TaintLedger`
    คลาสนี้เป็นแค่ทางลัดในการลงทะเบียนเท่านั้น
    """

    __slots__ = ("spans",)

    spans: tuple[TaintSpan, ...]

    def __new__(cls, value: str, spans: Iterable[TaintSpan] = ()) -> TaintedStr:
        obj = super().__new__(cls, value)
        obj.spans = tuple(spans)
        return obj

    def _derive(self, value: str, *others: object) -> TaintedStr:
        spans = self.spans
        for other in others:
            spans += spans_of(other)
        return TaintedStr(value, spans)

    def __add__(self, other: str) -> TaintedStr:
        return self._derive(str.__add__(self, other), other)

    def __radd__(self, other: str) -> TaintedStr:
        return self._derive(str.__add__(other, self), other)

    def __mod__(self, other: Any) -> TaintedStr:
        values = other if isinstance(other, tuple) else (other,)
        return self._derive(str.__mod__(self, other), *values)

    def __rmod__(self, other: str) -> TaintedStr:
        # Python เรียก reflected method ก่อนเมื่อ operand ขวาเป็น subclass ของซ้าย
        # จึงดักได้ตอน `"... %s" % body` ที่ template เป็น str ธรรมดา
        return self._derive(str.__mod__(other, self), other)

    def __getitem__(self, key: Any) -> TaintedStr:
        # slicing เก็บ span ไว้ทั้งหมดแบบระมัดระวังไว้ก่อน — การตัดสินว่าชิ้นไหน
        # ยังสืบสายอยู่เป็นงานของ ledger ไม่ใช่ของ str
        return self._derive(str.__getitem__(self, key))

    def join(self, iterable: Iterable[str], /) -> TaintedStr:
        parts = list(iterable)
        return self._derive(str.join(self, parts), *parts)

    def format(self, *args: object, **kwargs: object) -> TaintedStr:
        return self._derive(str.format(self, *args, **kwargs), *args, *kwargs.values())

    def strip(self, chars: str | None = None, /) -> TaintedStr:
        return self._derive(str.strip(self, chars))

    def replace(self, old: str, new: str, count: SupportsIndex = -1, /) -> TaintedStr:
        return self._derive(str.replace(self, old, new, count), new)

    def __repr__(self) -> str:
        sources = ",".join(sorted({s.source for s in self.spans}))
        return f"TaintedStr({str.__repr__(self)}, from={sources or '-'})"


def tainted(text: str, *, source: str, label: str = "untrusted") -> TaintedStr:
    """ทำเครื่องหมายว่าข้อความนี้มาจากแหล่งที่ควบคุมไม่ได้"""
    return TaintedStr(text, (TaintSpan(text=text, source=source, label=label),))
