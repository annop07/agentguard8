"""Property tests — คุณสมบัติที่ต้องจริงกับ *ทุก* input ไม่ใช่แค่ตัวอย่างที่นึกออก

ชั้น provenance ทั้งหมดเป็นการเทียบข้อความ ถ้า ``normalize()`` ทำลายความสัมพันธ์
"ชิ้นส่วนของข้อความ" เมื่อไหร่ ตัวบังคับใช้จะหลุดโดยไม่มีเทสต์ตัวอย่างไหนจับได้
"""

from __future__ import annotations

from hypothesis import assume, given
from hypothesis import strategies as st

from agentguard import TaintLedger, normalize

# ตัวอักษรหลายระบบเขียนปนกัน — ไทยคือกรณีที่ตัวกรอง ASCII-only จะพัง
ALPHABET = st.sampled_from(
    list("abcXYZ019 \t\n") + list("ก่ขาคำงเจไฉช") + list(".,-:;!?()'\"[]{}@#/\\_")
)
TEXT = st.text(alphabet=ALPHABET, min_size=1, max_size=120)


@given(TEXT)
def test_normalize_is_idempotent(text: str) -> None:
    once = normalize(text)
    assert normalize(once) == once


@given(TEXT)
def test_normalize_never_produces_padding_or_double_spaces(text: str) -> None:
    result = normalize(text)
    assert result == result.strip()
    assert "  " not in result


@given(TEXT)
def test_normalize_keeps_word_characters_of_any_script(text: str) -> None:
    """ตัวอักษรและตัวเลขต้องรอดครบ — ที่หายไปได้มีแค่เครื่องหมายวรรคตอนกับช่องว่างส่วนเกิน"""
    kept = [c for c in text.lower() if c.isalnum()]
    assert [c for c in normalize(text) if c.isalnum()] == kept


@st.composite
def text_and_fragment(draw: st.DrawFn) -> tuple[str, str]:
    """ข้อความหนึ่งก้อน กับชิ้นส่วนของมันที่ตัดมาจากตำแหน่งไหนก็ได้"""
    text = draw(TEXT)
    start = draw(st.integers(0, len(text) - 1))
    end = draw(st.integers(start + 1, len(text)))
    return text, text[start:end]


@given(text_and_fragment())
def test_every_fragment_of_a_tainted_text_is_detected(pair: tuple[str, str]) -> None:
    """คุณสมบัติที่ตัวบังคับใช้ทั้งหมดตั้งอยู่บนมัน

    ถ้า LLM คัดลอกชิ้นส่วนใดก็ตามของข้อความที่ taint ไว้มาเป็น argument ต้องถูกจับได้เสมอ
    — ไม่ว่าชิ้นนั้นจะเริ่มหรือจบตรงกลางคำ ตรงเครื่องหมาย หรือตรงช่องว่างก็ตาม

    พูดอีกแบบ: ``normalize()`` ต้องรักษาความสัมพันธ์ "เป็นชิ้นส่วนของ" ไว้เสมอ
    ถ้าวันไหนมันไม่รักษา ตัวบังคับใช้จะหลุดโดยไม่มีเทสต์ตัวอย่างไหนจับได้
    """
    text, fragment = pair
    assume(normalize(fragment) != "")

    ledger = TaintLedger(min_match_chars=1)
    ledger.add(text, source="src")
    assert ledger.match(fragment) is not None


@given(TEXT, TEXT)
def test_trusted_values_always_win(text: str, value: str) -> None:
    assume(normalize(value) != "")
    ledger = TaintLedger(min_match_chars=1)
    ledger.add(text, source="src")
    ledger.trust(value)
    assert ledger.match(value) is None
