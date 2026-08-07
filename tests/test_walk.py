"""การเดินเข้าไปใน argument — ใช้ร่วมกันระหว่างชั้นกฎกับชั้น taint

ถ้าสองชั้นนี้มองเห็นค่าไม่เหมือนกัน ชั้นใดชั้นหนึ่งจะมีจุดบอด จึงต้องใช้โค้ดชุดเดียวกัน
"""

from __future__ import annotations

import pytest

from taintguard._walk import MISSING, iter_scalars, lookup_path, text_of


class TestLookupPath:
    def test_flat_and_nested(self) -> None:
        args = {"a": 1, "p": {"q": {"r": 2}}}
        assert lookup_path(args, "a") == 1
        assert lookup_path(args, "p.q.r") == 2

    @pytest.mark.parametrize("path", ["nope", "p.nope", "a.b", "p.q.r.s"])
    def test_missing_paths(self, path: str) -> None:
        assert lookup_path({"a": 1, "p": {"q": {"r": 2}}}, path) is MISSING


class TestIterScalars:
    def test_flat_scalars(self) -> None:
        assert list(iter_scalars("x")) == ["x"]
        assert list(iter_scalars(3)) == [3]
        assert list(iter_scalars(3.5)) == [3.5]

    def test_walks_dicts_lists_tuples_and_sets(self) -> None:
        nested = {"a": ["x", ("y",)], "b": {"c": frozenset({"z"})}}
        assert sorted(iter_scalars(nested)) == ["x", "y", "z"]  # type: ignore[type-var]

    @pytest.mark.parametrize("value", [True, False, None])
    def test_bools_and_none_are_skipped(self, value: object) -> None:
        """``True`` ที่กลายเป็น ``"true"`` มีโอกาสไปชนข้อความจริงโดยบังเอิญสูง"""
        assert list(iter_scalars(value)) == []

    def test_bools_nested_inside_containers_are_skipped_too(self) -> None:
        assert list(iter_scalars({"ok": True, "id": "abc"})) == ["abc"]

    def test_unknown_objects_yield_nothing(self) -> None:
        assert list(iter_scalars(object())) == []


class TestTextOf:
    def test_integral_floats_lose_the_decimal_tail(self) -> None:
        """ไม่งั้น 49000.0 จะกลายเป็น '490000' หลัง normalize แล้วเทียบกับ '49000' ไม่ติด"""
        assert text_of(49_000.0) == "49000"

    def test_real_decimals_are_kept(self) -> None:
        assert text_of(4_999.5) == "4999.5"

    def test_ints_and_strings_pass_through(self) -> None:
        assert text_of(42) == "42"
        assert text_of("999-9") == "999-9"
