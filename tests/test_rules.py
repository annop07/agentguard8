"""กฎทุกข้อเป็น pure function — เทสต์ได้โดยไม่ต้องมี Guard, Session หรืออะไรทั้งสิ้น"""

from __future__ import annotations

import pytest

from taintguard import In, Matches, Max, Min, PolicyConfigError, Predicate, Present


class TestMax:
    def test_under_limit_passes(self) -> None:
        assert Max("amount", 5_000).check({"amount": 4_999}, {}) is None

    def test_at_limit_passes(self) -> None:
        assert Max("amount", 5_000).check({"amount": 5_000}, {}) is None

    def test_over_limit_names_the_cap_but_not_the_value(self) -> None:
        failure = Max("amount", 5_000).check({"amount": 49_000}, {})
        assert failure is not None
        assert "5000" in failure  # ขอบเขตมาจาก policy — บอกได้ และ LLM ต้องรู้เพื่อลองใหม่
        assert "49000" not in failure  # ค่าที่ส่งมา — ห้ามลง log

    def test_numeric_string_is_accepted(self) -> None:
        """LLM คืนตัวเลขมาเป็น string เป็นเรื่องปกติ ไม่ควรทำให้กฎหลุด"""
        assert Max("amount", 5_000).check({"amount": "4999"}, {}) is None
        assert Max("amount", 5_000).check({"amount": "49,000"}, {}) is not None

    def test_non_numeric_fails_closed(self) -> None:
        assert Max("amount", 5_000).check({"amount": "หนึ่งหมื่น"}, {}) is not None

    def test_bool_is_not_a_number(self) -> None:
        """bool เป็น subclass ของ int ใน Python — ต้องไม่ถูกนับเป็นตัวเลข"""
        assert Max("amount", 5_000).check({"amount": True}, {}) is not None

    def test_missing_field_passes(self) -> None:
        """กฎขอบเขต: ไม่มีค่า = ไม่มีอะไรให้เกินขอบ (ความ required เป็นหน้าที่ของ args_model)"""
        assert Max("amount", 5_000).check({}, {}) is None

    @pytest.mark.parametrize("value", [["a"], {"a": 1}, None])
    def test_non_scalar_values_fail_closed(self, value: object) -> None:
        assert Max("amount", 5_000).check({"amount": value}, {}) is not None

    def test_dotted_path(self) -> None:
        assert Max("payment.amount", 100).check({"payment": {"amount": 500}}, {}) is not None
        assert Max("payment.amount", 100).check({"payment": {"amount": 50}}, {}) is None


class TestMin:
    def test_above_minimum_passes(self) -> None:
        assert Min("days", 1).check({"days": 30}, {}) is None

    def test_below_minimum_fails(self) -> None:
        assert Min("days", 1).check({"days": 0}, {}) is not None

    def test_missing_field_passes(self) -> None:
        assert Min("days", 1).check({}, {}) is None


class TestIn:
    def test_value_in_literal_set(self) -> None:
        assert In("currency", values=["THB", "USD"]).check({"currency": "THB"}, {}) is None

    def test_value_outside_set_fails(self) -> None:
        assert In("currency", values=["THB"]).check({"currency": "BTC"}, {}) is not None

    def test_resolves_allowlist_from_session_context(self) -> None:
        rule = In("to_account", ctx="own_accounts")
        ctx = {"own_accounts": ["111-1", "222-2"]}
        assert rule.check({"to_account": "111-1"}, ctx) is None
        assert rule.check({"to_account": "999-9"}, ctx) is not None

    def test_missing_context_key_fails_closed(self) -> None:
        """policy อ้าง context ที่ไม่ได้ส่งมา = กฎหายไปเงียบๆ ถ้าไม่ fail closed"""
        failure = In("to_account", ctx="own_accounts").check({"to_account": "111-1"}, {})
        assert failure is not None
        assert "own_accounts" in failure

    def test_missing_field_fails_closed(self) -> None:
        """ต่างจาก Max: 'ต้องอยู่ในชุดที่อนุญาต' ไม่มีค่า = ไม่เข้าเงื่อนไข"""
        assert In("to_account", ctx="own_accounts").check({}, {"own_accounts": ["1"]}) is not None

    def test_string_comparison_fallback(self) -> None:
        """allowlist เก็บเป็น int แต่ LLM คืน string — ต้องเทียบกันได้"""
        assert In("user_id", values=[1, 2, 3]).check({"user_id": "2"}, {}) is None

    def test_requires_exactly_one_source(self) -> None:
        with pytest.raises(PolicyConfigError):
            In("x")
        with pytest.raises(PolicyConfigError):
            In("x", values=["a"], ctx="b")


class TestMatches:
    def test_pattern_match(self) -> None:
        rule = Matches("email", r"@company\.com$")
        assert rule.check({"email": "a@company.com"}, {}) is None
        assert rule.check({"email": "a@evil.com"}, {}) is not None

    def test_non_string_fails(self) -> None:
        assert Matches("email", r".+").check({"email": 42}, {}) is not None

    def test_missing_field_passes(self) -> None:
        assert Matches("email", r".+").check({}, {}) is None

    def test_invalid_regex_is_a_config_error(self) -> None:
        with pytest.raises(PolicyConfigError):
            Matches("x", "[unclosed")


class TestPresent:
    @pytest.mark.parametrize("args", [{}, {"memo": None}, {"memo": ""}])
    def test_absent_or_empty_fails(self, args: dict[str, object]) -> None:
        assert Present("memo").check(args, {}) is not None

    def test_zero_is_present(self) -> None:
        assert Present("count").check({"count": 0}, {}) is None

    def test_name(self) -> None:
        assert Present("memo").name == "Present(memo)"


class TestPredicate:
    def test_satisfied(self) -> None:
        rule = Predicate(lambda a, c: a["amount"] <= c["daily_left"], label="daily_cap")
        assert rule.check({"amount": 100}, {"daily_left": 500}) is None

    def test_not_satisfied_uses_custom_message(self) -> None:
        rule = Predicate(lambda a, c: False, label="always_false", message="nope")
        assert rule.check({}, {}) == "nope"

    def test_raising_predicate_fails_closed(self) -> None:
        """กฎที่พังต้องบล็อก ไม่ใช่ปล่อยผ่าน — ไม่งั้น KeyError กลายเป็นช่องโหว่"""
        rule = Predicate(lambda a, c: a["missing"] > 0, label="boom")
        failure = rule.check({}, {})
        assert failure is not None
        assert "KeyError" in failure

    def test_name_includes_label(self) -> None:
        assert Predicate(lambda a, c: True, label="daily_cap").name == "Predicate(daily_cap)"


SECRET = "SECRET-VALUE-9999"

# กฎทุกข้อกับ argument ที่จงใจให้ไม่ผ่าน โดยค่าที่ส่งเข้าไปคือ SECRET
_FAILING_CASES = [
    Max("f", 1),
    Min("f", 10**9),
    In("f", values=["something-else"]),
    Matches("f", r"^never-matches$"),
    Predicate(lambda a, c: False, label="always_false"),
]


@pytest.mark.parametrize("rule", _FAILING_CASES, ids=lambda r: r.name)
def test_no_rule_leaks_argument_values_into_its_message(rule) -> None:  # type: ignore[no-untyped-def]
    """ข้อความของกฎไหลลง audit log — ค่าที่ user/LLM ส่งมาต้องไม่ไปโผล่ตรงนั้น

    เทสต์นี้คุมกฎทุกตัวพร้อมกัน กฎใหม่ที่เพิ่มเข้ามาต้องมาต่อท้าย _FAILING_CASES ด้วย
    """
    failure = rule.check({"f": SECRET}, {})
    assert failure is not None, "กรณีนี้ต้องไม่ผ่าน ไม่งั้นเทสต์ไม่ได้ตรวจอะไรเลย"
    assert SECRET not in failure
    assert "f" in failure  # ยังต้องบอกได้ว่า field ไหนผิด
