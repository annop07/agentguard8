"""audit log — สิ่งที่ทำให้ชั้นบังคับใช้พิสูจน์ตัวเองได้"""

from __future__ import annotations

import json
from pathlib import Path

from agentguard import CallableSink, Guard, JsonlSink, MemorySink, ToolPolicy
from agentguard.audit import AuditEvent, args_digest


def test_allowed_calls_are_recorded_too(guard: Guard) -> None:
    """log ที่มีแต่เหตุการณ์ถูกบล็อก แยกไม่ออกว่าระบบทำงานอยู่หรือไม่ได้ทำงานเลย"""
    s = guard.session()
    s.check("get_invoice", {"id": 1})
    assert len(s.audit) == 1
    assert s.audit[0].action.value == "allow"
    assert s.audit[0].code is None


def test_raw_arguments_never_reach_the_log(guard: Guard, context: dict) -> None:
    s = guard.session(context=context)
    s.check("transfer_money", {"to_account": "999-9", "amount": 49_000})
    blob = s.audit[0].to_json()
    assert "999-9" not in blob
    assert "49000" not in blob
    assert len(s.audit[0].args_digest) == 16


def test_digest_is_stable_and_order_independent() -> None:
    assert args_digest({"a": 1, "b": 2}) == args_digest({"b": 2, "a": 1})
    assert args_digest({"a": 1}) != args_digest({"a": 2})


def test_digest_survives_unserialisable_values() -> None:
    assert len(args_digest({"when": object()})) == 16


def test_event_json_is_parseable_and_has_the_fields_a_siem_needs(
    guard: Guard, context: dict
) -> None:
    s = guard.session(context=context)
    s.check("transfer_money", {"to_account": "999-9", "amount": 100})
    data = json.loads(s.audit[0].to_json())
    assert data["code"] == "invariant_breach"  # enum เสถียร ใช้ตั้ง alert ได้
    assert data["rule"] == "require.In(to_account)"  # granular ไว้ debug policy
    assert data["session_id"] == s.session_id
    assert data["tool"] == "transfer_money"


def test_thai_text_is_not_escaped(guard: Guard) -> None:
    event = AuditEvent.from_decision(
        guard.session().check("drop_database", {}), session_id="s", args={"q": "ค่ากาแฟ"}
    )
    assert "ค่ากาแฟ" not in event.to_json()  # อยู่ใน digest ไม่ใช่ค่าดิบ
    assert "\\u0e04" not in event.to_json()  # และไม่มี escape ตกค้างจาก ensure_ascii


def test_guard_sink_receives_every_session(policies: list[ToolPolicy]) -> None:
    sink = MemorySink()
    guard = Guard(policies=policies, audit_sink=sink)
    guard.session().check("get_invoice", {})
    guard.session().check("get_invoice", {})
    assert len(sink.events) == 2
    assert sink.events[0].session_id != sink.events[1].session_id
    guard.close()


def test_callable_sink(policies: list[ToolPolicy]) -> None:
    seen: list[str] = []
    guard = Guard(policies=policies, audit_sink=CallableSink(lambda e: seen.append(e.tool)))
    guard.session().check("get_invoice", {})
    assert seen == ["get_invoice"]
    guard.close()  # ไม่มีอะไรให้ปิด แต่ต้องไม่พัง


def test_jsonl_sink_appends_one_line_per_event(
    policies: list[ToolPolicy], tmp_path: Path
) -> None:
    path = tmp_path / "nested" / "audit.jsonl"
    guard = Guard(policies=policies, audit_sink=JsonlSink(path))
    s = guard.session()
    s.check("get_invoice", {})
    s.check("drop_database", {})
    guard.close()

    lines = path.read_text(encoding="utf-8").strip().split("\n")
    assert len(lines) == 2
    assert json.loads(lines[1])["code"] == "unauthorized_tool"


def test_session_audit_is_a_copy(guard: Guard) -> None:
    s = guard.session()
    s.check("get_invoice", {})
    s.audit.clear()
    assert len(s.audit) == 1
