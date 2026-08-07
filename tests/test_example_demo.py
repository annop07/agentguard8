"""เดโมใน examples/ คือหน้าตาแรกที่คนเห็น — ถ้ามันเน่าโดยไม่มีใครรู้ก็แย่กว่าไม่มี"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType

import pytest

DEMO = Path(__file__).resolve().parents[1] / "examples" / "injection_demo.py"


@pytest.fixture
def demo() -> ModuleType:
    spec = importlib.util.spec_from_file_location("injection_demo", DEMO)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["injection_demo"] = module
    spec.loader.exec_module(module)
    return module


def test_without_the_guard_the_money_leaves(demo: ModuleType) -> None:
    demo._reset()
    demo.run_agent(demo.EMAIL_BODY, None)
    assert demo.LEDGER["988-7712"] == 49_000.0


def test_with_the_guard_nothing_moves(demo: ModuleType) -> None:
    from taintguard import Guard

    demo._reset()
    with Guard(demo.POLICIES, default_action="block").session(context=demo.CONTEXT) as session:
        demo.run_agent(demo.EMAIL_BODY, session)

    assert "988-7712" not in demo.LEDGER
    assert demo.LEDGER["111-1"] == 120_000.0
    assert session.stats == {"allowed": 2, "blocked": 1, "escalated": 0, "suppressed": 0}


def test_only_the_taint_layer_stops_it(demo: ModuleType) -> None:
    """จุดสำคัญของเดโม — invariant ทั้งสองข้อ *ผ่าน*

    เลขบัญชีของ attacker อยู่ใน known_suppliers และยอด 49,000 ต่ำกว่าเพดาน 50,000
    ถ้าชั้น taint ไม่มี เงินจะออกไปทั้งที่ policy เขียนไว้ครบถ้วนแล้ว
    """
    from taintguard import Guard, Reason

    guard = Guard(demo.POLICIES, default_action="block")
    args = {"to_account": "988-7712", "amount": 49_000.0}

    clean = guard.session(context=demo.CONTEXT)
    assert clean.check("transfer_money", args).allowed  # ไม่มี taint → ผ่านทุกกฎ

    guarded = guard.session(context=demo.CONTEXT)
    guarded.taint(demo.EMAIL_BODY, source=demo.EMAIL_ID)
    assert guarded.check("transfer_money", args).code is Reason.TAINTED_ARGUMENT


def test_the_companys_own_account_is_trusted(demo: ModuleType) -> None:
    """111-1 โผล่ในอีเมลด้วย แต่เป็นบัญชีของบริษัทเอง — ต้องไม่ถูกจับ"""
    from taintguard import Guard

    session = Guard(demo.POLICIES).session(context=demo.CONTEXT)
    session.taint(demo.EMAIL_BODY + " ref 111-1", source=demo.EMAIL_ID)
    session.trust("111-1")
    assert session.check("transfer_money", {"to_account": "111-1", "amount": 100}).allowed


def test_main_runs(demo: ModuleType, capsys: pytest.CaptureFixture[str]) -> None:
    demo.main()
    out = capsys.readouterr().out
    assert "tainted_argument" in out
    assert "audit log" in out


LOOP = Path(__file__).resolve().parents[1] / "examples" / "openai_loop.py"


@pytest.fixture
def loop_demo() -> ModuleType:
    spec = importlib.util.spec_from_file_location("openai_loop", LOOP)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["openai_loop"] = module
    spec.loader.exec_module(module)
    return module


def test_the_openai_loop_demo_blocks_the_transfer_and_keeps_going(
    loop_demo: ModuleType, capsys: pytest.CaptureFixture[str]
) -> None:
    """เดโมนี้ขายเรื่อง "loop ไม่พัง" — ถ้ามัน raise ขึ้นมาก็เท่ากับขายผิด"""
    loop_demo.LEDGER["111-1"] = 120_000.0
    loop_demo.main()

    out = capsys.readouterr().out
    assert "blocked_by_policy" in out
    assert loop_demo.LEDGER["111-1"] == 120_000.0
    # ทั้ง ALLOW และ BLOCK ลง audit — log ที่มีแต่ของที่ถูกบล็อกแยกไม่ออกว่าระบบทำงานไหม
    assert "audit  allow" in out and "audit  block" in out
