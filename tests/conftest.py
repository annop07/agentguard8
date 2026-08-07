from __future__ import annotations

import pytest
from pydantic import BaseModel, Field

from taintguard import Guard, In, Max, RiskClass, ToolPolicy


class TransferArgs(BaseModel):
    to_account: str
    amount: float = Field(gt=0)
    memo: str = ""


@pytest.fixture
def policies() -> list[ToolPolicy]:
    """ชุด policy ที่ครอบคลุมทุกชั้นความเสี่ยง ใช้ร่วมกันเกือบทุกไฟล์เทสต์"""
    return [
        ToolPolicy("get_invoice", risk=RiskClass.READ),
        ToolPolicy("search_docs", risk=RiskClass.READ),
        ToolPolicy("create_payable", risk=RiskClass.WRITE, require=[Max("amount", 100_000)]),
        ToolPolicy(
            "send_email",
            risk=RiskClass.EXTERNAL,
            requires_approval=False,
            max_calls_per_session=2,
        ),
        ToolPolicy(
            "transfer_money",
            risk=RiskClass.CRITICAL,
            args_model=TransferArgs,
            require=[In("to_account", ctx="own_accounts"), Max("amount", 5_000)],
            max_calls_per_session=1,
        ),
    ]


@pytest.fixture
def guard(policies: list[ToolPolicy]) -> Guard:
    return Guard(policies=policies)


@pytest.fixture
def context() -> dict[str, object]:
    return {"own_accounts": ["111-1", "222-2"]}
