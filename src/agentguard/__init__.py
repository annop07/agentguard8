"""AgentGuard — deterministic policy enforcement for AI agent tool calls.

AI agent ที่เรียก tool ได้เอง มีช่องโหว่ที่โค้ดปกติไม่มี: **ข้อมูลที่ agent อ่าน
กลายเป็นคำสั่งที่ agent ทำตามได้** attacker ไม่ต้องเข้าถึงระบบ แค่ฝากข้อความไว้ในอีเมล
เอกสาร หรือหน้าเว็บที่ agent จะไปอ่าน แล้วรอให้ agent เอาเข้า prompt เอง

AgentGuard เป็นชั้นที่คั่นระหว่าง "LLM บอกว่าจะเรียก tool อะไร" กับ "tool ทำงานจริง"
โดยตัดสินจาก policy, argument และที่มาของข้อมูลเท่านั้น — ไม่มีโมเดล ไม่มีการสุ่ม
input เดิมจึงได้ผลเดิมเสมอ และอธิบายกับผู้ตรวจสอบได้ว่าทำไมถึงบล็อก
"""

from agentguard.audit import AuditEvent, AuditSink, CallableSink, JsonlSink, MemorySink
from agentguard.decisions import Action, Decision, Reason
from agentguard.errors import AgentGuardError, ApprovalRequired, Blocked, PolicyConfigError
from agentguard.guard import Guard, Session
from agentguard.policy import RiskClass, ToolPolicy
from agentguard.rules import In, Matches, Max, Min, Predicate, Present, Rule
from agentguard.taint import TaintedStr, TaintLedger, TaintMatch, TaintSpan, normalize, tainted

__version__ = "0.1.0"

__all__ = [
    # core
    "Guard",
    "Session",
    "RiskClass",
    "ToolPolicy",
    # rules
    "Rule",
    "Max",
    "Min",
    "In",
    "Matches",
    "Present",
    "Predicate",
    # provenance
    "tainted",
    "TaintedStr",
    "TaintSpan",
    "TaintMatch",
    "TaintLedger",
    "normalize",
    # results
    "Action",
    "Decision",
    "Reason",
    # errors
    "AgentGuardError",
    "Blocked",
    "ApprovalRequired",
    "PolicyConfigError",
    # audit
    "AuditEvent",
    "AuditSink",
    "MemorySink",
    "JsonlSink",
    "CallableSink",
    "__version__",
]
