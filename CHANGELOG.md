# Changelog

รูปแบบตาม [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
เวอร์ชันตาม [Semantic Versioning](https://semver.org/spec/v2.0.0.html)

## [Unreleased]

### วางแผนไว้สำหรับ 0.2.0

- CLI — `taintguard lint` (ตรวจ policy ก่อน deploy) และ `taintguard replay`
  (เล่น audit log ซ้ำกับ policy ชุดใหม่ เพื่อดูว่าจะบล็อกอะไรเพิ่มก่อนเปิดใช้จริง)
- `taintguard[yaml]` — ประกาศ policy จากไฟล์
- `taintguard[semantic]` — adapter ของ goal-drift เอา *เจตนา* มาเสริม *ที่มาของข้อมูล*
- LangChain / OpenAI Agents SDK integration และ MCP proxy

## [0.1.0] — 2026-08-07

รุ่นแรกที่ปล่อยขึ้น PyPI

### เพิ่ม

**ชั้นบังคับใช้ 7 ขั้น** เรียงจากถูกที่สุดไปแพงที่สุด — capability scoping, policy lookup
(fail closed), schema, budget, argument invariants, taint/provenance, human approval
แต่ละขั้นคืน `code` ที่เป็น enum เสถียร ใช้ตั้ง alert ใน SIEM ได้

**Provenance matching** — `s.taint(text, source=...)` ลงทะเบียนข้อความที่ไม่น่าเชื่อถือ
แล้วทุก tool call ที่ความเสี่ยงสูงพอจะถูกถามว่า argument สืบสายมาจากข้อความนั้นไหม
เทียบข้อความล้วน ไม่มีโมเดล ไม่มี threshold input เดิมได้ผลเดิมเสมอ
`normalize()` ใช้ `unicodedata` ไม่ใช่ `\w` ของ `re` — รองรับภาษาไทยเต็ม

**Rules** — `Max`, `Min`, `In`, `Matches`, `Present`, `Predicate` ประกาศเป็น Python object
ที่ typed และเทสต์ได้ · กฎห้าม echo ค่า argument ลง `reason` เพื่อไม่ให้ค่าดิบรั่วลง audit

**Adapters** (`taintguard.adapters`) — เสียบเข้าโค้ดที่มีอยู่แล้วได้สามทาง:

| ทาง | พฤติกรรมตอนบล็อก | เหตุผล |
| --- | --- | --- |
| `session.check()` | คืน `Decision` | ผู้เรียกตัดสินใจเอง |
| `wrap_dispatcher()` | คืน error dict | อยู่ใน agent loop — raise จะทำให้ loop พังทั้งรอบ |
| `@guard.protect` | raise `Blocked` | เรียกฟังก์ชันตรงๆ ต้องหยุดจริง |

`ESCALATE` raise `ApprovalRequired` ทุกทาง เพราะยังไม่มีคำตอบให้คืนจนกว่าคนจะตัดสิน ·
`guarded_tool_result()` คืน message `role: "tool"` ที่ shape ไว้แล้วสำหรับ loop แบบ OpenAI
โดยไม่ต้องติดตั้ง `openai` · decorator หา session จาก `contextvars` จึงใช้กับ async ได้

**Audit** — บันทึกทุก decision รวมถึง `ALLOW` เพราะ log ที่มีแต่เหตุการณ์ถูกบล็อก
แยกไม่ออกระหว่าง "ระบบทำงานแล้วไม่มีอะไรผิดปกติ" กับ "ระบบไม่ได้ทำงานเลย" ·
argument เก็บเป็น digest ไม่ใช่ค่าดิบ · `MemorySink`, `JsonlSink`, `CallableSink`

**โหมด `observe`** — ตัดสินครบทุกชั้นและเขียน audit ครบ แต่ไม่หยุดอะไรเลย สำหรับติดตั้ง
ลงระบบที่ทำงานอยู่แล้ว มีเทสต์คุมว่ารายงานตรงกับสิ่งที่ `enforce` จะทำเป๊ะๆ

**เดโม** — `examples/injection_demo.py` และ `examples/openai_loop.py` รันได้ในเครื่องเปล่า
ไม่ต้องมี API key ไม่ต้องต่อเน็ต

### ขอบเขตที่รู้ตัว

- จับไม่ได้เมื่อ attacker สั่งลอยๆ ("โอนเงินทั้งหมดที่มี") แล้ว LLM ไปคำนวณค่าเองจาก tool
  ที่เชื่อถือได้ — เคสนั้นเป็นหน้าที่ของ `Max()` และ `requires_approval`
- `TaintedStr` เป็นตัวช่วยลงทะเบียน ไม่ใช่ตัวบังคับ — f-string, `plain.join()`,
  `plain.format()` ทำเครื่องหมายหาย ซึ่งบันทึกไว้เป็นเทสต์แล้ว

[Unreleased]: https://github.com/annop07/agentguard8/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/annop07/agentguard8/releases/tag/v0.1.0
