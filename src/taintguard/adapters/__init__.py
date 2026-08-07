"""ตัวเชื่อมกับโค้ดที่มีอยู่แล้ว — core ไม่รู้จักตัวไหนเลย

แยกออกมาเป็นแพ็กเกจย่อยเพราะ adapter ผูกกับ shape ของระบบอื่น (dispatcher signature,
tool_call ของ OpenAI) ซึ่งเปลี่ยนตามคนอื่น ส่วน core เปลี่ยนตามกฎของตัวเอง
"""

from taintguard.adapters.dispatcher import wrap_dispatcher
from taintguard.adapters.openai import guarded_tool_result, parse_tool_call

__all__ = ["guarded_tool_result", "parse_tool_call", "wrap_dispatcher"]
