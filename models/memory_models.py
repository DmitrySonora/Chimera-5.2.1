"""
Pydantic модели для Short-Term Memory (STM)
"""
from pydantic import BaseModel, Field
from typing import Dict, List, Any, Literal


class MemoryEntry(BaseModel):
    """Модель для валидации входных данных при сохранении в память"""
    user_id: str
    message_type: Literal['user', 'bot']
    content: str
    metadata: Dict[str, Any] = Field(default_factory=dict)
    
    
class MemoryContext(BaseModel):
    """Модель для возврата контекста из памяти"""
    user_id: str
    messages: List[Dict[str, str]]  # [{"role": "user", "content": "..."}, ...]
    total_messages: int
    format_type: str = "structured"  # structured для DeepSeek, text для отладки