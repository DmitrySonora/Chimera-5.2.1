"""
События для MemoryActor и STM буфера
"""
from typing import Optional
from actors.events.base_event import BaseEvent


class MemoryStoredEvent(BaseEvent):
    """Событие сохранения сообщения в память"""
    
    @classmethod
    def create(cls,
               user_id: str,
               message_type: str,
               content_length: int,
               has_metadata: bool = False,
               correlation_id: Optional[str] = None) -> 'MemoryStoredEvent':
        """
        Создать событие сохранения в память
        
        Args:
            user_id: ID пользователя
            message_type: Тип сообщения (user/bot)
            content_length: Длина сохраненного сообщения
            has_metadata: Есть ли метаданные
            correlation_id: ID корреляции
        """
        return cls(
            stream_id=f"memory_{user_id}",
            event_type="MemoryStoredEvent",
            data={
                "user_id": user_id,
                "message_type": message_type,
                "content_length": content_length,
                "has_metadata": has_metadata
            },
            version=0,  # Версия устанавливается EventVersionManager
            correlation_id=correlation_id
        )


class ContextRetrievedEvent(BaseEvent):
    """Событие получения контекста из памяти"""
    
    @classmethod
    def create(cls,
               user_id: str,
               context_size: int,
               retrieval_time_ms: float,
               format_type: str = "structured",
               correlation_id: Optional[str] = None) -> 'ContextRetrievedEvent':
        """
        Создать событие получения контекста
        
        Args:
            user_id: ID пользователя
            context_size: Количество сообщений в контексте
            retrieval_time_ms: Время получения в миллисекундах
            format_type: Формат контекста (structured/text)
            correlation_id: ID корреляции
        """
        return cls(
            stream_id=f"memory_{user_id}",
            event_type="ContextRetrievedEvent",
            data={
                "user_id": user_id,
                "context_size": context_size,
                "retrieval_time_ms": retrieval_time_ms,
                "format_type": format_type
            },
            version=0,  # Версия устанавливается EventVersionManager
            correlation_id=correlation_id
        )