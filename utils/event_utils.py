"""
Утилиты для работы с Event Store
"""
from typing import Dict
from actors.events import BaseEvent


class EventVersionManager:
    """Менеджер версий для потоков событий"""
    
    def __init__(self):
        self._stream_versions: Dict[str, int] = {}
    
    async def append_event(self, event: BaseEvent, actor_system) -> None:
        """
        Добавить событие с правильной версией.
        
        Args:
            event: Событие для добавления
            actor_system: Ссылка на ActorSystem с Event Store
        """
        if not actor_system or not hasattr(actor_system, '_event_store'):
            return
        if not actor_system._event_store:
            return
            
        stream_id = event.stream_id
        
        # Получаем текущую версию потока
        if stream_id not in self._stream_versions:
            # Проверяем, существует ли поток
            last_event = await actor_system._event_store.get_last_event(stream_id)
            if last_event:
                self._stream_versions[stream_id] = last_event.version + 1
            else:
                self._stream_versions[stream_id] = 0
        
        # Создаем событие с правильной версией
        versioned_event = BaseEvent.create(
            stream_id=event.stream_id,
            event_type=event.event_type,
            data=event.data,
            version=self._stream_versions[stream_id],
            correlation_id=event.correlation_id
        )
        
        # Добавляем событие
        await actor_system._event_store.append_event(versioned_event)
        
        # Увеличиваем версию для следующего события
        self._stream_versions[stream_id] += 1
    
    def reset_stream_version(self, stream_id: str) -> None:
        """Сбросить версию потока (для тестов)"""
        if stream_id in self._stream_versions:
            del self._stream_versions[stream_id]