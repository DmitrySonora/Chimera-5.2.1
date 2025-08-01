import asyncio
from typing import Dict, List, Optional, Tuple
from datetime import datetime
from collections import OrderedDict
import bisect

from actors.events.base_event import BaseEvent
from config.logging import get_logger
from config.settings import EVENT_STORE_STREAM_CACHE_SIZE
import config.settings
from utils.monitoring import measure_latency


class EventStoreConcurrencyError(Exception):
    """Raised when version conflict detected"""
    def __init__(self, stream_id: str, expected_version: int, actual_version: int):
        self.stream_id = stream_id
        self.expected_version = expected_version
        self.actual_version = actual_version
        super().__init__(
            f"Version conflict for stream {stream_id}: "
            f"expected {expected_version}, got {actual_version}"
        )


class LRUCache:
    """Простой LRU кэш для потоков событий"""
    def __init__(self, capacity: int):
        self.capacity = capacity
        self.cache: OrderedDict = OrderedDict()
    
    def get(self, key: str) -> Optional[List[BaseEvent]]:
        if key not in self.cache:
            return None
        # Перемещаем в конец (most recently used)
        self.cache.move_to_end(key)
        return self.cache[key]
    
    def put(self, key: str, value: List[BaseEvent]) -> None:
        if key in self.cache:
            self.cache.move_to_end(key)
        self.cache[key] = value
        # Удаляем старейший элемент если превышен размер
        if len(self.cache) > self.capacity:
            self.cache.popitem(last=False)
    
    def invalidate(self, key: str) -> None:
        if key in self.cache:
            del self.cache[key]


class EventStore:
    """
    In-memory реализация Event Store.
    Обеспечивает сохранение событий с версионированием и thread-safety.
    """
    
    def __init__(self):
        self.logger = get_logger("event_store")
        self._streams: Dict[str, List[BaseEvent]] = {}
        self._locks: Dict[str, asyncio.Lock] = {}
        self._timestamp_index: List[Tuple[datetime, str, int]] = []
        self._stream_cache = LRUCache(EVENT_STORE_STREAM_CACHE_SIZE)
        self._total_events = 0
        
        # Метрики Event Store
        self._total_appends = 0        # Всего операций append
        self._total_reads = 0          # Всего операций чтения
        self._cache_hits = 0           # Попадания в кэш
        self._cache_misses = 0         # Промахи кэша
        self._version_conflicts = 0    # Конфликты версий
        self._total_cleanups = 0       # Количество очисток
        
    @measure_latency
    async def append_event(self, event: BaseEvent) -> None:
        """
        Добавить событие в store.
        Проверяет версию для предотвращения lost updates.
        """
        # Получаем или создаем блокировку для потока
        if event.stream_id not in self._locks:
            self._locks[event.stream_id] = asyncio.Lock()
        
        async with self._locks[event.stream_id]:
            # Проверяем версию
            if event.stream_id in self._streams:
                current_version = len(self._streams[event.stream_id])
                if event.version != current_version:
                    self._version_conflicts += 1
                    raise EventStoreConcurrencyError(
                        event.stream_id, event.version, current_version
                    )
            else:
                # Новый поток
                if event.version != 0:
                    raise EventStoreConcurrencyError(
                        event.stream_id, event.version, 0
                    )
                self._streams[event.stream_id] = []
            
            # Добавляем событие
            self._streams[event.stream_id].append(event)
            
            # Обновляем timestamp индекс
            position = len(self._streams[event.stream_id]) - 1
            index_entry = (event.timestamp, event.stream_id, position)
            bisect.insort(self._timestamp_index, index_entry)
            
            # Инвалидируем кэш
            self._stream_cache.invalidate(event.stream_id)
            
            # Увеличиваем счетчик
            self._total_events += 1
            self._total_appends += 1
            
            # Проверяем необходимость очистки
            if self._total_events > config.settings.EVENT_STORE_MAX_MEMORY_EVENTS:
                await self._cleanup_old_events()
            
            self.logger.debug(
                f"Event {event.event_type} appended to stream {event.stream_id} "
                f"at version {event.version}"
            )
    
    async def get_stream(self, stream_id: str, from_version: int = 0) -> List[BaseEvent]:
        """
        Получить события потока начиная с указанной версии.
        Использует кэш для часто запрашиваемых потоков.
        """
        # Проверяем кэш
        cached = self._stream_cache.get(stream_id)
        if cached is not None and from_version == 0:
            self._cache_hits += 1
            self._total_reads += 1
            return cached.copy()
        
        self._cache_misses += 1
        self._total_reads += 1
        
        # Читаем из хранилища
        if stream_id not in self._streams:
            return []
        
        events = self._streams[stream_id][from_version:]
        
        # Кэшируем полный поток
        if from_version == 0 and events:
            self._stream_cache.put(stream_id, events.copy())
        
        return events
    
    @measure_latency
    async def get_events_after(
        self, 
        timestamp: datetime, 
        event_types: Optional[List[str]] = None
    ) -> List[BaseEvent]:
        """
        Получить события после указанного времени.
        Использует бинарный поиск для производительности.
        """
        # Бинарный поиск начальной позиции
        start_idx = bisect.bisect_left(
            self._timestamp_index,
            (timestamp, '', 0)
        )
        
        result = []
        for i in range(start_idx, len(self._timestamp_index)):
            ts, stream_id, position = self._timestamp_index[i]
            event = self._streams[stream_id][position]
            
            # Фильтр по типам если указан
            if event_types is None or event.event_type in event_types:
                result.append(event)
        
        return result
    
    async def get_last_event(self, stream_id: str) -> Optional[BaseEvent]:
        """Получить последнее событие потока"""
        if stream_id not in self._streams or not self._streams[stream_id]:
            return None
        return self._streams[stream_id][-1]
    
    async def stream_exists(self, stream_id: str) -> bool:
        """Проверить существование потока"""
        return stream_id in self._streams
    
    async def _cleanup_old_events(self) -> None:
        """
        Очистка старых событий при превышении лимита.
        Удаляет целые потоки, начиная с самых старых.
        """
        events_to_remove = self._total_events - config.settings.EVENT_STORE_MAX_MEMORY_EVENTS
        if events_to_remove <= 0:
            return
        
        self.logger.warning(
            f"Event store cleanup triggered. Need to remove {events_to_remove} events"
        )
        
        # Собираем информацию о потоках с их последним временем обновления
        stream_info = []
        for stream_id, events in self._streams.items():
            if events:
                last_timestamp = events[-1].timestamp
                stream_size = len(events)
                stream_info.append((last_timestamp, stream_id, stream_size))
        
        # Сортируем по времени последнего обновления (старые первые)
        stream_info.sort()
        
        removed_count = 0
        streams_to_remove = []
        
        # Удаляем целые потоки, пока не освободим достаточно места
        for last_timestamp, stream_id, stream_size in stream_info:
            if removed_count >= events_to_remove:
                break
            
            streams_to_remove.append(stream_id)
            removed_count += stream_size
            
            self.logger.info(
                f"Marking stream {stream_id} for removal ({stream_size} events)"
            )
            
        
        # Удаляем потоки
        for stream_id in streams_to_remove:
            del self._streams[stream_id]
            if stream_id in self._locks:
                del self._locks[stream_id]
        
        # Пересобираем timestamp индекс
        self._timestamp_index = []
        self._total_events = 0
        
        for stream_id, events in self._streams.items():
            for position, event in enumerate(events):
                self._timestamp_index.append((event.timestamp, stream_id, position))
                self._total_events += 1
        
        # Сортируем индекс по времени
        self._timestamp_index.sort()
        
        # Очищаем кэш
        self._stream_cache = LRUCache(config.settings.EVENT_STORE_STREAM_CACHE_SIZE)
        
        self.logger.info(
            f"Event store cleanup completed. Removed {len(streams_to_remove)} streams, "
            f"{removed_count} events total. Current total: {self._total_events}"
        )
        self._total_cleanups += 1

    def get_metrics(self) -> Dict[str, int]:
            """Получить метрики Event Store"""
            return {
                'total_events': self._total_events,
                'total_appends': self._total_appends,
                'total_reads': self._total_reads,
                'cache_hits': self._cache_hits,
                'cache_misses': self._cache_misses,
                'cache_hit_rate': round(self._cache_hits / max(1, self._total_reads) * 100, 2),
                'version_conflicts': self._version_conflicts,
                'total_cleanups': self._total_cleanups,
                'stream_count': len(self._streams),
                'index_size': len(self._timestamp_index)
            }

# Для будущей миграции на PostgreSQL:
# CREATE TABLE events (
#     event_id UUID PRIMARY KEY,
#     stream_id VARCHAR(255) NOT NULL,
#     event_type VARCHAR(100) NOT NULL,
#     data JSONB NOT NULL,
#     timestamp TIMESTAMP WITH TIME ZONE NOT NULL,
#     version INTEGER NOT NULL,
#     correlation_id UUID,
#     archived BOOLEAN DEFAULT FALSE,
#     UNIQUE(stream_id, version)
# );
# CREATE INDEX idx_events_stream_timestamp ON events(stream_id, timestamp);
# CREATE INDEX idx_events_type_timestamp ON events(event_type, timestamp);
# CREATE INDEX idx_events_timestamp_archived ON events(timestamp) WHERE NOT archived;