"""
PostgreSQL реализация Event Store с батчевой записью и полной совместимостью
"""
import asyncio
import json
from typing import Dict, List, Optional, Any
from datetime import datetime
from collections import deque
import uuid

from actors.events.base_event import BaseEvent
from actors.events.event_store import EventStoreConcurrencyError
from database.connection import db_connection
from config.logging import get_logger
from config.settings import (
    EVENT_STORE_BATCH_SIZE,
    EVENT_STORE_FLUSH_INTERVAL,
    EVENT_STORE_MAX_BUFFER_SIZE
)
from utils.monitoring import measure_latency


def generate_stream_lock_keys(stream_id: str) -> tuple[int, int]:
    """
    Генерирует два int4 ключа для advisory lock из stream_id.
    Использует полный MD5 хэш для минимизации коллизий.
    
    Args:
        stream_id: Идентификатор потока
        
    Returns:
        Кортеж (high_key, low_key) для pg_advisory_xact_lock
    """
    import hashlib
    
    # Генерируем MD5 хэш от stream_id
    hash_hex = hashlib.md5(stream_id.encode()).hexdigest()
    
    # Разбиваем на две части по 8 символов (32 бита каждая)
    # Используем знаковые int32 для PostgreSQL
    high_key = int(hash_hex[:8], 16) - 2**31  # Преобразуем в знаковый int32
    low_key = int(hash_hex[8:16], 16) - 2**31
    
    return high_key, low_key

class PostgresEventStore:
    """
    PostgreSQL реализация Event Store с батчевой записью.
    Полностью совместима с интерфейсом in-memory EventStore.
    """
    
    def __init__(self):
        self.logger = get_logger("postgres_event_store")
        self._write_buffer: deque = deque()
        self._flush_task: Optional[asyncio.Task] = None
        self._flush_lock = asyncio.Lock()
        self._is_initialized = False
        
        # Метрики
        self._total_events = 0
        self._total_appends = 0
        self._total_reads = 0
        self._version_conflicts = 0
        self._batch_writes = 0
        self._buffer_overflows = 0
        
    async def initialize(self) -> None:
        """Инициализировать подключение к БД и запустить фоновые задачи"""
        if self._is_initialized:
            return
            
        # Подключаемся к БД
        await db_connection.connect()
        
        # Проверяем схему
        await self._verify_schema()
        
        # Запускаем фоновую задачу периодического flush
        self._flush_task = asyncio.create_task(self._periodic_flush())
        
        self._is_initialized = True
        self.logger.info("PostgresEventStore initialized")
    
    async def close(self) -> None:
        """Закрыть Event Store и освободить ресурсы"""
        # Останавливаем фоновую задачу
        if self._flush_task:
            self._flush_task.cancel()
            try:
                await self._flush_task
            except asyncio.CancelledError:
                pass
        
        # Записываем оставшиеся события
        await self._flush_buffer()
        
        # НЕ отключаемся от БД - это ответственность внешнего кода
        # await db_connection.disconnect()
        
        self._is_initialized = False
        self.logger.info("PostgresEventStore closed")
    
    @measure_latency
    async def append_event(self, event: BaseEvent) -> None:
        """
        Добавить событие в store.
        Использует батчевую запись для оптимизации.
        """
        # Добавляем в буфер
        self._write_buffer.append(event)
        self._total_appends += 1
        
        # Проверяем размер буфера
        if len(self._write_buffer) >= EVENT_STORE_BATCH_SIZE:
            # Немедленный flush при достижении размера батча
            await self._flush_buffer()
        elif len(self._write_buffer) > EVENT_STORE_MAX_BUFFER_SIZE:
            # Защита от переполнения буфера
            self._buffer_overflows += 1
            self.logger.warning(
                f"Write buffer overflow, forcing flush. Size: {len(self._write_buffer)}"
            )
            await self._flush_buffer()
    
    async def get_stream(self, stream_id: str, from_version: int = 0) -> List[BaseEvent]:
        """Получить события потока начиная с указанной версии"""
        self._total_reads += 1
        
        query = """
            SELECT event_id, stream_id, event_type, data, timestamp, version, correlation_id
            FROM events
            WHERE stream_id = $1 AND version >= $2 AND NOT archived
            ORDER BY version ASC
        """
        
        rows = await db_connection.fetch(query, stream_id, from_version)
        
        events = []
        for row in rows:
            event = self._row_to_event(row)
            events.append(event)
            
        return events
    
    @measure_latency
    async def get_events_after(
        self, 
        timestamp: datetime, 
        event_types: Optional[List[str]] = None
    ) -> List[BaseEvent]:
        """Получить события после указанного времени"""
        if event_types:
            query = """
                SELECT event_id, stream_id, event_type, data, timestamp, version, correlation_id
                FROM events
                WHERE timestamp > $1 AND event_type = ANY($2) AND NOT archived
                ORDER BY timestamp ASC
                LIMIT 1000
            """
            rows = await db_connection.fetch(query, timestamp, event_types)
        else:
            query = """
                SELECT event_id, stream_id, event_type, data, timestamp, version, correlation_id
                FROM events
                WHERE timestamp > $1 AND NOT archived
                ORDER BY timestamp ASC
                LIMIT 1000
            """
            rows = await db_connection.fetch(query, timestamp)
        
        events = []
        for row in rows:
            event = self._row_to_event(row)
            events.append(event)
            
        return events
    
    async def get_last_event(self, stream_id: str) -> Optional[BaseEvent]:
        """Получить последнее событие потока"""
        query = """
            SELECT event_id, stream_id, event_type, data, timestamp, version, correlation_id
            FROM events
            WHERE stream_id = $1 AND NOT archived
            ORDER BY version DESC
            LIMIT 1
        """
        
        row = await db_connection.fetchrow(query, stream_id)
        
        if row:
            return self._row_to_event(row)
        return None
    
    async def stream_exists(self, stream_id: str) -> bool:
        """Проверить существование потока"""
        query = "SELECT EXISTS(SELECT 1 FROM events WHERE stream_id = $1 LIMIT 1)"
        return await db_connection.fetchval(query, stream_id)
    
    def get_metrics(self) -> Dict[str, int]:
        """Получить метрики Event Store"""
        return {
            'total_events': self._total_events,
            'total_appends': self._total_appends,
            'total_reads': self._total_reads,
            'version_conflicts': self._version_conflicts,
            'batch_writes': self._batch_writes,
            'buffer_size': len(self._write_buffer),
            'buffer_overflows': self._buffer_overflows,
            'db_pool_stats': db_connection.get_pool_stats()
        }
    
    async def _verify_schema(self) -> None:
        """Проверить версию схемы БД"""
        try:
            # Используем прямой запрос для получения значения
            query = "SELECT value ->> 'version' as version FROM event_store_metadata WHERE key = $1"
            version = await db_connection.fetchval(query, 'schema_version')
            
            if version is not None:
                schema_version = int(version)
                if schema_version != 1:
                    raise RuntimeError(
                        f"Incompatible schema version: {schema_version}, expected: 1"
                    )
                self.logger.info(f"Schema version verified: {schema_version}")
            else:
                raise RuntimeError("Schema version not found in metadata")
                
        except Exception as e:
            self.logger.error(f"Schema verification failed: {str(e)}")
            raise
    
    async def _periodic_flush(self) -> None:
        """Фоновая задача периодической записи буфера"""
        while True:
            try:
                await asyncio.sleep(EVENT_STORE_FLUSH_INTERVAL)
                
                if self._write_buffer:
                    await self._flush_buffer()
                    
            except asyncio.CancelledError:
                break
            except Exception as e:
                self.logger.error(f"Error in periodic flush: {str(e)}")
    
    async def _flush_buffer(self) -> None:
        """Записать все события из буфера в БД"""
        async with self._flush_lock:
            if not self._write_buffer:
                return
                
            # Копируем буфер и очищаем
            events_to_write = list(self._write_buffer)
            self._write_buffer.clear()
            
            # Группируем по потокам для проверки версий
            streams: Dict[str, List[BaseEvent]] = {}
            for event in events_to_write:
                if event.stream_id not in streams:
                    streams[event.stream_id] = []
                streams[event.stream_id].append(event)
            
            # Записываем каждый поток отдельно для корректной проверки версий
            written_count = 0
            for stream_id, stream_events in streams.items():
                try:
                    await self._write_stream_events(stream_id, stream_events)
                    written_count += len(stream_events)
                except EventStoreConcurrencyError as e:
                    self._version_conflicts += 1
                    self.logger.error(f"Version conflict for stream {stream_id}: {str(e)}")
                    # Возвращаем события обратно в буфер для повторной попытки
                    # Используем appendleft чтобы сохранить порядок
                    for event in reversed(stream_events):
                        self._write_buffer.appendleft(event)
                except Exception as e:
                    self.logger.error(f"Failed to write events for stream {stream_id}: {str(e)}")
                    # Возвращаем события обратно в буфер
                    # Используем appendleft чтобы сохранить порядок
                    for event in reversed(stream_events):
                        self._write_buffer.appendleft(event)
            
            if written_count > 0:
                self._batch_writes += 1
                self._total_events += written_count
                self.logger.debug(f"Flushed {written_count} events to database")
    
    async def _write_stream_events(self, stream_id: str, events: List[BaseEvent]) -> None:
        """Записать события одного потока с проверкой версий"""
        pool = db_connection.get_pool()
        
        async with pool.acquire() as conn:
            async with conn.transaction():
                # Блокируем все записи потока для обновления
                lock_query = """
                    SELECT version 
                    FROM events 
                    WHERE stream_id = $1 
                    ORDER BY version DESC 
                    LIMIT 1
                    FOR UPDATE
                """
                row = await conn.fetchrow(lock_query, stream_id)
                
                if row:
                    last_version = row['version']
                else:
                    # Если записей нет, проверяем что никто не вставляет параллельно
                    # используя advisory lock с двумя ключами для минимизации коллизий
                    high_key, low_key = generate_stream_lock_keys(stream_id)
                    await conn.execute(
                        "SELECT pg_advisory_xact_lock($1, $2)", 
                        high_key, 
                        low_key
                    )
                    
                    # Перепроверяем после блокировки
                    recheck_query = "SELECT MAX(version) FROM events WHERE stream_id = $1"
                    last_version = await conn.fetchval(recheck_query, stream_id)
                    last_version = last_version if last_version is not None else -1
                
                # Проверяем версии всех событий
                for event in events:
                    expected_version = last_version + 1
                    if event.version != expected_version:
                        raise EventStoreConcurrencyError(
                            stream_id, event.version, expected_version
                        )
                    last_version = event.version
                
                # Вставляем события батчем
                insert_query = """
                    INSERT INTO events 
                    (event_id, stream_id, event_type, data, timestamp, version, correlation_id)
                    VALUES ($1, $2, $3, $4::jsonb, $5, $6, $7)
                """
                
                # Подготавливаем данные для батчевой вставки
                values = []
                for event in events:
                    values.append((
                        uuid.UUID(event.event_id),
                        event.stream_id,
                        event.event_type,
                        json.dumps(event.data),  # Сериализуем для executemany
                        event.timestamp,
                        event.version,
                        uuid.UUID(event.correlation_id) if event.correlation_id else None
                    ))
                
                # Выполняем батчевую вставку
                await conn.executemany(insert_query, values)
    
    def _row_to_event(self, row: Dict[str, Any]) -> BaseEvent:
        """Преобразовать строку БД в объект BaseEvent"""
        # Проверяем тип data и парсим если нужно
        data = row['data']
        if isinstance(data, str):
            data = json.loads(data)
        
        # Создаем событие напрямую, чтобы обойти frozen=True
        return BaseEvent(
            event_id=str(row['event_id']),
            stream_id=row['stream_id'],
            event_type=row['event_type'],
            data=data,
            timestamp=row['timestamp'],
            version=row['version'],
            correlation_id=str(row['correlation_id']) if row['correlation_id'] else None
        )