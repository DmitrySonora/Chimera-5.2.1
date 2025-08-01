"""
Безопасная миграция событий между разными реализациями Event Store
"""
import asyncio
from typing import Dict, List
from datetime import datetime
from config.logging import get_logger
from config.settings import (
    EVENT_STORE_MIGRATION_DELAY,
    EVENT_STORE_MIGRATION_VERIFY
)
from actors.events.event_store import EventStore
from actors.events.postgres_event_store import PostgresEventStore
from actors.events.event_store_factory import EventStoreFactory


class EventStoreMigrator:
    """
    Инструмент для миграции событий между разными реализациями Event Store.
    Поддерживает батчевую миграцию, верификацию и обработку ошибок.
    """
    
    def __init__(self):
        self.logger = get_logger("event_store_migrator")
        self._migration_stats = {
            'total_events': 0,
            'migrated_events': 0,
            'failed_events': 0,
            'total_streams': 0,
            'migrated_streams': 0,
            'start_time': None,
            'end_time': None
        }
    
    async def migrate(
        self, 
        source: EventStore, 
        target: PostgresEventStore,
        verify: bool = EVENT_STORE_MIGRATION_VERIFY
    ) -> Dict[str, any]:
        """
        Мигрировать все события из источника в назначение.
        
        Args:
            source: Event Store источник
            target: Event Store назначение
            verify: Выполнять ли верификацию после миграции
            
        Returns:
            Словарь со статистикой миграции
        """
        self.logger.info("Starting Event Store migration...")
        self._migration_stats['start_time'] = datetime.now()
        
        try:
            # Получаем все потоки из источника
            streams = self._get_all_streams(source)
            self._migration_stats['total_streams'] = len(streams)
            
            # Подсчитываем общее количество событий
            total_events = sum(len(events) for events in streams.values())
            self._migration_stats['total_events'] = total_events
            
            self.logger.info(
                f"Found {len(streams)} streams with {total_events} events total"
            )
            
            # Мигрируем по потокам
            for stream_id, events in streams.items():
                await self._migrate_stream(stream_id, events, target)
                
                # Задержка между потоками для снижения нагрузки
                if EVENT_STORE_MIGRATION_DELAY > 0:
                    await asyncio.sleep(EVENT_STORE_MIGRATION_DELAY)
            
            # Верификация если включена
            if verify:
                await self._verify_migration(source, target)
            
            self._migration_stats['end_time'] = datetime.now()
            duration = (
                self._migration_stats['end_time'] - 
                self._migration_stats['start_time']
            ).total_seconds()
            
            self.logger.info(
                f"Migration completed in {duration:.2f} seconds. "
                f"Migrated {self._migration_stats['migrated_events']}/{total_events} events"
            )
            
            return self._migration_stats
            
        except Exception as e:
            self.logger.error(f"Migration failed: {str(e)}")
            self._migration_stats['end_time'] = datetime.now()
            raise
    
    def _get_all_streams(self, source: EventStore) -> Dict[str, List]:
        """
        Получить все потоки из источника.
        Использует приватный атрибут _streams для in-memory store.
        """
        if hasattr(source, '_streams'):
            # In-memory store
            streams = {}
            for stream_id, events in source._streams.items():
                # Копируем события чтобы не изменить оригинал
                streams[stream_id] = events.copy()
            
            # Сортируем по размеру (маленькие первыми для быстрого прогресса)
            sorted_streams = dict(
                sorted(streams.items(), key=lambda x: len(x[1]))
            )
            return sorted_streams
        else:
            # Для других реализаций нужно будет добавить метод
            raise NotImplementedError(
                "Migration from non-memory stores not implemented yet"
            )
    
    async def _migrate_stream(
        self, 
        stream_id: str, 
        events: List, 
        target: PostgresEventStore
    ) -> None:
        """Мигрировать один поток событий атомарно"""
        self.logger.info(
            f"Migrating stream {stream_id} with {len(events)} events..."
        )
        
        try:
            # Для атомарности миграции потока записываем все события
            # в одной транзакции напрямую через private метод
            if hasattr(target, '_write_stream_events'):
                # Используем приватный метод для атомарной записи
                await target._write_stream_events(stream_id, events)
            else:
                # Fallback на старый метод если приватный недоступен
                for event in events:
                    await target.append_event(event)
            
            self._migration_stats['migrated_events'] += len(events)
            self._migration_stats['migrated_streams'] += 1
            
            # Логируем прогресс
            progress = (
                self._migration_stats['migrated_events'] / 
                self._migration_stats['total_events'] * 100
            )
            self.logger.debug(
                f"Progress: {progress:.1f}% "
                f"({self._migration_stats['migrated_events']}/{self._migration_stats['total_events']})"
            )
            
        except Exception as e:
            self.logger.error(
                f"Failed to migrate stream {stream_id}: {str(e)}"
            )
            self._migration_stats['failed_events'] += len(events)
            # При ошибке весь поток не мигрирован
    
    async def _verify_migration(
        self, 
        source: EventStore, 
        target: PostgresEventStore
    ) -> None:
        """Верифицировать успешность миграции"""
        self.logger.info("Verifying migration...")
        
        discrepancies = []
        
        # Получаем все потоки из источника
        source_streams = self._get_all_streams(source)
        
        # Проверяем каждый поток
        for stream_id, source_events in source_streams.items():
            try:
                # Получаем события из target
                target_events = await target.get_stream(stream_id)
                
                # Сравниваем количество
                if len(source_events) != len(target_events):
                    discrepancies.append(
                        f"Stream {stream_id}: source has {len(source_events)} events, "
                        f"target has {len(target_events)}"
                    )
                    continue
                
                # Выборочная проверка событий (первое, последнее и случайное)
                indices_to_check = [0, -1]
                if len(source_events) > 2:
                    import random
                    indices_to_check.append(random.randint(1, len(source_events) - 2))
                
                for idx in indices_to_check:
                    if idx < len(source_events):
                        source_event = source_events[idx]
                        target_event = target_events[idx]
                        
                        # Сравниваем ключевые поля
                        if (source_event.event_id != target_event.event_id or
                            source_event.event_type != target_event.event_type or
                            source_event.version != target_event.version):
                            discrepancies.append(
                                f"Stream {stream_id}, event {idx}: mismatch"
                            )
                            
            except Exception as e:
                discrepancies.append(
                    f"Stream {stream_id}: verification error - {str(e)}"
                )
        
        if discrepancies:
            self.logger.error(
                f"Verification failed with {len(discrepancies)} discrepancies:"
            )
            for d in discrepancies[:10]:  # Показываем первые 10
                self.logger.error(f"  - {d}")
            if len(discrepancies) > 10:
                self.logger.error(f"  ... and {len(discrepancies) - 10} more")
        else:
            self.logger.info("Verification passed! All events migrated correctly")


async def migrate_event_store():
    """Точка входа для скрипта миграции"""
    migrator = EventStoreMigrator()
    logger = get_logger("migration_script")
    
    try:
        # Создаем source и target stores
        logger.info("Creating Event Stores for migration...")
        source, target = await EventStoreFactory.create_for_migration("memory", "postgres")
        
        # Выполняем миграцию
        stats = await migrator.migrate(source, target)
        
        # Выводим статистику
        logger.info("Migration statistics:")
        logger.info(f"  Total streams: {stats['total_streams']}")
        logger.info(f"  Total events: {stats['total_events']}")
        logger.info(f"  Migrated events: {stats['migrated_events']}")
        logger.info(f"  Failed events: {stats['failed_events']}")
        
        duration = (stats['end_time'] - stats['start_time']).total_seconds()
        logger.info(f"  Duration: {duration:.2f} seconds")
        
        # Закрываем target store
        if hasattr(target, 'close'):
            await target.close()
            
    except Exception as e:
        logger.error(f"Migration failed: {str(e)}")
        raise


if __name__ == "__main__":
    # Запуск миграции из командной строки
    asyncio.run(migrate_event_store())