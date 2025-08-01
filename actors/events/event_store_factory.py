"""
Фабрика для создания нужной реализации Event Store
"""
from typing import Union
from config.logging import get_logger
from config.settings import EVENT_STORE_TYPE
from actors.events.event_store import EventStore
from actors.events.postgres_event_store import PostgresEventStore


class EventStoreFactory:
    """
    Фабрика для выбора и создания реализации Event Store.
    Поддерживает graceful fallback на in-memory при проблемах с БД.
    """
    
    @staticmethod
    async def create() -> Union[EventStore, PostgresEventStore]:
        """
        Создать экземпляр Event Store согласно конфигурации.
        
        Returns:
            EventStore или PostgresEventStore в зависимости от настроек
            
        Raises:
            ValueError: При неизвестном типе store
        """
        logger = get_logger("event_store_factory")
        
        if EVENT_STORE_TYPE == "postgres":
            try:
                logger.info("Creating PostgreSQL Event Store...")
                store = PostgresEventStore()
                await store.initialize()
                logger.info("PostgreSQL Event Store created successfully")
                return store
                
            except Exception as e:
                logger.error(
                    f"Failed to initialize PostgreSQL Event Store: {str(e)}. "
                    f"Falling back to in-memory store"
                )
                # Fallback на in-memory реализацию
                logger.warning("Using in-memory Event Store as fallback")
                return EventStore()
                
        elif EVENT_STORE_TYPE == "memory":
            logger.info("Creating in-memory Event Store")
            return EventStore()
            
        else:
            raise ValueError(
                f"Unknown EVENT_STORE_TYPE: {EVENT_STORE_TYPE}. "
                f"Valid options: 'memory', 'postgres'"
            )
    
    @staticmethod
    async def create_for_migration(source_type: str, target_type: str) -> tuple:
        """
        Создать пару Event Store для миграции данных.
        
        Args:
            source_type: Тип источника ('memory' или 'postgres')
            target_type: Тип назначения ('memory' или 'postgres')
            
        Returns:
            Кортеж (source_store, target_store)
        """
        logger = get_logger("event_store_factory")
        
        # Создаем источник
        if source_type == "memory":
            source = EventStore()
            logger.info("Created in-memory source store")
        elif source_type == "postgres":
            source = PostgresEventStore()
            await source.initialize()
            logger.info("Created PostgreSQL source store")
        else:
            raise ValueError(f"Unknown source type: {source_type}")
        
        # Создаем назначение
        if target_type == "memory":
            target = EventStore()
            logger.info("Created in-memory target store")
        elif target_type == "postgres":
            target = PostgresEventStore()
            await target.initialize()
            logger.info("Created PostgreSQL target store")
        else:
            raise ValueError(f"Unknown target type: {target_type}")
        
        return source, target