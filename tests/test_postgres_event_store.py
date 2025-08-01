import asyncio
import pytest
import pytest_asyncio
from datetime import datetime, timedelta
from actors.events import BaseEvent, PostgresEventStore


@pytest_asyncio.fixture
async def postgres_store(clean_test_data):
    """Фикстура для создания PostgreSQL Event Store"""
    # Создаем store
    store = PostgresEventStore()
    await store.initialize()
    
    # Возвращаем store для использования в тестах
    yield store
    
    # Закрываем store (но не подключение к БД)
    await store.close()


@pytest.mark.asyncio
async def test_postgres_basic_append_and_retrieve(postgres_store):
    """Тест базового добавления и получения событий"""
    # Создаем событие
    event = BaseEvent.create(
        stream_id="test_stream_1",
        event_type="TestEvent",
        data={"message": "Hello PostgreSQL"},
        version=0
    )
    
    # Добавляем
    await postgres_store.append_event(event)
    
    # Форсируем запись
    await postgres_store._flush_buffer()
    
    # Получаем обратно
    events = await postgres_store.get_stream("test_stream_1")
    
    assert len(events) == 1
    assert events[0].event_id == event.event_id
    assert events[0].data["message"] == "Hello PostgreSQL"


@pytest.mark.asyncio
async def test_postgres_batch_write(postgres_store):
    """Тест батчевой записи событий"""
    # Создаем много событий
    events = []
    for i in range(150):  # Больше чем BATCH_SIZE
        event = BaseEvent.create(
            stream_id="test_stream_batch",
            event_type="BatchEvent",
            data={"index": i},
            version=i
        )
        events.append(event)
    
    # Добавляем все события
    for event in events:
        await postgres_store.append_event(event)
    
    # Проверяем метрики буфера
    metrics = postgres_store.get_metrics()
    assert metrics['batch_writes'] > 0  # Должен был произойти хотя бы один батч
    
    # Форсируем запись остатка
    await postgres_store._flush_buffer()
    
    # Проверяем что все записалось
    stored_events = await postgres_store.get_stream("test_stream_batch")
    assert len(stored_events) == 150


@pytest.mark.asyncio
async def test_postgres_version_conflict(postgres_store):
    """Тест обработки конфликтов версий"""
    # Добавляем первое событие
    event1 = BaseEvent.create(
        stream_id="test_version_conflict",
        event_type="TestEvent",
        data={"number": 1},
        version=0
    )
    await postgres_store.append_event(event1)
    await postgres_store._flush_buffer()
    
    # Пытаемся добавить с неправильной версией
    event2 = BaseEvent.create(
        stream_id="test_version_conflict",
        event_type="TestEvent",
        data={"number": 2},
        version=0  # Должна быть 1!
    )
    
    await postgres_store.append_event(event2)
    
    # Сохраняем метрики до flush
    metrics_before = postgres_store.get_metrics()
    conflicts_before = metrics_before['version_conflicts']
    
    # При flush конфликт должен быть обработан
    await postgres_store._flush_buffer()
    
    # Проверяем, что конфликт был зафиксирован
    metrics_after = postgres_store.get_metrics()
    assert metrics_after['version_conflicts'] == conflicts_before + 1
    
    # Проверяем, что событие вернулось в буфер
    assert metrics_after['buffer_size'] == 1
    
    # Проверяем, что в БД только первое событие
    events = await postgres_store.get_stream("test_version_conflict")
    assert len(events) == 1
    assert events[0].data["number"] == 1


@pytest.mark.asyncio
async def test_postgres_concurrent_streams(postgres_store):
    """Тест параллельной записи в разные потоки"""
    async def write_stream(stream_id: str, count: int):
        for i in range(count):
            event = BaseEvent.create(
                stream_id=stream_id,
                event_type="ConcurrentEvent",
                data={"index": i},
                version=i
            )
            await postgres_store.append_event(event)
    
    # Запускаем параллельную запись
    tasks = []
    for i in range(5):
        task = write_stream(f"test_concurrent_{i}", 20)
        tasks.append(task)
    
    await asyncio.gather(*tasks)
    await postgres_store._flush_buffer()
    
    # Проверяем все потоки
    for i in range(5):
        events = await postgres_store.get_stream(f"test_concurrent_{i}")
        assert len(events) == 20


@pytest.mark.asyncio
async def test_postgres_timestamp_filtering(postgres_store):
    """Тест фильтрации по времени"""
    base_time = datetime.now()
    
    # Добавляем события с разными типами
    for i in range(10):
        event = BaseEvent.create(
            stream_id="test_filter",
            event_type="TypeA" if i < 5 else "TypeB",
            data={"index": i},
            version=i
        )
        await postgres_store.append_event(event)
    
    await postgres_store._flush_buffer()
    
    # Получаем события после базового времени
    recent_events = await postgres_store.get_events_after(
        base_time - timedelta(minutes=1)
    )
    assert len(recent_events) == 10
    
    # Фильтруем по типу
    type_b_events = await postgres_store.get_events_after(
        base_time - timedelta(minutes=1),
        ["TypeB"]
    )
    assert len(type_b_events) == 5
    assert all(e.event_type == "TypeB" for e in type_b_events)


@pytest.mark.asyncio
async def test_postgres_metrics(postgres_store):
    """Тест сбора метрик"""
    # Добавляем события
    for i in range(10):
        event = BaseEvent.create(
            stream_id="test_metrics",
            event_type="MetricEvent",
            data={"index": i},
            version=i
        )
        await postgres_store.append_event(event)
    
    # Читаем поток
    await postgres_store.get_stream("test_metrics")
    
    # Проверяем метрики
    metrics = postgres_store.get_metrics()
    assert metrics['total_appends'] == 10
    assert metrics['total_reads'] == 1
    assert 'db_pool_stats' in metrics


if __name__ == "__main__":
    # Для локального запуска тестов
    pytest.main([__file__, "-v"])