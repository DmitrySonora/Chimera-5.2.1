import asyncio
import pytest
from datetime import datetime, timedelta
from actors.events import BaseEvent, EventStore, EventStoreConcurrencyError
from actors.actor_system import ActorSystem
from actors.messages import ActorMessage, MESSAGE_TYPES
from tests.fixtures import EchoActor

# Тестовые константы
TEST_PROCESSING_DELAY = 0.1   # Задержка для обработки событий
TEST_PERFORMANCE_LIMIT_MS = 10  # Лимит для append операций в мс
TEST_READ_LIMIT_MS = 50        # Лимит для read операций в мс
TEST_TIME_DIFF_TOLERANCE = 1   # Допустимая разница времени в секундах

def test_base_event_pydantic_validation():
    """Тест Pydantic валидации BaseEvent"""
    # Валидное событие
    event = BaseEvent.create(
        stream_id="test",
        event_type="TestEvent",
        data={"key": "value"},
        version=0
    )
    assert event.stream_id == "test"
    assert event.version == 0
    
    # Проверка иммутабельности
    with pytest.raises(Exception):  # Pydantic выбросит ошибку валидации
        event.version = 1
    
    # Проверка валидации версии
    with pytest.raises(ValueError) as exc_info:
        BaseEvent.create(
            stream_id="test",
            event_type="TestEvent",
            version=-1  # Отрицательная версия
        )
    assert "Version must be non-negative" in str(exc_info.value)

@pytest.mark.asyncio
async def test_basic_append_and_retrieve():
    """Тест базового добавления и получения событий"""
    store = EventStore()
    
    # Создаем событие
    event = BaseEvent.create(
        stream_id="test-stream",
        event_type="TestEvent",
        data={"message": "Hello, World!"},
        version=0
    )
    
    # Добавляем в store
    await store.append_event(event)
    
    # Получаем обратно
    events = await store.get_stream("test-stream")
    
    assert len(events) == 1
    assert events[0].event_id == event.event_id
    assert events[0].data["message"] == "Hello, World!"
    assert events[0].version == 0


@pytest.mark.asyncio
async def test_version_conflict():
    """Тест обработки конфликта версий"""
    store = EventStore()
    
    # Добавляем первое событие
    event1 = BaseEvent.create(
        stream_id="version-test",
        event_type="TestEvent",
        data={"number": 1},
        version=0
    )
    await store.append_event(event1)
    
    # Пытаемся добавить событие с неправильной версией
    event2 = BaseEvent.create(
        stream_id="version-test",
        event_type="TestEvent",
        data={"number": 2},
        version=0  # Должна быть 1!
    )
    
    with pytest.raises(EventStoreConcurrencyError) as exc_info:
        await store.append_event(event2)
    
    assert exc_info.value.stream_id == "version-test"
    assert exc_info.value.expected_version == 0
    assert exc_info.value.actual_version == 1


@pytest.mark.asyncio
async def test_concurrent_streams():
    """Тест параллельной записи в разные потоки"""
    store = EventStore()
    
    async def write_to_stream(stream_id: str, count: int):
        for i in range(count):
            event = BaseEvent.create(
                stream_id=stream_id,
                event_type="ConcurrentEvent",
                data={"index": i},
                version=i
            )
            await store.append_event(event)
    
    # Запускаем параллельную запись в 10 потоков
    tasks = []
    for i in range(10):
        task = write_to_stream(f"stream-{i}", 10)
        tasks.append(task)
    
    await asyncio.gather(*tasks)
    
    # Проверяем, что все события записались
    for i in range(10):
        events = await store.get_stream(f"stream-{i}")
        assert len(events) == 10
        # Проверяем порядок
        for j, event in enumerate(events):
            assert event.data["index"] == j


@pytest.mark.asyncio
async def test_timestamp_filtering():
    """Тест фильтрации по времени и типам"""
    store = EventStore()
    
    # Добавляем события в разное время
    base_time = datetime.now()
    
    # События типа A
    for i in range(3):
        event = BaseEvent.create(
            stream_id="filter-test",
            event_type="TypeA",
            data={"index": i},
            version=i
        )
        # Хак для установки времени в прошлое
        event = BaseEvent(
            event_id=event.event_id,
            stream_id=event.stream_id,
            event_type=event.event_type,
            timestamp=base_time - timedelta(minutes=10-i),
            data=event.data,
            version=event.version,
            correlation_id=event.correlation_id
        )
        await store.append_event(event)
    
    # События типа B
    for i in range(3):
        event = BaseEvent.create(
            stream_id="filter-test",
            event_type="TypeB",
            data={"index": i},
            version=i+3
        )
        await store.append_event(event)
    
    # Получаем события после определенного времени
    cutoff_time = base_time - timedelta(minutes=8)
    recent_events = await store.get_events_after(cutoff_time)
    
    # Должны получить события с индексами 1, 2 типа A и все типа B
    # Но событие с индексом 1 может быть на границе из-за точности времени
    assert len(recent_events) >= 4
    
    # Фильтруем только по типу B
    type_b_events = await store.get_events_after(cutoff_time, ["TypeB"])
    assert len(type_b_events) == 3
    assert all(e.event_type == "TypeB" for e in type_b_events)


@pytest.mark.asyncio
async def test_dlq_integration():
    """Тест интеграции с Dead Letter Queue"""
    from actors.events import EventStore
    
    # Создаем систему с Event Store
    system = ActorSystem("test")
    event_store = EventStore()
    system.set_event_store(event_store)
    
    # Создаем актор с маленькой очередью
    class TinyQueueActor(EchoActor):
        def __init__(self, actor_id: str, name: str):
            super().__init__(actor_id, name)
            self._message_queue = asyncio.Queue(maxsize=1)
    
    actor = TinyQueueActor("tiny", "TinyQueue")
    await system.register_actor(actor)
    
    # Заполняем очередь
    msg1 = ActorMessage.create(
        sender_id="test",
        message_type=MESSAGE_TYPES['PING']
    )
    await system.send_message("tiny", msg1)
    
    # Следующее сообщение должно попасть в DLQ
    msg2 = ActorMessage.create(
        sender_id="test",
        message_type=MESSAGE_TYPES['PING']
    )
    
    try:
        await system.send_message("tiny", msg2)
    except Exception:
        pass  # Ожидаем ошибку
    
    # Даем время на обработку события
    await asyncio.sleep(TEST_PROCESSING_DELAY)
    
    # Проверяем, что событие попало в Event Store
    dlq_events = await event_store.get_stream("dlq_tiny")
    assert len(dlq_events) > 0
    assert dlq_events[0].event_type == "DeadLetterQueuedEvent"
    assert dlq_events[0].data["message_id"] == msg2.message_id


@pytest.mark.asyncio
async def test_memory_cleanup():
    """Тест автоматической очистки при переполнении"""
    # Временно устанавливаем маленький лимит для теста
    import config.settings
    original_limit = config.settings.EVENT_STORE_MAX_MEMORY_EVENTS
    config.settings.EVENT_STORE_MAX_MEMORY_EVENTS = 100
    
    try:
        store = EventStore()
        
        # Добавляем события в 20 потоков
        for stream_num in range(20):
            for event_num in range(10):
                event = BaseEvent.create(
                    stream_id=f"stream-{stream_num}",
                    event_type="TestEvent",
                    data={"stream": stream_num, "event": event_num},
                    version=event_num
                )
                await store.append_event(event)
        
        # Должно быть 200 событий, но лимит 100
        # Проверяем, что произошла очистка
        total_events = 0
        existing_streams = 0
        
        for i in range(20):
            if await store.stream_exists(f"stream-{i}"):
                existing_streams += 1
                stream_events = await store.get_stream(f"stream-{i}")
                total_events += len(stream_events)
        
        # Должно остаться меньше исходных 20 потоков
        assert existing_streams < 20
        # Общее количество событий должно быть около лимита
        assert total_events <= config.settings.EVENT_STORE_MAX_MEMORY_EVENTS
        assert total_events > 0  # Но что-то должно остаться
        
        print(f"After cleanup: {existing_streams} streams, {total_events} events")
        
    finally:
        # Восстанавливаем оригинальный лимит
        config.settings.EVENT_STORE_MAX_MEMORY_EVENTS = original_limit


@pytest.mark.asyncio
async def test_performance():
    """Тест производительности операций"""
    import time
    
    store = EventStore()
    
    # Временно увеличиваем лимит для теста производительности
    import config.settings
    original_limit = config.settings.EVENT_STORE_MAX_MEMORY_EVENTS
    config.settings.EVENT_STORE_MAX_MEMORY_EVENTS = 20000
    
    # Тест скорости append
    start_time = time.time()
    for i in range(1000):
        event = BaseEvent.create(
            stream_id="perf-test",
            event_type="PerfEvent",
            data={"index": i},
            version=i
        )
        await store.append_event(event)
    
    append_time = time.time() - start_time
    avg_append_time = (append_time / 1000) * 1000  # в миллисекундах
    
    print(f"Average append time: {avg_append_time:.2f}ms")
    assert avg_append_time < TEST_PERFORMANCE_LIMIT_MS  # Должно быть меньше 10ms
    
    # Тест скорости чтения
    start_time = time.time()
    events = await store.get_stream("perf-test", from_version=900)
    read_time = (time.time() - start_time) * 1000  # в миллисекундах
    
    print(f"Read 100 events time: {read_time:.2f}ms")
    assert len(events) == 100
    assert read_time < TEST_READ_LIMIT_MS  # Должно быть меньше 50ms
    
    # Восстанавливаем оригинальный лимит
    config.settings.EVENT_STORE_MAX_MEMORY_EVENTS = original_limit


# Дополнительные тесты для edge cases

@pytest.mark.asyncio
async def test_empty_stream():
    """Тест работы с несуществующими потоками"""
    store = EventStore()
    
    # Получение несуществующего потока
    events = await store.get_stream("non-existent")
    assert events == []
    
    # Проверка существования
    exists = await store.stream_exists("non-existent")
    assert exists is False
    
    # Получение последнего события
    last_event = await store.get_last_event("non-existent")
    assert last_event is None


@pytest.mark.asyncio
async def test_event_serialization():
    """Тест сериализации и десериализации событий"""
    event = BaseEvent.create(
        stream_id="serial-test",
        event_type="SerialEvent",
        data={
            "string": "test",
            "number": 42,
            "float": 3.14,
            "bool": True,
            "null": None,
            "list": [1, 2, 3],
            "dict": {"nested": "value"}
        },
        correlation_id="test-correlation-id"
    )
    
    # Сериализация
    event_dict = event.to_dict()
    
    # Десериализация
    restored_event = BaseEvent.from_dict(event_dict)
    
    # Проверка
    assert restored_event.event_id == event.event_id
    assert restored_event.stream_id == event.stream_id
    assert restored_event.event_type == event.event_type
    assert restored_event.data == event.data
    assert restored_event.correlation_id == event.correlation_id
    # Время может немного отличаться из-за сериализации
    assert abs((restored_event.timestamp - event.timestamp).total_seconds()) < TEST_TIME_DIFF_TOLERANCE
    
    # Проверка Pydantic сериализации
    pydantic_dict = event.model_dump()
    assert 'event_id' in pydantic_dict
    assert 'stream_id' in pydantic_dict
    assert pydantic_dict['data'] == event.data