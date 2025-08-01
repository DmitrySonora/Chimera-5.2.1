import asyncio
import pytest
from actors.actor_system import ActorSystem
from actors.events import EventStore
from actors.messages import ActorMessage, MESSAGE_TYPES
from tests.fixtures import EchoActor

# Тестовые константы
TEST_BACKGROUND_TASK_DELAY = 0.1  # Задержка для фоновых задач


@pytest.mark.asyncio
async def test_event_store_integration_with_actor_system():
    """Тест полной интеграции Event Store с ActorSystem"""
    # Создаем компоненты
    system = ActorSystem("test-integration")
    event_store = EventStore()
    
    # Проверяем, что метод set_event_store существует
    assert hasattr(system, 'set_event_store'), "Метод set_event_store не найден"
    
    # Устанавливаем Event Store
    system.set_event_store(event_store)
    
    # Создаем актор с маленькой очередью для теста DLQ
    class TinyActor(EchoActor):
        def __init__(self, actor_id: str, name: str):
            super().__init__(actor_id, name)
            self._message_queue = asyncio.Queue(maxsize=1)
    
    actor = TinyActor("tiny", "TinyActor")
    await system.register_actor(actor)
    
    # Заполняем очередь
    msg1 = ActorMessage.create(
        sender_id="test",
        message_type=MESSAGE_TYPES['PING']
    )
    await system.send_message("tiny", msg1)
    
    # Вызываем переполнение
    msg2 = ActorMessage.create(
        sender_id="test",
        message_type=MESSAGE_TYPES['PING']
    )
    
    try:
        await system.send_message("tiny", msg2)
    except asyncio.QueueFull:
        pass
    
    # Важно: ждем немного для обработки фоновых задач
    await asyncio.sleep(TEST_BACKGROUND_TASK_DELAY)
    
    # Останавливаем систему (должна дождаться всех задач)
    await system.stop()
    
    # Проверяем, что событие попало в Event Store
    dlq_events = await event_store.get_stream("dlq_tiny")
    assert len(dlq_events) > 0, "DLQ события не сохранились"
    assert dlq_events[0].event_type == "DeadLetterQueuedEvent"
    
    print(f"✅ Интеграция работает: {len(dlq_events)} DLQ событий сохранено")


@pytest.mark.asyncio
async def test_background_tasks_complete_on_shutdown():
    """Тест, что все фоновые задачи завершаются при shutdown"""
    system = ActorSystem("test-shutdown")
    event_store = EventStore()
    system.set_event_store(event_store)
    
    # Создаем много событий DLQ
    for i in range(10):
        await system._send_to_dead_letter_queue(
            f"actor-{i}",
            ActorMessage.create("test", MESSAGE_TYPES['PING']),
            "Test error"
        )
    
    # Проверяем, что есть активные задачи
    active_tasks = [t for t in system._background_tasks if not t.done()]
    assert len(active_tasks) > 0, "Должны быть активные фоновые задачи"
    
    # Останавливаем систему
    await system.stop()
    
    # Все задачи должны быть завершены
    for task in system._background_tasks:
        assert task.done(), "Есть незавершенные задачи после shutdown"
    
    print(f"✅ Все {len(system._background_tasks)} фоновых задач завершены")