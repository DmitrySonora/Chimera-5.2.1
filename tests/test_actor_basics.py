# pytest tests/test_actor_basics.py -v

import asyncio
import pytest
from typing import Optional
from actors.actor_system import ActorSystem
from actors.base_actor import BaseActor
from actors.messages import ActorMessage, MESSAGE_TYPES
from tests.fixtures import EchoActor

# Тестовые константы
TEST_PROCESSING_DELAY = 0.1  # Задержка для обработки сообщений
TEST_SHUTDOWN_TIMEOUT = 0.5  # Таймаут для shutdown тестов
TEST_SLEEP_DURATION = 10     # Длительность сна для медленных операций

def test_actor_message_pydantic_validation():
    """Тест Pydantic валидации ActorMessage"""
    # Создание через конструктор
    msg1 = ActorMessage(
        sender_id="test",
        message_type=MESSAGE_TYPES['PING'],
        payload={"data": "test"}
    )
    assert msg1.sender_id == "test"
    assert msg1.message_type == MESSAGE_TYPES['PING']
    
    # Создание через фабричный метод
    msg2 = ActorMessage.create(
        sender_id="test2",
        message_type=MESSAGE_TYPES['PONG']
    )
    assert msg2.sender_id == "test2"
    assert msg2.payload == {}  # По умолчанию пустой dict
    
    # Проверка, что message_id генерируется автоматически
    assert msg1.message_id != msg2.message_id
    assert len(msg1.message_id) == 36  # UUID
    
    # Проверка обратной совместимости через __getitem__
    assert msg1['sender_id'] == "test"
    assert msg1['message_type'] == MESSAGE_TYPES['PING']


class FailingActor(BaseActor):
    """Актор для тестирования обработки ошибок"""
    
    async def initialize(self):
        pass
        
    async def shutdown(self):
        pass
        
    async def handle_message(self, message: ActorMessage) -> Optional[ActorMessage]:
        raise RuntimeError("Test error")


@pytest.mark.asyncio
async def test_actor_lifecycle():
    """Тест полного цикла жизни актора"""
    # Создаем систему и актор
    system = ActorSystem()
    actor = EchoActor("test-1", "echo")
    
    # Регистрируем актор
    await system.register_actor(actor)
    
    # Запускаем систему
    await system.start()
    assert system.is_running
    assert actor.is_running
    
    # Отправляем сообщение
    ping_msg = ActorMessage.create(
        sender_id="test",
        message_type=MESSAGE_TYPES['PING'],
        payload={'data': 'test'}
    )
    await system.send_message("test-1", ping_msg)
    
    # Даем время на обработку
    await asyncio.sleep(TEST_PROCESSING_DELAY)
    
    # Проверяем, что сообщение обработано
    assert actor.processed_count == 1
    
    # Останавливаем систему
    await system.stop()
    assert not system.is_running
    assert not actor.is_running


@pytest.mark.asyncio
async def test_actor_error_handling():
    """Тест обработки ошибок в handle_message"""
    system = ActorSystem()
    actor = FailingActor("error-1", "error")
    
    await system.register_actor(actor)
    await system.start()
    
    # Отправляем сообщение, которое вызовет ошибку
    msg = ActorMessage.create(
        sender_id="test",
        message_type="test"
    )
    await system.send_message("error-1", msg)
    
    # Даем время на обработку
    await asyncio.sleep(TEST_PROCESSING_DELAY)
    
    # Актор должен продолжить работу после ошибки
    assert actor.is_running
    
    await system.stop()


@pytest.mark.asyncio
async def test_message_broadcast():
    """Тест broadcast сообщений нескольким акторам"""
    system = ActorSystem()
    
    # Создаем несколько акторов
    actors = []
    for i in range(3):
        actor = EchoActor(f"echo-{i}", f"echo{i}")
        actors.append(actor)
        await system.register_actor(actor)
    
    await system.start()
    
    # Отправляем broadcast
    ping_msg = ActorMessage.create(
        sender_id="broadcast",
        message_type=MESSAGE_TYPES['PING']
    )
    await system.broadcast_message(ping_msg, exclude=["echo-1"])
    
    # Даем время на обработку
    await asyncio.sleep(TEST_PROCESSING_DELAY)
    
    # Проверяем, что сообщения получили только не исключенные акторы
    assert actors[0].processed_count == 1
    assert actors[1].processed_count == 0  # исключен
    assert actors[2].processed_count == 1
    
    await system.stop()


@pytest.mark.asyncio
async def test_queue_overflow():
    """Тест поведения при переполнении очереди"""
    # Создаем специальный актор с маленькой очередью
    class SmallQueueActor(EchoActor):
        def __init__(self, actor_id: str, name: str):
            super().__init__(actor_id, name)
            # Переопределяем очередь с маленьким размером
            self._message_queue = asyncio.Queue(maxsize=2)
    
    system = ActorSystem()
    actor = SmallQueueActor("overflow-1", "overflow")
    
    await system.register_actor(actor)
    # Не запускаем систему, чтобы сообщения накапливались
    
    # Заполняем очередь
    for i in range(2):
        msg = ActorMessage.create(
            sender_id="test",
            message_type=MESSAGE_TYPES['PING']
        )
        await actor.send_message(msg)
    
    # Следующее сообщение должно вызвать ошибку
    with pytest.raises(asyncio.QueueFull):
        msg = ActorMessage.create(
            sender_id="test",
            message_type=MESSAGE_TYPES['PING']
        )
        await actor.send_message(msg)


@pytest.mark.asyncio
async def test_shutdown_timeout():
    """Тест graceful shutdown с таймаутом"""
    class SlowActor(BaseActor):
        async def initialize(self):
            pass
            
        async def shutdown(self):
            # Имитируем долгое завершение
            await asyncio.sleep(10)
            
        async def handle_message(self, message: ActorMessage) -> Optional[ActorMessage]:
            return None
    
    system = ActorSystem()
    actor = SlowActor("slow-1", "slow")
    
    await system.register_actor(actor)
    await system.start()
    
    # Останавливаем с коротким таймаутом
    await system.stop(timeout=TEST_SHUTDOWN_TIMEOUT)
    
    # Система должна остановиться несмотря на долгий shutdown актора
    assert not system.is_running