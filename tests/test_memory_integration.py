import asyncio
import pytest
import os

from actors.actor_system import ActorSystem
from actors.memory_actor import MemoryActor
from actors.messages import ActorMessage, MESSAGE_TYPES
from config.logging import setup_logging

# Настраиваем логирование
setup_logging()

# Пропускаем тесты если нет конфигурации
pytestmark = pytest.mark.skipif(
    not os.getenv("DEEPSEEK_API_KEY") and not os.getenv("TELEGRAM_BOT_TOKEN"),
    reason="Integration tests require API keys"
)


@pytest.mark.asyncio
async def test_memory_circular_buffer():
    """Тест кольцевого буфера - старые сообщения удаляются"""
    from config.settings import STM_BUFFER_SIZE
    
    system = ActorSystem("test_circular")
    await system.create_and_set_event_store()
    
    memory = MemoryActor()
    await system.register_actor(memory)
    await system.start()
    
    try:
        test_user = 'circular_buffer_test_user'
        
        # Сохраняем больше сообщений чем размер буфера
        messages_to_store = STM_BUFFER_SIZE + 10
        
        for i in range(messages_to_store):
            await memory.store_interaction(
                user_id=test_user,
                message_type='user',
                content=f'Message {i}',
                metadata={'index': i}
            )
            # Небольшая задержка чтобы не перегружать БД
            if i % 10 == 0:
                await asyncio.sleep(0.1)
        
        # Получаем контекст
        context = await memory.get_context(
            user_id=test_user,
            limit=STM_BUFFER_SIZE * 2,  # Запрашиваем больше чем есть
            format_type='text'
        )
        
        # Проверяем что осталось только STM_BUFFER_SIZE сообщений
        assert context.total_messages == STM_BUFFER_SIZE, \
            f"Должно остаться {STM_BUFFER_SIZE} сообщений, найдено {context.total_messages}"
        
        # Проверяем что остались самые новые сообщения
        first_message_index = messages_to_store - STM_BUFFER_SIZE
        assert context.messages[0]['content'] == f'Message {first_message_index}'
        assert context.messages[-1]['content'] == f'Message {messages_to_store - 1}'
        
        print(f"Circular buffer works: kept last {STM_BUFFER_SIZE} messages")
        
    finally:
        await system.stop()


@pytest.mark.asyncio
async def test_memory_degraded_mode():
    """Тест работы в degraded mode при недоступной БД"""
    system = ActorSystem("test_degraded")
    
    # НЕ создаем Event Store чтобы спровоцировать degraded mode
    memory = MemoryActor()
    # Принудительно отключаем БД
    memory._pool = None
    memory._degraded_mode = True
    
    await system.register_actor(memory)
    await system.start()
    
    try:
        # Пытаемся сохранить - должно просто залогироваться
        store_msg = ActorMessage.create(
            sender_id="test",
            message_type=MESSAGE_TYPES['STORE_MEMORY'],
            payload={
                'user_id': 'degraded_test_user',
                'message_type': 'user',
                'content': 'This should not crash',
                'metadata': {}
            }
        )
        await system.send_message("memory", store_msg)
        
        # Небольшая задержка
        await asyncio.sleep(0.5)
        
        # Система не должна упасть
        assert memory.is_running, "MemoryActor должен продолжать работать"
        assert memory._metrics['store_memory_count'] == 1, "Счетчик должен увеличиться"
        
        print("Degraded mode works correctly - no crash on store")
        
    finally:
        await system.stop()


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])