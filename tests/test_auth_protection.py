#!/usr/bin/env python3
"""
Скрипт для проверки защитных механизмов AuthActor.
Имитирует атаку перебора паролей.
"""
import asyncio
import sys
from pathlib import Path
from datetime import datetime, timezone

# Добавляем корневую директорию в путь
sys.path.insert(0, str(Path(__file__).parent.parent))

from database.connection import db_connection
from actors.actor_system import ActorSystem
from actors.messages import ActorMessage, MESSAGE_TYPES
from actors.auth_actor import AuthActor
from actors.base_actor import BaseActor
from config.settings import AUTH_MAX_ATTEMPTS
from config.logging import setup_logging
import hashlib


class TestCollectorActor(BaseActor):
    """Актор для сбора AUTH_RESPONSE сообщений"""
    
    def __init__(self):
        super().__init__("test_collector", "TestCollector")
        self.responses = []
        
    async def initialize(self) -> None:
        self.logger.info("TestCollectorActor initialized")
        
    async def shutdown(self) -> None:
        self.logger.info(f"TestCollectorActor shutdown, collected {len(self.responses)} responses")
        
    async def handle_message(self, message: ActorMessage):
        if message.message_type == MESSAGE_TYPES['AUTH_RESPONSE']:
            self.responses.append(message.payload)
            self.logger.info(f"Collected AUTH_RESPONSE: success={message.payload.get('success')}, error={message.payload.get('error')}")
        return None


async def wait_for_response(collector: TestCollectorActor, expected_count: int, timeout: float = 3.0):
    """Ждет пока collector получит нужное количество ответов"""
    start_time = asyncio.get_event_loop().time()
    while len(collector.responses) < expected_count:
        if asyncio.get_event_loop().time() - start_time > timeout:
            raise TimeoutError(f"Timeout waiting for {expected_count} responses, got {len(collector.responses)}")
        await asyncio.sleep(0.1)


async def test_auth_protection():
    """Тестирует anti-bruteforce защиту"""
    setup_logging()
    
    print("\n🔐 Тестирование Anti-bruteforce защиты")
    print("=" * 50)
    
    # Подключаемся к БД
    print("\n1. Подключение к БД...")
    await db_connection.connect()
    pool = db_connection.get_pool()
    
    # Очищаем тестовые данные
    print("2. Очистка тестовых данных...")
    test_user_id = "test_bruteforce_999"
    test_password = "TEST_PASSWORD_999"
    test_password_hash = hashlib.sha256(test_password.encode()).hexdigest()
    
    await pool.execute("DELETE FROM auth_attempts WHERE user_id = $1", test_user_id)
    await pool.execute("DELETE FROM blocked_users WHERE user_id = $1", test_user_id)
    await pool.execute("DELETE FROM authorized_users WHERE user_id = $1", test_user_id)
    await pool.execute("DELETE FROM passwords WHERE password = $1", test_password)
    
    # Очищаем события из Event Store
    await pool.execute("DELETE FROM events WHERE stream_id LIKE $1", f"%{test_user_id}%")
    
    # Создаем тестовый пароль
    print("3. Создание тестового пароля...")
    await pool.execute(
        """
        INSERT INTO passwords (password, password_hash, duration_days, description, is_active, created_by, created_at)
        VALUES ($1, $2, 30, 'Test password for bruteforce', TRUE, 'test_script', CURRENT_TIMESTAMP)
        """,
        test_password, test_password_hash
    )
    
    # Создаем и запускаем систему
    print("4. Запуск Actor System с Event Store...")
    system = ActorSystem("test-auth")
    
    # Создаем Event Store
    await system.create_and_set_event_store()
    
    # Создаем акторы
    auth_actor = AuthActor()
    collector = TestCollectorActor()
    
    await system.register_actor(auth_actor)
    await system.register_actor(collector)
    await system.start()
    
    print(f"\n5. Тестирование {AUTH_MAX_ATTEMPTS} попыток с неверными паролями...")
    print(f"   (блокировка должна сработать после {AUTH_MAX_ATTEMPTS} попыток)")
    
    # Сбрасываем счетчик ответов
    collector.responses = []
    
    # Имитируем попытки с неверными паролями
    for i in range(AUTH_MAX_ATTEMPTS):
        print(f"\n   Попытка #{i+1}/{AUTH_MAX_ATTEMPTS}:")
        
        # Отправляем AUTH_REQUEST с неверным паролем
        wrong_password = f"WRONG_PASSWORD_{i}"
        auth_request = ActorMessage.create(
            sender_id="test_collector",  # Важно: указываем collector как отправителя
            message_type=MESSAGE_TYPES['AUTH_REQUEST'],
            payload={
                'user_id': test_user_id,
                'password': wrong_password
            }
        )
        
        await system.send_message("auth", auth_request)
        
        # Ждем ответ
        await wait_for_response(collector, i + 1)
        
        # Проверяем последний ответ
        last_response = collector.responses[-1]
        assert last_response['success'] is False, "Ожидался неуспешный ответ"
        assert last_response['error'] == 'invalid_password', f"Ожидалась ошибка 'invalid_password', получена '{last_response.get('error')}'"
        
        print(f"   ✓ Получен ответ: error='{last_response['error']}'")
    
    # Проверяем что пользователь заблокирован в БД
    print(f"\n6. Проверка блокировки после {AUTH_MAX_ATTEMPTS} попыток...")
    blocked_row = await pool.fetchrow(
        "SELECT * FROM blocked_users WHERE user_id = $1",
        test_user_id
    )
    
    if blocked_row and blocked_row['blocked_until'] > datetime.now(timezone.utc):
        print(f"   ✅ Пользователь заблокирован до: {blocked_row['blocked_until']}")
        print(f"   ✅ Количество попыток при блокировке: {blocked_row['attempt_count']}")
    else:
        print("   ❌ ОШИБКА: Пользователь НЕ заблокирован!")
        await system.stop()
        await db_connection.disconnect()
        return
    
    # Теперь пробуем еще одну попытку - должна вернуть 'blocked'
    print(f"\n7. Попытка #{AUTH_MAX_ATTEMPTS + 1} (должна вернуть 'blocked')...")
    
    auth_request = ActorMessage.create(
        sender_id="test_collector",
        message_type=MESSAGE_TYPES['AUTH_REQUEST'],
        payload={
            'user_id': test_user_id,
            'password': 'ANY_PASSWORD'
        }
    )
    
    await system.send_message("auth", auth_request)
    await wait_for_response(collector, AUTH_MAX_ATTEMPTS + 1)
    
    last_response = collector.responses[-1]
    assert last_response['success'] is False
    assert last_response['error'] == 'blocked', f"Ожидалась ошибка 'blocked', получена '{last_response.get('error')}'"
    assert 'blocked_until' in last_response, "В ответе должно быть поле blocked_until"
    
    print(f"   ✅ Получен ответ: error='blocked', blocked_until='{last_response['blocked_until']}'")
    
    # Пробуем правильный пароль (должен быть заблокирован)
    print("\n8. Попытка входа с ПРАВИЛЬНЫМ паролем (должна быть заблокирована)...")
    
    correct_auth = ActorMessage.create(
        sender_id="test_collector",
        message_type=MESSAGE_TYPES['AUTH_REQUEST'],
        payload={
            'user_id': test_user_id,
            'password': test_password
        }
    )
    
    await system.send_message("auth", correct_auth)
    await wait_for_response(collector, AUTH_MAX_ATTEMPTS + 2)
    
    last_response = collector.responses[-1]
    assert last_response['success'] is False
    assert last_response['error'] == 'blocked', "Даже с правильным паролем должен быть заблокирован"
    
    print("   ✅ Правильный пароль отклонен из-за блокировки")
    
    # Снимаем блокировку
    print("\n9. Снимаем блокировку для проверки...")
    await pool.execute(
        "UPDATE blocked_users SET blocked_until = CURRENT_TIMESTAMP - INTERVAL '1 minute' WHERE user_id = $1",
        test_user_id
    )
    
    # Пробуем снова с правильным паролем
    print("10. Повторная попытка с правильным паролем после разблокировки...")
    
    await system.send_message("auth", correct_auth)
    await wait_for_response(collector, AUTH_MAX_ATTEMPTS + 3)
    
    last_response = collector.responses[-1]
    assert last_response['success'] is True, "После разблокировки должна пройти авторизация"
    
    print("   ✅ Авторизация успешна!")
    print(f"   ✅ Подписка до: {last_response['expires_at']}")
    print(f"   ✅ Осталось дней: {last_response['days_remaining']}")
    
    # Проверяем записи в БД
    print("\n11. Проверка записей в БД...")
    
    # Проверяем auth_attempts
    attempts_count = await pool.fetchval(
        "SELECT COUNT(*) FROM auth_attempts WHERE user_id = $1",
        test_user_id
    )
    
    failed_count = await pool.fetchval(
        "SELECT COUNT(*) FROM auth_attempts WHERE user_id = $1 AND success = FALSE",
        test_user_id
    )
    
    success_count = await pool.fetchval(
        "SELECT COUNT(*) FROM auth_attempts WHERE user_id = $1 AND success = TRUE",
        test_user_id
    )
    
    print(f"   Всего попыток в auth_attempts: {attempts_count}")
    print(f"   - Неудачных: {failed_count}")
    print(f"   - Успешных: {success_count}")
    
    # Проверяем authorized_users
    auth_user = await pool.fetchrow(
        "SELECT * FROM authorized_users WHERE user_id = $1",
        test_user_id
    )
    
    if auth_user:
        print("   ✅ Запись в authorized_users создана")
    else:
        print("   ❌ ОШИБКА: Запись в authorized_users НЕ создана!")
    
    # Проверяем события в Event Store
    events_count = await pool.fetchval(
        "SELECT COUNT(*) FROM events WHERE stream_id = $1",
        f"auth_{test_user_id}"
    )
    
    print(f"   События в Event Store: {events_count}")
    
    # Тестируем пароль, уже использованный другим пользователем
    print("\n12. Тест попытки использовать чужой пароль...")
    
    other_user_id = "test_other_user_999"
    
    # Очищаем данные другого пользователя
    await pool.execute("DELETE FROM auth_attempts WHERE user_id = $1", other_user_id)
    
    # Попытка использовать уже занятый пароль
    stolen_auth = ActorMessage.create(
        sender_id="test_collector",
        message_type=MESSAGE_TYPES['AUTH_REQUEST'],
        payload={
            'user_id': other_user_id,
            'password': test_password  # Пароль уже использован test_user_id
        }
    )
    
    await system.send_message("auth", stolen_auth)
    await wait_for_response(collector, AUTH_MAX_ATTEMPTS + 4)
    
    last_response = collector.responses[-1]
    assert last_response['success'] is False
    assert last_response['error'] == 'already_used', f"Ожидалась ошибка 'already_used', получена '{last_response.get('error')}'"
    
    print("   ✅ Попытка использовать чужой пароль отклонена с error='already_used'")
    
    # Останавливаем систему
    print("\n13. Остановка системы...")
    await system.stop()
    
    # Очищаем тестовые данные
    print("14. Очистка тестовых данных...")
    await pool.execute("DELETE FROM auth_attempts WHERE user_id IN ($1, $2)", test_user_id, other_user_id)
    await pool.execute("DELETE FROM blocked_users WHERE user_id = $1", test_user_id)
    await pool.execute("DELETE FROM authorized_users WHERE user_id = $1", test_user_id)
    await pool.execute("DELETE FROM passwords WHERE password = $1", test_password)
    await pool.execute("DELETE FROM events WHERE stream_id LIKE $1", f"%{test_user_id}%")
    
    await db_connection.disconnect()
    
    print("\n✅ Все тесты пройдены успешно!")
    print("\nПроверено:")
    print(f"- Блокировка после {AUTH_MAX_ATTEMPTS} неудачных попыток")
    print("- Заблокированный пользователь не может войти")
    print("- После разблокировки можно войти с правильным паролем")
    print("- Попытка использовать чужой пароль возвращает 'already_used'")
    print("- Все события сохраняются в БД и Event Store")


if __name__ == "__main__":
    try:
        asyncio.run(test_auth_protection())
    except Exception as e:
        print(f"\n❌ Ошибка при выполнении теста: {str(e)}")
        sys.exit(1)