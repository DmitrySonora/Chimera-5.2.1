"""
Интеграционные тесты для команд авторизации.
БЕЗ МОКОВ - только реальные компоненты системы.
"""
import pytest
import asyncio
from datetime import datetime, timedelta, timezone
import hashlib
from actors.actor_system import ActorSystem
from actors.telegram_actor import TelegramInterfaceActor
from actors.auth_actor import AuthActor
from database.connection import db_connection
from config.settings import AUTH_PASSWORD_WAIT_TIMEOUT


@pytest.mark.asyncio
async def test_auth_command_flow(db_session):
    """Полный сценарий авторизации через /auth"""
    # Создаем систему акторов
    system = ActorSystem("test-auth-commands")
    await system.create_and_set_event_store()
    
    # Создаем и регистрируем акторы
    auth_actor = AuthActor()
    telegram_actor = TelegramInterfaceActor()
    
    await system.register_actor(auth_actor)
    await system.register_actor(telegram_actor)
    
    await system.start()
    
    try:
        # Создаем тестовый пароль в БД
        test_password = "TEST123"
        password_hash = hashlib.sha256(test_password.encode()).hexdigest()
        
        await db_connection.execute(
            """
            INSERT INTO passwords (password, password_hash, duration_days, description, is_active, created_by)
            VALUES ($1, $2, 30, 'Test password', TRUE, 'test_admin')
            """,
            test_password, password_hash
        )
        
        # 1. Отправляем команду /auth
        test_chat_id = 12345
        test_user_id = test_chat_id
        
        # Имитируем обработку команды
        await telegram_actor._handle_command(test_chat_id, "/auth")
        
        # Проверяем что пользователь в состоянии ожидания
        assert test_user_id in telegram_actor._awaiting_password
        
        # 2. Отправляем пароль
        # Создаем фейковое сообщение от Telegram
        update = {
            "message": {
                "chat": {"id": test_chat_id},
                "from": {"id": test_user_id, "username": "testuser"},
                "text": test_password
            }
        }
        
        await telegram_actor._process_update(update)
        
        # Проверяем что состояние ожидания очищено
        assert test_user_id not in telegram_actor._awaiting_password
        
        # Даем время на обработку
        await asyncio.sleep(0.5)
        
        # Проверяем авторизацию в БД
        result = await db_connection.fetchrow(
            "SELECT * FROM authorized_users WHERE user_id = $1",
            str(test_user_id)
        )
        
        assert result is not None
        assert result['password_used'] == test_password
        
        # 3. Проверяем что следующее сообщение НЕ воспринимается как пароль
        update2 = {
            "message": {
                "chat": {"id": test_chat_id},
                "from": {"id": test_user_id, "username": "testuser"},
                "text": "обычное сообщение"
            }
        }
        
        await telegram_actor._process_update(update2)
        
        # Убеждаемся что это не вызвало попытку авторизации
        assert test_user_id not in telegram_actor._awaiting_password
        
    finally:
        # Очистка
        await db_connection.execute("DELETE FROM passwords WHERE password = $1", test_password)
        await db_connection.execute("DELETE FROM authorized_users WHERE user_id = $1", str(test_user_id))
        await system.stop()


@pytest.mark.asyncio
async def test_auth_timeout(db_session):
    """Таймаут ожидания пароля"""
    system = ActorSystem("test-auth-timeout")
    await system.create_and_set_event_store()
    
    telegram_actor = TelegramInterfaceActor()
    auth_actor = AuthActor()
    
    await system.register_actor(telegram_actor)
    await system.register_actor(auth_actor)
    await system.start()
    
    try:
        test_chat_id = 23456
        test_user_id = test_chat_id
        
        # Отправляем /auth
        await telegram_actor._handle_command(test_chat_id, "/auth")
        assert test_user_id in telegram_actor._awaiting_password
        
        # Устанавливаем время в прошлое для имитации таймаута
        telegram_actor._awaiting_password[test_user_id] = datetime.now() - timedelta(seconds=AUTH_PASSWORD_WAIT_TIMEOUT + 1)
        
        # Очищаем устаревшие
        telegram_actor._cleanup_expired_passwords()
        
        # Проверяем что состояние очищено
        assert test_user_id not in telegram_actor._awaiting_password
        
    finally:
        await system.stop()


@pytest.mark.asyncio
async def test_status_command(db_session):
    """Проверка статуса для разных пользователей"""
    system = ActorSystem("test-status")
    await system.create_and_set_event_store()
    
    auth_actor = AuthActor()
    telegram_actor = TelegramInterfaceActor()
    
    await system.register_actor(auth_actor)
    await system.register_actor(telegram_actor)
    await system.start()
    
    try:
        # 1. Проверяем статус неавторизованного пользователя
        demo_chat_id = 34567
        demo_user_id = demo_chat_id
        
        # Отправляем /status
        await telegram_actor._handle_command(demo_chat_id, "/status")
        
        # Даем время на обработку
        await asyncio.sleep(0.5)
        
        # 2. Создаем авторизованного пользователя
        auth_user_id = "45678"
        auth_chat_id = 45678
        
        expires_at = datetime.now(timezone.utc) + timedelta(days=30)
        
        await db_connection.execute(
            """
            INSERT INTO authorized_users (user_id, password_used, expires_at, authorized_at, description)
            VALUES ($1, 'TEST', $2, CURRENT_TIMESTAMP, 'Test subscription')
            """,
            auth_user_id, expires_at
        )
        
        # Отправляем /status для авторизованного
        await telegram_actor._handle_command(auth_chat_id, "/status")
        
        # Даем время на обработку
        await asyncio.sleep(0.5)
        
    finally:
        await db_connection.execute("DELETE FROM authorized_users WHERE user_id = $1", auth_user_id)
        await system.stop()


@pytest.mark.asyncio
async def test_logout_command(db_session):
    """Выход из аккаунта"""
    system = ActorSystem("test-logout")
    await system.create_and_set_event_store()
    
    auth_actor = AuthActor()
    telegram_actor = TelegramInterfaceActor()
    
    await system.register_actor(auth_actor)
    await system.register_actor(telegram_actor)
    await system.start()
    
    try:
        # 1. Создаем авторизованного пользователя
        user_id = "56789"
        chat_id = 56789
        
        expires_at = datetime.now(timezone.utc) + timedelta(days=30)
        
        await db_connection.execute(
            """
            INSERT INTO authorized_users (user_id, password_used, expires_at, authorized_at, description)
            VALUES ($1, 'TEST', $2, CURRENT_TIMESTAMP, 'Test subscription')
            """,
            user_id, expires_at
        )
        
        # 2. Выполняем /logout
        await telegram_actor._handle_command(chat_id, "/logout")
        
        # Даем время на обработку
        await asyncio.sleep(0.5)
        
        # 3. Проверяем что пользователь деавторизован
        result = await db_connection.fetchrow(
            "SELECT * FROM authorized_users WHERE user_id = $1",
            user_id
        )
        
        assert result is None
        
        # 4. Проверяем /logout для неавторизованного
        await telegram_actor._handle_command(67890, "/logout")
        await asyncio.sleep(0.5)
        
    finally:
        await db_connection.execute("DELETE FROM authorized_users WHERE user_id = $1", user_id)
        await system.stop()


@pytest.mark.asyncio
async def test_command_resets_password_wait(db_session):
    """Команда вместо пароля сбрасывает состояние ожидания"""
    system = ActorSystem("test-command-reset")
    await system.create_and_set_event_store()
    
    telegram_actor = TelegramInterfaceActor()
    auth_actor = AuthActor()
    
    await system.register_actor(telegram_actor)
    await system.register_actor(auth_actor)
    await system.start()
    
    try:
        test_chat_id = 78901
        test_user_id = test_chat_id
        
        # Отправляем /auth
        await telegram_actor._handle_command(test_chat_id, "/auth")
        assert test_user_id in telegram_actor._awaiting_password
        
        # Отправляем другую команду
        await telegram_actor._handle_command(test_chat_id, "/status")
        
        # Проверяем что состояние сброшено
        assert test_user_id not in telegram_actor._awaiting_password
        
    finally:
        await system.stop()


@pytest.mark.asyncio
async def test_empty_password(db_session):
    """Обработка пустого пароля"""
    system = ActorSystem("test-empty-password")
    await system.create_and_set_event_store()
    
    telegram_actor = TelegramInterfaceActor()
    auth_actor = AuthActor()
    
    await system.register_actor(telegram_actor)
    await system.register_actor(auth_actor)
    await system.start()
    
    try:
        test_chat_id = 89012
        test_user_id = test_chat_id
        
        # Отправляем /auth
        await telegram_actor._handle_command(test_chat_id, "/auth")
        
        # Отправляем пустое сообщение
        update = {
            "message": {
                "chat": {"id": test_chat_id},
                "from": {"id": test_user_id},
                "text": "   "  # Только пробелы
            }
        }
        
        await telegram_actor._process_update(update)
        
        # Проверяем что состояние очищено
        assert test_user_id not in telegram_actor._awaiting_password
        
    finally:
        await system.stop()