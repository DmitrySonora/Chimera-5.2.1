"""
Интеграционные тесты для базовой функциональности AuthActor
"""
import pytest
import pytest_asyncio
import asyncio
import logging

from actors.actor_system import ActorSystem
from actors.auth_actor import AuthActor
from actors.messages import ActorMessage, MESSAGE_TYPES
from actors.telegram_actor import TelegramInterfaceActor
from database.connection import db_connection


@pytest_asyncio.fixture
async def actor_system():
    """Создание и очистка системы акторов для тестов"""
    system = ActorSystem("test-auth-system")
    await system.create_and_set_event_store()
    yield system
    await system.stop()


@pytest_asyncio.fixture
async def setup_auth_actor(actor_system, db_session):
    """Настройка AuthActor для тестов"""
    # Создаем и регистрируем AuthActor
    auth_actor = AuthActor()
    await actor_system.register_actor(auth_actor)
    
    # Запускаем систему
    await actor_system.start()
    
    yield auth_actor
    
    # Очистка после теста не нужна - фикстура actor_system сделает stop()

@pytest.mark.asyncio
async def test_auth_actor_initialization(actor_system, db_session):
    """Тест успешной инициализации AuthActor с реальной БД"""
    # Создаем и регистрируем AuthActor
    auth_actor = AuthActor()
    await actor_system.register_actor(auth_actor)
    
    # Запускаем систему
    await actor_system.start()
    
    # Проверяем что актор инициализирован
    assert auth_actor.is_running
    assert auth_actor._metrics['initialized'] is True
    assert auth_actor._degraded_mode is False
    
    # Проверяем что pool инициализирован (значит схема проверена)
    assert auth_actor._pool is not None
    
    # Проверяем что нет ошибок БД
    assert auth_actor._metrics['db_errors'] == 0

@pytest.mark.asyncio
async def test_auth_actor_degraded_mode(actor_system, caplog, monkeypatch):
    """Тест работы в деградированном режиме при недоступности БД"""
    # Создаем AuthActor
    auth_actor = AuthActor()
    
    # Патчим метод connect чтобы он выбрасывал исключение
    async def mock_connect():
        raise Exception("Database connection failed")
    
    monkeypatch.setattr(db_connection, "connect", mock_connect)
    monkeypatch.setattr(db_connection, "_is_connected", False)
    
    # Регистрируем и запускаем
    await actor_system.register_actor(auth_actor)
    await actor_system.start()
    
    # Проверяем degraded mode
    assert auth_actor._degraded_mode is True
    assert auth_actor._metrics['degraded_mode_entries'] > 0
    assert auth_actor._metrics['db_errors'] > 0
    
    # Проверяем логи
    assert "AuthActor entering degraded mode" in caplog.text

@pytest.mark.asyncio
async def test_auth_actor_message_recognition(setup_auth_actor, actor_system):
    """Тест распознавания всех типов сообщений"""
    auth_actor = setup_auth_actor
    
    # Сохраняем начальные значения счетчиков
    initial_check_limit = auth_actor._metrics['check_limit_count']
    initial_auth_request = auth_actor._metrics['auth_request_count']
    initial_admin_commands = auth_actor._metrics['admin_commands_count']
    
    # Отправляем CHECK_LIMIT
    check_msg = ActorMessage.create(
        sender_id="test",
        message_type=MESSAGE_TYPES['CHECK_LIMIT'],
        payload={'user_id': '123456'}
    )
    await actor_system.send_message("auth", check_msg)
    
    # Отправляем AUTH_REQUEST
    auth_msg = ActorMessage.create(
        sender_id="test",
        message_type=MESSAGE_TYPES['AUTH_REQUEST'],
        payload={'user_id': '123456', 'password': 'test123'}
    )
    await actor_system.send_message("auth", auth_msg)
    
    # Отправляем ADMIN_COMMAND
    admin_msg = ActorMessage.create(
        sender_id="test",
        message_type=MESSAGE_TYPES['ADMIN_COMMAND'],
        payload={'command': 'list_passwords', 'admin_id': '502312936'}
    )
    await actor_system.send_message("auth", admin_msg)
    
    # Даем время на обработку
    await asyncio.sleep(0.1)
    
    # Проверяем счетчики
    assert auth_actor._metrics['check_limit_count'] == initial_check_limit + 1
    assert auth_actor._metrics['auth_request_count'] == initial_auth_request + 1
    assert auth_actor._metrics['admin_commands_count'] == initial_admin_commands + 1

@pytest.mark.asyncio
async def test_auth_actor_unknown_message(setup_auth_actor, actor_system, caplog):
    """Тест обработки неизвестного типа сообщения"""
    # Отправляем неизвестный тип сообщения
    unknown_msg = ActorMessage.create(
        sender_id="test",
        message_type="unknown_type",
        payload={}
    )
    
    with caplog.at_level(logging.WARNING):
        await actor_system.send_message("auth", unknown_msg)
        await asyncio.sleep(0.1)
    
    # Проверяем warning в логах
    assert "Unknown message type received: unknown_type" in caplog.text

@pytest.mark.asyncio
async def test_auth_actor_metrics_collection(actor_system):
    """Тест корректности сбора метрик"""
    # Создаем AuthActor
    auth_actor = AuthActor()
    await actor_system.register_actor(auth_actor)
    await actor_system.start()
    
    # Отправляем несколько сообщений
    for i in range(3):
        msg = ActorMessage.create(
            sender_id="test",
            message_type=MESSAGE_TYPES['CHECK_LIMIT'],
            payload={'user_id': f'user_{i}'}
        )
        await actor_system.send_message("auth", msg)
    
    for i in range(2):
        msg = ActorMessage.create(
            sender_id="test",
            message_type=MESSAGE_TYPES['AUTH_REQUEST'],
            payload={'user_id': f'user_{i}', 'password': 'test'}
        )
        await actor_system.send_message("auth", msg)
    
    # Даем время на обработку
    await asyncio.sleep(0.1)
    
    # Останавливаем актор для проверки финальных метрик
    await auth_actor.stop()
    
    # Проверяем метрики
    assert auth_actor._metrics['check_limit_count'] == 3
    assert auth_actor._metrics['auth_request_count'] == 2

@pytest.mark.asyncio
async def test_auth_actor_registration_order(db_session):
    """Тест порядка регистрации акторов"""
    # Создаем систему
    system = ActorSystem("test-order-system")
    await system.create_and_set_event_store()
    
    # Создаем акторы в правильном порядке
    auth_actor = AuthActor()
    telegram_actor = TelegramInterfaceActor()
    
    # Регистрируем в правильном порядке
    await system.register_actor(auth_actor)
    await system.register_actor(telegram_actor)
    
    # Запускаем систему
    await system.start()
    
    # Проверяем что оба актора запущены
    assert auth_actor.is_running
    assert telegram_actor.is_running
    
    # Проверяем что AuthActor может получать сообщения до TelegramActor
    msg = ActorMessage.create(
        sender_id="test",
        message_type=MESSAGE_TYPES['CHECK_LIMIT'],
        payload={'user_id': '123'}
    )
    
    # Отправляем и проверяем что нет ошибок
    await system.send_message("auth", msg)
    await asyncio.sleep(0.1)
    
    # Останавливаем систему
    await system.stop()

@pytest.mark.asyncio
async def test_auth_actor_schema_verification(setup_auth_actor):
    """Тест проверки схемы БД"""
    auth_actor = setup_auth_actor
    
    # Проверяем что _verify_schema выполнилась успешно
    # (иначе бы был degraded_mode)
    assert auth_actor._degraded_mode is False
    assert auth_actor._metrics['initialized'] is True
    
    # Проверяем что pool инициализирован
    assert auth_actor._pool is not None