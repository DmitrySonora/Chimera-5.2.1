import pytest
import pytest_asyncio
import asyncio
import os
from database.connection import db_connection


@pytest.fixture(scope="session")
def event_loop():
    """Создаем один event loop для всей сессии тестов"""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest_asyncio.fixture(scope="session")
async def db_session():
    """Управляем подключением к БД для всей сессии тестов"""
    # Проверяем наличие POSTGRES_DSN
    if not os.getenv("POSTGRES_DSN"):
        pytest.skip("PostgreSQL tests require POSTGRES_DSN environment variable")
    
    # Подключаемся к БД один раз для всех тестов
    await db_connection.connect()
    
    # Очищаем все тестовые данные перед началом
    await db_connection.execute("DELETE FROM events WHERE stream_id LIKE 'test_%'")
    await db_connection.execute("DELETE FROM events WHERE stream_id LIKE 'perf_check_%'")
    await db_connection.execute("DELETE FROM events WHERE stream_id LIKE 'stress_test_%'")
    
    yield db_connection
    
    # После всех тестов отключаемся
    await db_connection.disconnect()


@pytest_asyncio.fixture
async def clean_test_data(db_session):
    """Очищаем тестовые данные перед каждым тестом"""
    # Очистка перед тестом
    await db_connection.execute("DELETE FROM events WHERE stream_id LIKE 'test_%'")
    
    yield
    
    # Очистка после теста
    await db_connection.execute("DELETE FROM events WHERE stream_id LIKE 'test_%'")