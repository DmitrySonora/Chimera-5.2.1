"""
Централизованное управление подключениями к PostgreSQL
"""
import asyncio
from typing import Optional, Dict, Any
import asyncpg
from asyncpg import Pool
from config.logging import get_logger
from config.settings import (
    POSTGRES_DSN,
    POSTGRES_POOL_MIN_SIZE,
    POSTGRES_POOL_MAX_SIZE,
    POSTGRES_COMMAND_TIMEOUT,
    POSTGRES_CONNECT_TIMEOUT,
    POSTGRES_RETRY_ATTEMPTS,
    POSTGRES_RETRY_DELAY
)


class DatabaseConnection:
    """
    Менеджер подключений к PostgreSQL с поддержкой пула соединений.
    Использует asyncpg для асинхронной работы с БД.
    """
    
    def __init__(self):
        self.logger = get_logger("database.connection")
        self._pool: Optional[Pool] = None
        self._is_connected = False
        
    async def connect(self, dsn: Optional[str] = None) -> None:
        """
        Создать пул подключений к PostgreSQL.
        
        Args:
            dsn: DSN строка подключения (если не указана, используется из конфига)
        """
        if self._is_connected:
            self.logger.warning("Already connected to database")
            return
            
        dsn = dsn or POSTGRES_DSN
        
        # Пытаемся подключиться с retry логикой
        for attempt in range(POSTGRES_RETRY_ATTEMPTS):
            try:
                self.logger.info(f"Connecting to PostgreSQL (attempt {attempt + 1}/{POSTGRES_RETRY_ATTEMPTS})...")
                
                self._pool = await asyncpg.create_pool(
                    dsn=dsn,
                    min_size=POSTGRES_POOL_MIN_SIZE,
                    max_size=POSTGRES_POOL_MAX_SIZE,
                    command_timeout=POSTGRES_COMMAND_TIMEOUT,
                    timeout=POSTGRES_CONNECT_TIMEOUT,
                    # Отключаем кэш statement'ов для динамических запросов
                    statement_cache_size=0,
                    # Устанавливаем UTC для всех подключений
                    server_settings={
                        'timezone': 'UTC',
                        'application_name': 'chimera_event_store'
                    }
                )
                
                # Проверяем подключение
                await self.health_check()
                
                self._is_connected = True
                self.logger.info("Successfully connected to PostgreSQL")
                return
                
            except Exception as e:
                self.logger.error(f"Failed to connect to PostgreSQL: {str(e)}")
                
                if attempt < POSTGRES_RETRY_ATTEMPTS - 1:
                    await asyncio.sleep(POSTGRES_RETRY_DELAY)
                else:
                    raise
    
    async def disconnect(self) -> None:
        """Закрыть пул подключений"""
        if self._pool:
            await self._pool.close()
            self._pool = None
            self._is_connected = False
            self.logger.info("Disconnected from PostgreSQL")
    
    async def health_check(self) -> bool:
        """
        Проверить здоровье подключения к БД.
        
        Returns:
            True если подключение активно, False иначе
        """
        if not self._pool:
            return False
            
        try:
            async with self._pool.acquire() as conn:
                result = await conn.fetchval("SELECT 1")
                return result == 1
        except Exception as e:
            self.logger.error(f"Health check failed: {str(e)}")
            return False
    
    async def execute_migration(self, sql: str) -> None:
        """
        Выполнить SQL миграцию в транзакции.
        
        Args:
            sql: SQL скрипт миграции
        """
        if not self._pool:
            raise RuntimeError("Not connected to database")
            
        async with self._pool.acquire() as conn:
            async with conn.transaction():
                try:
                    await conn.execute(sql)
                    self.logger.info("Migration executed successfully")
                except Exception as e:
                    self.logger.error(f"Migration failed: {str(e)}")
                    # Транзакция автоматически откатится
                    raise
    
    def get_pool(self) -> Pool:
        """
        Получить пул подключений для прямого использования.
        
        Returns:
            Пул подключений asyncpg
            
        Raises:
            RuntimeError: Если не подключен к БД
        """
        if not self._pool:
            raise RuntimeError("Not connected to database")
        return self._pool
    
    async def execute(self, query: str, *args, timeout: Optional[float] = None) -> str:
        """
        Выполнить запрос без возврата результата.
        
        Args:
            query: SQL запрос
            *args: Параметры запроса
            timeout: Таймаут выполнения
            
        Returns:
            Статус выполнения (например, 'INSERT 0 1')
        """
        if not self._pool:
            raise RuntimeError("Not connected to database")
            
        async with self._pool.acquire() as conn:
            return await conn.execute(query, *args, timeout=timeout)
    
    async def fetch(self, query: str, *args, timeout: Optional[float] = None) -> list:
        """
        Выполнить запрос и получить все строки.
        
        Args:
            query: SQL запрос
            *args: Параметры запроса
            timeout: Таймаут выполнения
            
        Returns:
            Список записей
        """
        if not self._pool:
            raise RuntimeError("Not connected to database")
            
        async with self._pool.acquire() as conn:
            return await conn.fetch(query, *args, timeout=timeout)
    
    async def fetchrow(self, query: str, *args, timeout: Optional[float] = None) -> Optional[Dict[str, Any]]:
        """
        Выполнить запрос и получить одну строку.
        
        Args:
            query: SQL запрос
            *args: Параметры запроса
            timeout: Таймаут выполнения
            
        Returns:
            Запись или None
        """
        if not self._pool:
            raise RuntimeError("Not connected to database")
            
        async with self._pool.acquire() as conn:
            return await conn.fetchrow(query, *args, timeout=timeout)
    
    async def fetchval(self, query: str, *args, timeout: Optional[float] = None) -> Any:
        """
        Выполнить запрос и получить одно значение.
        
        Args:
            query: SQL запрос
            *args: Параметры запроса
            timeout: Таймаут выполнения
            
        Returns:
            Значение первой колонки первой строки
        """
        if not self._pool:
            raise RuntimeError("Not connected to database")
            
        async with self._pool.acquire() as conn:
            return await conn.fetchval(query, *args, timeout=timeout)
    
    def get_pool_stats(self) -> Dict[str, int]:
        """Получить статистику пула подключений"""
        if not self._pool:
            return {"status": "disconnected"}
            
        return {
            "status": "connected",
            "size": self._pool.get_size(),
            "idle": self._pool.get_idle_size(),
            "min_size": self._pool.get_min_size(),
            "max_size": self._pool.get_max_size()
        }


# Глобальный экземпляр для использования в приложении
db_connection = DatabaseConnection()