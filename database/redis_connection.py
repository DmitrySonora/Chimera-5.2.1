"""
Централизованное управление подключениями к Redis
"""
import asyncio
from typing import Optional, Any
import redis.asyncio as aioredis
from redis.asyncio.connection import ConnectionPool
from config.logging import get_logger
from config.settings import (
    REDIS_URL,
    REDIS_POOL_MAX_SIZE,
    REDIS_CONNECT_TIMEOUT,
    REDIS_RETRY_ATTEMPTS,
    REDIS_RETRY_DELAY,
    REDIS_KEY_PREFIX
)


class RedisConnection:
    """
    Менеджер подключений к Redis с поддержкой пула соединений.
    Использует redis.asyncio для асинхронной работы.
    """
    
    def __init__(self):
        self.logger = get_logger("redis.connection")
        self._pool: Optional[ConnectionPool] = None
        self._client: Optional[aioredis.Redis] = None
        self._is_connected = False
        
    async def connect(self, url: Optional[str] = None) -> None:
        """
        Создать пул подключений к Redis.
        
        Args:
            url: URL подключения (если не указан, используется из конфига)
        """
        if self._is_connected:
            self.logger.warning("Already connected to Redis")
            return
            
        url = url or REDIS_URL
        
        # Пытаемся подключиться с retry логикой
        for attempt in range(REDIS_RETRY_ATTEMPTS):
            try:
                self.logger.info(f"Connecting to Redis (attempt {attempt + 1}/{REDIS_RETRY_ATTEMPTS})...")
                
                # Создаем пул подключений
                self._pool = aioredis.ConnectionPool.from_url(
                    url,
                    max_connections=REDIS_POOL_MAX_SIZE,
                    decode_responses=True,  # Автоматическое декодирование строк
                    socket_connect_timeout=REDIS_CONNECT_TIMEOUT,
                    socket_timeout=REDIS_CONNECT_TIMEOUT,
                    retry_on_timeout=True
                )
                
                # Создаем клиент
                self._client = aioredis.Redis(connection_pool=self._pool)
                
                # Проверяем подключение
                await self.health_check()
                
                self._is_connected = True
                self.logger.info("Successfully connected to Redis")
                return
                
            except Exception as e:
                self.logger.error(f"Failed to connect to Redis: {str(e)}")
                
                if attempt < REDIS_RETRY_ATTEMPTS - 1:
                    await asyncio.sleep(REDIS_RETRY_DELAY)
                else:
                    # Не бросаем исключение - работаем в degraded mode
                    self.logger.warning("Redis connection failed, working in degraded mode")
                    self._is_connected = False
                    return
    
    async def disconnect(self) -> None:
        """Закрыть пул подключений"""
        if self._client:
            await self._client.close()
            self._client = None
        if self._pool:
            await self._pool.disconnect()
            self._pool = None
        self._is_connected = False
        self.logger.info("Disconnected from Redis")
    
    async def health_check(self) -> bool:
        """
        Проверить здоровье подключения к Redis.
        
        Returns:
            True если подключение активно, False иначе
        """
        if not self._client:
            return False
            
        try:
            await self._client.ping()
            return True
        except Exception as e:
            self.logger.error(f"Health check failed: {str(e)}")
            return False
    
    def get_client(self) -> Optional[aioredis.Redis]:
        """
        Получить клиент Redis для прямого использования.
        
        Returns:
            Клиент Redis или None если не подключен
        """
        return self._client if self._is_connected else None
    
    def is_connected(self) -> bool:
        """Проверить статус подключения"""
        return self._is_connected
    
    def make_key(self, *parts: str) -> str:
        """
        Создать ключ с префиксом проекта.
        
        Args:
            *parts: Части ключа для объединения
            
        Returns:
            Полный ключ с префиксом
            
        Example:
            make_key("daily_limit", "user_123", "2024-01-01")
            -> "chimera:daily_limit:user_123:2024-01-01"
        """
        return f"{REDIS_KEY_PREFIX}:" + ":".join(parts)
    
    # Базовые операции для удобства
    async def increment(self, key: str, amount: int = 1) -> Optional[int]:
        """Инкрементировать значение по ключу"""
        if not self._client:
            return None
        try:
            return await self._client.incrby(key, amount)
        except Exception as e:
            self.logger.error(f"Failed to increment {key}: {str(e)}")
            return None
    
    async def get(self, key: str) -> Optional[str]:
        """Получить значение по ключу"""
        if not self._client:
            return None
        try:
            return await self._client.get(key)
        except Exception as e:
            self.logger.error(f"Failed to get {key}: {str(e)}")
            return None
    
    async def set(self, key: str, value: Any, ttl: Optional[int] = None) -> bool:
        """Установить значение с опциональным TTL"""
        if not self._client:
            return False
        try:
            if ttl:
                await self._client.setex(key, ttl, value)
            else:
                await self._client.set(key, value)
            return True
        except Exception as e:
            self.logger.error(f"Failed to set {key}: {str(e)}")
            return False
    
    async def delete(self, key: str) -> bool:
        """Удалить ключ"""
        if not self._client:
            return False
        try:
            await self._client.delete(key)
            return True
        except Exception as e:
            self.logger.error(f"Failed to delete {key}: {str(e)}")
            return False
    
    def get_pool_stats(self) -> dict:
        """Получить статистику пула подключений"""
        if not self._pool:
            return {"status": "disconnected"}
            
        return {
            "status": "connected" if self._is_connected else "degraded",
            "created_connections": self._pool.created_connections,
            "available_connections": len(self._pool._available_connections),
            "in_use_connections": len(self._pool._in_use_connections),
            "max_connections": self._pool.max_connections
        }


# Глобальный экземпляр для использования в приложении
redis_connection = RedisConnection()