import asyncio
import time
from enum import Enum
from typing import Optional, Type, Callable, Any
from config.logging import get_logger
from config.settings import (
    CIRCUIT_BREAKER_FAILURE_THRESHOLD,
    CIRCUIT_BREAKER_RECOVERY_TIMEOUT
)


class CircuitState(Enum):
    CLOSED = "closed"      # Нормальная работа
    OPEN = "open"          # Блокировка вызовов
    HALF_OPEN = "half_open"  # Тестовый режим


class CircuitBreakerError(Exception):
    """Исключение при открытом Circuit Breaker"""
    pass


class CircuitBreaker:
    """
    Circuit Breaker паттерн для защиты от каскадных сбоев.
    
    Состояния:
    - CLOSED: нормальная работа, пропускает вызовы
    - OPEN: блокирует вызовы после N ошибок
    - HALF_OPEN: пробует один вызов для проверки восстановления
    """
    
    def __init__(
        self, 
        name: str,
        failure_threshold: int = CIRCUIT_BREAKER_FAILURE_THRESHOLD,
        recovery_timeout: int = CIRCUIT_BREAKER_RECOVERY_TIMEOUT,
        expected_exception: Type[Exception] = asyncio.QueueFull
    ):
        self.name = name
        self.logger = get_logger(f"circuit_breaker.{name}")
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.expected_exception = expected_exception
        
        self._state = CircuitState.CLOSED
        self._failure_count = 0
        self._last_failure_time: Optional[float] = None
        self._success_count = 0
        self._total_calls = 0
        
    @property
    def state(self) -> CircuitState:
        """Текущее состояние с автоматическим переходом в HALF_OPEN"""
        if self._state == CircuitState.OPEN:
            if self._last_failure_time and \
               (time.time() - self._last_failure_time) > self.recovery_timeout:
                self._state = CircuitState.HALF_OPEN
                self.logger.info(f"Circuit breaker {self.name} moved to HALF_OPEN")
        return self._state
    
    async def call(self, func: Callable, *args, **kwargs) -> Any:
        """Выполнить функцию через Circuit Breaker"""
        self._total_calls += 1
        
        # Проверяем состояние
        if self.state == CircuitState.OPEN:
            self.logger.warning(f"Circuit breaker {self.name} is OPEN, rejecting call")
            raise CircuitBreakerError(
                f"Circuit breaker {self.name} is OPEN. "
                f"Will retry after {self.recovery_timeout}s"
            )
        
        try:
            # Выполняем функцию
            result = await func(*args, **kwargs)
            
            # Успешный вызов
            self._on_success()
            return result
            
        except self.expected_exception:
            # Ожидаемая ошибка
            self._on_failure()
            raise
        except Exception:
            # Неожиданная ошибка - пропускаем без изменения состояния
            raise
    
    def _on_success(self):
        """Обработка успешного вызова"""
        self._success_count += 1
        self._failure_count = 0
        
        if self._state == CircuitState.HALF_OPEN:
            self._state = CircuitState.CLOSED
            self.logger.info(f"Circuit breaker {self.name} moved to CLOSED")
    
    def _on_failure(self):
        """Обработка ошибки"""
        self._failure_count += 1
        self._last_failure_time = time.time()
        
        if self._failure_count >= self.failure_threshold:
            self._state = CircuitState.OPEN
            self.logger.error(
                f"Circuit breaker {self.name} moved to OPEN after "
                f"{self._failure_count} failures"
            )
    
    def get_metrics(self) -> dict:
        """Получить метрики Circuit Breaker"""
        return {
            'state': self._state.value,
            'failure_count': self._failure_count,
            'success_count': self._success_count,
            'total_calls': self._total_calls,
            'last_failure_time': self._last_failure_time
        }
    
    def reset(self):
        """Сбросить Circuit Breaker в начальное состояние"""
        self._state = CircuitState.CLOSED
        self._failure_count = 0
        self._last_failure_time = None
        self.logger.info(f"Circuit breaker {self.name} reset")