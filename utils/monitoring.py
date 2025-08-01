import time
from functools import wraps
from typing import Any, Callable
import logging
from config.settings import SLOW_OPERATION_THRESHOLD


from typing import TypeVar, cast

T = TypeVar('T', bound=Callable[..., Any])

def measure_latency(func: T) -> T:
    """
    Декоратор для измерения производительности async методов.
    Логирует только медленные операции (> 0.1 сек).
    """
    @wraps(func)
    async def wrapper(self, *args, **kwargs) -> Any:
        start_time = time.time()
        logger = getattr(self, 'logger', logging.getLogger(__name__))
        
        try:
            result = await func(self, *args, **kwargs)
            elapsed = time.time() - start_time
            
            # Логируем только медленные операции
            if elapsed > SLOW_OPERATION_THRESHOLD:
                logger.warning(
                    f"Slow operation: {func.__name__} took {elapsed:.3f}s"
                )
            
            return result
            
        except Exception as e:
            elapsed = time.time() - start_time
            logger.error(
                f"Error in {func.__name__} after {elapsed:.3f}s: {str(e)}"
            )
            raise
    
    return cast(T, wrapper)