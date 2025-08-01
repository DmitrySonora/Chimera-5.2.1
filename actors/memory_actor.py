from typing import Optional, Dict, Any
import asyncio
import json
import time

from actors.base_actor import BaseActor
from actors.messages import ActorMessage, MESSAGE_TYPES
from config.settings import (
    STM_QUERY_TIMEOUT,
    STM_METRICS_ENABLED,
    STM_METRICS_LOG_INTERVAL,
    STM_BUFFER_SIZE,
    STM_MESSAGE_MAX_LENGTH,
    STM_CONTEXT_FORMAT,
    STM_DEEPSEEK_ROLE_MAPPING
)
from database.connection import db_connection
from utils.monitoring import measure_latency
from utils.event_utils import EventVersionManager
from models.memory_models import MemoryEntry, MemoryContext
from actors.events.memory_events import MemoryStoredEvent, ContextRetrievedEvent


class MemoryActor(BaseActor):
    """
    Актор для управления кратковременной памятью (STM).
    Сохраняет историю диалогов в PostgreSQL для контекста генерации.
    """
    
    def __init__(self):
        super().__init__("memory", "Memory")
        self._pool = None
        self._degraded_mode = False
        self._event_version_manager = EventVersionManager()
        
        # Метрики
        self._metrics = {
            'initialized': False,
            'degraded_mode_entries': 0,
            'store_memory_count': 0,
            'get_context_count': 0,
            'clear_memory_count': 0,
            'unknown_message_count': 0,
            'db_errors': 0
        }
        
        # Задача для периодического логирования метрик
        self._metrics_task: Optional[asyncio.Task] = None
        
    async def initialize(self) -> None:
        """Инициализация актора и проверка схемы БД"""
        try:
            # Проверяем, нужно ли подключаться
            if not db_connection._is_connected:
                await db_connection.connect()
            
            # Получаем пул подключений
            self._pool = db_connection.get_pool()
            self.buffer_size = STM_BUFFER_SIZE
            
            # Проверяем существование таблицы и индексов
            await self._verify_schema()
            
            self._metrics['initialized'] = True
            
            # Запускаем периодическое логирование метрик
            if STM_METRICS_ENABLED:
                self._metrics_task = asyncio.create_task(self._metrics_loop())
            
            self.logger.info("MemoryActor initialized successfully")
            
        except Exception as e:
            self.logger.error(f"Failed to initialize MemoryActor: {str(e)}")
            self._degraded_mode = True
            self._metrics['degraded_mode_entries'] += 1
            self._increment_metric('db_errors')
            self.logger.warning("MemoryActor entering degraded mode - will work without persistence")
    
    async def shutdown(self) -> None:
        """Освобождение ресурсов"""
        # Останавливаем метрики
        if self._metrics_task and not self._metrics_task.done():
            self._metrics_task.cancel()
            try:
                await self._metrics_task
            except asyncio.CancelledError:
                pass
        
        # Логируем финальные метрики
        self._log_metrics(final=True)
        
        self.logger.info("MemoryActor shutdown completed")
    
    @measure_latency
    async def handle_message(self, message: ActorMessage) -> Optional[ActorMessage]:
        """Обработка входящих сообщений"""
        
        # Обработка STORE_MEMORY
        if message.message_type == MESSAGE_TYPES['STORE_MEMORY']:
            self._metrics['store_memory_count'] += 1
            await self._handle_store_memory(message)
            
        # Обработка GET_CONTEXT
        elif message.message_type == MESSAGE_TYPES['GET_CONTEXT']:
            self._metrics['get_context_count'] += 1
            await self._handle_get_context(message)
            return None  # Ответ отправляется внутри метода
            
        # Обработка CLEAR_USER_MEMORY
        elif message.message_type == MESSAGE_TYPES['CLEAR_USER_MEMORY']:
            self._metrics['clear_memory_count'] += 1
            await self._handle_clear_memory(message)
            
        else:
            self._metrics['unknown_message_count'] += 1
            self.logger.warning(
                f"Unknown message type received: {message.message_type}"
            )
        
        return None
    
    async def _verify_schema(self) -> None:
        """Проверка существования таблицы и индексов"""
        try:
            if self._pool is None:
                raise RuntimeError("Database pool not initialized")
                
            # Проверяем существование таблицы
            query = """
                SELECT EXISTS (
                    SELECT FROM information_schema.tables 
                    WHERE table_name = 'stm_buffer'
                )
            """
            table_exists = await self._pool.fetchval(query, timeout=STM_QUERY_TIMEOUT)
            
            if not table_exists:
                raise RuntimeError("Table stm_buffer does not exist. Run migrations first.")
            
            # Проверяем индексы
            index_query = """
                SELECT indexname 
                FROM pg_indexes 
                WHERE tablename = 'stm_buffer'
            """
            indexes = await self._pool.fetch(index_query, timeout=STM_QUERY_TIMEOUT)
            
            required_indexes = {
                'idx_stm_user_timestamp',
                'idx_stm_user_sequence', 
                'idx_stm_cleanup'
            }
            
            existing_indexes = {row['indexname'] for row in indexes}
            missing_indexes = required_indexes - existing_indexes
            
            if missing_indexes:
                self.logger.warning(f"Missing indexes: {missing_indexes}")
            
            self.logger.debug("Schema verification completed successfully")
            
        except Exception as e:
            self.logger.error(f"Schema verification failed: {str(e)}")
            raise
    
    async def _handle_store_memory(self, message: ActorMessage) -> None:
        """Обработчик сохранения в память"""
        if self._degraded_mode:
            self.logger.debug(
                f"STORE_MEMORY in degraded mode for user {message.payload.get('user_id')}"
            )
            return
        
        await self.store_interaction(
            user_id=message.payload['user_id'],
            message_type=message.payload['message_type'],
            content=message.payload['content'],
            metadata=message.payload.get('metadata')
        )
    
    async def _handle_get_context(self, message: ActorMessage) -> None:
        """Обработчик получения контекста"""
        # Определяем кому отвечать
        reply_to_actor = message.reply_to or message.sender_id
        if not reply_to_actor:
            self.logger.warning("GET_CONTEXT message without reply_to or sender_id")
            return
            
        if self._degraded_mode:
            # В degraded mode отправляем пустой контекст
            response = ActorMessage.create(
                sender_id=self.actor_id,
                message_type=MESSAGE_TYPES['CONTEXT_RESPONSE'],
                payload={
                    'user_id': message.payload.get('user_id'),
                    'context': [],
                    'degraded_mode': True,
                    'request_id': message.payload.get('request_id')  # Сохраняем request_id
                }
            )
            # Отправляем через ActorSystem
            if self.get_actor_system():
                await self.get_actor_system().send_message(reply_to_actor, response)
            return
        
        context = await self.get_context(
            user_id=message.payload['user_id'],
            limit=message.payload.get('limit'),
            format_type=message.payload.get('format_type')
        )
        
        # Создаем ответное сообщение
        response = ActorMessage.create(
            sender_id=self.actor_id,
            message_type=MESSAGE_TYPES['CONTEXT_RESPONSE'],
            payload={
                'user_id': context.user_id,
                'messages': context.messages,
                'total_messages': context.total_messages,
                'format_type': context.format_type,
                'request_id': message.payload.get('request_id')  # Сохраняем request_id
            }
        )
        
        # Отправляем через ActorSystem
        if self.get_actor_system():
            await self.get_actor_system().send_message(reply_to_actor, response)
    
    async def _handle_clear_memory(self, message: ActorMessage) -> None:
        """Обработчик очистки памяти (заглушка для этапа 3.2.1)"""
        if self._degraded_mode:
            self.logger.debug(
                f"CLEAR_USER_MEMORY in degraded mode for user {message.payload.get('user_id')}"
            )
            return
        
        # TODO: Реализация в этапе 3.2.2
        self.logger.debug("CLEAR_USER_MEMORY handler called (stub)")
    
    @measure_latency
    async def store_interaction(
        self,
        user_id: str,
        message_type: str,
        content: str,
        metadata: Optional[Dict[str, Any]] = None
    ) -> None:
        """
        Сохранить взаимодействие в кольцевой буфер STM.
        При превышении размера буфера автоматически удаляются старые записи.
        
        Args:
            user_id: ID пользователя
            message_type: Тип сообщения ('user' или 'bot')
            content: Текст сообщения
            metadata: Дополнительные метаданные
        """
        try:
            # 1. Валидация через Pydantic
            entry = MemoryEntry(
                user_id=user_id,
                message_type=message_type,
                content=content[:STM_MESSAGE_MAX_LENGTH],  # Обрезка
                metadata=metadata or {}
            )
            
            # 2. Если обрезали - добавить в metadata
            if len(content) > STM_MESSAGE_MAX_LENGTH:
                entry.metadata["truncated"] = True
                entry.metadata["original_length"] = len(content)
                self.logger.warning(
                    f"Truncated message for user {user_id}: "
                    f"{len(content)} -> {STM_MESSAGE_MAX_LENGTH}"
                )
            
            # 3. Транзакция с БД
            async with self._pool.acquire() as conn:
                async with conn.transaction():
                    # ВАЖНО: json.dumps для metadata!
                    await conn.execute(
                        """
                        INSERT INTO stm_buffer (user_id, message_type, content, metadata)
                        VALUES ($1, $2, $3, $4)
                        """,
                        entry.user_id,
                        entry.message_type,
                        entry.content,
                        json.dumps(entry.metadata)  # ← КРИТИЧНО!
                    )
                    
                    # Проверка количества
                    count = await conn.fetchval(
                        "SELECT COUNT(*) FROM stm_buffer WHERE user_id = $1",
                        user_id
                    )
                    
                    # Очистка если нужно
                    if count > self.buffer_size:
                        deleted = await conn.fetchval(
                            "SELECT cleanup_stm_buffer($1, $2)",
                            user_id,
                            self.buffer_size
                        )
                        if deleted > 0:
                            self.logger.info(
                                f"Cleaned {deleted} old messages for user {user_id}"
                            )
            
            # 4. Создать событие
            event = MemoryStoredEvent.create(
                user_id=user_id,
                message_type=message_type,
                content_length=len(entry.content),
                has_metadata=bool(entry.metadata)
            )
            await self._event_version_manager.append_event(
                event, 
                self.get_actor_system()
            )
            
        except Exception as e:
            self.logger.error(f"Failed to store interaction: {str(e)}")
            self._increment_metric('db_errors')
            raise
    
    @measure_latency
    async def get_context(
        self,
        user_id: str,
        limit: Optional[int] = None,
        format_type: Optional[str] = None
    ) -> MemoryContext:
        """
        Получить контекст диалога для пользователя.
        
        Args:
            user_id: ID пользователя
            limit: Максимальное количество сообщений (по умолчанию STM_BUFFER_SIZE)
            format_type: Формат вывода ('structured' для DeepSeek, 'text' для отладки)
            
        Returns:
            MemoryContext с отформатированными сообщениями
        """
        start_time = time.time()
        
        try:
            limit = limit or self.buffer_size
            format_type = format_type or STM_CONTEXT_FORMAT
            
            async with self._pool.acquire() as conn:
                # 1. Запрос данных (DESC для получения новейших)
                rows = await conn.fetch(
                    """
                    SELECT message_type, content, metadata, timestamp
                    FROM stm_buffer
                    WHERE user_id = $1
                    ORDER BY sequence_number DESC
                    LIMIT $2
                    """,
                    user_id,
                    limit,
                    timeout=STM_QUERY_TIMEOUT
                )
            
            # 2. Если пусто - быстрый возврат
            if not rows:
                return MemoryContext(
                    user_id=user_id,
                    messages=[],
                    total_messages=0,
                    format_type=format_type
                )
            
            # 3. ВАЖНО: развернуть порядок для хронологии
            # rows сейчас: [новейшее, ..., старейшее]
            # нужно: [старейшее, ..., новейшее]
            messages = []
            for row in reversed(rows):  # ← РАЗВОРОТ!
                if format_type == "structured":
                    # Формат для DeepSeek API
                    role = STM_DEEPSEEK_ROLE_MAPPING.get(
                        row["message_type"], 
                        row["message_type"]
                    )
                    messages.append({
                        "role": role,
                        "content": row["content"]
                    })
                else:
                    # Текстовый формат для отладки
                    messages.append({
                        "type": row["message_type"],
                        "content": row["content"],
                        "timestamp": row["timestamp"].isoformat() if row["timestamp"] else None
                    })
            
            # 4. Создать и вернуть результат
            context = MemoryContext(
                user_id=user_id,
                messages=messages,
                total_messages=len(messages),
                format_type=format_type
            )
            
            # 5. Событие о получении
            retrieval_time_ms = (time.time() - start_time) * 1000
            event = ContextRetrievedEvent.create(
                user_id=user_id,
                context_size=len(messages),
                retrieval_time_ms=retrieval_time_ms,
                format_type=format_type
            )
            await self._event_version_manager.append_event(
                event,
                self.get_actor_system()
            )
            
            self.logger.debug(
                f"Retrieved {len(messages)} messages for user {user_id} "
                f"in {retrieval_time_ms:.2f}ms"
            )
            
            return context
            
        except Exception as e:
            self.logger.error(f"Failed to get context: {str(e)}")
            self._increment_metric('db_errors')
            # Возвращаем пустой контекст при ошибке
            return MemoryContext(
                user_id=user_id,
                messages=[],
                total_messages=0,
                format_type=format_type or STM_CONTEXT_FORMAT
            )
    
    def _increment_metric(self, metric_name: str, value: int = 1) -> None:
        """Инкремент метрики"""
        if metric_name in self._metrics:
            self._metrics[metric_name] += value
    
    async def _metrics_loop(self) -> None:
        """Периодическое логирование метрик"""
        while self.is_running:
            try:
                await asyncio.sleep(STM_METRICS_LOG_INTERVAL)
                self._log_metrics()
            except asyncio.CancelledError:
                break
            except Exception as e:
                self.logger.error(f"Error in metrics loop: {str(e)}")
    
    def _log_metrics(self, final: bool = False) -> None:
        """Логирование метрик"""
        log_msg = "MemoryActor metrics"
        if final:
            log_msg = "MemoryActor final metrics"
        
        self.logger.info(
            f"{log_msg} - "
            f"Store: {self._metrics['store_memory_count']}, "
            f"Get: {self._metrics['get_context_count']}, "
            f"Clear: {self._metrics['clear_memory_count']}, "
            f"Unknown: {self._metrics['unknown_message_count']}, "
            f"DB errors: {self._metrics['db_errors']}, "
            f"Degraded mode: {self._degraded_mode}"
        )