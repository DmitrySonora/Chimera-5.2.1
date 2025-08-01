from typing import Dict, List, Optional, Any
import asyncio
from config.logging import get_logger
from actors.base_actor import BaseActor
from actors.messages import ActorMessage
from actors.events.base_event import BaseEvent
from utils.monitoring import measure_latency
from utils.circuit_breaker import CircuitBreaker, CircuitBreakerError
from config.settings import (
    ACTOR_SYSTEM_NAME, 
    ACTOR_SHUTDOWN_TIMEOUT,
    ACTOR_MESSAGE_RETRY_ENABLED,
    ACTOR_MESSAGE_MAX_RETRIES,
    ACTOR_MESSAGE_RETRY_DELAY,
    ACTOR_MESSAGE_RETRY_MAX_DELAY,
    DLQ_MAX_SIZE,
    DLQ_CLEANUP_INTERVAL,
    DLQ_METRICS_ENABLED
)

class ActorSystem:
    """Система управления акторами"""
    
    def __init__(self, name: str = ACTOR_SYSTEM_NAME):
        self.name = name
        self.logger = get_logger(f"actor_system.{name}")
        self._actors: Dict[str, BaseActor] = {}
        self._tasks: List[asyncio.Task] = []
        self.is_running = False
        self._dead_letter_queue: List[Dict[str, Any]] = []
        self._dlq_cleanup_task: Optional[asyncio.Task] = None
        self._dlq_total_messages = 0  # Счетчик всех сообщений в DLQ
        self._dlq_cleaned_messages = 0  # Счетчик очищенных сообщений
        self._event_store = None  # Будет инициализирован отдельно
        self._background_tasks: List[asyncio.Task] = []  # Tracking для фоновых задач
        self._circuit_breakers: Dict[str, CircuitBreaker] = {}  # Circuit breakers для акторов
        
    @measure_latency
    async def register_actor(self, actor: BaseActor) -> None:
        """Зарегистрировать актор в системе"""
        if actor.actor_id in self._actors:
            raise ValueError(f"Actor {actor.actor_id} already registered")
            
        self._actors[actor.actor_id] = actor
        
        # Автоматически устанавливаем ссылку на ActorSystem
        actor.set_actor_system(self)
        
        self.logger.info(f"Registered actor {actor.actor_id}")
        
        # Если система запущена, запускаем актор
        if self.is_running:
            await actor.start()
            
    async def unregister_actor(self, actor_id: str) -> None:
        """Удалить актор из системы"""
        if actor_id not in self._actors:
            self.logger.warning(f"Actor {actor_id} not found")
            return
            
        actor = self._actors[actor_id]
        
        # Останавливаем актор если он запущен
        if actor.is_running:
            await actor.stop()
            
        del self._actors[actor_id]
        self.logger.info(f"Unregistered actor {actor_id}")
        
    async def get_actor(self, actor_id: str) -> Optional[BaseActor]:
        """Получить актор по ID"""
        return self._actors.get(actor_id)
        
    @measure_latency
    async def send_message(self, actor_id: str, message: ActorMessage) -> None:
        """Отправить сообщение конкретному актору с опциональным retry"""
        actor = self._actors.get(actor_id)
        if not actor:
            raise ValueError(f"Actor {actor_id} not found")
        
        if not ACTOR_MESSAGE_RETRY_ENABLED:
            await actor.send_message(message)
            return
        
        # Создаем Circuit Breaker для актора если его еще нет
        from config.settings import CIRCUIT_BREAKER_ENABLED
        if CIRCUIT_BREAKER_ENABLED and actor_id not in self._circuit_breakers:
            self._circuit_breakers[actor_id] = CircuitBreaker(
                name=f"actor_{actor_id}",
                expected_exception=asyncio.QueueFull
            )
        
        # Retry механизм с exponential backoff
        retry_count = 0
        delay = ACTOR_MESSAGE_RETRY_DELAY
        
        while retry_count <= ACTOR_MESSAGE_MAX_RETRIES:
            try:
                # Используем Circuit Breaker если включен
                if CIRCUIT_BREAKER_ENABLED and actor_id in self._circuit_breakers:
                    await self._circuit_breakers[actor_id].call(
                        actor.send_message, message
                    )
                else:
                    await actor.send_message(message)
                return  # Успешно отправлено
            except CircuitBreakerError as e:
                # Circuit Breaker открыт - сразу в DLQ
                self.logger.error(f"Circuit breaker open for {actor_id}: {str(e)}")
                await self._send_to_dead_letter_queue(actor_id, message, str(e))
                raise
            except asyncio.QueueFull as e:
                retry_count += 1
                if retry_count > ACTOR_MESSAGE_MAX_RETRIES:
                    self.logger.error(
                        f"Failed to send message to {actor_id} after "
                        f"{ACTOR_MESSAGE_MAX_RETRIES} retries"
                    )
                    # Отправляем в Dead Letter Queue
                    await self._send_to_dead_letter_queue(actor_id, message, str(e))
                    raise
                
                self.logger.warning(
                    f"Message queue full for {actor_id}, retry "
                    f"{retry_count}/{ACTOR_MESSAGE_MAX_RETRIES} after {delay:.1f}s"
                )
                await asyncio.sleep(delay)
                # Exponential backoff
                delay = min(delay * 2, ACTOR_MESSAGE_RETRY_MAX_DELAY)
        
    @measure_latency
    async def broadcast_message(
        self, 
        message: ActorMessage, 
        exclude: List[str] = None
    ) -> None:
        """Отправить сообщение всем акторам (кроме исключенных)"""
        exclude = exclude or []
        
        tasks = []
        for actor_id, actor in self._actors.items():
            if actor_id not in exclude:
                tasks.append(actor.send_message(message))
                
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
            
        # Собираем ID акторов, которым отправили сообщение
        target_actors = [
            actor_id for actor_id in self._actors.keys() 
            if actor_id not in exclude
        ]
        
        self.logger.debug(
            f"Broadcasted message {message.message_type} to "
            f"{len(tasks)} actors: {target_actors}"
        )
        
    async def _send_to_dead_letter_queue(
        self, 
        actor_id: str, 
        message: ActorMessage, 
        error: str
    ) -> None:
        """Сохранить необработанное сообщение в Dead Letter Queue"""
        dead_letter = {
            'timestamp': asyncio.get_event_loop().time(),
            'actor_id': actor_id,
            'message': message,
            'error': error
        }
        self._dead_letter_queue.append(dead_letter)
        self._dlq_total_messages += 1
        
        self.logger.error(
            f"Message {message.message_id} sent to DLQ. "
            f"Actor: {actor_id}, Error: {error}"
        )
        
        # Создать событие для Event Store
        if hasattr(self, '_event_store') and self._event_store:
            dlq_event = BaseEvent.create(
                stream_id=f"dlq_{actor_id}",
                event_type="DeadLetterQueuedEvent",
                data={
                    "actor_id": actor_id,
                    "message_id": message.message_id,
                    "message_type": message.message_type,
                    "error": error,
                    "payload": message.payload
                },
                correlation_id=message.message_id
            )
            # Используем create_task чтобы не блокировать основной поток
            task = asyncio.create_task(self._event_store.append_event(dlq_event))
            self._background_tasks.append(task)
            # Очищаем завершенные задачи
            self._background_tasks = [t for t in self._background_tasks if not t.done()]
        
        # Проверяем размер DLQ
        if len(self._dead_letter_queue) > DLQ_MAX_SIZE * 0.9:
            self.logger.warning(
                f"DLQ is 90% full: {len(self._dead_letter_queue)}/{DLQ_MAX_SIZE}"
            )
    
    def get_dead_letter_queue(self) -> List[Dict[str, Any]]:
        """Получить содержимое Dead Letter Queue"""
        return self._dead_letter_queue.copy()
    
    def clear_dead_letter_queue(self) -> int:
        """Очистить Dead Letter Queue и вернуть количество удаленных сообщений"""
        count = len(self._dead_letter_queue)
        self._dead_letter_queue.clear()
        self.logger.info(f"Cleared {count} messages from Dead Letter Queue")
        return count
    
    def get_dlq_metrics(self) -> Dict[str, int]:
        """Получить метрики Dead Letter Queue"""
        return {
            'current_size': len(self._dead_letter_queue),
            'total_messages': self._dlq_total_messages,
            'cleaned_messages': self._dlq_cleaned_messages,
            'max_size': DLQ_MAX_SIZE
        }
    
    async def _dlq_cleanup_loop(self) -> None:
        """Периодическая очистка Dead Letter Queue"""
        while self.is_running:
            try:
                await asyncio.sleep(DLQ_CLEANUP_INTERVAL)
                
                if len(self._dead_letter_queue) > DLQ_MAX_SIZE:
                    # Удаляем старые сообщения
                    messages_to_remove = len(self._dead_letter_queue) - DLQ_MAX_SIZE
                    _ = self._dead_letter_queue[:messages_to_remove]
                    self._dead_letter_queue = self._dead_letter_queue[messages_to_remove:]
                    
                    self._dlq_cleaned_messages += messages_to_remove
                    self.logger.warning(
                        f"DLQ cleanup: removed {messages_to_remove} old messages. "
                        f"Total cleaned: {self._dlq_cleaned_messages}"
                    )
                    
                # Логируем метрики DLQ
                if DLQ_METRICS_ENABLED:
                    self.logger.info(
                        f"DLQ metrics - Current size: {len(self._dead_letter_queue)}, "
                        f"Total received: {self._dlq_total_messages}, "
                        f"Total cleaned: {self._dlq_cleaned_messages}"
                    )
                    
                # Логируем метрики Event Store если он подключен
                if self._event_store and hasattr(self._event_store, 'get_metrics'):
                    es_metrics = self._event_store.get_metrics()
                    self.logger.info(
                        f"Event Store metrics - "
                        f"Events: {es_metrics['total_events']}, "
                        f"Appends: {es_metrics['total_appends']}, "
                        f"Reads: {es_metrics['total_reads']}, "
                        f"Cache hit rate: {es_metrics['cache_hit_rate']}%"
                    )
                    
            except Exception as e:
                self.logger.error(f"Error in DLQ cleanup loop: {str(e)}")
    
    async def start(self) -> None:
        """Запустить систему акторов"""
        if self.is_running:
            self.logger.warning("Actor system already running")
            return
            
        self.logger.info("Starting actor system")
        self.is_running = True
        
        # Запускаем все акторы
        for actor in self._actors.values():
            await actor.start()
            
        # Запускаем задачу очистки DLQ
        if DLQ_CLEANUP_INTERVAL > 0:
            self._dlq_cleanup_task = asyncio.create_task(self._dlq_cleanup_loop())
            self.logger.info("Started DLQ cleanup task")
            
        self.logger.info(f"Started {len(self._actors)} actors")
        
    async def stop(self, timeout: float = ACTOR_SHUTDOWN_TIMEOUT) -> None:
        """Остановить систему акторов"""
        # Всегда ждем фоновые задачи, даже если система не запущена
        if hasattr(self, '_background_tasks') and self._background_tasks:
            active_tasks = [t for t in self._background_tasks if not t.done()]
            if active_tasks:
                self.logger.info(f"Waiting for {len(active_tasks)} background tasks")
                await asyncio.gather(*active_tasks, return_exceptions=True)
        
        if not self.is_running:
            self.logger.warning("Actor system not running")
            return
            
        self.logger.info("Stopping actor system")
        self.is_running = False
                
        # Останавливаем задачу очистки DLQ
        if self._dlq_cleanup_task and not self._dlq_cleanup_task.done():
            self._dlq_cleanup_task.cancel()
            try:
                await self._dlq_cleanup_task
            except asyncio.CancelledError:
                pass
        
        # Останавливаем все акторы
        stop_tasks = []
        for actor in self._actors.values():
            stop_tasks.append(actor.stop())
            
        if stop_tasks:
            try:
                await asyncio.wait_for(
                    asyncio.gather(*stop_tasks, return_exceptions=True),
                    timeout=timeout
                )
            except asyncio.TimeoutError:
                self.logger.error("Timeout stopping actors, forcing shutdown")
                # Принудительная отмена всех задач
                for task in self._tasks:
                    if not task.done():
                        task.cancel()
                        
        self.logger.info("Actor system stopped")
        
    def set_event_store(self, event_store) -> None:
        """Установить Event Store для системы акторов"""
        self._event_store = event_store
        self.logger.info("Event Store connected to Actor System")
    
    async def create_and_set_event_store(self) -> None:
        """Создать и установить Event Store согласно конфигурации"""
        from actors.events import EventStoreFactory
        
        self._event_store = await EventStoreFactory.create()
        self.logger.info(f"Event Store ({type(self._event_store).__name__}) connected to Actor System")