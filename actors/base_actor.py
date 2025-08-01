from abc import ABC, abstractmethod
from typing import Optional
import asyncio
from config.logging import get_logger
from config.settings import (
    ACTOR_MESSAGE_QUEUE_SIZE, 
    ACTOR_MESSAGE_TIMEOUT,
    ACTOR_SHUTDOWN_TIMEOUT
)
from actors.messages import ActorMessage, MESSAGE_TYPES

class BaseActor(ABC):
    """Абстрактный базовый класс для всех акторов системы"""
    
    def __init__(self, actor_id: str, name: str):
        self.actor_id = actor_id
        self.name = name
        self.logger = get_logger(f"actor.{name}.{actor_id}")
        self.is_running = False
        self._message_queue = asyncio.Queue(maxsize=ACTOR_MESSAGE_QUEUE_SIZE)
        self._task: Optional[asyncio.Task] = None
        
    @abstractmethod
    async def initialize(self) -> None:
        """Инициализация ресурсов актора"""
        pass
        
    @abstractmethod
    async def shutdown(self) -> None:
        """Освобождение ресурсов актора"""
        pass
        
    @abstractmethod
    async def handle_message(self, message: ActorMessage) -> Optional[ActorMessage]:
        """Обработка входящего сообщения"""
        pass
        
    async def send_message(self, message: ActorMessage) -> None:
        """Отправить сообщение актору (добавить в очередь)"""
        try:
            # Используем put_nowait для немедленного исключения при переполнении
            self._message_queue.put_nowait(message)
            self.logger.debug(f"Message {message.message_type} added to queue")
        except asyncio.QueueFull:
            self.logger.error(
                f"Message queue full, dropping message {message.message_id}"
            )
            raise
            
    async def start(self) -> None:
        """Запустить актор"""
        if self.is_running:
            self.logger.warning("Actor already running")
            return
            
        self.logger.info(f"Starting actor {self.name}")
        self.is_running = True
        
        # Инициализация
        await self.initialize()
        
        # Запуск message loop
        self._task = asyncio.create_task(self._message_loop())
        self.logger.info(f"Actor {self.name} started")
        
    async def stop(self) -> None:
        """Остановить актор"""
        if not self.is_running:
            self.logger.warning("Actor not running")
            return
            
        self.logger.info(f"Stopping actor {self.name}")
        self.is_running = False
        
        # Отправляем SHUTDOWN сообщение
        shutdown_msg = ActorMessage.create(
            sender_id="system",
            message_type=MESSAGE_TYPES['SHUTDOWN']
        )
        await self.send_message(shutdown_msg)
        
        # Ждем завершения задачи
        if self._task:
            try:
                await asyncio.wait_for(self._task, timeout=ACTOR_SHUTDOWN_TIMEOUT)
            except asyncio.TimeoutError:
                self.logger.error(f"Actor {self.name} shutdown timeout")
                self._task.cancel()
                
        # Освобождаем ресурсы
        await self.shutdown()
        self.logger.info(f"Actor {self.name} stopped")
        
    async def _message_loop(self) -> None:
        """Основной цикл обработки сообщений"""
        self.logger.debug("Message loop started")
        
        while self.is_running:
            try:
                # Ждем сообщение с таймаутом
                message = await asyncio.wait_for(
                    self._message_queue.get(),
                    timeout=ACTOR_MESSAGE_TIMEOUT
                )
                
                self.logger.debug(
                    f"Processing message {message.message_type} "
                    f"from {message.sender_id}"
                )
                
                # Обработка SHUTDOWN
                if message.message_type == MESSAGE_TYPES['SHUTDOWN']:
                    self.logger.info("Received shutdown message")
                    break
                    
                # Обработка сообщения
                try:
                    response = await self.handle_message(message)
                    if response:
                        self.logger.debug(f"Generated response: {response.message_type}")
                except Exception as e:
                    await self.handle_error(e, message)
                    
            except asyncio.TimeoutError:
                # Таймаут - нормальная ситуация, продолжаем
                continue
            except Exception as e:
                self.logger.error(f"Unexpected error in message loop: {str(e)}")
                
        self.logger.debug("Message loop ended")
        
    async def handle_error(self, error: Exception, message: ActorMessage) -> None:
        """Обработка ошибок"""
        self.logger.error(
            f"Error handling message {message.message_type}: {str(error)}",
            exc_info=True
        )
    
    def set_actor_system(self, actor_system) -> None:
        """
        Установить ссылку на ActorSystem.
        Стандартный метод для всех акторов.
        
        Args:
            actor_system: Ссылка на ActorSystem
        """
        self._actor_system = actor_system
        self.logger.debug(f"ActorSystem reference set for {self.name}")
    
    def get_actor_system(self):
        """Получить ссылку на ActorSystem"""
        return getattr(self, '_actor_system', None)