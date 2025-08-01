"""
PerceptionActor - актор для асинхронного анализа эмоций в тексте.
Использует EmotionAnalyzer для определения эмоционального состояния.
"""
from typing import Optional
import asyncio
from concurrent.futures import ThreadPoolExecutor

from actors.base_actor import BaseActor
from actors.messages import ActorMessage, MESSAGE_TYPES
from models.emotion_analyzer import EmotionAnalyzer
from config.settings import (
    PERCEPTION_EMOTION_TIMEOUT,
    PERCEPTION_THREAD_POOL_SIZE,
    PERCEPTION_LOG_ERRORS
)
from utils.monitoring import measure_latency


class PerceptionActor(BaseActor):
    """
    Актор для анализа эмоций в текстовых сообщениях.
    
    Обрабатывает сообщения типа ANALYZE_EMOTION и возвращает
    эмоциональный вектор и доминирующие эмоции.
    """
    
    def __init__(self, actor_id: str):
        """
        Инициализация PerceptionActor.
        
        Args:
            actor_id: Уникальный идентификатор актора
        """
        super().__init__(actor_id, "PerceptionActor")
        self._emotion_analyzer: Optional[EmotionAnalyzer] = None
        self._thread_pool: Optional[ThreadPoolExecutor] = None
        self._analysis_count = 0
        self._error_count = 0
        
    async def initialize(self) -> None:
        """Инициализация ресурсов актора"""
        try:
            # Инициализируем EmotionAnalyzer
            self._emotion_analyzer = EmotionAnalyzer()
            
            # Создаем пул потоков для асинхронного выполнения
            self._thread_pool = ThreadPoolExecutor(
                max_workers=PERCEPTION_THREAD_POOL_SIZE,
                thread_name_prefix="emotion-analyzer"
            )
            
            self.logger.info(
                f"PerceptionActor initialized with thread pool size: {PERCEPTION_THREAD_POOL_SIZE}"
            )
            
        except Exception as e:
            self.logger.error(f"Failed to initialize PerceptionActor: {str(e)}")
            raise
            
    async def shutdown(self) -> None:
        """Освобождение ресурсов актора"""
        # Закрываем пул потоков
        if self._thread_pool:
            self._thread_pool.shutdown(wait=True)
            
        self.logger.info(
            f"PerceptionActor shutdown. Analyzed: {self._analysis_count}, "
            f"Errors: {self._error_count}"
        )
        
    @measure_latency
    async def handle_message(self, message: ActorMessage) -> Optional[ActorMessage]:
        """
        Обработка входящих сообщений.
        
        Поддерживает только ANALYZE_EMOTION сообщения.
        
        Args:
            message: Входящее сообщение
            
        Returns:
            ActorMessage с результатом анализа или None
        """
        # Обрабатываем только ANALYZE_EMOTION
        if message.message_type != MESSAGE_TYPES['ANALYZE_EMOTION']:
            return None
            
        # Извлекаем данные из payload
        text = message.payload.get('text', '')
        user_id = message.payload.get('user_id', '')
        
        if not text:
            self.logger.warning(f"Empty text received for user {user_id}")
            return self._create_neutral_response(user_id, message.reply_to, "Empty text")
            
        try:
            # Выполняем анализ асинхронно
            emotion_vector, dominant_emotions = await self._analyze_emotion_async(text)
            
            self._analysis_count += 1
            
            # Создаем успешный ответ
            response = ActorMessage.create(
                sender_id=self.actor_id,
                message_type=MESSAGE_TYPES['EMOTION_RESULT'],
                payload={
                    'user_id': user_id,
                    'emotions': emotion_vector,
                    'dominant_emotions': dominant_emotions,
                    'text': text[:50]  # Добавляем превью текста
                }
            )
            
            # Отправляем ответ обратно отправителю
            if message.reply_to and self.get_actor_system():
                await self.get_actor_system().send_message(message.reply_to, response)
                self.logger.info(
                    f"Sent EMOTION_RESULT to {message.reply_to} for user {user_id}: "
                    f"dominant={dominant_emotions[:3]}"
                )
            else:
                self.logger.warning(f"No reply_to address for EMOTION_RESULT (user: {user_id})")
            
            return None
            
        except asyncio.TimeoutError:
            self._error_count += 1
            if PERCEPTION_LOG_ERRORS:
                self.logger.error(f"Emotion analysis timeout for user {user_id}")
            return self._create_neutral_response(user_id, message.reply_to, "Analysis timeout")
            
        except Exception as e:
            self._error_count += 1
            if PERCEPTION_LOG_ERRORS:
                self.logger.error(f"Emotion analysis error for user {user_id}: {str(e)}")
            return self._create_neutral_response(user_id, message.reply_to, str(e))
            
    async def _analyze_emotion_async(self, text: str) -> tuple[dict, list]:
        """
        Асинхронная обертка для анализа эмоций.
        
        Args:
            text: Текст для анализа
            
        Returns:
            Кортеж (emotion_vector, dominant_emotions)
            
        Raises:
            asyncio.TimeoutError: При превышении таймаута
        """
        if not self._emotion_analyzer or not self._thread_pool:
            raise RuntimeError("PerceptionActor not properly initialized")
            
        loop = asyncio.get_event_loop()
        
        # Выполняем анализ в отдельном потоке с таймаутом
        try:
            # Получаем полный вектор эмоций
            emotion_vector = await asyncio.wait_for(
                loop.run_in_executor(
                    self._thread_pool,
                    self._emotion_analyzer.get_emotion_vector,
                    text
                ),
                timeout=PERCEPTION_EMOTION_TIMEOUT
            )
            
            # Получаем доминирующие эмоции
            dominant_emotions = await asyncio.wait_for(
                loop.run_in_executor(
                    self._thread_pool,
                    self._emotion_analyzer.analyze_text,
                    text,
                    False  # return_all=False
                ),
                timeout=PERCEPTION_EMOTION_TIMEOUT
            )
            
            return emotion_vector, dominant_emotions
            
        except asyncio.TimeoutError:
            self.logger.warning(
                f"Emotion analysis timeout after {PERCEPTION_EMOTION_TIMEOUT}s"
            )
            raise
            
    def _create_neutral_response(
        self, 
        user_id: str, 
        reply_to: Optional[str], 
        error: str
    ) -> ActorMessage:
        """
        Создает нейтральный ответ при ошибке анализа.
        
        Args:
            user_id: ID пользователя
            reply_to: Кому отвечать
            error: Описание ошибки
            
        Returns:
            ActorMessage с нейтральным эмоциональным вектором
        """
        response = ActorMessage.create(
            sender_id=self.actor_id,
            message_type=MESSAGE_TYPES['EMOTION_RESULT'],
            payload={
                'user_id': user_id,
                'emotions': {'neutral': 1.0},
                'dominant_emotions': ['neutral'],
                'error': error
            }
        )
        
        # Отправляем нейтральный ответ
        if reply_to and self.get_actor_system():
            asyncio.create_task(
                self.get_actor_system().send_message(reply_to, response)
            )
            self.logger.info(f"Sent neutral EMOTION_RESULT to {reply_to} for user {user_id}: {error}")
        
        return None