"""
Тесты для PerceptionActor - изолированное тестирование анализа эмоций
"""
import pytest
import asyncio
from actors.perception_actor import PerceptionActor
from actors.messages import ActorMessage, MESSAGE_TYPES


@pytest.mark.asyncio
async def test_perception_actor_initialization():
    """Тест инициализации PerceptionActor"""
    actor = PerceptionActor("perception_test")
    
    # Инициализация
    await actor.initialize()
    
    # Проверяем, что ресурсы инициализированы
    assert actor._emotion_analyzer is not None
    assert actor._thread_pool is not None
    assert actor._analysis_count == 0
    assert actor._error_count == 0
    
    # Очистка
    await actor.shutdown()
    
    print("✅ PerceptionActor успешно инициализирован и остановлен")


@pytest.mark.asyncio
async def test_analyze_positive_emotion():
    """Тест анализа позитивной эмоции"""
    actor = PerceptionActor("perception_test")
    await actor.initialize()
    
    try:
        # Создаем тестовое сообщение с позитивным текстом
        message = ActorMessage.create(
            sender_id="test_sender",
            message_type=MESSAGE_TYPES['ANALYZE_EMOTION'],
            payload={
                'text': 'Обожаю эту кофейню! Лучший кофе в городе!',
                'user_id': 'test_user_123'
            },
            reply_to="test_sender"
        )
        
        # Обрабатываем сообщение
        result = await actor.handle_message(message)
        
        # Проверяем результат
        assert result is not None
        assert result.message_type == MESSAGE_TYPES['EMOTION_RESULT']
        assert result.reply_to == "test_sender"
        
        # Проверяем payload
        payload = result.payload
        assert payload['user_id'] == 'test_user_123'
        assert 'emotions' in payload
        assert 'dominant_emotions' in payload
        assert 'error' not in payload
        
        # Проверяем, что обнаружены позитивные эмоции
        dominant = payload['dominant_emotions']
        assert isinstance(dominant, list)
        assert len(dominant) > 0
        
        # Ожидаем admiration или love в доминирующих эмоциях
        positive_emotions = {'admiration', 'love', 'joy', 'excitement'}
        assert any(emotion in positive_emotions for emotion in dominant), \
            f"Expected positive emotions, got: {dominant}"
        
        # Проверяем эмоциональный вектор
        emotions = payload['emotions']
        assert isinstance(emotions, dict)
        assert len(emotions) == 28  # Все 28 эмоций
        assert all(0 <= v <= 1 for v in emotions.values())  # Значения в диапазоне [0,1]
        
        print(f"✅ Позитивные эмоции обнаружены: {dominant}")
        
    finally:
        await actor.shutdown()


@pytest.mark.asyncio
async def test_analyze_negative_emotion():
    """Тест анализа негативной эмоции"""
    actor = PerceptionActor("perception_test")
    await actor.initialize()
    
    try:
        message = ActorMessage.create(
            sender_id="test_sender",
            message_type=MESSAGE_TYPES['ANALYZE_EMOTION'],
            payload={
                'text': 'Это просто отвратительно! Худший сервис!',
                'user_id': 'test_user_456'
            },
            reply_to="test_sender"
        )
        
        result = await actor.handle_message(message)
        
        assert result is not None
        dominant = result.payload['dominant_emotions']
        
        # Ожидаем негативные эмоции
        negative_emotions = {'disgust', 'anger', 'disapproval', 'annoyance'}
        assert any(emotion in negative_emotions for emotion in dominant), \
            f"Expected negative emotions, got: {dominant}"
        
        print(f"✅ Негативные эмоции обнаружены: {dominant}")
        
    finally:
        await actor.shutdown()


@pytest.mark.asyncio
async def test_empty_text_handling():
    """Тест обработки пустого текста"""
    actor = PerceptionActor("perception_test")
    await actor.initialize()
    
    try:
        message = ActorMessage.create(
            sender_id="test_sender",
            message_type=MESSAGE_TYPES['ANALYZE_EMOTION'],
            payload={
                'text': '',
                'user_id': 'test_user_789'
            },
            reply_to="test_sender"
        )
        
        result = await actor.handle_message(message)
        
        assert result is not None
        payload = result.payload
        
        # При пустом тексте должен вернуться нейтральный вектор
        assert payload['emotions'] == {'neutral': 1.0}
        assert payload['dominant_emotions'] == ['neutral']
        assert payload['error'] == 'Empty text'
        
        print("✅ Пустой текст корректно обработан (нейтральный ответ)")
        
    finally:
        await actor.shutdown()


@pytest.mark.asyncio
async def test_wrong_message_type():
    """Тест обработки неправильного типа сообщения"""
    actor = PerceptionActor("perception_test")
    await actor.initialize()
    
    try:
        # Отправляем сообщение другого типа
        message = ActorMessage.create(
            sender_id="test_sender",
            message_type=MESSAGE_TYPES['PING'],
            payload={'data': 'test'}
        )
        
        result = await actor.handle_message(message)
        
        # Актор должен вернуть None для неподдерживаемых типов
        assert result is None
        
        print("✅ Неподдерживаемый тип сообщения игнорируется")
        
    finally:
        await actor.shutdown()


@pytest.mark.asyncio
async def test_error_handling():
    """Тест обработки ошибок при анализе"""
    actor = PerceptionActor("perception_test")
    await actor.initialize()
    
    try:
        # Временно ломаем анализатор для теста
        original_analyzer = actor._emotion_analyzer
        actor._emotion_analyzer = None
        
        message = ActorMessage.create(
            sender_id="test_sender",
            message_type=MESSAGE_TYPES['ANALYZE_EMOTION'],
            payload={
                'text': 'Тестовый текст',
                'user_id': 'test_user_error'
            },
            reply_to="test_sender"
        )
        
        result = await actor.handle_message(message)
        
        assert result is not None
        payload = result.payload
        
        # При ошибке должен вернуться нейтральный вектор
        assert payload['emotions'] == {'neutral': 1.0}
        assert payload['dominant_emotions'] == ['neutral']
        assert 'error' in payload
        assert actor._error_count == 1
        
        print("✅ Ошибки корректно обрабатываются")
        
        # Восстанавливаем анализатор
        actor._emotion_analyzer = original_analyzer
        
    finally:
        await actor.shutdown()


@pytest.mark.asyncio
async def test_concurrent_analysis():
    """Тест параллельной обработки нескольких сообщений"""
    actor = PerceptionActor("perception_test")
    await actor.initialize()
    
    try:
        # Создаем несколько сообщений
        messages = [
            ActorMessage.create(
                sender_id="test_sender",
                message_type=MESSAGE_TYPES['ANALYZE_EMOTION'],
                payload={
                    'text': f'Тестовое сообщение номер {i}',
                    'user_id': f'user_{i}'
                },
                reply_to="test_sender"
            )
            for i in range(5)
        ]
        
        # Обрабатываем параллельно
        tasks = [actor.handle_message(msg) for msg in messages]
        results = await asyncio.gather(*tasks)
        
        # Проверяем, что все обработаны
        assert all(result is not None for result in results)
        assert all(result.message_type == MESSAGE_TYPES['EMOTION_RESULT'] for result in results)
        assert actor._analysis_count == 5
        
        print("✅ Параллельная обработка работает корректно")
        
    finally:
        await actor.shutdown()


@pytest.mark.asyncio
async def test_metrics_tracking():
    """Тест отслеживания метрик"""
    actor = PerceptionActor("perception_test")
    await actor.initialize()
    
    try:
        # Успешный анализ
        success_msg = ActorMessage.create(
            sender_id="test",
            message_type=MESSAGE_TYPES['ANALYZE_EMOTION'],
            payload={'text': 'Хороший текст', 'user_id': 'user1'}
        )
        await actor.handle_message(success_msg)
        
        # Пустой текст (ошибка)
        empty_msg = ActorMessage.create(
            sender_id="test", 
            message_type=MESSAGE_TYPES['ANALYZE_EMOTION'],
            payload={'text': '', 'user_id': 'user2'}
        )
        await actor.handle_message(empty_msg)
        
        # Проверяем метрики
        assert actor._analysis_count == 1  # Только успешные
        assert actor._error_count == 0  # Пустой текст не считается ошибкой
        
        print(f"✅ Метрики отслеживаются: analysis={actor._analysis_count}, errors={actor._error_count}")
        
    finally:
        await actor.shutdown()


if __name__ == "__main__":
    # Для запуска отдельно
    pytest.main([__file__, "-v", "-s"])