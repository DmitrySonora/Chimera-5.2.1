"""
Интеграционные тесты для EmotionAnalyzer
"""
import pytest
import time
import torch
from models.emotion_analyzer import EmotionAnalyzer, EMOTION_LABELS


class TestEmotionAnalyzer:
    """Тесты для анализатора эмоций DeBERTa"""
    
    @pytest.fixture(scope="class")
    def analyzer(self):
        """Создаем анализатор один раз для всех тестов класса"""
        return EmotionAnalyzer()
    
    def test_model_initialization(self):
        """Тест успешной загрузки модели"""
        start_time = time.time()
        analyzer = EmotionAnalyzer()
        load_time = time.time() - start_time
        
        # Проверка наличия модели и токенизатора
        assert analyzer.model is not None, "Модель не загружена"
        assert analyzer.tokenizer is not None, "Токенизатор не загружен"
        
        # Проверка времени загрузки
        assert load_time < 30, f"Загрузка заняла {load_time:.2f}с, должно быть < 30с"
        
        print(f"✅ Модель загружена за {load_time:.2f} секунд")
    
    def test_cuda_fallback(self):
        """Тест fallback на CPU при недоступности CUDA"""
        # Пытаемся создать анализатор с CUDA
        analyzer = EmotionAnalyzer(device="cuda")
        
        # Если CUDA недоступна, должен быть fallback на CPU
        if not torch.cuda.is_available():
            assert analyzer.device == "cpu", "Не произошел fallback на CPU"
            print("✅ Fallback на CPU работает корректно")
        else:
            assert analyzer.device == "cuda", "CUDA доступна, но не используется"
            print("✅ CUDA используется корректно")
    
    def test_reference_phrases(self, analyzer):
        """Тест анализа эталонных фраз"""
        test_cases = [
            ("Обожаю вашу кофейню!", ['admiration', 'love']),
            ("Это просто отвратительно", ['disgust', 'disapproval']),
            ("Не понимаю, объясни еще раз", ['confusion']),
            ("Спасибо большое за помощь!", ['gratitude']),
            ("Боюсь, что не справлюсь", ['fear', 'nervousness']),
            ("Как интересно! Расскажи подробнее", ['curiosity', 'excitement']),
            ("Мне очень грустно сегодня", ['sadness']),
            ("Ты молодец! Горжусь тобой", ['admiration', 'pride', 'approval']),
            ("Это было так смешно!", ['amusement', 'joy']),
            ("Я в полном восторге!", ['excitement', 'joy']),
        ]
        
        success_count = 0
        for text, expected_emotions in test_cases:
            detected = analyzer.analyze_text(text)
            
            # Проверяем, что хотя бы одна ожидаемая эмоция обнаружена
            found = any(emotion in detected for emotion in expected_emotions)
            
            if found:
                success_count += 1
                print(f"✅ '{text}' → {detected}")
            else:
                print(f"❌ '{text}' → {detected}, ожидалось {expected_emotions}")
        
        # Требуем минимум 70% успешных определений
        success_rate = success_count / len(test_cases)
        assert success_rate >= 0.7, f"Успешно определено только {success_rate*100:.0f}% эмоций"
        
        print(f"\n📊 Успешность определения: {success_rate*100:.0f}%")
    
    def test_emotion_vector(self, analyzer):
        """Тест получения полного эмоционального вектора"""
        text = "Спасибо за помощь, очень приятно!"
        vector = analyzer.get_emotion_vector(text)
        
        # Проверка структуры
        assert isinstance(vector, dict), "Должен вернуться словарь"
        assert len(vector) == 28, f"Должно быть 28 эмоций, получено {len(vector)}"
        
        # Проверка наличия всех ключей
        for emotion in EMOTION_LABELS:
            assert emotion in vector, f"Отсутствует эмоция: {emotion}"
        
        # Проверка диапазона значений
        for emotion, value in vector.items():
            assert 0 <= value <= 1, f"Значение {emotion}={value} вне диапазона [0,1]"
            assert isinstance(value, float), f"Значение {emotion} не float"
        
        # Проверка округления
        assert all(len(str(v).split('.')[-1]) <= 3 for v in vector.values()), \
            "Значения должны быть округлены до 3 знаков"
        
        print(f"✅ Вектор эмоций корректен, gratitude={vector['gratitude']}")
    
    def test_long_text_handling(self, analyzer):
        """Тест обработки длинных текстов"""
        # Создаем текст длиннее 128 токенов
        long_text = "Это очень длинный текст. " * 50
        
        # Не должно быть исключений
        emotions = analyzer.analyze_text(long_text)
        assert isinstance(emotions, list), "Должен вернуться список"
        
        # Проверяем также вектор
        vector = analyzer.get_emotion_vector(long_text)
        assert len(vector) == 28, "Вектор должен содержать все эмоции"
        
        print("✅ Длинные тексты обрабатываются корректно")
    
    def test_performance_single_text(self, analyzer):
        """Тест производительности для одного текста"""
        text = "Я очень рад встрече с вами!"
        
        # Прогрев
        _ = analyzer.analyze_text(text)
        
        # Измерение
        start_time = time.time()
        _ = analyzer.analyze_text(text)
        elapsed = (time.time() - start_time) * 1000
        
        assert elapsed < 200, f"Анализ занял {elapsed:.0f}мс, должно быть < 200мс"
        print(f"✅ Анализ одного текста: {elapsed:.0f}мс")
    
    def test_performance_batch(self, analyzer):
        """Тест производительности для батча текстов"""
        texts = [
            "Отличная работа!",
            "Мне грустно",
            "Это удивительно!",
            "Я в ярости!",
            "Спасибо за помощь",
            "Не понимаю",
            "Как интересно!",
            "Боюсь опоздать",
            "Обожаю это место",
            "Какая гадость!",
        ]
        
        start_time = time.time()
        for text in texts:
            _ = analyzer.analyze_text(text)
        elapsed = (time.time() - start_time) * 1000
        
        assert elapsed < 1000, f"Батч занял {elapsed:.0f}мс, должно быть < 1000мс"
        print(f"✅ Анализ батча из {len(texts)} текстов: {elapsed:.0f}мс")
    
    def test_threshold_application(self, analyzer):
        """Тест применения индивидуальных порогов"""
        # Тестируем на нейтральном тексте
        neutral_text = "Сегодня обычный день"
        emotions = analyzer.analyze_text(neutral_text)
        
        # grief имеет очень низкий порог (0.02), но не должен определяться на нейтральном тексте
        assert 'grief' not in emotions, "grief не должен определяться на нейтральном тексте"
        
        # Тестируем высокий порог
        mild_admiration = "Неплохо сделано"
        emotions = analyzer.analyze_text(mild_admiration)
        
        # admiration имеет высокий порог (0.551), может не определиться на слабой похвале
        print(f"Эмоции для '{mild_admiration}': {emotions}")
        
        # Проверяем полный вектор для понимания вероятностей
        vector = analyzer.get_emotion_vector(mild_admiration)
        print(f"admiration вероятность: {vector['admiration']}")
        print(f"approval вероятность: {vector['approval']}")
        
        print("✅ Индивидуальные пороги применяются корректно")
    
    def test_russian_emotion_names(self, analyzer):
        """Тест получения русских названий эмоций"""
        text = "Спасибо вам огромное!"
        russian_emotions = analyzer.get_russian_emotions(text)
        
        assert isinstance(russian_emotions, list), "Должен вернуться список"
        assert all(isinstance(e, str) for e in russian_emotions), "Все элементы должны быть строками"
        
        # Проверяем, что возвращаются русские названия
        if 'gratitude' in analyzer.analyze_text(text):
            assert 'благодарность' in russian_emotions, "Должна быть русская версия gratitude"
        
        print(f"✅ Русские эмоции: {russian_emotions}")
    
    def test_error_handling(self, analyzer):
        """Тест обработки ошибок"""
        # Пустой текст - модель может определить как neutral
        empty_result = analyzer.analyze_text("")
        assert isinstance(empty_result, list), "Должен вернуться список"
        # Пустой текст часто определяется как neutral, что логично
        if empty_result:
            assert 'neutral' in empty_result, f"Ожидался 'neutral' для пустого текста, получено: {empty_result}"
        
        # None вместо текста
        try:
            _ = analyzer.analyze_text(None)
        except Exception:
            # Ожидаемое поведение - исключение от токенизатора
            pass
        
        # Проверка на очень короткий текст
        short_result = analyzer.analyze_text("а")
        assert isinstance(short_result, list), "Должен вернуться список для короткого текста"
        
        print("✅ Обработка ошибок работает корректно")


if __name__ == "__main__":
    # Запуск тестов
    pytest.main([__file__, "-v", "-s"])