import pytest
import time
from actors.user_session_actor import UserSessionActor, UserSession
from config.logging import setup_logging

# Настраиваем логирование для тестов
setup_logging()


class TestContextualPatterns:
    """Тесты для контекстного определения режимов"""
    
    @pytest.mark.asyncio
    async def test_word_ambiguity_explain(self):
        """Тест многозначности слова 'объясни'"""
        actor = UserSessionActor()
        session = UserSession(user_id="test_user")
        
        # Expert контекст
        test_cases_expert = [
            ("Объясни устройство нейрона", "expert"),
            ("Объясни как работает двигатель", "expert"),
            ("Объясни принцип работы транзистора", "expert"),
            ("Объясни механизм фотосинтеза", "expert")
        ]
        
        # Talk контекст
        test_cases_talk = [
            ("Объясни, почему мне плохо", "talk"),
            ("Объясни, почему я грущу", "talk"),
            ("Объясни, что со мной происходит", "talk"),
            ("Объясни, зачем мне это нужно", "talk")
        ]
        
        for text, expected_mode in test_cases_expert + test_cases_talk:
            mode, confidence = actor._determine_generation_mode(text, session)
            assert mode == expected_mode, f"Text '{text}' should be {expected_mode} mode, got {mode}"
            assert confidence > 0.5, f"Confidence should be > 0.5 for clear context, got {confidence}"
    
    @pytest.mark.asyncio
    async def test_word_ambiguity_write(self):
        """Тест многозначности слова 'напиши'"""
        actor = UserSessionActor()
        session = UserSession(user_id="test_user")
        
        # Creative контекст
        test_cases_creative = [
            ("Напиши рассказ о драконе", "creative"),
            ("Напиши стихи про осень", "creative"),
            ("Напиши сказку для детей", "creative"),
            ("Напиши сценарий короткометражки", "creative")
        ]
        
        # Talk контекст
        test_cases_talk = [
            ("Напиши мне, когда придешь", "talk"),
            ("Напиши, если будет время", "talk"),
            ("Напиши мне завтра", "talk"),
            ("Напиши, как освободишься", "talk")
        ]
        
        for text, expected_mode in test_cases_creative + test_cases_talk:
            mode, confidence = actor._determine_generation_mode(text, session)
            assert mode == expected_mode, f"Text '{text}' should be {expected_mode} mode, got {mode}"
    
    @pytest.mark.asyncio
    async def test_word_ambiguity_mood(self):
        """Тест многозначности слова 'настроение'"""
        actor = UserSessionActor()
        session = UserSession(user_id="test_user")
        
        # Talk контекст
        mode, confidence = actor._determine_generation_mode("Как твое настроение?", session)
        assert mode == "talk", "Personal mood should be talk mode"
        
        # Expert контекст
        mode, confidence = actor._determine_generation_mode("Настроение рынка акций сегодня", session)
        assert mode == "expert", "Market mood should be expert mode"
        
        mode, confidence = actor._determine_generation_mode("Анализ настроения биржи", session)
        assert mode == "expert", "Stock market sentiment should be expert mode"
    
    @pytest.mark.asyncio
    async def test_priority_levels(self):
        """Тест приоритетов: точные фразы > контекстные > доменные"""
        actor = UserSessionActor()
        session = UserSession(user_id="test_user")
        
        # Точная фраза должна перевесить все
        text = "Объясни как работает квантовый компьютер"  # exact phrase + domain markers
        mode, confidence = actor._determine_generation_mode(text, session)
        assert mode == "expert"
        assert confidence > 0.8, "Exact phrase should give high confidence"
        
        # Контекстное слово с усилителем
        text = "Объясни устройство атома"  # contextual word + enhancer
        mode, confidence = actor._determine_generation_mode(text, session)
        assert mode == "expert"
        assert confidence > 0.6
        
        # Только доменные маркеры
        text = "Квантовый электрон в молекуле"  # only domain markers
        mode, confidence = actor._determine_generation_mode(text, session)
        assert mode == "expert"
        assert confidence < 0.6, "Domain markers alone should give lower confidence"
    
    @pytest.mark.asyncio 
    async def test_suppressor_effect(self):
        """Тест работы подавителей"""
        actor = UserSessionActor()
        session = UserSession(user_id="test_user")
        
        # Без подавителя - expert
        mode1, conf1 = actor._determine_generation_mode("Расскажи про теорию относительности", session)
        assert mode1 == "expert"
        
        # С подавителем - creative или talk
        mode2, conf2 = actor._determine_generation_mode("Расскажи историю про космос", session)
        assert mode2 in ["creative", "talk"], f"Suppressor should change mode, got {mode2}"
        
        # Уверенность должна снизиться
        assert conf2 <= conf1, "Suppressor should reduce confidence"
    
    @pytest.mark.asyncio
    async def test_fallback_to_simple_patterns(self):
        """Тест fallback на старые паттерны"""
        actor = UserSessionActor()
        session = UserSession(user_id="test_user")
        
        # Текст без контекстных паттернов, но со старыми
        mode, confidence = actor._determine_generation_mode("Привет!", session)
        assert mode == "talk", "Should fallback to simple patterns"
        
        # Проверяем через _last_detection_details
        if hasattr(actor, '_last_detection_details'):
            details = actor._last_detection_details
            assert any('simple:' in str(p) for patterns in details.values() for p in patterns.get('patterns', []))
    
    @pytest.mark.asyncio
    async def test_edge_cases(self):
        """Тест граничных случаев"""
        actor = UserSessionActor()
        session = UserSession(user_id="test_user")
        
        # Пустой текст
        mode, conf = actor._determine_generation_mode("", session)
        assert mode == "talk"  # default
        assert conf == 0.5
        
        # Очень короткий текст
        mode, conf = actor._determine_generation_mode("Да", session)
        assert mode == "talk"
        assert conf == 0.5
        
        # Очень длинный текст (> 1000 символов)
        long_text = "Объясни " + "очень " * 200 + "подробно"
        start_time = time.time()
        mode, conf = actor._determine_generation_mode(long_text, session)
        elapsed = (time.time() - start_time) * 1000  # в миллисекундах
        
        assert elapsed < 10, f"Detection took {elapsed}ms, should be < 10ms"
        assert mode == "expert"  # Should still detect the pattern
    
    @pytest.mark.asyncio
    async def test_performance(self):
        """Тест производительности определения режима"""
        actor = UserSessionActor()
        session = UserSession(user_id="test_user")
        
        test_texts = [
            "Объясни как работает нейронная сеть и почему она эффективна",
            "Придумай историю про дракона, который изучал квантовую физику",
            "Как твое настроение сегодня? Хочется просто поговорить",
            "Проанализируй причины экономического кризиса 2008 года",
            "Напиши стихотворение о любви в стиле Пушкина"
        ]
        
        times = []
        for text in test_texts * 10:  # 50 проверок
            start = time.time()
            mode, conf = actor._determine_generation_mode(text, session)
            elapsed = (time.time() - start) * 1000
            times.append(elapsed)
        
        avg_time = sum(times) / len(times)
        max_time = max(times)
        
        assert avg_time < 5, f"Average detection time {avg_time}ms should be < 5ms"
        assert max_time < 10, f"Max detection time {max_time}ms should be < 10ms"
        
        # 95 перцентиль
        times.sort()
        percentile_95 = times[int(len(times) * 0.95)]
        assert percentile_95 < 5, f"95th percentile {percentile_95}ms should be < 5ms"
    
    @pytest.mark.asyncio
    async def test_detection_details_logging(self):
        """Тест логирования деталей определения"""
        actor = UserSessionActor()
        session = UserSession(user_id="test_user")
        
        # Инициализируем _last_detection_details
        actor._last_detection_details = {}
        
        # Сложный текст с разными паттернами
        text = "Объясни устройство квантового компьютера"
        mode, conf = actor._determine_generation_mode(text, session)
        
        # Проверяем сохранение деталей
        assert hasattr(actor, '_last_detection_details')
        details = actor._last_detection_details
        
        # Должны быть детали для expert режима
        assert 'expert' in details
        assert 'patterns' in details['expert']
        assert 'score' in details['expert']
        
        # Должна быть контекстная фраза или точная фраза
        expert_patterns = details['expert']['patterns']
        assert len(expert_patterns) > 0, "Should have some patterns detected"
        
        # Проверяем, что есть хотя бы один из ожидаемых паттернов
        has_expected_pattern = any(
            'exact_phrase:' in p or 'enhanced:' in p or 'domains:' in p 
            for p in expert_patterns
        )
        assert has_expected_pattern, f"Should have contextual patterns, got: {expert_patterns}"
    
    @pytest.mark.asyncio
    async def test_mixed_signals(self):
        """Тест текстов со смешанными сигналами"""
        actor = UserSessionActor()
        session = UserSession(user_id="test_user")
        
        # Expert + Creative
        text = "Придумай научное объяснение почему драконы дышат огнем"
        mode, conf = actor._determine_generation_mode(text, session)
        # Оба режима валидны, проверяем что выбран один из них
        assert mode in ['creative', 'expert']
        assert conf > 0.5
        
        # Talk + Expert  
        text = "Мне грустно, объясни почему люди грустят"
        mode, conf = actor._determine_generation_mode(text, session)
        # Talk должен победить из-за личного контекста
        assert mode == 'talk'


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])