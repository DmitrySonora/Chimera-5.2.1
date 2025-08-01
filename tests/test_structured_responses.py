import pytest
from models.structured_responses import (
    BaseResponse, TalkResponse, ExpertResponse, CreativeResponse,
    parse_response, get_response_model
)
from config.settings import PYDANTIC_STRING_LIST_COERCE


class TestStructuredResponses:
    """Тесты для Pydantic моделей структурированных ответов"""
    
    def test_base_response_valid(self):
        """Тест валидного базового ответа"""
        response = BaseResponse(response="Привет, я Химера!")
        assert response.response == "Привет, я Химера!"
    
    def test_base_response_empty(self):
        """Тест пустого ответа - должна быть ошибка"""
        with pytest.raises(ValueError):
            BaseResponse(response="")
        
        with pytest.raises(ValueError):
            BaseResponse(response="   ")  # Только пробелы
    
    def test_talk_response_full(self):
        """Тест полного talk ответа"""
        response = TalkResponse(
            response="Как интересно!",
            emotional_tone="восторженный",
            engagement_level=0.8
        )
        assert response.emotional_tone == "восторженный"
        assert response.engagement_level == 0.8
    
    def test_talk_response_partial(self):
        """Тест частичного talk ответа - опциональные поля"""
        response = TalkResponse(response="Ответ без эмоций")
        assert response.emotional_tone is None
        assert response.engagement_level is None
    
    def test_engagement_level_validation(self):
        """Тест валидации engagement_level"""
        # Валидные значения
        TalkResponse(response="Тест", engagement_level=0.0)
        TalkResponse(response="Тест", engagement_level=1.0)
        TalkResponse(response="Тест", engagement_level=0.5)
        
        # Невалидные значения
        with pytest.raises(ValueError):
            TalkResponse(response="Тест", engagement_level=1.5)
        
        with pytest.raises(ValueError):
            TalkResponse(response="Тест", engagement_level=-0.1)
    
    def test_expert_response(self):
        """Тест expert ответа"""
        response = ExpertResponse(
            response="Нейросети работают так...",
            confidence=0.9,
            sources=["Учебник ML", "Статья в Nature"],
            assumptions=["Пользователь знает Python"]
        )
        assert response.confidence == 0.9
        assert len(response.sources) == 2
        assert len(response.assumptions) == 1
    
    def test_creative_response(self):
        """Тест creative ответа"""
        response = CreativeResponse(
            response="Дракон спал на облаке из снов...",
            style_markers=["метафора", "персонификация"],
            metaphors=["облако из снов", "чешуя как звёзды"]
        )
        assert len(response.style_markers) == 2
        assert "облако из снов" in response.metaphors
    
    def test_parse_response_from_dict(self):
        """Тест парсинга из словаря"""
        data = {
            "response": "Тестовый ответ",
            "emotional_tone": "спокойный",
            "engagement_level": 0.6
        }
        response = parse_response(data, mode='talk')
        assert isinstance(response, TalkResponse)
        assert response.emotional_tone == "спокойный"
    
    def test_parse_response_from_json_string(self):
        """Тест парсинга из JSON строки"""
        json_str = '{"response": "Ответ эксперта", "confidence": 0.85}'
        response = parse_response(json_str, mode='expert')
        assert isinstance(response, ExpertResponse)
        assert response.confidence == 0.85
    
    def test_get_response_model(self):
        """Тест получения правильной модели по режиму"""
        assert get_response_model('base') == BaseResponse
        assert get_response_model('talk') == TalkResponse
        assert get_response_model('expert') == ExpertResponse
        assert get_response_model('creative') == CreativeResponse
        assert get_response_model('unknown') == BaseResponse  # Fallback
    
    def test_list_coercion(self):
        """Тест преобразования элементов списков в строки"""
        if PYDANTIC_STRING_LIST_COERCE:
            # Числа должны преобразоваться в строки
            response = ExpertResponse(
                response="Тест",
                sources=[1, 2, 3]  # Числа вместо строк
            )
            assert response.sources == ['1', '2', '3']
        else:
            # В строгом режиме должна быть ошибка
            with pytest.raises(ValueError):
                ExpertResponse(
                    response="Тест",
                    sources=[1, 2, 3]
                )
    
    def test_model_export(self):
        """Тест экспорта модели обратно в dict"""
        response = TalkResponse(
            response="Привет!",
            emotional_tone="дружелюбный",
            engagement_level=0.7
        )
        data = response.model_dump()
        assert data['response'] == "Привет!"
        assert data['emotional_tone'] == "дружелюбный"
        assert data['engagement_level'] == 0.7
    
    def test_model_export_exclude_none(self):
        """Тест экспорта без None значений"""
        response = TalkResponse(response="Минимальный ответ")
        data = response.model_dump(exclude_none=True)
        assert 'response' in data
        assert 'emotional_tone' not in data
        assert 'engagement_level' not in data
    
    def test_parse_response_error_handling(self):
        """Тест обработки ошибок при парсинге"""
        # Невалидный JSON
        with pytest.raises(ValueError) as exc_info:
            parse_response("{invalid json}", mode='base')
        assert "Invalid JSON" in str(exc_info.value)
        
        # Отсутствующее обязательное поле
        with pytest.raises(ValueError):
            parse_response({"no_response": "field"}, mode='base')


if __name__ == "__main__":
    pytest.main([__file__, "-v"])