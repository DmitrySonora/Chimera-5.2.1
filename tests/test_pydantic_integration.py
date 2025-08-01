import pytest

from actors.generation_actor import GenerationActor
from config.prompts import MODE_GENERATION_PARAMS


class TestPydanticIntegration:
    """Интеграционные тесты для проверки Pydantic и режимных параметров"""
    
    @pytest.mark.asyncio
    async def test_pydantic_validation_in_generation(self):
        """Тест Pydantic валидации в GenerationActor"""
        actor = GenerationActor()
        
        # Инициализируем минимальные зависимости
        from config.logging import get_logger
        actor.logger = get_logger("test")
        from utils.event_utils import EventVersionManager
        actor._event_version_manager = EventVersionManager()
        
        # Тест успешной валидации
        valid_data = {
            "response": "Тестовый ответ",
            "emotional_tone": "дружелюбный",
            "engagement_level": 0.8
        }
        is_valid, errors = await actor._validate_structured_response(valid_data, mode="talk")
        assert is_valid is True
        assert len(errors) == 0
        print("✅ Валидация корректных данных успешна")
        
        # Тест обнаружения ошибок
        invalid_data = {
            "response": "",  # Пустой ответ
            "confidence": "высокая"  # Должно быть число
        }
        is_valid, errors = await actor._validate_structured_response(invalid_data, mode="expert")
        assert is_valid is False
        assert len(errors) > 0
        assert any("response" in error for error in errors)
        print(f"✅ Обнаружены ошибки валидации: {errors[:2]}")
        
        # Тест валидации creative режима
        creative_data = {
            "response": "Дракон спал на облаке",
            "style_markers": ["метафора", "персонификация"],
            "metaphors": ["облако из снов"]
        }
        is_valid, errors = await actor._validate_structured_response(creative_data, mode="creative")
        assert is_valid is True
        print("✅ Валидация creative режима успешна")
    
    @pytest.mark.asyncio
    async def test_mode_parameters_application(self):
        """Тест применения режимных параметров"""
        print("\n📊 Параметры генерации для разных режимов:\n")
        
        for mode, params in MODE_GENERATION_PARAMS.items():
            print(f"Режим '{mode}':")
            print(f"  • temperature: {params.get('temperature', 'default')}")
            print(f"  • top_p: {params.get('top_p', 'default')}")
            print(f"  • max_tokens: {params.get('max_tokens', 'default')}")
            print(f"  • frequency_penalty: {params.get('frequency_penalty', 'default')}")
            print(f"  • presence_penalty: {params.get('presence_penalty', 'default')}")
            print()
        
        # Проверяем различия
        talk_temp = MODE_GENERATION_PARAMS["talk"]["temperature"]
        expert_temp = MODE_GENERATION_PARAMS["expert"]["temperature"]
        creative_temp = MODE_GENERATION_PARAMS["creative"]["temperature"]
        
        assert talk_temp != expert_temp, "Параметры talk и expert должны различаться"
        assert expert_temp != creative_temp, "Параметры expert и creative должны различаться"
        assert expert_temp < talk_temp, "Expert должен быть менее креативным чем talk"
        
        print("✅ Параметры для режимов корректно различаются")


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])