import pytest
from actors.generation_actor import GenerationActor
from actors.messages import ActorMessage, MESSAGE_TYPES
from config.prompts import PROMPTS, JSON_SCHEMA_INSTRUCTIONS
from config.logging import setup_logging

setup_logging()


@pytest.mark.asyncio
async def test_build_mode_prompt_real_prompts():
    """Тест реальной логики построения промптов с режимами"""
    actor = GenerationActor()
    
    # Тест 1: Базовый режим возвращает только базовый промпт
    base_prompt = PROMPTS["base"]["normal"]
    result = actor._build_mode_prompt(base_prompt, "base", False)
    assert result == base_prompt
    print("\n✅ Base mode: промпт не изменился")
    
    # Тест 2: Режим talk добавляет модификатор
    result_talk = actor._build_mode_prompt(base_prompt, "talk", False)
    talk_modifier = PROMPTS["talk"]["normal"]
    expected_talk = f"{base_prompt}\n\n{talk_modifier}"
    assert result_talk == expected_talk
    assert len(result_talk) > len(base_prompt)
    print(f"✅ Talk mode: добавлен модификатор, длина {len(base_prompt)} -> {len(result_talk)}")
    
    # Тест 3: Режим expert добавляет свой модификатор
    result_expert = actor._build_mode_prompt(base_prompt, "expert", False)
    expert_modifier = PROMPTS["expert"]["normal"]
    expected_expert = f"{base_prompt}\n\n{expert_modifier}"
    assert result_expert == expected_expert
    assert result_expert != result_talk  # Разные режимы дают разные результаты
    print("✅ Expert mode: добавлен другой модификатор")
    
    # Тест 4: JSON режим с инструкциями
    base_json = PROMPTS["base"]["json"]
    result_talk_json = actor._build_mode_prompt(base_json, "talk", True)
    talk_json_modifier = PROMPTS["talk"]["json"]
    expected_with_instructions = f"{base_json}\n\n{talk_json_modifier}\n\n{JSON_SCHEMA_INSTRUCTIONS['talk']}"
    assert result_talk_json == expected_with_instructions
    print("✅ Talk JSON mode: добавлены модификатор + инструкции схемы")
    
    # Тест 5: Неизвестный режим
    result_unknown = actor._build_mode_prompt(base_prompt, "unknown_mode", False)
    assert result_unknown == base_prompt
    print("✅ Unknown mode: fallback на базовый промпт")


@pytest.mark.asyncio
async def test_format_context_with_modes():
    """Тест правильной передачи режима в _format_context"""
    actor = GenerationActor()
    
    # Проверяем talk режим
    messages = actor._format_context("Привет!", include_prompt=True, mode="talk")
    assert len(messages) == 2
    assert messages[0]["role"] == "system"
    
    # Проверяем, что промпт содержит и базу, и модификатор talk
    system_content = messages[0]["content"]
    assert "Ты — Химера" in system_content  # Базовая часть
    assert "собеседница" in system_content  # Модификатор talk
    print("\n✅ Format context: режим talk правильно применен")
    
    # Проверяем expert режим
    messages_expert = actor._format_context("Объясни квантовую физику", include_prompt=True, mode="expert")
    expert_content = messages_expert[0]["content"]
    assert "эксперт и аналитик" in expert_content  # Модификатор expert
    assert "академическую строгость" in expert_content  # Характеристика expert режима
    assert expert_content != system_content  # Разные режимы
    print("✅ Format context: режим expert дает другой промпт")


@pytest.mark.asyncio
async def test_mode_metrics_update():
    """Тест обновления метрик при валидации"""
    actor = GenerationActor()
    
    # Проверяем начальное состояние
    assert all(count == 0 for count in actor._mode_success_counts.values())
    assert all(count == 0 for count in actor._mode_failure_counts.values())
    
    # Симулируем успешную валидацию для talk
    valid_response = {"response": "Привет!", "emotional_tone": "дружелюбный", "engagement_level": 0.8}
    is_valid, errors = await actor._validate_structured_response(valid_response, mode="talk")
    
    # Вручную обновляем метрики (как в реальном коде)
    if is_valid:
        actor._mode_success_counts["talk"] += 1
    else:
        actor._mode_failure_counts["talk"] += 1
    
    assert actor._mode_success_counts["talk"] == 1
    assert actor._mode_failure_counts["talk"] == 0
    print("\n✅ Metrics: успешная валидация talk увеличила счетчик")
    
    # Симулируем неудачную валидацию для expert
    invalid_response = {"response": "Ответ", "confidence": "высокая"}  # confidence должна быть числом
    is_valid, errors = await actor._validate_structured_response(invalid_response, mode="expert")
    
    if is_valid:
        actor._mode_success_counts["expert"] += 1
    else:
        actor._mode_failure_counts["expert"] += 1
    
    assert actor._mode_failure_counts["expert"] == 1
    assert len(errors) > 0
    print("✅ Metrics: неудачная валидация expert увеличила счетчик ошибок")
    
    # Проверяем вывод при shutdown
    await actor.shutdown()
    # В логах должно быть: "Mode validation success: ..." и "Mode validation failures: ..."


@pytest.mark.asyncio 
async def test_mode_propagation_through_methods():
    """Тест передачи режима через всю цепочку методов"""
    actor = GenerationActor()
    
    # Создаем тестовое сообщение с режимом
    test_message = ActorMessage.create(
        sender_id="test",
        message_type=MESSAGE_TYPES['GENERATE_RESPONSE'],
        payload={
            'user_id': 'test_user',
            'chat_id': 123,
            'text': 'Тестовое сообщение',
            'include_prompt': True,
            'mode': 'creative',  # Задаем режим
            'mode_confidence': 0.9
        }
    )
    
    # Проверяем, что handle_message извлекает режим из payload
    # Для этого временно переопределим _generate_response
    captured_mode = None
    original_generate = actor._generate_response
    
    async def capture_mode(text, user_id, include_prompt=True, mode="base"):
        nonlocal captured_mode
        captured_mode = mode
        return "Тестовый ответ"
    
    actor._generate_response = capture_mode
    
    # Обрабатываем сообщение
    await actor.handle_message(test_message)
    
    # Проверяем, что режим был правильно передан
    assert captured_mode == "creative"
    print("\n✅ Mode propagation: режим 'creative' успешно передан через handle_message")
    
    # Восстанавливаем оригинальный метод
    actor._generate_response = original_generate
    
    
    
    @pytest.mark.asyncio
    async def test_mode_parameters_usage():
        """Тест использования режимных параметров генерации"""
        from config.prompts import MODE_GENERATION_PARAMS, GENERATION_PARAMS_LOG_CONFIG
        
        # Проверяем, что параметры определены для всех режимов
        assert "base" in MODE_GENERATION_PARAMS
        assert "talk" in MODE_GENERATION_PARAMS
        assert "expert" in MODE_GENERATION_PARAMS
        assert "creative" in MODE_GENERATION_PARAMS
        
        # Проверяем различие параметров
        talk_temp = MODE_GENERATION_PARAMS["talk"]["temperature"]
        expert_temp = MODE_GENERATION_PARAMS["expert"]["temperature"]
        creative_temp = MODE_GENERATION_PARAMS["creative"]["temperature"]
        
        assert talk_temp > expert_temp  # talk должен быть более креативным
        assert expert_temp < creative_temp  # expert самый точный
        
        # Проверяем, что max_tokens различаются
        assert MODE_GENERATION_PARAMS["creative"]["max_tokens"] > MODE_GENERATION_PARAMS["talk"]["max_tokens"]
        assert MODE_GENERATION_PARAMS["expert"]["max_tokens"] > MODE_GENERATION_PARAMS["talk"]["max_tokens"]
        
        # Проверяем настройки логирования
        assert isinstance(GENERATION_PARAMS_LOG_CONFIG.get("log_parameters_usage"), bool)
        
        print("\n✅ Mode parameters defined correctly")
        print(f"Talk temperature: {talk_temp} (эмоциональность)")
        print(f"Expert temperature: {expert_temp} (точность)")
        print(f"Creative temperature: {creative_temp} (богатство)")


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])