"""
Pydantic модели для структурированных JSON-ответов Химеры.
Заменяют словарные схемы из response_schemas.py.
"""
from pydantic import BaseModel, Field, field_validator, ConfigDict
from typing import List, Optional, Dict, Any, Union
from config.settings import (
    PYDANTIC_RESPONSE_MIN_LENGTH,
    PYDANTIC_CONFIDENCE_MIN,
    PYDANTIC_CONFIDENCE_MAX,
    PYDANTIC_STRING_LIST_COERCE,
    PYDANTIC_VALIDATION_STRICT
)


class BaseResponse(BaseModel):
    """Базовая модель для всех ответов - поле response обязательно"""
    model_config = ConfigDict(
        # Для будущей интеграции с ORM
        from_attributes=True,
        # Более понятные сообщения об ошибках
        validate_assignment=True,
        # Строгий режим если включен в конфиге
        strict=PYDANTIC_VALIDATION_STRICT
    )
    
    response: str = Field(
        ..., 
        min_length=PYDANTIC_RESPONSE_MIN_LENGTH,
        description="Текст ответа Химеры"
    )
    
    @field_validator('response')
    @classmethod
    def response_not_empty(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError('Response cannot be empty')
        return v


class TalkResponse(BaseResponse):
    """Модель ответа для режима беседы (talk)"""
    emotional_tone: Optional[str] = Field(
        None, 
        description="Эмоциональный тон ответа"
    )
    engagement_level: Optional[float] = Field(
        None,
        ge=PYDANTIC_CONFIDENCE_MIN,
        le=PYDANTIC_CONFIDENCE_MAX,
        description="Уровень вовлеченности (0-1)"
    )


class ExpertResponse(BaseResponse):
    """Модель ответа для экспертного режима"""
    confidence: Optional[float] = Field(
        None,
        ge=PYDANTIC_CONFIDENCE_MIN,
        le=PYDANTIC_CONFIDENCE_MAX,
        description="Уверенность в ответе (0-1)"
    )
    sources: Optional[List[Union[str, Any]]] = Field(
        default_factory=list,
        description="Источники или основания для ответа"
    )
    assumptions: Optional[List[Union[str, Any]]] = Field(
        default_factory=list,
        description="Ключевые допущения в ответе"
    )
    
    @field_validator('sources', 'assumptions', mode='before')
    @classmethod
    def validate_string_lists(cls, v: Any) -> List[str]:
        """Проверка и преобразование элементов списка в строки"""
        if v is None:
            return []
        if not isinstance(v, list):
            return [str(v)]
        
        if PYDANTIC_STRING_LIST_COERCE:
            return [str(item) for item in v]
        else:
            # Строгий режим - все должны быть строками
            if not all(isinstance(item, str) for item in v):
                raise ValueError("All list items must be strings")
            return v


class CreativeResponse(BaseResponse):
    """Модель ответа для творческого режима"""
    style_markers: Optional[List[Union[str, Any]]] = Field(
        default_factory=list,
        description="Стилистические маркеры текста"
    )
    metaphors: Optional[List[Union[str, Any]]] = Field(
        default_factory=list,
        description="Использованные метафоры и образы"
    )
    
    @field_validator('style_markers', 'metaphors', mode='before')
    @classmethod
    def validate_string_lists(cls, v: Any) -> List[str]:
        """Проверка и преобразование элементов списка в строки"""
        if v is None:
            return []
        if not isinstance(v, list):
            return [str(v)]
        
        if PYDANTIC_STRING_LIST_COERCE:
            return [str(item) for item in v]
        else:
            # Строгий режим - все должны быть строками
            if not all(isinstance(item, str) for item in v):
                raise ValueError("All list items must be strings")
            return v


# Маппинг режимов на модели
RESPONSE_MODELS = {
    'base': BaseResponse,
    'talk': TalkResponse,
    'expert': ExpertResponse,
    'creative': CreativeResponse
}


def get_response_model(mode: str) -> type[BaseResponse]:
    """Получить модель для указанного режима"""
    return RESPONSE_MODELS.get(mode, BaseResponse)


def parse_response(json_data: Union[str, Dict[str, Any]], mode: str = 'base') -> BaseResponse:
    """
    Распарсить JSON в соответствующую модель.
    
    Args:
        json_data: JSON строка или словарь
        mode: Режим генерации
        
    Returns:
        Экземпляр соответствующей модели
        
    Raises:
        ValueError: При ошибке валидации
    """
    import json
    
    # Если передана строка - парсим JSON
    if isinstance(json_data, str):
        try:
            data = json.loads(json_data)
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON: {str(e)}")
    else:
        data = json_data
    
    # Получаем модель и парсим
    model_class = get_response_model(mode)
    try:
        return model_class(**data)
    except Exception as e:
        # Оборачиваем в ValueError для единообразия
        raise ValueError(str(e)) from e


def get_json_schema(mode: str = 'base') -> Dict[str, Any]:
    """Получить JSON Schema для режима (для промптов)"""
    model_class = get_response_model(mode)
    return model_class.model_json_schema()