"""
Схемы валидации для структурированных JSON-ответов Химеры.
Каждая схема определяет обязательные и опциональные поля,
а также функции валидации для проверки значений.
"""
from typing import Dict, Callable, Any, Optional


# Режимы генерации
GENERATION_MODES = {
    'BASE': 'base',
    'TALK': 'talk',
    'EXPERT': 'expert',
    'CREATIVE': 'creative'
}

# Схемы валидации для каждого режима
RESPONSE_SCHEMAS = {
    'base': {
        'required': ['response'],
        'optional': [],
        'validators': {
            'response': lambda x: isinstance(x, str) and len(x) > 0
        }
    },
    
    'talk': {
        'required': ['response'],
        'optional': ['emotional_tone', 'engagement_level'],
        'validators': {
            'response': lambda x: isinstance(x, str) and len(x) > 0,
            'emotional_tone': lambda x: isinstance(x, str),
            'engagement_level': lambda x: isinstance(x, (int, float)) and 0 <= x <= 1
        }
    },
    
    'expert': {
        'required': ['response'],
        'optional': ['confidence', 'sources', 'assumptions'],
        'validators': {
            'response': lambda x: isinstance(x, str) and len(x) > 0,
            'confidence': lambda x: isinstance(x, (int, float)) and 0 <= x <= 1,
            'sources': lambda x: isinstance(x, list) and all(isinstance(s, str) for s in x),
            'assumptions': lambda x: isinstance(x, list) and all(isinstance(a, str) for a in x)
        }
    },
    
    'creative': {
        'required': ['response'],
        'optional': ['style_markers', 'metaphors'],
        'validators': {
            'response': lambda x: isinstance(x, str) and len(x) > 0,
            'style_markers': lambda x: isinstance(x, list) and all(isinstance(m, str) for m in x),
            'metaphors': lambda x: isinstance(x, list) and all(isinstance(m, str) for m in x)
        }
    }
}


def get_schema(mode: str) -> Optional[Dict[str, Any]]:
    """
    Получить схему валидации для указанного режима.
    
    Args:
        mode: Название режима генерации
        
    Returns:
        Схема валидации или None если режим не найден
    """
    return RESPONSE_SCHEMAS.get(mode)


def validate_field(field_name: str, value: Any, validator: Callable) -> bool:
    """
    Валидировать отдельное поле.
    
    Args:
        field_name: Имя поля
        value: Значение поля
        validator: Функция валидации
        
    Returns:
        True если поле валидно, False иначе
    """
    try:
        return validator(value)
    except Exception:
        return False