from pydantic import BaseModel, Field, ConfigDict, field_validator
from typing import Dict, Any, Optional
from datetime import datetime
import uuid


class BaseEvent(BaseModel):
    """
    Базовый класс для всех событий в системе.
    Иммутабельный для предотвращения изменений после создания.
    """
    model_config = ConfigDict(
        # Эквивалент frozen=True
        frozen=True,
        # Разрешаем произвольные типы
        arbitrary_types_allowed=True,
        # Для обратной совместимости
        populate_by_name=True
    )
    
    event_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    stream_id: str = ""
    event_type: str = ""
    timestamp: datetime = Field(default_factory=datetime.now)
    data: Dict[str, Any] = Field(default_factory=dict)
    version: int = 0
    correlation_id: Optional[str] = None
    
    @field_validator('version')
    @classmethod
    def version_non_negative(cls, v: int) -> int:
        if v < 0:
            raise ValueError('Version must be non-negative')
        return v
    
    @classmethod
    def create(cls,
               stream_id: str,
               event_type: str,
               data: Optional[Dict[str, Any]] = None,
               version: int = 0,
               correlation_id: Optional[str] = None) -> 'BaseEvent':
        """Фабричный метод для удобного создания событий"""
        return cls(
            stream_id=stream_id,
            event_type=event_type,
            data=data or {},
            version=version,
            correlation_id=correlation_id
        )
    
    def to_dict(self) -> Dict[str, Any]:
        """Сериализация события в словарь для JSON"""
        from config.settings import EVENT_TIMESTAMP_FORMAT
        
        # Используем Pydantic model_dump вместо ручной сериализации
        result = self.model_dump()
        # Форматируем timestamp
        result['timestamp'] = self.timestamp.strftime(EVENT_TIMESTAMP_FORMAT)
        return result
    
    @staticmethod
    def from_dict(data: Dict[str, Any]) -> 'BaseEvent':
        """Десериализация события из словаря"""
        from config.settings import EVENT_TIMESTAMP_FORMAT
        
        # Преобразуем timestamp обратно в datetime
        data_copy = data.copy()
        data_copy['timestamp'] = datetime.strptime(
            data_copy['timestamp'], 
            EVENT_TIMESTAMP_FORMAT
        )
        
        # Используем Pydantic для создания объекта
        return BaseEvent(**data_copy)