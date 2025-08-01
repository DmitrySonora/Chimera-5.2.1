"""
Демонстрация использования Pydantic для типизированных настроек.
ВНИМАНИЕ: Это демонстрационный файл на будущее, не интегрирован в основной код.

Для использования потребуется установить: pip install pydantic-settings
"""

from typing import Literal
from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class ActorSystemSettings(BaseSettings):
    """Настройки Actor System с валидацией"""
    model_config = SettingsConfigDict(
        env_prefix='CHIMERA_',
        env_file='.env',
        env_file_encoding='utf-8',
        case_sensitive=False
    )
    
    # Actor System
    actor_system_name: str = Field(
        default="chimera",
        description="Имя системы акторов"
    )
    actor_message_queue_size: int = Field(
        default=1000,
        ge=10,
        le=10000,
        description="Размер очереди сообщений"
    )
    actor_shutdown_timeout: float = Field(
        default=5.0,
        ge=0.1,
        le=60.0,
        description="Таймаут остановки в секундах"
    )
    
    # Retry механизм
    actor_message_retry_enabled: bool = True
    actor_message_max_retries: int = Field(default=3, ge=0, le=10)
    actor_message_retry_delay: float = Field(default=0.1, ge=0.01, le=5.0)
    
    @field_validator('actor_system_name')
    @classmethod
    def validate_name(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError('System name cannot be empty')
        return v.strip()


class LoggingSettings(BaseSettings):
    """Настройки логирования с валидацией"""
    
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"
    enable_json_logging: bool = True
    json_log_file: str = "logs/chimera.json"
    
    # Ротация
    log_rotation_enabled: bool = True
    log_max_bytes: int = Field(
        default=1_048_576,  # 1 MB
        ge=1024,  # Минимум 1 KB
        le=104_857_600  # Максимум 100 MB
    )
    log_backup_count: int = Field(default=5, ge=0, le=100)


class DeepSeekSettings(BaseSettings):
    """Настройки DeepSeek API"""
    model_config = SettingsConfigDict(env_prefix='DEEPSEEK_')
    
    api_key: str = Field(
        default="",
        description="API ключ DeepSeek"
    )
    base_url: str = "https://api.deepseek.com/v1"
    model: str = "deepseek-chat"
    timeout: int = Field(default=30, ge=5, le=300)
    max_retries: int = Field(default=3, ge=0, le=10)
    
    @field_validator('api_key')
    @classmethod
    def validate_api_key(cls, v: str) -> str:
        if not v:
            raise ValueError('DeepSeek API key is required')
        if len(v) < 10:
            raise ValueError('Invalid API key format')
        return v


class Settings(BaseSettings):
    """Главный класс настроек, объединяющий все секции"""
    
    # Композиция настроек
    actor_system: ActorSystemSettings = Field(default_factory=ActorSystemSettings)
    logging: LoggingSettings = Field(default_factory=LoggingSettings)
    deepseek: DeepSeekSettings = Field(default_factory=DeepSeekSettings)
    
    # Глобальные настройки
    daily_message_limit: int = Field(
        default=10,
        ge=1,
        le=1000,
        description="Дневной лимит сообщений"
    )
    
    # Режимы генерации
    generation_mode_default: Literal["base", "talk", "expert", "creative"] = "talk"
    mode_confidence_threshold: float = Field(default=0.3, ge=0.0, le=1.0)
    
    def validate_consistency(self) -> None:
        """Проверка консистентности настроек между собой"""
        # Пример: если включена ротация, должен быть указан файл
        if self.logging.log_rotation_enabled and not self.logging.json_log_file:
            raise ValueError("Log file must be specified when rotation is enabled")
        
        # Пример: retry delay не должен превышать shutdown timeout
        if self.actor_system.actor_message_retry_delay > self.actor_system.actor_shutdown_timeout:
            raise ValueError("Retry delay cannot exceed shutdown timeout")


# Пример использования:
if __name__ == "__main__":
    # Загрузка настроек с валидацией
    try:
        settings = Settings()
        settings.validate_consistency()
        
        print("✅ Настройки загружены успешно:")
        print(f"  • Actor System: {settings.actor_system.actor_system_name}")
        print(f"  • Log Level: {settings.logging.log_level}")
        print(f"  • DeepSeek Model: {settings.deepseek.model}")
        print(f"  • Daily Limit: {settings.daily_message_limit}")
        
    except Exception as e:
        print(f"❌ Ошибка валидации настроек: {e}")