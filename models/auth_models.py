"""
Pydantic модели для системы авторизации через временные пароли
"""
from pydantic import BaseModel, Field, field_validator, ConfigDict
from typing import Optional, Literal
from datetime import datetime


class Password(BaseModel):
    """Модель пароля, созданного администратором"""
    model_config = ConfigDict(
        arbitrary_types_allowed=True,
        validate_assignment=True
    )
    
    password: str
    password_hash: str
    duration_days: int
    description: str
    is_active: bool = True
    used_by: Optional[str] = None
    used_at: Optional[datetime] = None
    created_by: str
    created_at: datetime = Field(default_factory=datetime.now)
    deactivated_at: Optional[datetime] = None
    
    @field_validator('duration_days')
    @classmethod
    def validate_duration(cls, v: int) -> int:
        from config.settings import PASSWORD_DURATIONS
        if v not in PASSWORD_DURATIONS:
            raise ValueError(f'Duration must be one of: {PASSWORD_DURATIONS}')
        return v
    
    @field_validator('password')
    @classmethod
    def validate_password(cls, v: str) -> str:
        if not v or ' ' in v:
            raise ValueError('Password cannot be empty or contain spaces')
        return v
    
    @field_validator('used_at')
    @classmethod
    def validate_usage_consistency(cls, v: Optional[datetime], info) -> Optional[datetime]:
        # Проверяем согласованность used_by и used_at
        used_by = info.data.get('used_by')
        if (used_by is None and v is not None) or (used_by is not None and v is None):
            raise ValueError('used_by and used_at must be both set or both null')
        return v
    
    def is_available(self) -> bool:
        """Проверка доступности пароля для использования"""
        return self.is_active and self.used_by is None
    
    def mask_password(self) -> str:
        """Маскирование пароля для логов"""
        if len(self.password) < 5:
            # Для коротких паролей показываем первый и последний символ
            return f"{self.password[0]}***{self.password[-1]}" if len(self.password) > 1 else "***"
        # Для обычных паролей первые 2 и последние 2 символа
        return f"{self.password[:2]}***{self.password[-2:]}"


class AuthorizedUser(BaseModel):
    """Модель авторизованного пользователя"""
    model_config = ConfigDict(
        arbitrary_types_allowed=True,
        validate_assignment=True
    )
    
    user_id: str
    password_used: str
    expires_at: datetime
    authorized_at: datetime
    description: Optional[str] = None
    updated_at: Optional[datetime] = None
    
    @field_validator('user_id')
    @classmethod
    def validate_user_id(cls, v: str) -> str:
        if not v.isdigit():
            raise ValueError('user_id must contain only digits')
        return v
    
    @field_validator('expires_at')
    @classmethod
    def validate_expiration(cls, v: datetime, info) -> datetime:
        authorized_at = info.data.get('authorized_at')
        if authorized_at and v <= authorized_at:
            raise ValueError('expires_at must be after authorized_at')
        return v
    
    def is_active(self) -> bool:
        """Проверка активности подписки"""
        return self.expires_at > datetime.now()
    
    def days_remaining(self) -> int:
        """Количество дней до истечения"""
        if not self.is_active():
            return 0
        delta = self.expires_at - datetime.now()
        return delta.days


class AuthAttempt(BaseModel):
    """Модель попытки авторизации"""
    model_config = ConfigDict(
        arbitrary_types_allowed=True,
        validate_assignment=True
    )
    
    user_id: str
    password_attempt: str
    success: bool
    error_reason: Optional[Literal['invalid', 'expired', 'deactivated', 'already_used']] = None
    timestamp: datetime = Field(default_factory=datetime.now)
    
    def mask_password(self) -> str:
        """Маскирование пароля для логов"""
        if len(self.password_attempt) < 5:
            return f"{self.password_attempt[0]}***{self.password_attempt[-1]}" if len(self.password_attempt) > 1 else "***"
        return f"{self.password_attempt[:2]}***{self.password_attempt[-2:]}"


class BlockedUser(BaseModel):
    """Модель заблокированного пользователя"""
    model_config = ConfigDict(
        arbitrary_types_allowed=True,
        validate_assignment=True
    )
    
    user_id: str
    blocked_until: datetime
    attempt_count: int
    last_attempt: datetime
    
    def is_blocked(self) -> bool:
        """Проверка активности блокировки"""
        return self.blocked_until > datetime.now()
    
    def seconds_until_unblock(self) -> int:
        """Секунды до разблокировки"""
        if not self.is_blocked():
            return 0
        delta = self.blocked_until - datetime.now()
        return int(delta.total_seconds())