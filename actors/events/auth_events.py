"""
События для AuthActor и системы авторизации
"""
from typing import Optional
from datetime import datetime, timezone
from actors.events.base_event import BaseEvent


class AuthAttemptEvent(BaseEvent):
    """Событие попытки авторизации"""
    
    @classmethod
    def create(cls,
               user_id: str,
               password_attempt: str,
               success: bool,
               error_reason: Optional[str] = None) -> 'AuthAttemptEvent':
        """Создать событие попытки авторизации"""
        # Маскируем пароль для безопасности
        if len(password_attempt) < 5:
            masked_password = f"{password_attempt[0]}***{password_attempt[-1]}" if len(password_attempt) > 1 else "***"
        else:
            masked_password = f"{password_attempt[:2]}***{password_attempt[-2:]}"
        
        return cls(
            stream_id=f"auth_{user_id}",
            event_type="AuthAttemptEvent",
            data={
                "user_id": user_id,
                "masked_password": masked_password,
                "success": success,
                "error_reason": error_reason
            },
            version=0  # Версия устанавливается EventVersionManager
        )


class AuthSuccessEvent(BaseEvent):
    """Событие успешной авторизации"""
    
    @classmethod
    def create(cls,
               user_id: str,
               password: str,
               expires_at: datetime,
               description: str) -> 'AuthSuccessEvent':
        """Создать событие успешной авторизации"""
        # Маскируем пароль и вычисляем срок действия
        if len(password) < 5:
            masked_password = f"{password[0]}***{password[-1]}" if len(password) > 1 else "***"
        else:
            masked_password = f"{password[:2]}***{password[-2:]}"
        
        # Вычисляем количество дней
        duration_days = (expires_at - datetime.now(timezone.utc)).days
        
        return cls(
            stream_id=f"auth_{user_id}",
            event_type="AuthSuccessEvent",
            data={
                "user_id": user_id,
                "masked_password": masked_password,
                "expires_at": expires_at.isoformat(),
                "description": description,
                "duration_days": duration_days
            },
            version=0
        )


class PasswordUsedEvent(BaseEvent):
    """Событие использования пароля"""
    
    @classmethod
    def create(cls,
               password: str,
               used_by: str,
               expires_at: datetime) -> 'PasswordUsedEvent':
        """Создать событие использования пароля"""
        # Маскируем пароль
        if len(password) < 5:
            masked_password = f"{password[0]}***{password[-1]}" if len(password) > 1 else "***"
        else:
            masked_password = f"{password[:2]}***{password[-2:]}"
        
        return cls(
            stream_id=f"password_{masked_password}",
            event_type="PasswordUsedEvent",
            data={
                "masked_password": masked_password,
                "used_by": used_by,
                "expires_at": expires_at.isoformat(),
                "used_at": datetime.now().isoformat()
            },
            version=0
        )


class BlockedUserEvent(BaseEvent):
    """Событие блокировки пользователя"""
    
    @classmethod
    def create(cls,
               user_id: str,
               blocked_until: datetime,
               attempt_count: int) -> 'BlockedUserEvent':
        """Создать событие блокировки пользователя"""
        # Вычисляем длительность блокировки
        block_duration_seconds = int((blocked_until - datetime.now(timezone.utc)).total_seconds())
        
        return cls(
            stream_id=f"auth_{user_id}",
            event_type="BlockedUserEvent",
            data={
                "user_id": user_id,
                "blocked_until": blocked_until.isoformat(),
                "attempt_count": attempt_count,
                "block_duration_seconds": block_duration_seconds
            },
            version=0
        )


class PasswordCreatedEvent(BaseEvent):
    """Событие создания пароля администратором"""
    
    @classmethod
    def create(cls,
               password: str,
               duration_days: int,
               description: str,
               created_by: str) -> 'PasswordCreatedEvent':
        """Создать событие создания пароля администратором"""
        # Маскируем пароль
        if len(password) < 5:
            masked_password = f"{password[0]}***{password[-1]}" if len(password) > 1 else "***"
        else:
            masked_password = f"{password[:2]}***{password[-2:]}"
        
        return cls(
            stream_id=f"admin_{created_by}",
            event_type="PasswordCreatedEvent",
            data={
                "masked_password": masked_password,
                "duration_days": duration_days,
                "description": description,
                "created_by": created_by
            },
            version=0
        )


class PasswordDeactivatedEvent(BaseEvent):
    """Событие деактивации пароля"""
    
    @classmethod
    def create(cls,
               password: str,
               deactivated_by: str,
               was_used: bool,
               used_by: Optional[str] = None) -> 'PasswordDeactivatedEvent':
        """Создать событие деактивации пароля"""
        # Маскируем пароль
        if len(password) < 5:
            masked_password = f"{password[0]}***{password[-1]}" if len(password) > 1 else "***"
        else:
            masked_password = f"{password[:2]}***{password[-2:]}"
        
        return cls(
            stream_id=f"admin_{deactivated_by}",
            event_type="PasswordDeactivatedEvent",
            data={
                "masked_password": masked_password,
                "deactivated_by": deactivated_by,
                "was_used": was_used,
                "used_by": used_by
            },
            version=0
        )