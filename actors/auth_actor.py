"""
AuthActor - актор для управления авторизацией и контроля доступа.
Обрабатывает проверку лимитов, авторизацию паролем и админские команды.
"""
from typing import Optional, Tuple
import asyncio
from datetime import datetime, timezone, timedelta
from actors.base_actor import BaseActor
from actors.messages import ActorMessage, MESSAGE_TYPES
from database.connection import db_connection
from utils.monitoring import measure_latency
from utils.event_utils import EventVersionManager
from config.settings import (
    AUTH_SCHEMA_CHECK_TIMEOUT,
    AUTH_CLEANUP_INTERVAL,
    AUTH_METRICS_LOG_INTERVAL,
    DAILY_MESSAGE_LIMIT
)
import hashlib
from database.redis_connection import redis_connection


class AuthActor(BaseActor):
    """
    Актор для управления авторизацией и контроля доступа.
    
    Основные функции:
    - Проверка дневных лимитов для демо-пользователей
    - Авторизация через временные пароли
    - Управление подписками
    - Администрирование паролей
    - Anti-bruteforce защита
    """
    
    def __init__(self):
        """Инициализация с фиксированным actor_id и именем"""
        super().__init__("auth", "Auth")
        self._pool = None
        self._degraded_mode = False
        self._event_version_manager = EventVersionManager()
        self._redis_connection = None  # Redis подключение
        
        # Метрики для отслеживания работы
        self._metrics = {
            'initialized': False,
            'degraded_mode_entries': 0,
            'check_limit_count': 0,
            'auth_request_count': 0,
            'auth_success_count': 0,
            'auth_failed_count': 0,
            'blocked_users_count': 0,
            'admin_commands_count': 0,
            'db_errors': 0
        }
        
        # Задачи для фоновых операций
        self._cleanup_task = None
        self._metrics_task = None
        
    async def initialize(self) -> None:
        """Инициализация ресурсов актора"""
        try:
            # Проверяем подключение к БД
            if not db_connection._is_connected:
                await db_connection.connect()
            
            # Получаем пул подключений
            self._pool = db_connection.get_pool()
            
            # Проверяем схему БД
            await self._verify_schema()
            
            # Запускаем фоновые задачи
            if AUTH_CLEANUP_INTERVAL > 0:
                self._cleanup_task = asyncio.create_task(self._cleanup_loop())
                
            if AUTH_METRICS_LOG_INTERVAL > 0:
                self._metrics_task = asyncio.create_task(self._metrics_loop())
            
            # Подключаемся к Redis
            await redis_connection.connect()
            self._redis_connection = redis_connection
            
            self._metrics['initialized'] = True
            self.logger.info("AuthActor initialized successfully with Redis support")
            
        except Exception as e:
            self.logger.error(f"Failed to initialize AuthActor: {str(e)}")
            self._degraded_mode = True
            self._metrics['degraded_mode_entries'] += 1
            self._increment_metric('db_errors')
            self.logger.warning("AuthActor entering degraded mode - will work without persistence")
    
    async def shutdown(self) -> None:
        """Освобождение ресурсов актора"""
        # Останавливаем фоновые задачи
        for task in [self._cleanup_task, self._metrics_task]:
            if task and not task.done():
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass
        
        # Отключаемся от Redis
        if self._redis_connection:
            await redis_connection.disconnect()
        
        # Логируем финальные метрики
        self.logger.info(
            f"AuthActor shutdown. Metrics: "
            f"Check limits: {self._metrics['check_limit_count']}, "
            f"Auth requests: {self._metrics['auth_request_count']}, "
            f"Auth success: {self._metrics['auth_success_count']}, "
            f"Auth failed: {self._metrics['auth_failed_count']}, "
            f"Blocked users: {self._metrics['blocked_users_count']}, "
            f"Admin commands: {self._metrics['admin_commands_count']}, "
            f"DB errors: {self._metrics['db_errors']}"
        )
    
    @measure_latency
    async def handle_message(self, message: ActorMessage) -> Optional[ActorMessage]:
        """Обработка входящих сообщений"""
        
        # Проверка лимитов пользователя
        if message.message_type == MESSAGE_TYPES['CHECK_LIMIT']:
            self._metrics['check_limit_count'] += 1
            await self._handle_check_limit(message)
            
        # Запрос авторизации
        elif message.message_type == MESSAGE_TYPES['AUTH_REQUEST']:
            self._metrics['auth_request_count'] += 1
            
            # Извлекаем данные
            user_id = message.payload.get('user_id')
            password = message.payload.get('password')
            chat_id = message.payload.get('chat_id')
            
            if not user_id or not password:
                self.logger.warning("AUTH_REQUEST received without user_id or password")
                return None
            
            self.logger.debug(f"Processing AUTH_REQUEST for user {user_id}")
            
            # ПЕРВЫМ делом проверяем блокировку
            is_blocked, blocked_until = await self._check_user_blocked(user_id)
            if is_blocked:
                response = ActorMessage.create(
                    sender_id=self.actor_id,
                    message_type=MESSAGE_TYPES['AUTH_RESPONSE'],
                    payload={
                        'user_id': user_id,
                        'chat_id': chat_id,
                        'success': False,
                        'error': 'blocked',
                        'blocked_until': blocked_until.isoformat() if blocked_until else None
                    }
                )
                if self.get_actor_system() and message.sender_id:
                    await self.get_actor_system().send_message(message.sender_id, response)
                return None
            
            # В degraded mode не обрабатываем
            if self._degraded_mode or not self._pool:
                response = ActorMessage.create(
                    sender_id=self.actor_id,
                    message_type=MESSAGE_TYPES['AUTH_RESPONSE'],
                    payload={
                        'user_id': user_id,
                        'chat_id': chat_id,
                        'success': False,
                        'error': 'temporary_error'
                    }
                )
                if self.get_actor_system() and message.sender_id:
                    await self.get_actor_system().send_message(message.sender_id, response)
                return None
            
            try:
                from config.settings import AUTH_MAX_ATTEMPTS
                
                # Хешируем пароль
                password_hash = hashlib.sha256(password.encode()).hexdigest()
                
                # 1. Ищем пароль в БД
                password_query = """
                    SELECT password_hash, duration_days, description, used_by, expires_at
                    FROM passwords
                    WHERE password = $1 AND is_active = TRUE
                """
                
                password_row = await self._pool.fetchrow(password_query, password)
                
                if not password_row:
                    # Пароль не найден
                    self.logger.debug(f"Password not found for user {user_id}")
                    # Логируем неудачную попытку
                    await self._pool.execute(
                        """
                        INSERT INTO auth_attempts (user_id, password_attempt, success, error_reason, timestamp)
                        VALUES ($1, $2, FALSE, 'invalid', CURRENT_TIMESTAMP)
                        """,
                        user_id, password
                    )
                    
                    # Проверяем количество попыток
                    failed_count = await self._increment_failed_attempts(user_id)
                    if failed_count >= AUTH_MAX_ATTEMPTS:
                        await self._block_user(user_id, failed_count)
                    
                    # Увеличиваем метрику
                    self._metrics['auth_failed_count'] += 1
                    
                    # Отправляем ответ об ошибке
                    response = ActorMessage.create(
                        sender_id=self.actor_id,
                        message_type=MESSAGE_TYPES['AUTH_RESPONSE'],
                        payload={
                            'user_id': user_id,
                            'chat_id': chat_id,
                            'success': False,
                            'error': 'invalid_password'
                        }
                    )
                    if self.get_actor_system() and message.sender_id:
                        await self.get_actor_system().send_message(message.sender_id, response)
                    return None
                
                # Проверяем хеш
                if password_row['password_hash'] != password_hash:
                    self.logger.debug(f"Invalid password hash for user {user_id}")
                    # Логируем неудачную попытку
                    await self._pool.execute(
                        """
                        INSERT INTO auth_attempts (user_id, password_attempt, success, error_reason, timestamp)
                        VALUES ($1, $2, FALSE, 'invalid', CURRENT_TIMESTAMP)
                        """,
                        user_id, password
                    )
                    
                    # Проверяем количество попыток
                    failed_count = await self._increment_failed_attempts(user_id)
                    if failed_count >= AUTH_MAX_ATTEMPTS:
                        await self._block_user(user_id, failed_count)
                    
                    # Увеличиваем метрику
                    self._metrics['auth_failed_count'] += 1
                    
                    # Отправляем ответ об ошибке
                    response = ActorMessage.create(
                        sender_id=self.actor_id,
                        message_type=MESSAGE_TYPES['AUTH_RESPONSE'],
                        payload={
                            'user_id': user_id,
                            'chat_id': chat_id,
                            'success': False,
                            'error': 'invalid_password'
                        }
                    )
                    if self.get_actor_system() and message.sender_id:
                        await self.get_actor_system().send_message(message.sender_id, response)
                    return None
                
                # 2. Проверяем, нужно ли обновлять подписку
                if password_row['used_by'] == user_id:
                    # Повторная авторизация тем же паролем - ничего не обновляем
                    self.logger.debug(f"Re-authentication with same password for user {user_id}")
                    bind_result = True  # Пароль уже привязан к этому пользователю
                    
                    # Получаем существующий expires_at из authorized_users
                    auth_query = "SELECT expires_at FROM authorized_users WHERE user_id = $1"
                    auth_row = await self._pool.fetchrow(auth_query, user_id)
                    if auth_row:
                        expires_at = auth_row['expires_at'].replace(tzinfo=timezone.utc)
                    else:
                        # Если записи нет, вычисляем новый expires_at
                        expires_at = datetime.now(timezone.utc) + timedelta(days=password_row['duration_days'])
                    
                else:
                    # Первое использование или попытка использовать чужой пароль
                    expires_at = datetime.now(timezone.utc) + timedelta(days=password_row['duration_days'])
                    
                    # 3. Привязываем пароль к пользователю
                    bind_result = await self._pool.fetchval(
                        "SELECT bind_password_to_user($1, $2, $3) as success",
                        password,
                        user_id,
                        expires_at
                    )
                
                if not bind_result:
                    # Пароль уже использован другим пользователем
                    self.logger.debug("Password already used by another user")
                    # Логируем неудачную попытку
                    await self._pool.execute(
                        """
                        INSERT INTO auth_attempts (user_id, password_attempt, success, error_reason, timestamp)
                        VALUES ($1, $2, FALSE, 'already_used', CURRENT_TIMESTAMP)
                        """,
                        user_id, password
                    )
                    
                    # НЕ увеличиваем счетчик попыток для already_used
                    # Увеличиваем метрику
                    self._metrics['auth_failed_count'] += 1
                    
                    # Отправляем ответ об ошибке
                    response = ActorMessage.create(
                        sender_id=self.actor_id,
                        message_type=MESSAGE_TYPES['AUTH_RESPONSE'],
                        payload={
                            'user_id': user_id,
                            'chat_id': chat_id,
                            'success': False,
                            'error': 'already_used'
                        }
                    )
                    if self.get_actor_system() and message.sender_id:
                        await self.get_actor_system().send_message(message.sender_id, response)
                    return None
                
                self.logger.debug(f"Password bound to user {user_id}")
                
                # 4. Создаем/обновляем подписку только для новых паролей
                if password_row['used_by'] != user_id:
                    # Новый пароль - создаем или обновляем подписку
                    await self._pool.execute(
                        """
                        INSERT INTO authorized_users (user_id, password_used, expires_at, authorized_at, description)
                        VALUES ($1, $2, $3, CURRENT_TIMESTAMP, $4)
                        ON CONFLICT (user_id) DO UPDATE
                        SET password_used = $2, 
                            expires_at = $3,
                            updated_at = CURRENT_TIMESTAMP
                        """,
                        user_id,
                        password,
                        expires_at,
                        password_row['description']
                    )
                else:
                    # Повторная авторизация - создаем запись если её нет (после logout)
                    await self._pool.execute(
                        """
                        INSERT INTO authorized_users (user_id, password_used, expires_at, authorized_at, description)
                        VALUES ($1, $2, $3, CURRENT_TIMESTAMP, $4)
                        ON CONFLICT (user_id) DO UPDATE
                        SET updated_at = CURRENT_TIMESTAMP
                        """,
                        user_id,
                        password,
                        expires_at,
                        password_row['description']
                    )
                
                # 5. Логируем успешную попытку
                await self._pool.execute(
                    """
                    INSERT INTO auth_attempts (user_id, password_attempt, success, timestamp)
                    VALUES ($1, $2, TRUE, CURRENT_TIMESTAMP)
                    """,
                    user_id, password
                )
                self.logger.debug(f"Auth attempt logged for user {user_id}")
                
                # 6. Создаем события
                from actors.events.auth_events import AuthSuccessEvent, PasswordUsedEvent
                
                # Событие успешной авторизации
                success_event = AuthSuccessEvent.create(
                    user_id=user_id,
                    password=password,
                    expires_at=expires_at,
                    description=password_row['description']
                )
                await self._event_version_manager.append_event(success_event, self.get_actor_system())
                
                # Событие использования пароля (только при первом использовании)
                if password_row['used_by'] is None:
                    used_event = PasswordUsedEvent.create(
                        password=password,
                        used_by=user_id,
                        expires_at=expires_at
                    )
                    await self._event_version_manager.append_event(used_event, self.get_actor_system())
                
                # 7. Отправляем успешный ответ
                response_payload = {
                    'user_id': user_id,
                    'chat_id': chat_id,
                    'success': True,
                    'expires_at': expires_at.isoformat(),
                    'days_remaining': (expires_at - datetime.now(timezone.utc)).days,
                    'description': password_row['description']
                }
                
                response = ActorMessage.create(
                    sender_id=self.actor_id,
                    message_type=MESSAGE_TYPES['AUTH_RESPONSE'],
                    payload=response_payload
                )
                
                if self.get_actor_system() and message.sender_id:
                    await self.get_actor_system().send_message(message.sender_id, response)
                
                # Обновляем метрики
                self._metrics['auth_success_count'] += 1
                
                self.logger.info(
                    f"User {user_id} successfully authorized until {expires_at.isoformat()}"
                )
                
            except Exception as e:
                self.logger.error(f"Error processing AUTH_REQUEST for user {user_id}: {str(e)}", exc_info=True)
                self._increment_metric('db_errors')
                
                # При любой ошибке - отправляем неуспешный ответ
                response = ActorMessage.create(
                    sender_id=self.actor_id,
                    message_type=MESSAGE_TYPES['AUTH_RESPONSE'],
                    payload={
                        'user_id': user_id,
                        'chat_id': chat_id,
                        'success': False,
                        'error': 'temporary_error'
                    }
                )
                if self.get_actor_system() and message.sender_id:
                    await self.get_actor_system().send_message(message.sender_id, response)
            
        # Запрос на выход
        elif message.message_type == MESSAGE_TYPES['LOGOUT_REQUEST']:
            user_id = message.payload.get('user_id')
            chat_id = message.payload.get('chat_id')
            
            if not user_id:
                self.logger.warning("LOGOUT_REQUEST without user_id")
                return None
                
            # Проверяем, авторизован ли пользователь
            try:
                if self._pool:
                    # Проверяем наличие активной подписки
                    check_query = """
                        SELECT EXISTS(
                            SELECT 1 FROM authorized_users 
                            WHERE user_id = $1 AND expires_at > CURRENT_TIMESTAMP
                        )
                    """
                    is_authorized = await self._pool.fetchval(check_query, user_id)
                    
                    if is_authorized:
                        # Удаляем запись
                        delete_query = "DELETE FROM authorized_users WHERE user_id = $1"
                        await self._pool.execute(delete_query, user_id)
                        
                        # Создаем событие
                        from actors.events import BaseEvent
                        logout_event = BaseEvent.create(
                            stream_id=f"auth_{user_id}",
                            event_type="LogoutEvent",
                            data={
                                "user_id": user_id,
                                "timestamp": datetime.now().isoformat()
                            }
                        )
                        await self._event_version_manager.append_event(logout_event, self.get_actor_system())
                        
                        success = True
                        self.logger.info(f"User {user_id} logged out successfully")
                    else:
                        success = False
                        self.logger.debug(f"User {user_id} was not authorized")
                else:
                    # В degraded mode
                    success = False
                    
            except Exception as e:
                self.logger.error(f"Error processing LOGOUT_REQUEST: {str(e)}")
                self._increment_metric('db_errors')
                success = False
            
            # Отправляем ответ
            response = ActorMessage.create(
                sender_id=self.actor_id,
                message_type=MESSAGE_TYPES['LOGOUT_RESPONSE'],
                payload={
                    'user_id': user_id,
                    'chat_id': chat_id,
                    'success': success
                }
            )
            
            if self.get_actor_system() and message.sender_id:
                await self.get_actor_system().send_message(message.sender_id, response)
            
        # Админская команда
        elif message.message_type == MESSAGE_TYPES['ADMIN_COMMAND']:
            self._metrics['admin_commands_count'] += 1
            await self._handle_admin_command(message)
            
        else:
            self.logger.warning(
                f"Unknown message type received: {message.message_type}"
            )
        
        return None  # Fire-and-forget паттерн
    
    async def _handle_check_limit(self, message: ActorMessage) -> None:
        """Обработка запроса на проверку лимитов пользователя"""
        # Извлекаем user_id
        user_id = message.payload.get('user_id')
        if not user_id:
            self.logger.warning("CHECK_LIMIT received without user_id")
            return
        
        self.logger.debug(f"Checking limit for user {user_id}")
        
        # Извлекаем дополнительные данные из запроса
        chat_id = message.payload.get('chat_id')
        is_status_check = message.payload.get('is_status_check', False)
        
        # Значения по умолчанию для демо-пользователя
        response_payload = {
            'user_id': user_id,
            'chat_id': chat_id,
            'is_status_check': is_status_check,
            'unlimited': False,
            'messages_today': 0,  # Временно всегда 0
            'limit': DAILY_MESSAGE_LIMIT,
            'expires_at': None,
        }
        
        # Проверяем в БД только если не в degraded mode
        if not self._degraded_mode and self._pool:
            try:
                # Запрос к БД
                query = """
                    SELECT expires_at, password_used 
                    FROM authorized_users 
                    WHERE user_id = $1
                """
                
                row = await self._pool.fetchrow(query, user_id)
                
                if row:
                    expires_at = row['expires_at']
                    # Проверяем, не истекла ли подписка
                    if expires_at.replace(tzinfo=timezone.utc) > datetime.now(timezone.utc):
                        # Активная подписка
                        response_payload = {
                            'user_id': user_id,
                            'chat_id': chat_id,
                            'is_status_check': is_status_check,
                            'unlimited': True,
                            'messages_today': 0,  # Временно всегда 0
                            'limit': None,
                            'expires_at': expires_at.isoformat(),
                        }
                        self.logger.info(
                            f"User {user_id} has active subscription until {expires_at.isoformat()}"
                        )
                    else:
                        # Подписка истекла
                        self.logger.debug(f"User {user_id} subscription expired at {expires_at.isoformat()}")
                else:
                    # Пользователь не найден
                    self.logger.debug(f"User {user_id} using demo access")
                    
            except Exception as e:
                self.logger.error(f"Database error checking limit for user {user_id}: {str(e)}", exc_info=True)
                self._increment_metric('db_errors')
                # При ошибке БД используем демо-лимит (fail-open)
        
        # Для демо-пользователей проверяем счетчики Redis
        if not response_payload['unlimited']:
            messages_today = await self._get_daily_message_count(user_id)
            if messages_today is None:
                # Redis недоступен - разрешаем в degraded mode
                self.logger.warning(f"Redis unavailable, allowing user {user_id} in degraded mode")
                messages_today = 0
            
            # Обновляем payload
            response_payload['messages_today'] = messages_today
            
            # Если это не просто проверка статуса - увеличиваем счетчик
            if not is_status_check and messages_today < response_payload['limit']:
                new_count = await self._increment_daily_message_count(user_id)
                if new_count is not None:
                    response_payload['messages_today'] = new_count
                else:
                    # Redis недоступен - все равно увеличиваем локальное значение
                    response_payload['messages_today'] = messages_today + 1
            
            self.logger.debug(f"Demo user {user_id}: {response_payload['messages_today']}/{response_payload['limit']} messages today")
        
        # Добавляем request_id в payload
        response_payload['request_id'] = message.payload.get('request_id')
        
        # Отправляем ответ
        if self.get_actor_system() and message.sender_id:
            response = ActorMessage.create(
                sender_id=self.actor_id,
                message_type=MESSAGE_TYPES['LIMIT_RESPONSE'],
                payload=response_payload
            )
            await self.get_actor_system().send_message(message.sender_id, response)
            self.logger.debug(f"Sent LIMIT_RESPONSE to {message.sender_id} for user {user_id}")
    
    async def _verify_schema(self) -> None:
        """Проверка существования таблиц БД"""
        try:
            if self._pool is None:
                raise RuntimeError("Database pool not initialized")
            
            # Проверяем существование всех таблиц авторизации
            required_tables = ['passwords', 'authorized_users', 'auth_attempts', 'blocked_users']
            
            query = """
                SELECT table_name 
                FROM information_schema.tables 
                WHERE table_schema = 'public' 
                AND table_name = ANY($1)
            """
            
            rows = await self._pool.fetch(
                query, 
                required_tables,
                timeout=AUTH_SCHEMA_CHECK_TIMEOUT
            )
            
            existing_tables = {row['table_name'] for row in rows}
            missing_tables = set(required_tables) - existing_tables
            
            if missing_tables:
                raise RuntimeError(
                    f"Required auth tables missing: {', '.join(missing_tables)}. "
                    f"Please run migration 003_create_auth_tables.sql"
                )
            
            self.logger.debug("Auth schema verification completed successfully")
            
        except Exception as e:
            self.logger.error(f"Schema verification failed: {str(e)}")
            raise
    
    async def _cleanup_loop(self) -> None:
        """Периодическая очистка старых данных"""
        while self.is_running:
            try:
                await asyncio.sleep(AUTH_CLEANUP_INTERVAL)
                
                # Очистка старых попыток авторизации
                # TODO: реализация в подэтапе 5.1.3
                
                self.logger.debug("Auth cleanup completed")
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                self.logger.error(f"Error in cleanup loop: {str(e)}")
    
    async def _metrics_loop(self) -> None:
        """Периодическое логирование метрик"""
        while self.is_running:
            try:
                await asyncio.sleep(AUTH_METRICS_LOG_INTERVAL)
                
                if self._metrics['check_limit_count'] > 0 or self._metrics['auth_request_count'] > 0:
                    self.logger.info(
                        f"AuthActor metrics - "
                        f"Limits checked: {self._metrics['check_limit_count']}, "
                        f"Auth requests: {self._metrics['auth_request_count']}, "
                        f"Success rate: {self._calculate_success_rate():.1%}, "
                        f"Degraded mode: {self._degraded_mode}"
                    )
                    
            except asyncio.CancelledError:
                break
            except Exception as e:
                self.logger.error(f"Error in metrics loop: {str(e)}")
    
    # Вспомогательные методы-заглушки для будущей реализации
    
    async def _check_user_blocked(self, user_id: str) -> Tuple[bool, Optional[datetime]]:
        """
        Проверяет, заблокирован ли пользователь.
        
        Returns:
            (is_blocked, blocked_until) - кортеж из флага и времени разблокировки
        """
        try:
            query = """
                SELECT blocked_until 
                FROM blocked_users 
                WHERE user_id = $1 AND blocked_until > CURRENT_TIMESTAMP
            """
            
            row = await self._pool.fetchrow(query, user_id)
            
            if row:
                blocked_until = row['blocked_until'].replace(tzinfo=timezone.utc)
                self.logger.info(f"Blocked user {user_id} tried to authenticate")
                return True, blocked_until
            
            return False, None
            
        except Exception as e:
            self.logger.error(f"Error checking user block status: {str(e)}")
            self._increment_metric('db_errors')
            return False, None  # При ошибке БД разрешаем попытку
    
    async def _increment_failed_attempts(self, user_id: str) -> int:
        """
        Подсчитывает количество неудачных попыток за последние 15 минут.
        
        Returns:
            Текущее количество неудачных попыток
        """
        try:
            from config.settings import AUTH_ATTEMPTS_WINDOW
            
            query = """
                SELECT COUNT(*) as count
                FROM auth_attempts 
                WHERE user_id = $1 
                  AND success = FALSE 
                  AND timestamp > CURRENT_TIMESTAMP - INTERVAL '%s seconds'
            """ % AUTH_ATTEMPTS_WINDOW
            
            count = await self._pool.fetchval(query, user_id)
            
            self.logger.debug(f"User {user_id} has {count} failed attempts in last {AUTH_ATTEMPTS_WINDOW} seconds")
            
            return count or 0
            
        except Exception as e:
            self.logger.error(f"Error counting failed attempts: {str(e)}")
            self._increment_metric('db_errors')
            return 0  # При ошибке БД возвращаем 0
    
    async def _block_user(self, user_id: str, attempt_count: int) -> None:
        """
        Блокирует пользователя на 15 минут.
        
        Args:
            user_id: ID пользователя
            attempt_count: Количество попыток для записи
        """
        try:
            from config.settings import AUTH_BLOCK_DURATION
            
            blocked_until = datetime.now(timezone.utc) + timedelta(seconds=AUTH_BLOCK_DURATION)
            
            query = """
                INSERT INTO blocked_users (user_id, blocked_until, attempt_count, last_attempt)
                VALUES ($1, $2, $3, CURRENT_TIMESTAMP)
                ON CONFLICT (user_id) DO UPDATE 
                SET blocked_until = $2,
                    attempt_count = $3,
                    last_attempt = CURRENT_TIMESTAMP
            """
            
            await self._pool.execute(query, user_id, blocked_until, attempt_count)
            
            self.logger.warning(f"User {user_id} blocked after {attempt_count} failed attempts")
            
            # Создаем событие блокировки
            from actors.events.auth_events import BlockedUserEvent
            blocked_event = BlockedUserEvent.create(
                user_id=user_id,
                blocked_until=blocked_until,
                attempt_count=attempt_count
            )
            await self._event_version_manager.append_event(blocked_event, self.get_actor_system())
            
            # Обновляем метрику
            self._metrics['blocked_users_count'] += 1
            
        except Exception as e:
            self.logger.error(f"Error blocking user: {str(e)}")
            self._increment_metric('db_errors')
    
    async def _reset_daily_counters(self) -> None:
        """Сброс дневных счетчиков сообщений"""
        # TODO: реализация в подэтапе 5.1.3
        pass
    
    async def _get_daily_message_count(self, user_id: str) -> Optional[int]:
        """
        Получить количество сообщений пользователя за сегодня из Redis.
        
        Returns:
            Количество сообщений или None если Redis недоступен
        """
        if not self._redis_connection or not self._redis_connection.is_connected():
            return None
            
        try:
            # Формируем ключ с текущей датой
            from datetime import date
            today = date.today().isoformat()
            key = self._redis_connection.make_key("daily_limit", user_id, today)
            
            # Получаем значение
            value = await self._redis_connection.get(key)
            return int(value) if value else 0
            
        except Exception as e:
            self.logger.error(f"Failed to get message count for user {user_id}: {str(e)}")
            return None
    
    async def _increment_daily_message_count(self, user_id: str) -> Optional[int]:
        """
        Увеличить счетчик сообщений пользователя на 1.
        
        Returns:
            Новое значение счетчика или None если Redis недоступен
        """
        if not self._redis_connection or not self._redis_connection.is_connected():
            return None
            
        try:
            # Формируем ключ с текущей датой
            from datetime import date
            today = date.today().isoformat()
            key = self._redis_connection.make_key("daily_limit", user_id, today)
            
            # Инкрементируем с TTL 24 часа
            from config.settings import REDIS_DAILY_LIMIT_TTL
            new_value = await self._redis_connection.increment(key)
            
            # Устанавливаем TTL только при первом инкременте
            if new_value == 1:
                client = self._redis_connection.get_client()
                if client:
                    await client.expire(key, REDIS_DAILY_LIMIT_TTL)
            
            self.logger.debug(f"Incremented message count for user {user_id}: {new_value}")
            return new_value
            
        except Exception as e:
            self.logger.error(f"Failed to increment message count for user {user_id}: {str(e)}")
            return None
    
    async def _reset_daily_message_count(self, user_id: str) -> bool:
        """
        Сбросить счетчик сообщений пользователя (для админских команд).
        
        Returns:
            True если успешно, False если ошибка
        """
        if not self._redis_connection or not self._redis_connection.is_connected():
            return False
            
        try:
            # Формируем ключ с текущей датой
            from datetime import date
            today = date.today().isoformat()
            key = self._redis_connection.make_key("daily_limit", user_id, today)
            
            # Удаляем ключ
            await self._redis_connection.delete(key)
            self.logger.info(f"Reset message count for user {user_id}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to reset message count for user {user_id}: {str(e)}")
            return False
    
    def _increment_metric(self, metric_name: str, value: int = 1) -> None:
        """Инкремент метрики"""
        if metric_name in self._metrics:
            self._metrics[metric_name] += value
    
    def _increment_metric(self, metric_name: str, value: int = 1) -> None:
        """Инкремент метрики"""
        if metric_name in self._metrics:
            self._metrics[metric_name] += value
    
    def _calculate_success_rate(self) -> float:
        """Вычисление процента успешных авторизаций"""
        total = self._metrics['auth_request_count']
        if total == 0:
            return 0.0
        return self._metrics['auth_success_count'] / total
        
    async def _handle_admin_command(self, message: ActorMessage) -> None:
        """Обработка админских команд"""
        command = message.payload.get('command', '')
        args = message.payload.get('args', [])
        user_id = message.payload.get('user_id')
        chat_id = message.payload.get('chat_id')
        
        self.logger.info(f"Processing admin command '{command}' from user {user_id}")
        
        # В degraded mode не обрабатываем админские команды
        if self._degraded_mode or not self._pool:
            response_text = "⚠️ Система авторизации временно недоступна"
        else:
            # Базовый роутинг команд (будет расширен в следующих частях)
            if command == 'admin_add_password':
                response_text = await self._admin_add_password(args, user_id)
            elif command == 'admin_list_passwords':
                response_text = await self._admin_list_passwords(args)
            elif command == 'admin_deactivate_password':
                response_text = await self._admin_deactivate_password(args, user_id)
            elif command == 'admin_stats':
                response_text = await self._admin_stats()
            elif command == 'admin_auth_log':
                response_text = await self._admin_auth_log(args)
            elif command == 'admin_blocked_users':
                response_text = await self._admin_blocked_users()
            elif command == 'admin_unblock_user':
                response_text = await self._admin_unblock_user(args)
            else:
                from config.messages import ADMIN_MESSAGES
                response_text = ADMIN_MESSAGES["unknown_command"].format(command=command)
        
        # Отправляем ответ обратно в TelegramActor
        response = ActorMessage.create(
            sender_id=self.actor_id,
            message_type=MESSAGE_TYPES['ADMIN_RESPONSE'],
            payload={
                'chat_id': chat_id,
                'text': response_text
            }
        )
        
        if self.get_actor_system() and message.sender_id:
            await self.get_actor_system().send_message(message.sender_id, response)
    
    async def _admin_add_password(self, args: list, admin_id: str) -> str:
        """Создание нового пароля"""
        from config.messages import ADMIN_MESSAGES
        from config.settings import PASSWORD_DURATIONS
        
        # Базовая проверка
        if len(args) < 1:
            return ADMIN_MESSAGES["password_usage"]
        
        password = args[0]
        
        # Если есть второй аргумент - проверяем его формат
        if len(args) >= 2:
            try:
                days = int(args[1])
            except ValueError:
                return ADMIN_MESSAGES["password_invalid_days_format"]
                
            if days not in PASSWORD_DURATIONS:
                return ADMIN_MESSAGES["password_invalid_days"].format(
                    durations=", ".join(map(str, PASSWORD_DURATIONS))
                )
        
        # Теперь проверяем полное количество аргументов
        if len(args) < 3:
            return ADMIN_MESSAGES["password_usage"]
        
        description = " ".join(args[2:])
        
        try:
            # Проверяем существование пароля
            existing = await self._pool.fetchrow(
                "SELECT 1 FROM passwords WHERE password = $1",
                password
            )
            
            if existing:
                return ADMIN_MESSAGES["password_already_exists"].format(password=password)
            
            # Хешируем пароль
            password_hash = hashlib.sha256(password.encode()).hexdigest()
            
            # Создаем пароль
            await self._pool.execute("""
                INSERT INTO passwords (password, password_hash, created_by, duration_days, description, is_active)
                VALUES ($1, $2, $3, $4, $5, TRUE)
            """, password, password_hash, admin_id, days, description)
            
            # Создаем событие
            from actors.events.auth_events import PasswordCreatedEvent
            event = PasswordCreatedEvent.create(
                password=password,
                duration_days=days,
                description=description,
                created_by=admin_id
            )
            await self._event_version_manager.append_event(event, self.get_actor_system())
            
            self.logger.info(f"Password '{password}' created by admin {admin_id}")
            
            return ADMIN_MESSAGES["password_created"].format(
                password=password,
                days=days,
                description=description
            )
            
        except Exception as e:
            self.logger.error(f"Error creating password: {str(e)}", exc_info=True)
            return ADMIN_MESSAGES["command_error"].format(error=str(e))
    
    async def _admin_list_passwords(self, args: list) -> str:
        """Список всех паролей"""
        from config.messages import ADMIN_MESSAGES
        
        # Проверяем параметр full
        show_full = len(args) > 0 and args[0] == 'full'
        
        try:
            # Получаем все пароли
            passwords = await self._pool.fetch("""
                SELECT 
                    password,
                    description,
                    duration_days,
                    is_active,
                    created_at,
                    used_by,
                    expires_at
                FROM passwords
                ORDER BY created_at DESC
            """)
            
            if not passwords:
                return ADMIN_MESSAGES["passwords_empty"]
            
            # Формируем ответ
            lines = [ADMIN_MESSAGES["passwords_header"].format(count=len(passwords))]
            
            for i, pwd in enumerate(passwords, 1):
                # Маскируем пароль если не full
                if show_full:
                    display_password = pwd['password']
                else:
                    # Маскируем пароль
                    p = pwd['password']
                    if len(p) < 5:
                        display_password = f"{p[0]}***{p[-1]}" if len(p) > 1 else "***"
                    else:
                        display_password = f"{p[:2]}***{p[-2:]}"
                
                # Определяем статус
                if pwd['used_by']:
                    if pwd['expires_at']:
                        if pwd['expires_at'] > datetime.now(timezone.utc):
                            status = f"истекает {pwd['expires_at'].strftime('%d.%m')}"
                        else:
                            status = f"истек {pwd['expires_at'].strftime('%d.%m')}"
                    else:
                        status = "использован"
                else:
                    status = "не использован"
                
                # Выбираем шаблон
                template = ADMIN_MESSAGES["password_item_active" if pwd['is_active'] else "password_item_inactive"]
                
                lines.append(template.format(
                    index=i,
                    password=display_password,
                    description=pwd['description'],
                    days=pwd['duration_days'],
                    created=pwd['created_at'].strftime('%d.%m'),
                    status=status
                ))
            
            return "\n\n".join(lines)
            
        except Exception as e:
            self.logger.error(f"Error listing passwords: {str(e)}", exc_info=True)
            return ADMIN_MESSAGES["command_error"].format(error=str(e))
    
    async def _admin_deactivate_password(self, args: list, admin_id: str) -> str:
        """Деактивация пароля"""
        from config.messages import ADMIN_MESSAGES
        
        # Проверка аргументов
        if len(args) < 1:
            return ADMIN_MESSAGES["password_deactivate_usage"]
        
        password = args[0]
        
        try:
            # Проверяем существование и статус
            pwd_row = await self._pool.fetchrow("""
                SELECT is_active, used_by
                FROM passwords
                WHERE password = $1
            """, password)
            
            if not pwd_row:
                return ADMIN_MESSAGES["password_not_found"].format(password=password)
            
            if not pwd_row['is_active']:
                return ADMIN_MESSAGES["password_already_inactive"].format(password=password)
            
            # Деактивируем
            await self._pool.execute("""
                UPDATE passwords
                SET is_active = FALSE
                WHERE password = $1
            """, password)
            
            # Создаем событие
            from actors.events.auth_events import PasswordDeactivatedEvent
            event = PasswordDeactivatedEvent.create(
                password=password,
                deactivated_by=admin_id,  # берем из параметра метода
                was_used=pwd_row['used_by'] is not None,
                used_by=pwd_row['used_by']
            )
            await self._event_version_manager.append_event(event, self.get_actor_system())
            
            self.logger.info(f"Password '{password}' deactivated")
            
            return ADMIN_MESSAGES["password_deactivated"].format(password=password)
            
        except Exception as e:
            self.logger.error(f"Error deactivating password: {str(e)}", exc_info=True)
            return ADMIN_MESSAGES["command_error"].format(error=str(e))
    
    async def _admin_stats(self) -> str:
        """Общая статистика системы"""
        from config.messages import ADMIN_MESSAGES
        
        try:
            # Статистика паролей
            password_stats = await self._pool.fetchrow("""
                SELECT 
                    COUNT(*) FILTER (WHERE is_active = TRUE) as active,
                    COUNT(*) FILTER (WHERE is_active = FALSE) as inactive,
                    COUNT(*) FILTER (WHERE used_by IS NOT NULL) as used
                FROM passwords
            """)
            
            # Статистика пользователей
            user_stats = await self._pool.fetchrow("""
                SELECT 
                    COUNT(DISTINCT user_id) as total_users
                FROM auth_attempts
            """)
            
            # Активные авторизации
            auth_stats = await self._pool.fetchrow("""
                SELECT COUNT(*) as authorized
                FROM authorized_users
                WHERE expires_at > CURRENT_TIMESTAMP
            """)
            
            # Заблокированные пользователи
            blocked_stats = await self._pool.fetchrow("""
                SELECT COUNT(*) as blocked
                FROM blocked_users
                WHERE blocked_until > CURRENT_TIMESTAMP
            """)
            
            # Группировка по длительности
            duration_stats = await self._pool.fetch("""
                SELECT duration_days, COUNT(*) as count
                FROM passwords
                GROUP BY duration_days
                ORDER BY duration_days
            """)
            
            # Активность за последние 24 часа
            activity_stats = await self._pool.fetchrow("""
                SELECT 
                    COUNT(*) as attempts,
                    COUNT(*) FILTER (WHERE success = TRUE) as success,
                    COUNT(*) FILTER (WHERE success = FALSE) as failed
                FROM auth_attempts
                WHERE timestamp > CURRENT_TIMESTAMP - INTERVAL '24 hours'
            """)
            
            # Формируем ответ
            lines = [ADMIN_MESSAGES["stats_header"]]
            
            # Пароли
            lines.append("\n" + ADMIN_MESSAGES["stats_passwords"].format(
                active=password_stats['active'] or 0,
                inactive=password_stats['inactive'] or 0,
                used=password_stats['used'] or 0
            ))
            
            # Пользователи
            lines.append("\n" + ADMIN_MESSAGES["stats_users"].format(
                total=user_stats['total_users'] or 0,
                authorized=auth_stats['authorized'] or 0,
                blocked=blocked_stats['blocked'] or 0
            ))
            
            # По длительности
            if duration_stats:
                duration_lines = []
                for stat in duration_stats:
                    duration_lines.append(f"• {stat['duration_days']} дней: {stat['count']} паролей")
                
                lines.append("\n" + ADMIN_MESSAGES["stats_by_duration"].format(
                    durations="\n".join(duration_lines)
                ))
            
            # Активность
            lines.append("\n" + ADMIN_MESSAGES["stats_recent_activity"].format(
                attempts=activity_stats['attempts'] or 0,
                success=activity_stats['success'] or 0,
                failed=activity_stats['failed'] or 0
            ))
            
            return "\n".join(lines)
            
        except Exception as e:
            self.logger.error(f"Error generating stats: {str(e)}", exc_info=True)
            return ADMIN_MESSAGES["command_error"].format(error=str(e))
    
    async def _admin_auth_log(self, args: list) -> str:
        """Просмотр логов авторизации"""
        from config.messages import ADMIN_MESSAGES
        
        # Проверяем параметр user_id
        user_filter = None
        filter_text = ""
        
        if len(args) > 0:
            user_id = args[0]
            # Проверяем формат user_id
            if not user_id.isdigit():
                return ADMIN_MESSAGES["auth_log_invalid_user"]
            user_filter = user_id
            filter_text = f" (user {user_id})"
        
        try:
            # Базовый запрос
            if user_filter:
                query = """
                    SELECT 
                        a.user_id,
                        a.password_attempt,
                        a.success,
                        a.error_reason,
                        a.timestamp,
                        p.duration_days
                    FROM auth_attempts a
                    LEFT JOIN passwords p ON a.password_attempt = p.password
                    WHERE a.user_id = $1
                    ORDER BY a.timestamp DESC
                    LIMIT 20
                """
                logs = await self._pool.fetch(query, user_filter)
            else:
                query = """
                    SELECT 
                        a.user_id,
                        a.password_attempt,
                        a.success,
                        a.error_reason,
                        a.timestamp,
                        p.duration_days
                    FROM auth_attempts a
                    LEFT JOIN passwords p ON a.password_attempt = p.password
                    ORDER BY a.timestamp DESC
                    LIMIT 20
                """
                logs = await self._pool.fetch(query)
            
            if not logs:
                return ADMIN_MESSAGES["auth_log_empty"].format(filter=filter_text)
            
            # Получаем информацию о блокировках
            blocked_users = {}
            if not user_filter:
                blocks = await self._pool.fetch("""
                    SELECT user_id, blocked_until, attempt_count
                    FROM blocked_users
                    WHERE blocked_until > CURRENT_TIMESTAMP
                """)
                blocked_users = {b['user_id']: b for b in blocks}
            
            # Формируем ответ
            lines = [ADMIN_MESSAGES["auth_log_header"].format(filter=filter_text)]
            
            for log in logs:
                time_str = log['timestamp'].strftime('%d.%m %H:%M')
                
                # Маскируем пароль
                pwd = log['password_attempt']
                if len(pwd) < 5:
                    masked_pwd = f"{pwd[0]}***{pwd[-1]}" if len(pwd) > 1 else "***"
                else:
                    masked_pwd = f"{pwd[:2]}***{pwd[-2:]}"
                
                if log['success']:
                    # Успешная авторизация
                    days = log['duration_days'] or "неизв."
                    lines.append("\n" + ADMIN_MESSAGES["auth_log_entry_success"].format(
                        time=time_str,
                        user_id=log['user_id'],
                        password=masked_pwd,
                        days=days
                    ))
                else:
                    # Неудачная попытка
                    reason_map = {
                        'invalid': 'неверный пароль',
                        'expired': 'пароль истек',
                        'deactivated': 'пароль деактивирован',
                        'already_used': 'пароль уже использован',
                        'blocked': 'пользователь заблокирован'
                    }
                    reason = reason_map.get(log['error_reason'], log['error_reason'] or 'неизвестно')
                    
                    lines.append("\n" + ADMIN_MESSAGES["auth_log_entry_failed"].format(
                        time=time_str,
                        user_id=log['user_id'],
                        password=masked_pwd,
                        reason=reason
                    ))
                
                # Проверяем блокировку
                if log['user_id'] in blocked_users and not user_filter:
                    block = blocked_users[log['user_id']]
                    seconds = int((block['blocked_until'] - datetime.now(timezone.utc)).total_seconds())
                    if seconds > 0:
                        lines.append(ADMIN_MESSAGES["auth_log_entry_blocked"].format(
                            time="",  # пустое время, так как это дополнительная информация
                            user_id=log['user_id'],
                            seconds=seconds
                        ))
            
            return "\n".join(lines)
            
        except Exception as e:
            self.logger.error(f"Error getting auth log: {str(e)}", exc_info=True)
            return ADMIN_MESSAGES["command_error"].format(error=str(e))
    
    async def _admin_blocked_users(self) -> str:
        """Список заблокированных пользователей"""
        from config.messages import ADMIN_MESSAGES
        
        try:
            # Получаем всех заблокированных пользователей
            blocked = await self._pool.fetch("""
                SELECT 
                    user_id,
                    blocked_until,
                    attempt_count,
                    last_attempt
                FROM blocked_users
                WHERE blocked_until > CURRENT_TIMESTAMP
                ORDER BY blocked_until DESC
            """)
            
            if not blocked:
                return ADMIN_MESSAGES["blocked_users_empty"]
            
            # Формируем ответ
            lines = [ADMIN_MESSAGES["blocked_users_header"].format(count=len(blocked))]
            
            for user in blocked:
                # Вычисляем оставшееся время
                now = datetime.now(timezone.utc)
                time_left_seconds = int((user['blocked_until'] - now).total_seconds())
                
                if time_left_seconds > 3600:
                    # Больше часа - показываем в часах и минутах
                    hours = time_left_seconds // 3600
                    minutes = (time_left_seconds % 3600) // 60
                    time_left = f"{hours}ч {minutes}мин"
                elif time_left_seconds > 60:
                    # Больше минуты - показываем в минутах
                    minutes = time_left_seconds // 60
                    time_left = f"{minutes} мин"
                else:
                    # Меньше минуты - показываем в секундах
                    time_left = f"{time_left_seconds} сек"
                
                # Форматируем время последней попытки
                last_attempt = user['last_attempt'].strftime('%d.%m %H:%M')
                
                lines.append("\n" + ADMIN_MESSAGES["blocked_user_entry"].format(
                    user_id=user['user_id'],
                    time_left=time_left,
                    attempts=user['attempt_count'],
                    last_attempt=last_attempt
                ))
            
            return "\n".join(lines)
            
        except Exception as e:
            self.logger.error(f"Error getting blocked users: {str(e)}", exc_info=True)
            return ADMIN_MESSAGES["command_error"].format(error=str(e))
    
    async def _admin_unblock_user(self, args: list) -> str:
        """Разблокировка пользователя"""
        from config.messages import ADMIN_MESSAGES
        
        # Проверка аргументов
        if len(args) < 1:
            return ADMIN_MESSAGES["unblock_usage"]
        
        user_id = args[0]
        
        # Проверка формата user_id
        if not user_id.isdigit():
            return ADMIN_MESSAGES["unblock_invalid_user"]
        
        try:
            # Проверяем, заблокирован ли пользователь
            blocked = await self._pool.fetchrow("""
                SELECT blocked_until
                FROM blocked_users
                WHERE user_id = $1 AND blocked_until > CURRENT_TIMESTAMP
            """, user_id)
            
            if not blocked:
                return ADMIN_MESSAGES["unblock_not_blocked"].format(user_id=user_id)
            
            # Удаляем блокировку
            await self._pool.execute("""
                DELETE FROM blocked_users
                WHERE user_id = $1
            """, user_id)
            
            # Также удаляем недавние неудачные попытки для сброса счетчиков
            from config.settings import AUTH_ATTEMPTS_WINDOW
            cutoff_time = datetime.now(timezone.utc) - timedelta(seconds=AUTH_ATTEMPTS_WINDOW)
            
            await self._pool.execute("""
                DELETE FROM auth_attempts
                WHERE user_id = $1 
                AND success = FALSE
                AND timestamp > $2
            """, user_id, cutoff_time)
            
            self.logger.info(f"User {user_id} unblocked by admin")
            
            # Создаем событие (опционально - можно добавить UnblockedByAdminEvent)
            # Но пока просто логируем действие
            
            return ADMIN_MESSAGES["unblock_success"].format(user_id=user_id)
            
        except Exception as e:
            self.logger.error(f"Error unblocking user {user_id}: {str(e)}", exc_info=True)
            return ADMIN_MESSAGES["command_error"].format(error=str(e))