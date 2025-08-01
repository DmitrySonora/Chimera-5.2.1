from typing import Optional, Dict, Any
import asyncio
import aiohttp
from datetime import datetime

from actors.base_actor import BaseActor
from actors.messages import ActorMessage, MESSAGE_TYPES
from config.messages import USER_MESSAGES
from config.settings import (
    TELEGRAM_BOT_TOKEN,
    TELEGRAM_POLLING_TIMEOUT,
    TELEGRAM_TYPING_UPDATE_INTERVAL,
    TELEGRAM_MAX_MESSAGE_LENGTH,
    TELEGRAM_TYPING_CLEANUP_THRESHOLD,
    TELEGRAM_API_DEFAULT_TIMEOUT,
    TELEGRAM_MAX_TYPING_TASKS,
    DAILY_MESSAGE_LIMIT
)
from utils.monitoring import measure_latency


class TelegramInterfaceActor(BaseActor):
    """
    Интерфейс между Telegram Bot API и Actor System.
    Обрабатывает входящие сообщения и отправляет ответы.
    """
    
    def __init__(self):
        super().__init__("telegram", "Telegram")
        self._session: Optional[aiohttp.ClientSession] = None
        self._update_offset = 0
        self._polling_task: Optional[asyncio.Task] = None
        self._typing_tasks: Dict[int, asyncio.Task] = {}  # chat_id -> task
        self._base_url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}"
        self._typing_cleanup_counter = 0
        self._awaiting_password: Dict[int, datetime] = {}  # user_id -> timestamp
        
    async def initialize(self) -> None:
        """Инициализация HTTP сессии и запуск polling"""
        if not TELEGRAM_BOT_TOKEN:
            raise ValueError("TELEGRAM_BOT_TOKEN not set in config/settings.py")
            
        self._session = aiohttp.ClientSession()
        
        # Проверяем токен
        me = await self._api_call("getMe")
        self.logger.info(f"Connected as @{me['result']['username']}")
        
        # Запускаем polling
        self._polling_task = asyncio.create_task(self._polling_loop())
        
        # Запускаем периодическую очистку паролей
        self._password_cleanup_task = asyncio.create_task(self._password_cleanup_loop())
        
        self.logger.info("TelegramInterfaceActor initialized")
        
    async def shutdown(self) -> None:
        """Остановка polling и освобождение ресурсов"""
        # Останавливаем polling
        if self._polling_task:
            self._polling_task.cancel()
            try:
                await self._polling_task
            except asyncio.CancelledError:
                pass
                
        # Останавливаем очистку паролей
        if hasattr(self, '_password_cleanup_task') and self._password_cleanup_task:
            self._password_cleanup_task.cancel()
            try:
                await self._password_cleanup_task
            except asyncio.CancelledError:
                pass
        
        # Останавливаем все typing индикаторы
        for task in self._typing_tasks.values():
            task.cancel()
            
        # Очищаем словарь
        self._typing_tasks.clear()
        
        # Закрываем HTTP сессию
        if self._session:
            await self._session.close()
            
        self.logger.info("TelegramInterfaceActor shutdown")
        
    @measure_latency
    async def handle_message(self, message: ActorMessage) -> Optional[ActorMessage]:
        """Обработка сообщений от других акторов"""
        
        # Новое сообщение от Telegram для обработки
        if message.message_type == MESSAGE_TYPES['PROCESS_USER_MESSAGE']:
            # Извлекаем данные и отправляем в UserSessionActor
            user_msg = ActorMessage.create(
                sender_id=self.actor_id,
                message_type=MESSAGE_TYPES['USER_MESSAGE'],
                payload=message.payload
            )
            
            # Отправляем в UserSessionActor через ActorSystem
            if self.get_actor_system():
                await self.get_actor_system().send_message("user_session", user_msg)
            
        # Ответ бота готов
        elif message.message_type == MESSAGE_TYPES['BOT_RESPONSE']:
            await self._send_bot_response(message)
            
        # Ошибка генерации
        elif message.message_type == MESSAGE_TYPES['ERROR']:
            await self._send_error_message(message)
            
        # Streaming чанк (для будущего)
        elif message.message_type == MESSAGE_TYPES['STREAMING_CHUNK']:
            # TODO: Реализовать в следующих этапах
            pass
            
        # Превышение лимита
        elif message.message_type == MESSAGE_TYPES['LIMIT_EXCEEDED']:
            await self._send_limit_exceeded_message(message)
            
        # Ответ на авторизацию
        elif message.message_type == MESSAGE_TYPES['AUTH_RESPONSE']:
            await self._handle_auth_response(message)
            
        # Ответ на logout
        elif message.message_type == MESSAGE_TYPES['LOGOUT_RESPONSE']:
            await self._handle_logout_response(message)
            
        # Ответ на админскую команду
        elif message.message_type == MESSAGE_TYPES['ADMIN_RESPONSE']:
            await self._handle_admin_response(message)
            
        # Модифицированная обработка LIMIT_RESPONSE для /status
        elif message.message_type == MESSAGE_TYPES['LIMIT_RESPONSE']:
            # Проверяем, это ответ на /status?
            if message.payload.get('is_status_check'):
                await self._handle_status_response(message)
            
        return None
    
    async def _polling_loop(self) -> None:
        """Основной цикл получения обновлений от Telegram"""
        self.logger.info("Started Telegram polling")
        
        while self.is_running:
            try:
                # Получаем обновления
                updates = await self._get_updates()
                
                # Обрабатываем каждое обновление
                for update in updates:
                    await self._process_update(update)
                    
            except asyncio.CancelledError:
                break
            except Exception as e:
                self.logger.error(f"Polling error: {str(e)}")
                await asyncio.sleep(5)  # Пауза перед переподключением
                
        self.logger.info("Stopped Telegram polling")
    
    async def _password_cleanup_loop(self) -> None:
        """Периодическая очистка устаревших состояний ожидания пароля"""
        while self.is_running:
            try:
                await asyncio.sleep(10)  # Проверяем каждые 10 секунд
                self._cleanup_expired_passwords()
            except asyncio.CancelledError:
                break
            except Exception as e:
                self.logger.error(f"Error in password cleanup loop: {str(e)}")
    
    async def _get_updates(self) -> list:
        """Получение обновлений через long polling"""
        try:
            result = await self._api_call(
                "getUpdates",
                params={
                    "offset": self._update_offset,
                    "timeout": TELEGRAM_POLLING_TIMEOUT,
                    "allowed_updates": ["message"]
                },
                timeout=TELEGRAM_POLLING_TIMEOUT + 5
            )
            
            updates = result.get("result", [])
            
            # Обновляем offset
            if updates:
                self._update_offset = updates[-1]["update_id"] + 1
                
            return updates
            
        except asyncio.TimeoutError:
            return []  # Нормальная ситуация для long polling
        except Exception as e:
            self.logger.error(f"Failed to get updates: {str(e)}")
            return []
    
    async def _process_update(self, update: Dict[str, Any]) -> None:
        """Обработка одного обновления от Telegram"""
        # Извлекаем сообщение
        message = update.get("message")
        if not message:
            return
            
        # Извлекаем данные
        chat_id = message["chat"]["id"]
        user_id = message["from"]["id"]
        username = message["from"].get("username")
        text = message.get("text", "")
        
        # Игнорируем не-текстовые сообщения пока
        if not text:
            return
            
        # Обработка команд
        if text.startswith("/"):
            await self._handle_command(chat_id, text)
            return
            
        # Проверяем, ожидаем ли пароль от этого пользователя
        if user_id in self._awaiting_password:
            # Удаляем из состояния ожидания
            del self._awaiting_password[user_id]
            
            # Проверка на пустой пароль
            if not text.strip():
                await self._send_message(chat_id, "Пароль не может быть пустым")
                return
            
            # Отправляем запрос на авторизацию
            auth_msg = ActorMessage.create(
                sender_id=self.actor_id,
                message_type=MESSAGE_TYPES['AUTH_REQUEST'],
                payload={
                    'user_id': str(user_id),
                    'password': text.strip(),
                    'chat_id': chat_id
                }
            )
            
            if self.get_actor_system():
                await self.get_actor_system().send_message("auth", auth_msg)
                
            self.logger.info(f"Sent AUTH_REQUEST for user {user_id}")
            return
            
        # Запускаем typing индикатор
        await self._start_typing(chat_id)
        
        # Создаем сообщение для обработки через Actor System
        process_msg = ActorMessage.create(
            sender_id=self.actor_id,
            message_type=MESSAGE_TYPES['PROCESS_USER_MESSAGE'],
            payload={
                'user_id': str(user_id),
                'chat_id': chat_id,
                'username': username,
                'text': text,
                'timestamp': datetime.now().isoformat()
            }
        )
        
        # Отправляем себе же для обработки через Actor System
        if self.get_actor_system():
            await self.get_actor_system().send_message(self.actor_id, process_msg)
        
        self.logger.debug(f"Queued message from user {user_id}: {text[:50]}...")
    
    async def _handle_command(self, chat_id: int, command: str) -> None:
        """Обработка команд бота"""
        # Очистка устаревших состояний ожидания пароля
        self._cleanup_expired_passwords()
        
        # Если ожидаем пароль, но получили команду - сбрасываем состояние
        user_id = chat_id  # В личных сообщениях chat_id = user_id
        if user_id in self._awaiting_password:
            del self._awaiting_password[user_id]
            self.logger.debug(f"Reset password wait state for user {user_id} due to command")
        
        if command == "/start":
            from config.settings import DAILY_MESSAGE_LIMIT
            welcome_text = USER_MESSAGES["welcome"].format(
                DAILY_MESSAGE_LIMIT=DAILY_MESSAGE_LIMIT
            )
            await self._send_message(chat_id, welcome_text)
            
        elif command == "/auth":
            # Добавляем в состояние ожидания
            self._awaiting_password[user_id] = datetime.now()
            await self._send_message(chat_id, USER_MESSAGES["auth_prompt"])
            
        elif command == "/status":
            # Отправляем запрос на проверку статуса
            check_msg = ActorMessage.create(
                sender_id=self.actor_id,
                message_type=MESSAGE_TYPES['CHECK_LIMIT'],
                payload={
                    'user_id': str(user_id),
                    'chat_id': chat_id,
                    'is_status_check': True
                }
            )
            if self.get_actor_system():
                await self.get_actor_system().send_message("auth", check_msg)
                
        elif command == "/logout":
            # Отправляем запрос на выход
            logout_msg = ActorMessage.create(
                sender_id=self.actor_id,
                message_type=MESSAGE_TYPES['LOGOUT_REQUEST'],
                payload={
                    'user_id': str(user_id),
                    'chat_id': chat_id
                }
            )
            if self.get_actor_system():
                await self.get_actor_system().send_message("auth", logout_msg)
                
        elif command.startswith("/admin_"):
            # Проверка прав администратора
            from config.settings import ADMIN_USER_IDS
            user_id = chat_id  # В личных сообщениях chat_id = user_id
            
            if user_id not in ADMIN_USER_IDS:
                from config.messages import ADMIN_MESSAGES
                await self._send_message(chat_id, ADMIN_MESSAGES["access_denied"])
                return
            
            # Парсинг команды и аргументов
            parts = command.split(maxsplit=1)
            admin_command = parts[0][1:]  # убираем слеш
            args = parts[1].split() if len(parts) > 1 else []
            
            # Отправка команды в AuthActor
            admin_msg = ActorMessage.create(
                sender_id=self.actor_id,
                message_type=MESSAGE_TYPES['ADMIN_COMMAND'],
                payload={
                    'command': admin_command,
                    'args': args,
                    'user_id': str(user_id),
                    'chat_id': chat_id
                }
            )
            
            if self.get_actor_system():
                await self.get_actor_system().send_message("auth", admin_msg)
                
            self.logger.info(f"Sent ADMIN_COMMAND '{admin_command}' from user {user_id}")
            
        else:
            await self._send_message(chat_id, USER_MESSAGES["unknown_command"])
    
    async def _send_bot_response(self, message: ActorMessage) -> None:
        """Отправка ответа бота пользователю"""
        chat_id = message.payload['chat_id']
        text = message.payload['text']
        
        # Останавливаем typing
        await self._stop_typing(chat_id)
        
        # Отправляем сообщение
        await self._send_message(chat_id, text)
        
        # Пересылаем BOT_RESPONSE в UserSessionActor для сохранения в память
        if self.get_actor_system():
            await self.get_actor_system().send_message("user_session", message)
    
    async def _send_error_message(self, message: ActorMessage) -> None:
        """Отправка сообщения об ошибке"""
        chat_id = message.payload['chat_id']
        error_type = message.payload.get('error_type', 'api_error')
        
        # Останавливаем typing
        await self._stop_typing(chat_id)
        
        # Выбираем сообщение
        error_text = USER_MESSAGES.get(error_type, USER_MESSAGES["api_error"])
        
        await self._send_message(chat_id, error_text)
    
    async def _send_limit_exceeded_message(self, message: ActorMessage) -> None:
        """Отправка уведомления о превышении дневного лимита"""
        # Извлекаем данные из payload
        chat_id = message.payload.get('chat_id')
        if not chat_id:
            self.logger.warning("LIMIT_EXCEEDED received without chat_id")
            return
        
        # Останавливаем typing
        await self._stop_typing(chat_id)
        
        # Получаем значения для подстановки
        messages_today = message.payload.get('messages_today', 0)
        limit = message.payload.get('limit', DAILY_MESSAGE_LIMIT)
        
        # Логируем отправку уведомления
        self.logger.info(
            f"Sending limit exceeded notification to chat {chat_id}: "
            f"{messages_today}/{limit}"
        )
        
        # Получаем шаблон и форматируем
        limit_text = USER_MESSAGES["limit_exceeded"].format(
            messages_today=messages_today,
            limit=limit
        )
        
        # Отправляем сообщение
        await self._send_message(chat_id, limit_text)
    
    async def _send_message(self, chat_id: int, text: str, parse_mode: Optional[str] = "Markdown") -> None:
        """Отправка сообщения в Telegram"""
        # Разбиваем длинные сообщения
        chunks = self._split_long_message(text)
        
        for chunk in chunks:
            try:
                data = {
                    "chat_id": chat_id,
                    "text": chunk
                }
                if parse_mode:
                    data["parse_mode"] = parse_mode
                    
                await self._api_call(
                    "sendMessage",
                    data=data
                )
            except Exception as e:
                self.logger.error(f"Failed to send message to {chat_id}: {str(e)}")
                # Пробуем без Markdown
                try:
                    await self._api_call(
                        "sendMessage",
                        data={
                            "chat_id": chat_id,
                            "text": chunk
                        }
                    )
                except Exception as e2:
                    self.logger.error(f"Failed to send plain message: {str(e2)}")
    
    def _split_long_message(self, text: str) -> list:
        """Разбивка длинного сообщения на части"""
        if len(text) <= TELEGRAM_MAX_MESSAGE_LENGTH:
            return [text]
            
        # Разбиваем по параграфам
        chunks = []
        current = ""
        
        for paragraph in text.split("\n\n"):
            if len(current) + len(paragraph) + 2 > TELEGRAM_MAX_MESSAGE_LENGTH:
                if current:
                    chunks.append(current.strip())
                current = paragraph
            else:
                if current:
                    current += "\n\n"
                current += paragraph
                
        if current:
            chunks.append(current.strip())
            
        return chunks
    
    async def _start_typing(self, chat_id: int) -> None:
        """Запуск typing индикатора"""
        # Останавливаем предыдущий если есть
        await self._stop_typing(chat_id)
        
        # Периодическая очистка завершенных задач
        self._typing_cleanup_counter += 1
        if self._typing_cleanup_counter >= TELEGRAM_TYPING_CLEANUP_THRESHOLD:
            self._cleanup_typing_tasks()
            self._typing_cleanup_counter = 0
        
        # Проверяем лимит активных typing задач
        if len(self._typing_tasks) >= TELEGRAM_MAX_TYPING_TASKS:
            self.logger.warning(
                f"Typing tasks limit reached ({TELEGRAM_MAX_TYPING_TASKS}), "
                f"forcing cleanup"
            )
            # Принудительная очистка всех завершенных задач
            self._cleanup_typing_tasks()
            
            # Если все еще превышен лимит, удаляем самые старые
            if len(self._typing_tasks) >= TELEGRAM_MAX_TYPING_TASKS:
                # Удаляем первые 10% задач (самые старые)
                to_remove = max(1, len(self._typing_tasks) // 10)
                for _ in range(to_remove):
                    oldest_chat_id = next(iter(self._typing_tasks))
                    self._typing_tasks[oldest_chat_id].cancel()
                    del self._typing_tasks[oldest_chat_id]
                self.logger.warning(f"Forcefully removed {to_remove} oldest typing tasks")
        
        # Создаем новую задачу
        self._typing_tasks[chat_id] = asyncio.create_task(
            self._typing_loop(chat_id)
        )
    
    async def _stop_typing(self, chat_id: int) -> None:
        """Остановка typing индикатора"""
        if chat_id in self._typing_tasks:
            self._typing_tasks[chat_id].cancel()
            del self._typing_tasks[chat_id]
    
    async def _typing_loop(self, chat_id: int) -> None:
        """Цикл обновления typing индикатора"""
        try:
            while True:
                await self._api_call(
                    "sendChatAction",
                    data={
                        "chat_id": chat_id,
                        "action": "typing"
                    }
                )
                await asyncio.sleep(TELEGRAM_TYPING_UPDATE_INTERVAL)
        except asyncio.CancelledError:
            pass
    
    def _cleanup_typing_tasks(self) -> None:
        """Очистка завершенных typing задач из словаря"""
        completed_chats = []
        for chat_id, task in self._typing_tasks.items():
            if task.done():
                completed_chats.append(chat_id)
        
        for chat_id in completed_chats:
            del self._typing_tasks[chat_id]
            
        if completed_chats:
            self.logger.debug(f"Cleaned {len(completed_chats)} completed typing tasks")
    
    def _cleanup_expired_passwords(self) -> None:
        """Очистка устаревших состояний ожидания пароля"""
        from config.settings import AUTH_PASSWORD_WAIT_TIMEOUT
        
        now = datetime.now()
        expired_users = []
        
        for user_id, timestamp in self._awaiting_password.items():
            if (now - timestamp).total_seconds() > AUTH_PASSWORD_WAIT_TIMEOUT:
                expired_users.append(user_id)
        
        for user_id in expired_users:
            del self._awaiting_password[user_id]
            
        if expired_users:
            self.logger.debug(f"Cleaned {len(expired_users)} expired password wait states")
    
    async def _handle_auth_response(self, message: ActorMessage) -> None:
        """Обработка ответа на авторизацию"""
        chat_id = message.payload.get('chat_id')
        if not chat_id:
            self.logger.warning("AUTH_RESPONSE without chat_id")
            return
            
        success = message.payload.get('success', False)
        
        if success:
            # Форматируем дату
            expires_at = message.payload.get('expires_at', '')
            days_remaining = message.payload.get('days_remaining', 0)
            
            # Преобразуем ISO дату в читаемый формат
            try:
                from datetime import datetime
                dt = datetime.fromisoformat(expires_at.replace('Z', '+00:00'))
                expires_date = dt.strftime("%d.%m.%Y")
            except:
                expires_date = expires_at
            
            text = USER_MESSAGES["auth_success"].format(
                expires_date=expires_date,
                days_remaining=days_remaining
            )
        else:
            # Определяем тип ошибки
            error = message.payload.get('error', 'temporary_error')
            
            if error == 'invalid_password':
                text = USER_MESSAGES["auth_error_invalid"]
            elif error == 'blocked':
                # Вычисляем минуты до разблокировки
                blocked_until = message.payload.get('blocked_until')
                try:
                    from datetime import datetime, timezone
                    dt = datetime.fromisoformat(blocked_until.replace('Z', '+00:00'))
                    now = datetime.now(timezone.utc)
                    seconds = (dt - now).total_seconds()
                    minutes = max(1, int(seconds / 60))
                except:
                    minutes = 15
                    
                text = USER_MESSAGES["auth_error_blocked"].format(minutes=minutes)
            elif error == 'already_used':
                text = USER_MESSAGES["auth_error_already_used"]
            else:
                text = USER_MESSAGES["auth_error_temporary"]
        
        await self._send_message(chat_id, text)
    
    async def _handle_logout_response(self, message: ActorMessage) -> None:
        """Обработка ответа на logout"""
        chat_id = message.payload.get('chat_id')
        if not chat_id:
            self.logger.warning("LOGOUT_RESPONSE without chat_id")
            return
            
        success = message.payload.get('success', False)
        
        if success:
            text = USER_MESSAGES["logout_confirm"]
        else:
            text = USER_MESSAGES["logout_not_authorized"]
            
        await self._send_message(chat_id, text)
    
    async def _handle_admin_response(self, message: ActorMessage) -> None:
        """Обработка ответа на админскую команду"""
        chat_id = message.payload.get('chat_id')
        if not chat_id:
            self.logger.warning("ADMIN_RESPONSE without chat_id")
            return
            
        text = message.payload.get('text', '')
        if not text:
            self.logger.warning("ADMIN_RESPONSE without text")
            return
            
        # Отправляем без parse_mode чтобы избежать проблем с символами _ в командах
        await self._send_message(chat_id, text, parse_mode=None)
    
    async def _handle_status_response(self, message: ActorMessage) -> None:
        """Обработка ответа на /status"""
        chat_id = message.payload.get('chat_id')
        if not chat_id:
            self.logger.warning("LIMIT_RESPONSE for status without chat_id")
            return
            
        unlimited = message.payload.get('unlimited', False)
        
        if unlimited:
            # Форматируем дату
            expires_at = message.payload.get('expires_at', '')
            try:
                from datetime import datetime, timezone
                dt = datetime.fromisoformat(expires_at.replace('Z', '+00:00'))
                expires_date = dt.strftime("%d.%m.%Y")
                now = datetime.now(timezone.utc)
                days_remaining = (dt - now).days
            except:
                expires_date = expires_at
                days_remaining = 0
                
            text = USER_MESSAGES["status_authorized"].format(
                expires_date=expires_date,
                days_remaining=days_remaining
            )
        else:
            messages_today = message.payload.get('messages_today', 0)
            limit = message.payload.get('limit', DAILY_MESSAGE_LIMIT)
            
            text = USER_MESSAGES["status_demo"].format(
                messages_today=messages_today,
                daily_limit=limit
            )
            
        await self._send_message(chat_id, text)
    
    async def _api_call(
        self, 
        method: str, 
        data: Optional[Dict] = None,
        params: Optional[Dict] = None,
        timeout: Optional[int] = None
    ) -> Dict:
        """Базовый метод для вызова Telegram API"""
        url = f"{self._base_url}/{method}"
        
        async with self._session.post(
            url,
            json=data,
            params=params,
            timeout=timeout or TELEGRAM_API_DEFAULT_TIMEOUT
        ) as response:
            result = await response.json()
            
            if not result.get("ok"):
                raise Exception(f"Telegram API error: {result}")
                
            return result