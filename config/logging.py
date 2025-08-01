import logging
import sys
from pathlib import Path
from pythonjsonlogger import jsonlogger
from config.settings import (
    LOG_LEVEL, 
    LOG_FORMAT, 
    LOG_DATE_FORMAT,
    ENABLE_JSON_LOGGING,
    JSON_LOG_FILE,
    LOG_ROTATION_ENABLED,
    LOG_MAX_BYTES,
    LOG_BACKUP_COUNT
)
from logging.handlers import RotatingFileHandler


class ColoredFormatter(logging.Formatter):
    """Форматтер для красивого цветного вывода логов с эмодзи"""
    
    # ANSI escape коды для цветов
    COLORS = {
        'DEBUG': '\033[36m',      # Cyan
        'INFO': '\033[32m',       # Green  
        'WARNING': '\033[33m',    # Yellow
        'ERROR': '\033[31m',      # Red
        'CRITICAL': '\033[35m',   # Magenta
        'RESET': '\033[0m',       # Reset
        'BOLD': '\033[1m',        # Bold
        'DIM': '\033[2m',         # Dim
    }
    
    # Эмодзи для уровней логирования
    EMOJIS = {
        'DEBUG': '🐛',
        'INFO': '✓', 
        'WARNING': '⚠️',
        'ERROR': '❌',
        'CRITICAL': '🔥'
    }
    
    # Эмодзи для разных компонентов системы
    COMPONENT_EMOJIS = {
        'actor.UserSession': '🧟‍♀️️',
        'actor.Generation': '👽',
        'actor.Memory': '💭',
        'actor.Perception': '❤️‍🔥 ',
        'actor.Telegram': '🦎',
        'actor_system': '🐍',
        'emotion_analyzer': '❤️‍🔥 ',
        'event_store': '📚',
        'circuit_breaker': '⚡',
        'database.connection': '📚',
        'default': '📝'
    }
    
    def format(self, record):
        # Определяем эмодзи компонента
        component_emoji = self.COMPONENT_EMOJIS['default']
        for component, emoji in self.COMPONENT_EMOJIS.items():
            if component in record.name:
                component_emoji = emoji
                break
        
        # Уровень и его атрибуты
        level = record.levelname
        level_color = self.COLORS.get(level, self.COLORS['RESET'])
        level_emoji = self.EMOJIS.get(level, '')
        
        # Форматируем время
        time_str = self.formatTime(record, self.datefmt)
        colored_time = f"{self.COLORS['DIM']}{time_str}{self.COLORS['RESET']}"
        
        # Форматируем имя логгера
        name_parts = record.name.split('.')
        if len(name_parts) > 2:
            # Сокращаем длинные имена
            short_name = f"{name_parts[0]}.{name_parts[-1]}"
        else:
            short_name = record.name
        
        # Цветной уровень
        colored_level = f"{level_color}{self.COLORS['DIM']}{level:8s}{self.COLORS['RESET']}"
        
        # Специальные эмодзи для определенных сообщений
        msg = record.getMessage()
        if 'starting' in msg.lower() or 'started' in msg.lower():
            msg = f"✨ {msg}"
        elif 'stopping' in msg.lower() or 'stopped' in msg.lower():
            msg = f"️💢 {msg}"
        elif 'connected' in msg.lower() or 'connection' in msg.lower():
            msg = f"🪢 {msg}"
        elif 'registered' in msg.lower() or 'initialized' in msg.lower():
            msg = f"💥 {msg}"
        elif 'error' in msg.lower() or 'failed' in msg.lower():
            msg = f"☠️ {msg}"
        elif 'shutdown' in msg.lower() or 'shutdown' in msg.lower():
            msg = f"㊗️ {msg}"
        
        # Раскрашиваем сообщение для ошибок
        if level in ['ERROR', 'CRITICAL']:
            msg = f"{level_color}{msg}{self.COLORS['RESET']}"
        
        # Собираем итоговую строку
        return f"{colored_time} {component_emoji} {level_emoji} {colored_level} {self.COLORS['DIM']}{short_name}{self.COLORS['RESET']} - {msg}"


# Глобальная переменная для хранения настроенности логирования
_logging_configured = False
_console_handler = None
_json_handler = None


def setup_logging():
    """Настройка системы логирования с поддержкой текстового и JSON форматов"""
    global _logging_configured, _console_handler, _json_handler
    
    if _logging_configured:
        return logging.getLogger()
    
    # Создаем директорию для логов если её нет
    if ENABLE_JSON_LOGGING:
        log_dir = Path(JSON_LOG_FILE).parent
        log_dir.mkdir(exist_ok=True)
    
    # Создаем форматтеры
    # Проверяем, поддерживает ли терминал цвета (для macOS и Linux всегда True)
    supports_color = hasattr(sys.stdout, 'isatty') and sys.stdout.isatty()
    
    if supports_color:
        # Используем цветной форматтер для консоли
        console_formatter = ColoredFormatter(datefmt=LOG_DATE_FORMAT)
    else:
        # Fallback на обычный форматтер
        console_formatter = logging.Formatter(LOG_FORMAT, datefmt=LOG_DATE_FORMAT)
    
    json_formatter = jsonlogger.JsonFormatter(
        '%(asctime)s %(name)s %(levelname)s %(message)s',
        datefmt=LOG_DATE_FORMAT
    )
    
    # Создаем обработчик для вывода в консоль
    _console_handler = logging.StreamHandler(sys.stdout)
    _console_handler.setFormatter(console_formatter)
    _console_handler.setLevel(LOG_LEVEL)
    
    # Настраиваем корневой логгер
    root_logger = logging.getLogger()
    root_logger.setLevel(LOG_LEVEL)
    root_logger.addHandler(_console_handler)
    
    # Добавляем JSON обработчик если включен
    if ENABLE_JSON_LOGGING:
        if LOG_ROTATION_ENABLED:
            # Используем RotatingFileHandler для автоматической ротации
            _json_handler = RotatingFileHandler(
                JSON_LOG_FILE,
                maxBytes=LOG_MAX_BYTES,
                backupCount=LOG_BACKUP_COUNT,
                encoding='utf-8'
            )
        else:
            # Обычный FileHandler без ротации
            _json_handler = logging.FileHandler(JSON_LOG_FILE, encoding='utf-8')
        
        _json_handler.setFormatter(json_formatter)
        _json_handler.setLevel(LOG_LEVEL)
        root_logger.addHandler(_json_handler)
    
    # Отключаем лишние логи от библиотек
    logging.getLogger("asyncio").setLevel(logging.WARNING)
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("openai").setLevel(logging.WARNING)
    
    # Применяем форматтер ко всем существующим логгерам
    for logger_name in logging.root.manager.loggerDict:
        logger = logging.getLogger(logger_name)
        logger.handlers = []  # Очищаем старые обработчики
        logger.propagate = True  # Используем обработчики родителя
    
    _logging_configured = True
    
    # Логируем приветственное сообщение с эмодзи
    # root_logger.info("🐲 Логи выводит Химера Невероятная:")
    
    return root_logger


def get_logger(name: str) -> logging.Logger:
    """Получить логгер с указанным именем"""
    logger = logging.getLogger(name)
    
    # Убеждаемся, что логгер использует правильные настройки
    if _logging_configured:
        logger.handlers = []  # Очищаем собственные обработчики
        logger.propagate = True  # Используем обработчики корневого логгера
        logger.setLevel(LOG_LEVEL)
    
    return logger