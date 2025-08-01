"""
Тексты сообщений для логирования на русском языке
"""

LOG_MESSAGES = {
    # ActorSystem
    "actor_registered": "Зарегистрирован актор {actor_id}",
    "actor_already_registered": "Актор {actor_id} уже зарегистрирован",
    "actor_not_found": "Актор {actor_id} не найден",
    "actor_unregistered": "Актор {actor_id} удален из системы",
    "actor_system_starting": "Запуск системы акторов",
    "actor_system_already_running": "Система акторов уже запущена",
    "actor_system_started": "Запущено {count} акторов",
    "actor_system_stopping": "Остановка системы акторов",
    "actor_system_not_running": "Система акторов не запущена",
    "actor_system_stopped": "Система акторов остановлена",
    "actor_system_shutdown_timeout": "Таймаут остановки акторов, принудительное завершение",
    "event_store_connected": "Event Store подключен к системе акторов",
    
    # BaseActor
    "actor_starting": "Запуск актора {name}",
    "actor_already_running": "Актор уже запущен",
    "actor_started": "Актор {name} запущен",
    "actor_stopping": "Остановка актора {name}",
    "actor_not_running_stop": "Актор не запущен",
    "actor_stopped": "Актор {name} остановлен",
    "actor_shutdown_timeout": "Таймаут остановки актора {name}",
    "actor_message_received": "Получено сообщение {message_type} от {sender_id}",
    "actor_shutdown_received": "Получено сообщение остановки",
    "actor_message_loop_started": "Цикл обработки сообщений запущен",
    "actor_message_loop_ended": "Цикл обработки сообщений завершен",
    "actor_message_error": "Ошибка обработки сообщения {message_type}: {error}",
    "actor_queue_full": "Очередь сообщений переполнена, сообщение {message_id} отброшено",
    
    # UserSessionActor
    "session_initialized": "UserSessionActor инициализирован",
    "session_shutdown": "UserSessionActor остановлен, очищено {count} сессий",
    "session_created": "Создана новая сессия для пользователя {user_id}",
    "generate_response_created": "Создан запрос GENERATE_RESPONSE для пользователя {user_id}",
    
    # GenerationActor
    "generation_initialized": "GenerationActor инициализирован с DeepSeek API",
    "generation_shutdown": "GenerationActor остановлен. Сгенерировано {count} ответов, ошибок JSON: {failures}",
    "generation_starting": "Генерация ответа для пользователя {user_id}",
    "generation_completed": "Сгенерирован ответ для пользователя {user_id}: {preview}...",
    "generation_failed": "Ошибка генерации для пользователя {user_id}: {error}",
    "json_parse_failed": "Ошибка парсинга JSON для пользователя {user_id}, используется fallback",
    "cache_metrics": "Метрики кэша - Генераций: {count}, Средний hit rate: {avg_rate:.2%}, Последний: {last_rate:.2%}",
    
    # TelegramActor
    "telegram_initialized": "TelegramInterfaceActor инициализирован",
    "telegram_connected": "Подключен как @{username}",
    "telegram_shutdown": "TelegramInterfaceActor остановлен",
    "telegram_polling_started": "Запущен polling Telegram",
    "telegram_polling_stopped": "Остановлен polling Telegram",
    "telegram_polling_error": "Ошибка polling: {error}",
    "telegram_update_error": "Ошибка получения обновлений: {error}",
    "telegram_message_processed": "Обработано сообщение от пользователя {user_id}: {preview}...",
    "telegram_send_error": "Ошибка отправки сообщения в чат {chat_id}: {error}",
    "telegram_send_plain_error": "Ошибка отправки простого сообщения: {error}",
    
    # Circuit Breaker
    "circuit_breaker_open": "Circuit breaker {name} открыт, вызов отклонен",
    "circuit_breaker_half_open": "Circuit breaker {name} перешел в режим HALF_OPEN",
    "circuit_breaker_closed": "Circuit breaker {name} перешел в режим CLOSED",
    "circuit_breaker_failure": "Circuit breaker {name} открыт после {count} ошибок",
    "circuit_breaker_reset": "Circuit breaker {name} сброшен",
    
    # Dead Letter Queue
    "dlq_message_sent": "Сообщение {message_id} отправлено в DLQ. Актор: {actor_id}, Ошибка: {error}",
    "dlq_cleared": "Очищено {count} сообщений из Dead Letter Queue",
    "dlq_cleanup": "DLQ очистка: удалено {count} старых сообщений. Всего очищено: {total}",
    "dlq_warning": "DLQ заполнен на 90%: {current}/{max}",
    "dlq_metrics": "Метрики DLQ - Текущий размер: {size}, Всего получено: {total}, Очищено: {cleaned}",
    
    # Retry механизм
    "retry_attempt": "Очередь сообщений для {actor_id} переполнена, попытка {attempt}/{max} через {delay:.1f}с",
    "retry_failed": "Не удалось отправить сообщение в {actor_id} после {max} попыток",
    
    # Event Store
    "event_appended": "Событие {event_type} добавлено в поток {stream_id} с версией {version}",
    "event_store_cleanup": "Запущена очистка Event Store. Нужно удалить {count} событий",
    "event_store_cleanup_done": "Очистка Event Store завершена. Удалено {streams} потоков, {events} событий",
    "event_store_metrics": "Метрики Event Store - События: {events}, Добавлений: {appends}, Чтений: {reads}, Cache hit: {cache_hit}%",
}