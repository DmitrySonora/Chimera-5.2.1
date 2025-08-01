-- Таблицы для системы авторизации через временные пароли
-- Концепция: администратор создает пароли, пользователи их активируют

-- Таблица всех созданных паролей
CREATE TABLE IF NOT EXISTS passwords (
    password VARCHAR(100) PRIMARY KEY,
    password_hash VARCHAR(255) NOT NULL,
    duration_days INTEGER NOT NULL CHECK (duration_days IN (30, 90, 180, 365)),
    description TEXT NOT NULL,
    is_active BOOLEAN DEFAULT TRUE,
    used_by VARCHAR(255),
    used_at TIMESTAMP WITH TIME ZONE,
    created_by VARCHAR(255) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    deactivated_at TIMESTAMP WITH TIME ZONE,
    CONSTRAINT password_usage_consistency CHECK (
        (used_by IS NULL AND used_at IS NULL) OR 
        (used_by IS NOT NULL AND used_at IS NOT NULL)
    )
);

-- Индексы для passwords
CREATE INDEX IF NOT EXISTS idx_passwords_active_unused 
    ON passwords(is_active, used_by) WHERE is_active = TRUE AND used_by IS NULL;
CREATE INDEX IF NOT EXISTS idx_passwords_created_by 
    ON passwords(created_by);
CREATE INDEX IF NOT EXISTS idx_passwords_used_by 
    ON passwords(used_by) WHERE used_by IS NOT NULL;

-- Таблица активных авторизаций пользователей
CREATE TABLE IF NOT EXISTS authorized_users (
    user_id VARCHAR(255) PRIMARY KEY,
    password_used VARCHAR(100) NOT NULL,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    authorized_at TIMESTAMP WITH TIME ZONE NOT NULL,
    description TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE
);

-- Индексы для authorized_users
CREATE INDEX IF NOT EXISTS idx_authorized_users_expires 
    ON authorized_users(expires_at);
CREATE INDEX IF NOT EXISTS idx_authorized_users_password 
    ON authorized_users(password_used);

-- Таблица логирования всех попыток авторизации
CREATE TABLE IF NOT EXISTS auth_attempts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id VARCHAR(255) NOT NULL,
    password_attempt VARCHAR(100) NOT NULL,
    success BOOLEAN NOT NULL,
    error_reason VARCHAR(50),
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Индексы для auth_attempts
CREATE INDEX IF NOT EXISTS idx_auth_attempts_user_timestamp 
    ON auth_attempts(user_id, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_auth_attempts_timestamp 
    ON auth_attempts(timestamp);

-- Таблица временно заблокированных пользователей
CREATE TABLE IF NOT EXISTS blocked_users (
    user_id VARCHAR(255) PRIMARY KEY,
    blocked_until TIMESTAMP WITH TIME ZONE NOT NULL,
    attempt_count INTEGER NOT NULL,
    last_attempt TIMESTAMP WITH TIME ZONE NOT NULL
);

-- Комментарии для документации
COMMENT ON TABLE passwords IS 'Временные пароли, создаваемые администратором';
COMMENT ON COLUMN passwords.password IS 'Текст пароля (открытый для показа админу)';
COMMENT ON COLUMN passwords.password_hash IS 'Хеш пароля для проверки при вводе';
COMMENT ON COLUMN passwords.duration_days IS 'Срок действия подписки в днях (30/90/180/365)';
COMMENT ON COLUMN passwords.used_by IS 'telegram_id пользователя, привязавшего пароль';

COMMENT ON TABLE authorized_users IS 'Активные подписки пользователей';
COMMENT ON COLUMN authorized_users.expires_at IS 'Дата окончания подписки';
COMMENT ON COLUMN authorized_users.password_used IS 'Какой пароль использовал для активации';

COMMENT ON TABLE auth_attempts IS 'История всех попыток авторизации для аудита';
COMMENT ON COLUMN auth_attempts.error_reason IS 'invalid/expired/deactivated/already_used';

COMMENT ON TABLE blocked_users IS 'Anti-bruteforce защита через временную блокировку';

-- Функция для атомарной привязки пароля к пользователю
CREATE OR REPLACE FUNCTION bind_password_to_user(
    p_password VARCHAR(100),
    p_user_id VARCHAR(255),
    p_expires_at TIMESTAMP WITH TIME ZONE
) RETURNS BOOLEAN AS $$
DECLARE
    v_row_count INTEGER;
BEGIN
    -- Атомарно обновляем пароль, если он доступен или уже использован этим же пользователем
    UPDATE passwords
    SET used_by = p_user_id,
        used_at = CURRENT_TIMESTAMP
    WHERE password = p_password
      AND is_active = TRUE
      AND (used_by IS NULL OR used_by = p_user_id);
    
    GET DIAGNOSTICS v_row_count = ROW_COUNT;
    
    RETURN v_row_count > 0;
END;
$$ LANGUAGE plpgsql;