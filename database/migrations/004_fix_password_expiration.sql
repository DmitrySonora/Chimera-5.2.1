-- Добавляем поля для хранения оригинального срока действия
ALTER TABLE passwords ADD COLUMN IF NOT EXISTS first_used_at TIMESTAMP WITH TIME ZONE;
ALTER TABLE passwords ADD COLUMN IF NOT EXISTS expires_at TIMESTAMP WITH TIME ZONE;

-- Обновляем функцию привязки пароля
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
        used_at = CURRENT_TIMESTAMP,
        first_used_at = COALESCE(first_used_at, CURRENT_TIMESTAMP),
        expires_at = COALESCE(expires_at, p_expires_at)
    WHERE password = p_password
      AND is_active = TRUE
      AND (used_by IS NULL OR used_by = p_user_id);
    
    GET DIAGNOSTICS v_row_count = ROW_COUNT;
    
    RETURN v_row_count > 0;
END;
$$ LANGUAGE plpgsql;

-- Комментарии для документации
COMMENT ON COLUMN passwords.first_used_at IS 'Время первого использования пароля';
COMMENT ON COLUMN passwords.expires_at IS 'Оригинальный срок действия подписки';