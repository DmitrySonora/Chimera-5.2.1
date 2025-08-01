-- Основная таблица событий
CREATE TABLE IF NOT EXISTS events (
    event_id UUID PRIMARY KEY,
    stream_id VARCHAR(255) NOT NULL,
    event_type VARCHAR(100) NOT NULL,
    data JSONB NOT NULL,
    timestamp TIMESTAMP WITH TIME ZONE NOT NULL,
    version INTEGER NOT NULL,
    correlation_id UUID,
    archived BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT unique_stream_version UNIQUE(stream_id, version)
);

-- Индексы для производительности
CREATE INDEX IF NOT EXISTS idx_events_stream_timestamp 
    ON events(stream_id, timestamp);
CREATE INDEX IF NOT EXISTS idx_events_type_timestamp 
    ON events(event_type, timestamp);
CREATE INDEX IF NOT EXISTS idx_events_timestamp_archived 
    ON events(timestamp) WHERE NOT archived;
CREATE INDEX IF NOT EXISTS idx_events_correlation_id 
    ON events(correlation_id) WHERE correlation_id IS NOT NULL;

-- Таблица метаданных для версионирования схемы
CREATE TABLE IF NOT EXISTS event_store_metadata (
    key VARCHAR(50) PRIMARY KEY,
    value JSONB NOT NULL,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Инициализация метаданных
INSERT INTO event_store_metadata (key, value) 
VALUES ('schema_version', '{"version": 1}')
ON CONFLICT (key) DO NOTHING;

-- Функция для автоматического обновления updated_at
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Триггер для event_store_metadata (создаётся только если ещё не существует)
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_trigger
        WHERE tgname = 'update_event_store_metadata_updated_at'
    ) THEN
        CREATE TRIGGER update_event_store_metadata_updated_at 
        BEFORE UPDATE ON event_store_metadata
        FOR EACH ROW
        EXECUTE FUNCTION update_updated_at_column();
    END IF;
END;
$$;
