-- Short-term memory buffer table
CREATE TABLE IF NOT EXISTS stm_buffer (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id VARCHAR(255) NOT NULL,
    message_type VARCHAR(20) NOT NULL CHECK (message_type IN ('user', 'bot')),
    content TEXT NOT NULL,
    timestamp TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    sequence_number BIGSERIAL NOT NULL,
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT unique_user_sequence UNIQUE(user_id, sequence_number)
);

-- Performance indexes
CREATE INDEX IF NOT EXISTS idx_stm_user_timestamp 
    ON stm_buffer(user_id, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_stm_user_sequence 
    ON stm_buffer(user_id, sequence_number DESC);
CREATE INDEX IF NOT EXISTS idx_stm_cleanup 
    ON stm_buffer(user_id, sequence_number ASC);

-- Comments for documentation
COMMENT ON TABLE stm_buffer IS 'Short-term memory buffer for storing recent interactions';
COMMENT ON COLUMN stm_buffer.message_type IS 'Type of message: user or bot';
COMMENT ON COLUMN stm_buffer.sequence_number IS 'Monotonically increasing number for ordering within user context';
COMMENT ON COLUMN stm_buffer.metadata IS 'Additional data: mode, emotions, confidence, etc.';

-- Cleanup function for atomic operations
CREATE OR REPLACE FUNCTION cleanup_stm_buffer(
    p_user_id VARCHAR(255),
    p_keep_count INTEGER
) RETURNS INTEGER AS $$
DECLARE
    v_deleted_count INTEGER;
BEGIN
    WITH to_delete AS (
        SELECT id
        FROM stm_buffer
        WHERE user_id = p_user_id
        ORDER BY sequence_number DESC
        OFFSET p_keep_count
    )
    DELETE FROM stm_buffer
    WHERE id IN (SELECT id FROM to_delete);
    
    GET DIAGNOSTICS v_deleted_count = ROW_COUNT;
    RETURN v_deleted_count;
END;
$$ LANGUAGE plpgsql;

-- Grant permissions if needed
-- GRANT ALL ON stm_buffer TO chimera_user;
-- GRANT USAGE ON SEQUENCE stm_buffer_sequence_number_seq TO chimera_user;