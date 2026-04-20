-- ==========================================================
-- Ticket Bot Detection System — PostgreSQL Schema
-- ==========================================================

CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ── Sessions ──────────────────────────────────────────────
CREATE TABLE sessions (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    session_token           VARCHAR(128) NOT NULL UNIQUE,
    user_id                 VARCHAR(128),
    ip_address              INET NOT NULL,
    user_agent              TEXT,
    created_at              TIMESTAMPTZ DEFAULT NOW(),
    completed_at            TIMESTAMPTZ,

    -- Behavioral signals
    time_to_select          FLOAT,
    time_to_checkout        FLOAT,
    mouse_entropy           FLOAT,
    mouse_path_length       INTEGER,
    scroll_events           INTEGER,
    focus_events            INTEGER,
    hover_duration          FLOAT,
    keystroke_regularity    FLOAT,
    selection_method        VARCHAR(32),

    -- Device fingerprints
    canvas_fp               VARCHAR(128),
    audio_fp                VARCHAR(128),
    webgl_fp                VARCHAR(128),
    viewport                VARCHAR(32),
    tz_offset               INTEGER,

    -- Risk output
    risk_score              FLOAT,
    risk_verdict            VARCHAR(16) CHECK (risk_verdict IN ('human','suspicious','bot')),
    risk_reason             TEXT,
    action                  VARCHAR(16) CHECK (action IN ('pass','queue','block')),
    action_at               TIMESTAMPTZ
);

-- ── IP Velocity ───────────────────────────────────────────
CREATE TABLE ip_velocity (
    subnet                  CIDR PRIMARY KEY,
    request_count           INTEGER DEFAULT 0,
    session_count           INTEGER DEFAULT 0,
    blocked_count           INTEGER DEFAULT 0,
    last_seen               TIMESTAMPTZ DEFAULT NOW(),
    flagged                 BOOLEAN DEFAULT FALSE,
    flag_reason             TEXT,
    updated_at              TIMESTAMPTZ DEFAULT NOW()
);

-- ── Device Fingerprints ───────────────────────────────────
CREATE TABLE device_fingerprints (
    fingerprint_hash        VARCHAR(128) PRIMARY KEY,
    fingerprint_type        VARCHAR(16) DEFAULT 'canvas',
    first_seen              TIMESTAMPTZ DEFAULT NOW(),
    last_seen               TIMESTAMPTZ DEFAULT NOW(),
    session_count           INTEGER DEFAULT 1,
    bot_count               INTEGER DEFAULT 0,
    trust_score             FLOAT DEFAULT 0.5
);

-- ── Silent Queue ──────────────────────────────────────────
CREATE TABLE checkout_queue (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    session_id              UUID REFERENCES sessions(id),
    user_id                 VARCHAR(128),
    ticket_ids              JSONB NOT NULL,
    checkout_data           JSONB NOT NULL,
    queued_at               TIMESTAMPTZ DEFAULT NOW(),
    expires_at              TIMESTAMPTZ DEFAULT NOW() + INTERVAL '5 minutes',
    reviewed_at             TIMESTAMPTZ,
    review_action           VARCHAR(16) CHECK (review_action IN ('approved','rejected','expired')),
    reviewed_by             VARCHAR(64)
);

-- ── Audit Log (append-only) ───────────────────────────────
CREATE TABLE audit_log (
    id                      BIGSERIAL PRIMARY KEY,
    session_id              UUID REFERENCES sessions(id),
    event_type              VARCHAR(64) NOT NULL,
    event_data              JSONB,
    created_at              TIMESTAMPTZ DEFAULT NOW()
);

-- ── Indexes ───────────────────────────────────────────────
CREATE INDEX idx_sessions_ip         ON sessions(ip_address);
CREATE INDEX idx_sessions_user       ON sessions(user_id);
CREATE INDEX idx_sessions_created    ON sessions(created_at DESC);
CREATE INDEX idx_sessions_verdict    ON sessions(risk_verdict);
CREATE INDEX idx_sessions_token      ON sessions(session_token);
CREATE INDEX idx_audit_session       ON audit_log(session_id);
CREATE INDEX idx_audit_created       ON audit_log(created_at DESC);
CREATE INDEX idx_queue_expires       ON checkout_queue(expires_at)
    WHERE review_action IS NULL;

-- ── Auto-expire queue entries ─────────────────────────────
CREATE OR REPLACE FUNCTION expire_queue_entries()
RETURNS void LANGUAGE sql AS $$
    UPDATE checkout_queue
    SET review_action = 'expired', reviewed_at = NOW()
    WHERE expires_at < NOW() AND review_action IS NULL;
$$;
