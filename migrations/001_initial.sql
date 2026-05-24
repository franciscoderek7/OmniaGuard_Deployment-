-- R&D: OmniaGuard Initial Database Schema
-- Run this in Supabase SQL Editor (Dashboard → SQL Editor → New Query)
-- SR&ED: Database design for multi-agent security platform

-- ============================================
-- SCAN RESULTS TABLE
-- Stores all agent scan outputs for audit trail
-- ============================================
CREATE TABLE IF NOT EXISTS scan_results (
    id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
    agent_name TEXT NOT NULL,
    agent_number INTEGER NOT NULL CHECK (agent_number BETWEEN 1 AND 14),
    target TEXT NOT NULL,
    scan_type TEXT NOT NULL,
    severity TEXT NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info')),
    summary TEXT,
    findings JSONB DEFAULT '{}',
    recommendations TEXT[] DEFAULT '{}',
    triggered_by TEXT DEFAULT 'manual',  -- 'manual', 'scheduled', 'alert'
    telegram_chat_id BIGINT,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Index for fast lookups
CREATE INDEX idx_scan_results_agent ON scan_results(agent_name);
CREATE INDEX idx_scan_results_severity ON scan_results(severity);
CREATE INDEX idx_scan_results_target ON scan_results(target);
CREATE INDEX idx_scan_results_created ON scan_results(created_at DESC);

-- ============================================
-- ALERTS TABLE
-- Active security alerts requiring attention
-- ============================================
CREATE TABLE IF NOT EXISTS alerts (
    id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
    scan_result_id UUID REFERENCES scan_results(id),
    severity TEXT NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low')),
    title TEXT NOT NULL,
    description TEXT,
    status TEXT DEFAULT 'open' CHECK (status IN ('open', 'acknowledged', 'investigating', 'resolved', 'false_positive')),
    assigned_to TEXT,
    resolved_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_alerts_status ON alerts(status);
CREATE INDEX idx_alerts_severity ON alerts(severity);

-- ============================================
-- MONITORED ASSETS TABLE
-- Assets being continuously monitored
-- ============================================
CREATE TABLE IF NOT EXISTS monitored_assets (
    id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
    asset_type TEXT NOT NULL CHECK (asset_type IN ('domain', 'ip', 'email', 'cloud_account', 'endpoint', 'network')),
    asset_value TEXT NOT NULL,
    label TEXT,
    scan_frequency TEXT DEFAULT 'daily' CHECK (scan_frequency IN ('hourly', 'daily', 'weekly', 'monthly')),
    last_scanned_at TIMESTAMPTZ,
    last_severity TEXT,
    active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE UNIQUE INDEX idx_monitored_assets_unique ON monitored_assets(asset_type, asset_value);

-- ============================================
-- USERS TABLE (Telegram users authorized to use bot)
-- ============================================
CREATE TABLE IF NOT EXISTS authorized_users (
    id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
    telegram_id BIGINT UNIQUE NOT NULL,
    telegram_username TEXT,
    role TEXT DEFAULT 'viewer' CHECK (role IN ('admin', 'analyst', 'viewer')),
    active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- ============================================
-- AUDIT LOG TABLE (SR&ED compliance)
-- ============================================
CREATE TABLE IF NOT EXISTS audit_log (
    id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
    action TEXT NOT NULL,
    actor TEXT NOT NULL,
    details JSONB DEFAULT '{}',
    ip_address TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_audit_log_created ON audit_log(created_at DESC);
CREATE INDEX idx_audit_log_action ON audit_log(action);

-- ============================================
-- SCHEDULED SCANS TABLE
-- Automated recurring scans
-- ============================================
CREATE TABLE IF NOT EXISTS scheduled_scans (
    id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
    asset_id UUID REFERENCES monitored_assets(id),
    agent_name TEXT NOT NULL,
    scan_type TEXT NOT NULL,
    cron_expression TEXT NOT NULL,  -- e.g., '0 */6 * * *' for every 6 hours
    last_run_at TIMESTAMPTZ,
    next_run_at TIMESTAMPTZ,
    active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- ============================================
-- ROW LEVEL SECURITY (RLS)
-- ============================================
ALTER TABLE scan_results ENABLE ROW LEVEL SECURITY;
ALTER TABLE alerts ENABLE ROW LEVEL SECURITY;
ALTER TABLE monitored_assets ENABLE ROW LEVEL SECURITY;
ALTER TABLE authorized_users ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_log ENABLE ROW LEVEL SECURITY;
ALTER TABLE scheduled_scans ENABLE ROW LEVEL SECURITY;

-- Service role can do everything (backend)
CREATE POLICY "Service role full access" ON scan_results FOR ALL
    USING (auth.role() = 'service_role');
CREATE POLICY "Service role full access" ON alerts FOR ALL
    USING (auth.role() = 'service_role');
CREATE POLICY "Service role full access" ON monitored_assets FOR ALL
    USING (auth.role() = 'service_role');
CREATE POLICY "Service role full access" ON authorized_users FOR ALL
    USING (auth.role() = 'service_role');
CREATE POLICY "Service role full access" ON audit_log FOR ALL
    USING (auth.role() = 'service_role');
CREATE POLICY "Service role full access" ON scheduled_scans FOR ALL
    USING (auth.role() = 'service_role');

-- ============================================
-- INITIAL DATA
-- ============================================

-- Add Derek as admin
INSERT INTO authorized_users (telegram_id, telegram_username, role)
VALUES (0, 'franciscoderek7', 'admin')
ON CONFLICT (telegram_id) DO NOTHING;

-- Done
SELECT 'OmniaGuard database initialized successfully' AS status;
