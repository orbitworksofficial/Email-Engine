-- Migration 002: Additional tables for API key auth, email drafts, rate limiting, schema versioning
-- Run AFTER 001_create_email_engine_tables.sql

-- Schema version tracking
CREATE TABLE IF NOT EXISTS public.schema_versions (
    version INT PRIMARY KEY,
    description TEXT NOT NULL,
    applied_at TIMESTAMPTZ DEFAULT NOW()
);
INSERT INTO public.schema_versions (version, description) VALUES (1, '001_create_email_engine_tables') ON CONFLICT DO NOTHING;
INSERT INTO public.schema_versions (version, description) VALUES (2, '002_add_drafts_api_keys_rate_limits') ON CONFLICT DO NOTHING;

-- Tenant API Keys (hashed) — source of tenant identity, replaces X-Tenant-ID header
CREATE TABLE IF NOT EXISTS public.tenant_api_keys (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL,
    api_key_hash VARCHAR(64) NOT NULL,  -- sha256 of raw key, never store plaintext
    label VARCHAR(100),                 -- human label e.g. "meta-ads-integration"
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    last_used_at TIMESTAMPTZ,
    CONSTRAINT unique_api_key_hash UNIQUE (api_key_hash)
);
CREATE INDEX IF NOT EXISTS idx_tenant_api_keys_hash ON public.tenant_api_keys(api_key_hash) WHERE is_active = true;

-- Email Drafts — for human-in-the-loop approval before send
CREATE TABLE IF NOT EXISTS public.email_drafts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL,
    campaign_state_id UUID REFERENCES public.email_campaign_states(id) ON DELETE CASCADE,
    step_number INT NOT NULL,
    recipient_email TEXT NOT NULL,   -- encrypted
    subject TEXT NOT NULL,
    body_html TEXT NOT NULL,
    status VARCHAR(50) DEFAULT 'pending_review',  -- pending_review, approved, rejected, sent
    reviewed_by VARCHAR(255),
    reviewed_at TIMESTAMPTZ,
    approved_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    CONSTRAINT unique_draft_campaign_step UNIQUE (tenant_id, campaign_state_id, step_number)
);
CREATE INDEX IF NOT EXISTS idx_email_drafts_tenant_status ON public.email_drafts(tenant_id, status);

-- Rate limit counters (sliding window per tenant per endpoint)
CREATE TABLE IF NOT EXISTS public.rate_limit_counters (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL,
    endpoint VARCHAR(100) NOT NULL,
    window_start TIMESTAMPTZ NOT NULL,
    count INT DEFAULT 1,
    CONSTRAINT unique_tenant_endpoint_window UNIQUE (tenant_id, endpoint, window_start)
);
CREATE INDEX IF NOT EXISTS idx_rate_limit_tenant_endpoint ON public.rate_limit_counters(tenant_id, endpoint, window_start);

-- RLS for new tables
ALTER TABLE public.tenant_api_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.email_drafts ENABLE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation_api_keys ON public.tenant_api_keys
    FOR ALL USING (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid);

CREATE POLICY tenant_isolation_email_drafts ON public.email_drafts
    FOR ALL USING (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid);
