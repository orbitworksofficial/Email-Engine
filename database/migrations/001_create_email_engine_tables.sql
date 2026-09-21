-- DDL Migration: 001_create_email_engine_tables.sql
-- Description: Core tables for OrbitWorks Multi-Channel AI Email Automation Engine with RLS & state tracking

-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- 1. Webhook Raw Events Log Table (Idempotency & Auditing)
CREATE TABLE IF NOT EXISTS public.webhook_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL,
    provider VARCHAR(50) NOT NULL, -- meta_ads, linkedin_ads, google_ads, calendly, website, resend
    event_id VARCHAR(255),
    payload_hash VARCHAR(64) NOT NULL, -- sha256 of raw payload
    raw_payload JSONB NOT NULL,
    status VARCHAR(50) DEFAULT 'received', -- received, processing, completed, failed
    processed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    CONSTRAINT unique_tenant_provider_event UNIQUE (tenant_id, provider, event_id),
    CONSTRAINT unique_tenant_payload_hash UNIQUE (tenant_id, payload_hash)
);

-- 2. Suppression / Opt-Out List Table
CREATE TABLE IF NOT EXISTS public.suppression_list (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL,
    email VARCHAR(255) NOT NULL,
    reason VARCHAR(100) NOT NULL, -- unsubscribed, bounced, spam_complaint, manual
    created_at TIMESTAMPTZ DEFAULT NOW(),
    CONSTRAINT unique_tenant_suppressed_email UNIQUE (tenant_id, email)
);

-- 3. Email Campaign State Table
CREATE TABLE IF NOT EXISTS public.email_campaign_states (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL,
    lead_id TEXT NOT NULL,
    email_hash VARCHAR(64),
    channel_source VARCHAR(50) NOT NULL, -- meta_ads, linkedin_ads, google_ads, calendly, website
    utm_source VARCHAR(255),
    utm_medium VARCHAR(255),
    utm_campaign VARCHAR(255),
    gclid VARCHAR(255),
    current_step INT DEFAULT 1,
    status VARCHAR(50) DEFAULT 'active', -- active, paused_replied, paused_booked, paused_unsubscribed, bounced, failed, completed
    calendly_event_uri VARCHAR(500),
    meeting_scheduled_at TIMESTAMPTZ,
    next_scheduled_at TIMESTAMPTZ,
    context_data JSONB DEFAULT '{}'::jsonb,
    opt_out_reason VARCHAR(255),
    unsubscribed_at TIMESTAMPTZ,
    bounced_at TIMESTAMPTZ,
    reply_detected_at TIMESTAMPTZ,
    retry_count INT DEFAULT 0,
    last_error TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    CONSTRAINT unique_tenant_lead UNIQUE (tenant_id, lead_id)
);

-- 4. Email Telemetry and Dispatch Logs Table
CREATE TABLE IF NOT EXISTS public.email_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL,
    campaign_state_id UUID REFERENCES public.email_campaign_states(id) ON DELETE CASCADE,
    step_number INT NOT NULL,
    resend_message_id VARCHAR(255),
    recipient_email TEXT NOT NULL,
    subject TEXT NOT NULL,
    body_html TEXT NOT NULL,
    status VARCHAR(50) DEFAULT 'sent', -- sent, delivered, opened, clicked, bounced, replied, failed
    sent_at TIMESTAMPTZ DEFAULT NOW(),
    delivered_at TIMESTAMPTZ,
    opened_at TIMESTAMPTZ,
    clicked_at TIMESTAMPTZ,
    replied_at TIMESTAMPTZ,
    CONSTRAINT unique_tenant_campaign_step UNIQUE (tenant_id, campaign_state_id, step_number)
);

-- Indexes for Fast Query Performance
CREATE INDEX IF NOT EXISTS idx_campaign_states_tenant_status ON public.email_campaign_states(tenant_id, status);
CREATE INDEX IF NOT EXISTS idx_campaign_states_tenant_email_hash ON public.email_campaign_states(tenant_id, email_hash);
CREATE INDEX IF NOT EXISTS idx_campaign_states_lead ON public.email_campaign_states(lead_id);

CREATE INDEX IF NOT EXISTS idx_campaign_states_next_scheduled ON public.email_campaign_states(next_scheduled_at) WHERE status = 'active';
CREATE INDEX IF NOT EXISTS idx_email_logs_tenant_campaign ON public.email_logs(tenant_id, campaign_state_id);
CREATE INDEX IF NOT EXISTS idx_suppression_tenant_email ON public.suppression_list(tenant_id, email);
CREATE INDEX IF NOT EXISTS idx_webhook_events_tenant_hash ON public.webhook_events(tenant_id, payload_hash);

-- Row-Level Security (RLS) Configuration
ALTER TABLE public.webhook_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.suppression_list ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.email_campaign_states ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.email_logs ENABLE ROW LEVEL SECURITY;

-- Dynamic Tenant RLS Policies
CREATE POLICY tenant_isolation_webhook_events ON public.webhook_events
    FOR ALL USING (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid);

CREATE POLICY tenant_isolation_suppression_list ON public.suppression_list
    FOR ALL USING (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid);

CREATE POLICY tenant_isolation_campaign_states ON public.email_campaign_states
    FOR ALL USING (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid);

CREATE POLICY tenant_isolation_email_logs ON public.email_logs
    FOR ALL USING (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid);

-- RPC Wrapper for session context setting (strictly granted to service_role)
CREATE OR REPLACE FUNCTION public.set_config(setting text, value text, is_local boolean)
RETURNS void AS $$
BEGIN
  PERFORM set_config(setting, value, is_local);
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

REVOKE EXECUTE ON FUNCTION public.set_config(text, text, boolean) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.set_config(text, text, boolean) TO service_role;
