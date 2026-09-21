# OrbitWorks Multi-Channel AI Email Automation Engine — Production Deployment Guide

## 1. System Overview
The OrbitWorks Multi-Channel AI Email Automation Engine is a production-ready FastAPI backend designed to ingest leads from Meta Ads, LinkedIn Ads, and Landing Pages, synthesize hyper-personalized 1-on-1 consultative emails using Groq Llama-3 & OpenAI GPT-4o-mini, dispatch emails via Resend from verified domain `outreach@orb-itworks.com`, and track campaign states in Supabase.

---

## 2. Server Environment Variables (.env)

Configure these variables in your production server environment (Render, Railway, AWS, DigitalOcean, or Docker):

```env
# Application Environment
ENVIRONMENT=production
APP_SECRET_KEY=your_secure_32_byte_app_secret
PII_ENCRYPTION_KEY=your_secure_32_byte_pii_encryption_key
DEFAULT_TENANT_ID=00000000-0000-0000-0000-000000000001

# Supabase Database
SUPABASE_URL=https://your-project.supabase.co
SUPABASE_SERVICE_ROLE_KEY=your_supabase_service_role_key

# AI Copywriting & Dispatch
GROQ_API_KEY=gsk_your_groq_api_key
OPENAI_API_KEY=sk-proj-your_openai_api_key
RESEND_API_KEY=re_your_resend_api_key
DEFAULT_SENDER_EMAIL=outreach@orb-itworks.com
UNSUBSCRIBE_BASE_URL=https://api.yourdomain.com/api/v1/unsubscribe

# Webhook Secrets
CALENDLY_SCHEDULING_URL=https://calendly.com/hello-orb-itworks/30min
LINKEDIN_ADS_SECRET=your_linkedin_client_secret
META_WEBHOOK_VERIFY_TOKEN=your_meta_webhook_verify_token
META_APP_SECRET=your_meta_app_secret
WEBSITE_WEBHOOK_SECRET=your_website_webhook_secret
CALENDLY_WEBHOOK_SECRET=your_calendly_signing_secret
```

---

## 3. Server Execution Processes

The engine requires two background processes to be managed by systemd, Supervisor, Docker, or Process Manager:

### Process 1: FastAPI Web Server
```bash
gunicorn -w 4 -k uvicorn.workers.UvicornWorker ai_email_engine.main:app -b 0.0.0.0:8000
```

### Process 2: Sequence Scheduler & Crash Recovery Worker
```bash
python3 -m ai_email_engine.workers.sequence_scheduler
```

---

## 4. Post-Deployment Verification (Kashif's Checklist)

Once deployed to `https://api.yourdomain.com`:

### Step A: Health Check
```bash
curl https://api.yourdomain.com/health
```
**Expected Response:** `{"status": "healthy", "environment": "production"}`

### Step B: Live Webhook Ingestion & Email Dispatch Test
```bash
curl -X POST "https://api.yourdomain.com/api/v1/webhooks/website" \
  -H "Content-Type: application/json" \
  -H "X-Webhook-Signature: website_webhook_secret_key" \
  -d '{
    "email": "kashif_test@gmail.com",
    "full_name": "Kashif Test",
    "company_name": "Deployment Test Corp",
    "notes": "Testing post-deployment live webhook ingestion"
  }'
```
**Expected Response:** `HTTP 202 Accepted`.

### Step C: Register Calendly Webhook Subscription
Run this command to register Calendly with your live production domain:
```bash
curl -X POST "https://api.calendly.com/webhook_subscriptions" \
  -H "Authorization: Bearer <CALENDLY_PAT_TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{
    "url": "https://api.yourdomain.com/api/v1/webhooks/calendly",
    "events": ["invitee.created", "invitee.canceled"],
    "organization": "https://api.calendly.com/organizations/6848171c-cc5a-4104-97cf-b4a8e277983d",
    "scope": "organization"
  }'
```
Copy the returned `signing_key` and set it as `CALENDLY_WEBHOOK_SECRET` in your server environment variables.
