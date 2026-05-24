# OmniaGuard Deployment Guide

> Fastest path: Supabase serverless (free) + Telegram polling
> Production path: Docker on VPS + webhook mode

---

## Deployment Option 1: Local/Free (Tonight)

**Cost: $0 | Time: 5 minutes**

Run the bot locally or on any machine with Python:

```bash
# Clone repo
git clone https://github.com/franciscoderek7/omniaguard.git
cd omniaguard

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Linux/Mac
# venv\Scripts\activate   # Windows

# Install dependencies
pip install -r requirements.txt

# Configure environment
cp .env.example .env
# Edit .env with your actual keys:
#   TELEGRAM_BOT_TOKEN=your_token
#   TOGETHER_API_KEY=your_key
#   SUPABASE_URL=your_url
#   SUPABASE_ANON_KEY=your_key
#   SUPABASE_SERVICE_KEY=your_key

# Self-test (verify all 14 agents)
python main.py --test

# Start bot (polling mode)
python main.py
```

The bot will start polling Telegram for messages. Test it:
1. Open Telegram
2. Find your bot (the one you created with BotFather)
3. Send `/start`
4. Send `/status`

---

## Deployment Option 2: Supabase Edge Functions (Free, Serverless)

**Cost: $0 | Time: 15 minutes**

Deploy as serverless functions on Supabase:

```bash
# Install Supabase CLI
npm install -g supabase

# Login
supabase login

# Link to project
supabase link --project-ref your-project-id

# Deploy edge function
supabase functions deploy omniaguard-webhook --no-verify-jwt
```

Then set Telegram webhook:
```bash
curl -X POST "https://api.telegram.org/bot<TOKEN>/setWebhook" \
  -d "url=https://your-project-id.supabase.co/functions/v1/omniaguard-webhook"
```

---

## Deployment Option 3: Docker on VPS (Production)

**Cost: ~$5-10/month | Time: 10 minutes**

```bash
# On your VPS (Hetzner, DigitalOcean, etc.)
git clone https://github.com/franciscoderek7/omniaguard.git
cd omniaguard

# Configure
cp .env.example .env
nano .env  # Add your keys

# Build and run
docker build -t omniaguard .
docker run -d --name omniaguard --env-file .env -p 8000:8000 omniaguard

# Verify
curl http://localhost:8000/health

# Set webhook
curl -X POST "https://api.telegram.org/bot<TOKEN>/setWebhook" \
  -d "url=https://api.omniaguard.com/webhook"
```

---

## Verification Checklist

```bash
# 1. Bot responds to /start
# Open Telegram → message your bot → /start

# 2. Health endpoint (webhook mode only)
curl https://api.omniaguard.com/health
# Expected: {"status": "operational", "agents": 14, "platform": "OmniaGuard"}

# 3. Self-test
python main.py --test
# Expected: 14 passed, 0 failed

# 4. Scan test
# In Telegram: /scan omniaguard.com
# Expected: Network scan results with severity rating
```

---

## Quick Reference

| Command | What It Does |
|---|---|
| `python main.py` | Start bot (polling) |
| `python main.py --webhook` | Start webhook server |
| `python main.py --test` | Run self-test |
| `docker build -t omniaguard .` | Build container |
| `docker run -d --env-file .env -p 8000:8000 omniaguard` | Run container |

---

## Troubleshooting

| Issue | Fix |
|---|---|
| Bot doesn't respond | Check TELEGRAM_BOT_TOKEN in .env |
| "Unauthorized" from Together AI | Check TOGETHER_API_KEY in .env |
| Supabase connection failed | Check SUPABASE_URL and keys |
| Webhook not receiving | Verify DNS + SSL + webhook URL |
| Agent scan timeout | Together AI may be slow — increase timeout |
