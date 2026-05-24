# OmniaGuard Telegram Bot — Setup Guide

## Prerequisites
- Telegram bot token from @BotFather (you already have @OmniguardSec_bot)
- Free Cloudflare account (workers.cloudflare.com)

## Setup Steps (5 minutes)

### Step 1: Create Cloudflare Worker
1. Go to https://workers.cloudflare.com
2. Sign up (free) or log in
3. Click "Create a Worker"
4. Delete the default code
5. Paste the contents of `cloudflare-worker.js`
6. Click "Save and Deploy"
7. Copy your Worker URL (e.g., `https://omniaguard-bot.your-subdomain.workers.dev`)

### Step 2: Add Environment Variable
1. In the Worker dashboard, go to Settings → Variables
2. Add: `BOT_TOKEN` = your BotFather token (the one for @OmniguardSec_bot)
3. Click "Encrypt" then "Save"

### Step 3: Set Webhook
Run this in your terminal (replace YOUR_TOKEN and YOUR_WORKER_URL):

```bash
curl "https://api.telegram.org/botYOUR_TOKEN/setWebhook?url=YOUR_WORKER_URL/webhook"
```

Expected response: `{"ok":true,"result":true,"description":"Webhook was set"}`

### Step 4: Test
1. Open Telegram
2. Message @OmniguardSec_bot
3. Send `/start`
4. Should receive: "OmniaGuard — Constitutional Shield for Agentic AI..."

## Bot Commands
| Command | Response |
|---------|----------|
| /start | Welcome + command list |
| /pricing | 3 tiers with prices |
| /status | 14 agents all ACTIVE |
| /contact | Email, phone, web |

## Keyword Routing
| Keywords | Response Type |
|----------|--------------|
| pay, pricing, cost, buy | Pricing tiers + Stripe links |
| sign up, register, join | Email capture + onboarding |
| protect, secure, attack | Capabilities + tier selection |
| children, guardian | Stats + disclaimer |
| 17 companies, empire | Stats + disclaimer |
| Anything else | "Clarify objective: secure, deploy, or escalate?" |

## Cloudflare Workers Free Tier
- 100,000 requests/day
- No credit card required
- Global edge deployment
- Zero cold starts

## Alternative: Vercel Serverless
If you prefer Vercel over Cloudflare:
1. Create `api/webhook.js` in a new Vercel project
2. Same logic applies — just wrap in `export default async function handler(req, res) {...}`
3. Deploy and set webhook URL to `https://your-project.vercel.app/api/webhook`
