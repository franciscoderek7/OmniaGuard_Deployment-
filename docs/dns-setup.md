# OmniaGuard DNS Setup — Porkbun

> Domain: omniaguard.com
> Registrar: Porkbun
> Deployment: Supabase Edge Functions (serverless)

---

## Option A: Serverless (Supabase — Recommended, $0/month)

Since we're deploying on Supabase Edge Functions, DNS points to Supabase:

### Porkbun DNS Records

| Type | Host | Value | TTL |
|---|---|---|---|
| CNAME | @ | `your-project-id.supabase.co` | 600 |
| CNAME | www | `your-project-id.supabase.co` | 600 |
| CNAME | api | `your-project-id.supabase.co` | 600 |

### Steps:
1. Log into Porkbun → Domain Management → omniaguard.com
2. Click "DNS" tab
3. Delete any existing A records for @ and www
4. Add the CNAME records above
5. In Supabase: Settings → Custom Domains → Add `omniaguard.com`
6. Supabase will provide verification TXT record — add that too
7. Wait 5-30 minutes for propagation

---

## Option B: VPS Deployment (Hetzner — if you get a server later)

If you later deploy to a VPS:

| Type | Host | Value | TTL |
|---|---|---|---|
| A | @ | `YOUR_SERVER_IP` | 300 |
| A | www | `YOUR_SERVER_IP` | 300 |
| A | api | `YOUR_SERVER_IP` | 300 |

---

## Verification

After DNS propagation (5-30 min):

```bash
# Check DNS resolution
dig omniaguard.com
dig api.omniaguard.com

# Check HTTPS
curl -I https://omniaguard.com
curl https://api.omniaguard.com/health
```

---

## Telegram Webhook (After DNS is Live)

Once `api.omniaguard.com` resolves:

```bash
# Set webhook URL
curl -X POST "https://api.telegram.org/bot<TOKEN>/setWebhook" \
  -H "Content-Type: application/json" \
  -d '{"url": "https://api.omniaguard.com/webhook"}'

# Verify webhook
curl "https://api.telegram.org/bot<TOKEN>/getWebhookInfo"
```

---

## SSL/TLS

- Supabase: Automatic SSL (Let's Encrypt) — no action needed
- VPS: Use Caddy (auto-SSL) or certbot with nginx
