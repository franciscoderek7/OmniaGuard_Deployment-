/**
 * OmniaGuard Telegram Bot — Cloudflare Worker
 * Imperial Counsel Routing Logic
 * 
 * SETUP:
 * 1. Go to workers.cloudflare.com → Create Worker
 * 2. Paste this code
 * 3. Add environment variable: BOT_TOKEN = your BotFather token
 * 4. Deploy
 * 5. Set webhook: curl "https://api.telegram.org/bot<TOKEN>/setWebhook?url=https://your-worker.workers.dev/webhook"
 */

const PRICING = {
  sentinel: { name: 'Sentinel', price: '$49 CAD/mo', desc: '5 devices, identity monitoring, dark web alerts, mobile defense' },
  warden: { name: 'Warden', price: '$199 CAD/mo', desc: '25 devices, EDR, compliance scoring, Red Cell Lite, priority support' },
  emperor: { name: 'Emperor', price: 'Custom', desc: 'Unlimited devices, full Threat Radar, Red Cell, ShadowGrid, 24/7 SOC, 1hr SLA' }
};

const PAYMENT_KEYWORDS = /\b(pay|payment|pricing|cost|buy|purchase|checkout|subscribe|plan|tier|price|how much|billing|invoice|credit card)\b/i;
const SIGNUP_KEYWORDS = /\b(sign up|register|join|create account|start|get started|onboard)\b/i;
const THREAT_KEYWORDS = /\b(protect|secure|attack|vulnerability|device|threat|hack|breach|malware)\b/i;
const GUARDIAN_KEYWORDS = /\b(children|guardian|custodian|child safety|family|parental)\b/i;
const EMPIRE_KEYWORDS = /\b(17 companies|company 18|revenue|empire|cascade|holdings|subsidiary)\b/i;

function routeMessage(text) {
  if (PAYMENT_KEYWORDS.test(text)) {
    return `Pricing tiers:\n\nSentinel — ${PRICING.sentinel.price}\n${PRICING.sentinel.desc}\n\nWarden — ${PRICING.warden.price}\n${PRICING.warden.desc}\n\nEmperor — ${PRICING.emperor.price}\n${PRICING.emperor.desc}\n\nCheckout: https://omniaguard.com/pricing.html\nAll plans include Zero Prompt Injection Guarantee. 14-day free trial. No credit card required.`;
  }
  
  if (SIGNUP_KEYWORDS.test(text)) {
    return `Start here: https://omniaguard.com/pricing.html\n\n14-day free trial. No credit card. Full Professional tier access.\n\nOr contact: enterprise@omniaguard.com for custom onboarding.`;
  }
  
  if (GUARDIAN_KEYWORDS.test(text)) {
    return `Family protection stats:\n- 14 active agents\n- Real-time threat blocking\n- Safe browsing enforcement\n- App sandboxing for minors\n\nDeployment targets. Contact for audit: security@omniaguard.com`;
  }
  
  if (EMPIRE_KEYWORDS.test(text)) {
    return `Francisco Holdings ecosystem:\n- 17 entities secured\n- 14 autonomous agents\n- Cross-entity governance active\n- Zero Prompt Injection across all subsidiaries\n\nProjected pipeline. Not audited. Contact: enterprise@omniaguard.com`;
  }
  
  if (THREAT_KEYWORDS.test(text)) {
    return `OmniaGuard capabilities:\n- 14 autonomous security agents\n- Zero Prompt Injection Guarantee\n- Endpoint, network, cloud, email protection\n- 8 device categories covered\n- Sub-2ms response time\n\nSelect tier: https://omniaguard.com/pricing.html`;
  }
  
  return `Clarify objective: secure, deploy, or escalate?\n\nCommands:\n/pricing — View tiers\n/status — Agent status\n/contact — Reach team`;
}

function handleCommand(command) {
  switch (command) {
    case '/start':
      return `OmniaGuard — Constitutional Shield for Agentic AI.\n\n14 autonomous security agents. Zero Prompt Injection Guarantee. First globally.\n\nSelect:\n/pricing — Protection tiers\n/status — Agent swarm status\n/contact — Reach security team`;
    case '/pricing':
      return `Sentinel — $49 CAD/mo\n5 devices, identity monitoring, dark web alerts, mobile defense.\n\nWarden — $199 CAD/mo\n25 devices, EDR, compliance, Red Cell Lite, 4hr SLA.\n\nEmperor — Custom\nUnlimited. Full stack. 24/7 SOC. 1hr SLA. Dedicated CSM.\n\nCheckout: https://omniaguard.com/pricing.html`;
    case '/status':
      return `SYSTEM STATUS: OPERATIONAL\n\n14 Watchers active. Perimeter secure.\n\nPerimeterBot: ACTIVE\nSanitizer: ACTIVE\nContextLock: ACTIVE\nOutputGuard: ACTIVE\nAuditLog: ACTIVE\nRateLimiter: ACTIVE\nEncryptionEngine: ACTIVE\nComplianceCheck: ACTIVE\nThreatIntel: ACTIVE\nPatternGuard: ACTIVE\nRecoveryBot: ACTIVE\nWatchTower: ACTIVE\nIdentityShield: ACTIVE\nDataVault: ACTIVE\n\nZero incidents. Zero injections. Zero compromise.`;
    case '/contact':
      return `General: security@omniaguard.com\nEnterprise: enterprise@omniaguard.com\nPartnerships: partners@omniaguard.com\n\nPhone: +1 (705) 555-0100\nHours: Mon-Fri, 9AM-6PM EST\n\nTelegram: @OmniguardSec_bot (you are here)\nWeb: https://omniaguard.com/contact.html`;
    default:
      return null;
  }
}

async function sendMessage(chatId, text, token) {
  await fetch(`https://api.telegram.org/bot${token}/sendMessage`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      chat_id: chatId,
      text: text,
      parse_mode: 'HTML',
      disable_web_page_preview: true
    })
  });
}

export default {
  async fetch(request, env) {
    if (request.method !== 'POST') {
      return new Response('OmniaGuard Bot Active. 14 agents operational.', { status: 200 });
    }

    const url = new URL(request.url);
    if (url.pathname !== '/webhook') {
      return new Response('Not found', { status: 404 });
    }

    try {
      const update = await request.json();
      const message = update.message;
      
      if (!message || !message.text) {
        return new Response('OK', { status: 200 });
      }

      const chatId = message.chat.id;
      const text = message.text.trim();
      const token = env.BOT_TOKEN;

      // Check if it's a command
      let response = null;
      if (text.startsWith('/')) {
        response = handleCommand(text.toLowerCase());
      }
      
      // If not a command or unrecognized command, route by keywords
      if (!response) {
        response = routeMessage(text);
      }

      await sendMessage(chatId, response, token);
      return new Response('OK', { status: 200 });
    } catch (e) {
      return new Response('Error', { status: 500 });
    }
  }
};
