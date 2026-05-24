/**
 * OmniaGuard Imperial Counsel — Chat Widget
 * Keyword-routed conversion funnel. No emojis. No philosophy.
 * Active voice. Max 80 words unless technical spec.
 */
(function() {
  const PAYMENT_RE = /\b(pay|payment|pricing|cost|buy|purchase|checkout|subscribe|plan|tier|price|how much|billing|invoice|credit card)\b/i;
  const SIGNUP_RE = /\b(sign up|register|join|create account|start|get started|onboard)\b/i;
  const THREAT_RE = /\b(protect|secure|attack|vulnerability|device|threat|hack|breach|malware|defend)\b/i;
  const GUARDIAN_RE = /\b(children|guardian|custodian|child safety|family|parental|kids)\b/i;
  const EMPIRE_RE = /\b(17 companies|company 18|revenue|empire|cascade|holdings|subsidiary|portfolio)\b/i;

  function route(msg) {
    if (PAYMENT_RE.test(msg)) {
      return `Three tiers. All CAD. All include Zero Prompt Injection Guarantee.\n\nSentinel — $49/mo\n5 devices. Identity monitoring. Dark web alerts. Mobile defense.\n\nWarden — $199/mo\n25 devices. EDR. Compliance scoring. Red Cell Lite. 4hr SLA.\n\nEmperor — Custom\nUnlimited. Full stack. 24/7 SOC. 1hr SLA.\n\n→ pricing.html`;
    }
    if (SIGNUP_RE.test(msg)) {
      return `Start: 14-day free trial. No credit card.\n\nEnter your email below. Welcome sequence deploys immediately.\n\nOr contact: enterprise@omniaguard.com for custom onboarding.`;
    }
    if (GUARDIAN_RE.test(msg)) {
      return `Family protection:\n• 14 active agents\n• Real-time threat blocking\n• App sandboxing for minors\n• Safe browsing enforcement\n\nDeployment targets. Contact for audit.`;
    }
    if (EMPIRE_RE.test(msg)) {
      return `Francisco Holdings ecosystem:\n• 17 entities secured\n• 14 autonomous agents\n• Cross-entity governance active\n• Zero injection across all subsidiaries\n\nProjected pipeline. Not audited.`;
    }
    if (THREAT_RE.test(msg)) {
      return `OmniaGuard capabilities:\n• 14 autonomous security agents\n• Zero Prompt Injection Guarantee\n• 8 device categories covered\n• Sub-2ms response time\n• Constitutional Shield architecture\n\nSelect tier: pricing.html`;
    }
    return `Clarify objective: secure, deploy, or escalate?\n\nCommands: pricing, sign up, status, contact`;
  }

  // Build widget HTML
  const style = document.createElement('style');
  style.textContent = `
    #og-chat-btn{position:fixed;bottom:24px;right:24px;width:56px;height:56px;border-radius:50%;background:#00FF41;border:none;cursor:pointer;z-index:9999;display:flex;align-items:center;justify-content:center;box-shadow:0 4px 20px rgba(0,255,65,.3);transition:transform .15s ease-out}
    #og-chat-btn:hover{transform:scale(1.08)}
    #og-chat-btn:active{transform:scale(.95)}
    #og-chat-btn svg{width:28px;height:28px;fill:#0a0a0a}
    #og-chat-panel{position:fixed;bottom:92px;right:24px;width:360px;max-height:480px;background:#0d1117;border:1px solid #1a2332;border-radius:12px;z-index:9999;display:none;flex-direction:column;box-shadow:0 8px 40px rgba(0,0,0,.6);font-family:Inter,sans-serif}
    #og-chat-panel.open{display:flex}
    #og-chat-hdr{padding:14px 16px;border-bottom:1px solid #1a2332;display:flex;align-items:center;gap:8px}
    #og-chat-hdr .dot{width:8px;height:8px;border-radius:50%;background:#00FF41;animation:pulse-dot 2s infinite}
    @keyframes pulse-dot{0%,100%{opacity:1}50%{opacity:.4}}
    #og-chat-hdr span{color:#e6edf3;font-size:13px;font-weight:600}
    #og-chat-hdr small{color:#7d8590;font-size:11px;margin-left:auto}
    #og-chat-msgs{flex:1;overflow-y:auto;padding:12px 16px;display:flex;flex-direction:column;gap:10px;max-height:320px}
    .og-msg{max-width:85%;padding:10px 14px;border-radius:10px;font-size:12px;line-height:1.5;white-space:pre-line}
    .og-msg.bot{background:#161b22;color:#e6edf3;align-self:flex-start;border:1px solid #1a2332}
    .og-msg.user{background:#00FF41;color:#0a0a0a;align-self:flex-end;font-weight:500}
    #og-chat-input{display:flex;border-top:1px solid #1a2332;padding:10px 12px;gap:8px}
    #og-chat-input input{flex:1;background:#161b22;border:1px solid #1a2332;border-radius:8px;padding:8px 12px;color:#e6edf3;font-size:12px;outline:none}
    #og-chat-input input:focus{border-color:#00FF41}
    #og-chat-input button{background:#00FF41;border:none;border-radius:8px;padding:8px 14px;color:#0a0a0a;font-size:12px;font-weight:600;cursor:pointer}
    #og-chat-input button:hover{background:#00cc33}
    @media(max-width:480px){#og-chat-panel{width:calc(100vw - 32px);right:16px;bottom:84px}}
  `;
  document.head.appendChild(style);

  const btn = document.createElement('button');
  btn.id = 'og-chat-btn';
  btn.setAttribute('aria-label', 'Open chat');
  btn.innerHTML = '<svg viewBox="0 0 24 24"><path d="M20 2H4c-1.1 0-2 .9-2 2v18l4-4h14c1.1 0 2-.9 2-2V4c0-1.1-.9-2-2-2zm0 14H5.2L4 17.2V4h16v12z"/></svg>';
  document.body.appendChild(btn);

  const panel = document.createElement('div');
  panel.id = 'og-chat-panel';
  panel.innerHTML = `
    <div id="og-chat-hdr"><div class="dot"></div><span>Imperial Counsel</span><small>14 agents online</small></div>
    <div id="og-chat-msgs"></div>
    <div id="og-chat-input"><input type="text" placeholder="Type objective..." id="og-input"><button id="og-send">Send</button></div>
  `;
  document.body.appendChild(panel);

  const msgs = document.getElementById('og-chat-msgs');
  const input = document.getElementById('og-input');
  const send = document.getElementById('og-send');

  function addMsg(text, type) {
    const div = document.createElement('div');
    div.className = 'og-msg ' + type;
    div.textContent = text;
    msgs.appendChild(div);
    msgs.scrollTop = msgs.scrollHeight;
  }

  // Welcome message
  addMsg('OmniaGuard Imperial Counsel. 14 agents active. State your objective.', 'bot');

  btn.addEventListener('click', function() {
    panel.classList.toggle('open');
    if (panel.classList.contains('open')) input.focus();
  });

  function handleSend() {
    const val = input.value.trim();
    if (!val) return;
    addMsg(val, 'user');
    input.value = '';
    setTimeout(function() {
      addMsg(route(val), 'bot');
    }, 300);
  }

  send.addEventListener('click', handleSend);
  input.addEventListener('keydown', function(e) {
    if (e.key === 'Enter') handleSend();
  });
})();
