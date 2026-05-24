(function() {
  'use strict';
  var KB = {
    pricing: {
      keywords: ['price', 'pricing', 'cost', 'how much', 'plan', 'tier', 'pay', 'subscription', 'afford', 'budget', 'money', 'save', 'roi', 'investment', 'expensive', 'cheap'],
      response: "Our plans are designed to scale with your needs:\n\n\u2022 Starter \u2014 $99/mo (10K API calls, 14 agents, basic protection)\n\u2022 Professional \u2014 $499/mo (100K calls, multi-tenant, compliance reporting)\n\u2022 Enterprise \u2014 $2,499/mo (unlimited, dedicated engineer, on-premise option)\n\nAll plans include a 14-day free trial. No credit card required.\n\nWant me to help you choose the right plan?"
    },
    security: {
      keywords: ['security', 'secure', 'protect', 'injection', 'prompt injection', 'jailbreak', 'attack', 'threat', 'hack', 'breach', 'vulnerability', 'safe'],
      response: "OmniaGuard provides multi-layered AI security:\n\n\u2022 Zero Prompt Injection Guarantee \u2014 99.97% detection rate\n\u2022 14 specialized security agents working in parallel\n\u2022 Input sanitization + semantic analysis + context isolation\n\u2022 Real-time threat monitoring and blocking\n\u2022 Sub-2ms response time (no latency impact)\n\nIf any injection bypasses our system, we provide a full incident report and remediation within 1 hour.\n\nWould you like to see a demo?"
    },
    howItWorks: {
      keywords: ['how does it work', 'how it works', 'explain', 'what do you do', 'what is omniaguard', 'overview', 'about', 'features', 'sdk'],
      response: "OmniaGuard is a security SDK that protects AI agents from prompt injection, jailbreaking, and data exfiltration.\n\nHow it works:\n1. Install our SDK (Python, Node.js, Go, or REST API)\n2. Wrap your AI calls with OmniaGuard\n3. 14 security agents automatically monitor every interaction\n4. Threats are blocked in real-time, zero latency impact\n\nIntegration takes under 30 minutes. Compatible with OpenAI, Anthropic, Google AI, Cohere, and custom models.\n\nWant to start a free trial?"
    },
    data: {
      keywords: ['data', 'privacy', 'gdpr', 'pipeda', 'complian', 'soc', 'iso', 'audit', 'encrypt'],
      response: "Your data security is our top priority:\n\n\u2022 Cryptographic tenant isolation \u2014 your data never touches other customers\n\u2022 SOC 2 Type II compliant\n\u2022 PIPEDA (Canada) and GDPR (EU) ready\n\u2022 ISO 42001 AI governance roadmap\n\u2022 Full audit trail with SIEM integration\n\u2022 Zero data retention on our servers \u2014 we process, we don't store\n\nEnterprise plans include on-premise deployment for maximum control."
    },
    trial: {
      keywords: ['try', 'trial', 'demo', 'test', 'free', 'start', 'sign up', 'signup', 'register', 'get started', 'begin'],
      response: "Great! Here's how to get started:\n\n1. Visit our pricing page to select a plan\n2. Start your 14-day free trial (no credit card needed)\n3. Install the SDK in under 30 minutes\n4. Your AI agents are protected immediately\n\nOr I can have our team reach out for a personalized demo.\n\nVisit: omniaguard.com/pricing.html"
    },
    agents: {
      keywords: ['agent', '14 agent', 'sentinel', 'cipher', 'warden', 'what agents', 'how many'],
      response: "OmniaGuard deploys 14 specialized security agents:\n\n\u2022 Sentinel \u2014 Perimeter defense\n\u2022 Cipher \u2014 Encryption management\n\u2022 Warden \u2014 Access control\n\u2022 Specter \u2014 Threat detection\n\u2022 Arbiter \u2014 Policy enforcement\n\u2022 Nexus \u2014 API gateway security\n\u2022 Phantom \u2014 Stealth monitoring\n\u2022 Oracle \u2014 Predictive analysis\n\u2022 Bastion \u2014 Firewall management\n\u2022 Aegis \u2014 Data protection\n\u2022 Vigil \u2014 Compliance monitoring\n\u2022 Prism \u2014 Content filtering\n\u2022 Echo \u2014 Audit logging\n\u2022 Forge \u2014 Key management\n\nAll 14 work in parallel with sub-2ms overhead."
    },
    integration: {
      keywords: ['integrat', 'compatible', 'openai', 'anthropic', 'python', 'node', 'api', 'install', 'setup', 'framework'],
      response: "OmniaGuard integrates with all major AI platforms:\n\n\u2022 OpenAI (GPT-4, GPT-4o, o1)\n\u2022 Anthropic (Claude)\n\u2022 Google AI (Gemini)\n\u2022 Cohere, Hugging Face, custom models\n\nSDKs available for:\n\u2022 Python (pip install omniaguard)\n\u2022 Node.js (npm install @omniaguard/sdk)\n\u2022 Go\n\u2022 REST API (any language)\n\nTypical integration: under 30 minutes."
    },
    contact: {
      keywords: ['contact', 'email', 'phone', 'reach', 'talk', 'human', 'support', 'help'],
      response: "You can reach our team:\n\n\u2022 Email: info@omniaguard.com\n\u2022 Response time: 4 hours (Professional), 1 hour (Enterprise)\n\u2022 Demo requests: omniaguard.com/contact.html\n\nOr leave your email here and we'll reach out within 24 hours."
    }
  };
  var failCount = 0;
  function findResponse(msg) {
    var lower = msg.toLowerCase();
    var keys = Object.keys(KB);
    for (var i = 0; i < keys.length; i++) {
      var entry = KB[keys[i]];
      for (var j = 0; j < entry.keywords.length; j++) {
        if (lower.indexOf(entry.keywords[j]) !== -1) {
          failCount = 0;
          return entry.response;
        }
      }
    }
    if (/^(hi|hello|hey|good morning|good afternoon|good evening|yo|sup)/i.test(lower)) {
      failCount = 0;
      return "Hello! Welcome to OmniaGuard. I can help you with:\n\n\u2022 How OmniaGuard works\n\u2022 Pricing and plans\n\u2022 Security features\n\u2022 Integration and setup\n\u2022 Starting a free trial\n\nWhat would you like to know?";
    }
    if (/thank|thanks|thx|appreciate/i.test(lower)) {
      failCount = 0;
      return "You're welcome! Is there anything else I can help you with?";
    }
    failCount++;
    if (failCount >= 2) {
      failCount = 0;
      return "I want to make sure you get the right answer. Our team can help directly:\n\n\u2022 Email: info@omniaguard.com\n\u2022 Or visit omniaguard.com/contact.html\n\nWe'll respond within 24 hours.";
    }
    return "I'd be happy to help. Could you tell me more about what you're looking for? I can assist with:\n\n\u2022 Pricing and ROI\n\u2022 Security capabilities\n\u2022 How to get started\n\u2022 Technical integration\n\u2022 Compliance questions\n\nJust ask in plain language and I'll do my best.";
  }
  var style = document.createElement('style');
  style.textContent = '#og-chat-btn{position:fixed;bottom:24px;right:24px;width:56px;height:56px;border-radius:50%;background:linear-gradient(135deg,#00d4ff,#7c3aed);border:none;cursor:pointer;z-index:9999;display:flex;align-items:center;justify-content:center;box-shadow:0 4px 20px rgba(0,212,255,.25);transition:transform .15s ease-out}#og-chat-btn:hover{transform:scale(1.08)}#og-chat-btn:active{transform:scale(.95)}#og-chat-btn svg{width:28px;height:28px;fill:#fff}#og-chat-panel{position:fixed;bottom:92px;right:24px;width:380px;max-height:520px;background:#0a192f;border:1px solid rgba(100,255,218,.15);border-radius:14px;z-index:9999;display:none;flex-direction:column;box-shadow:0 12px 48px rgba(0,0,0,.5);font-family:-apple-system,BlinkMacSystemFont,Segoe UI,system-ui,sans-serif}#og-chat-panel.open{display:flex}#og-chat-hdr{padding:16px 18px;border-bottom:1px solid rgba(100,255,218,.1);display:flex;align-items:center;gap:10px;background:rgba(10,25,47,.95);border-radius:14px 14px 0 0}#og-chat-hdr .dot{width:8px;height:8px;border-radius:50%;background:#64ffda;animation:ogpulse 2s infinite}@keyframes ogpulse{0%,100%{opacity:1}50%{opacity:.4}}#og-chat-hdr .title{color:#e6f1ff;font-size:14px;font-weight:600}#og-chat-hdr .subtitle{color:#8892b0;font-size:11px;margin-left:auto}#og-chat-hdr .close-btn{background:none;border:none;color:#8892b0;font-size:18px;cursor:pointer;padding:0 4px;margin-left:8px}#og-chat-hdr .close-btn:hover{color:#e6f1ff}#og-chat-msgs{flex:1;overflow-y:auto;padding:14px 18px;display:flex;flex-direction:column;gap:12px;max-height:340px}#og-chat-msgs::-webkit-scrollbar{width:4px}#og-chat-msgs::-webkit-scrollbar-track{background:transparent}#og-chat-msgs::-webkit-scrollbar-thumb{background:rgba(100,255,218,.2);border-radius:2px}.og-msg{max-width:88%;padding:12px 16px;border-radius:12px;font-size:13px;line-height:1.6;white-space:pre-line}.og-msg.bot{background:rgba(30,41,59,.8);color:#e6f1ff;align-self:flex-start;border:1px solid rgba(100,255,218,.08)}.og-msg.user{background:linear-gradient(135deg,#00d4ff,#7c3aed);color:#fff;align-self:flex-end;font-weight:500;border-radius:12px 12px 4px 12px}.og-typing{max-width:60px;padding:12px 16px;border-radius:12px;background:rgba(30,41,59,.8);align-self:flex-start;border:1px solid rgba(100,255,218,.08);font-size:13px;color:#8892b0}#og-chat-input{display:flex;border-top:1px solid rgba(100,255,218,.1);padding:12px 14px;gap:8px;background:rgba(10,25,47,.95);border-radius:0 0 14px 14px}#og-chat-input input{flex:1;background:rgba(30,41,59,.6);border:1px solid rgba(100,255,218,.15);border-radius:8px;padding:10px 14px;color:#e6f1ff;font-size:13px;outline:none;transition:border-color .2s}#og-chat-input input:focus{border-color:rgba(100,255,218,.4)}#og-chat-input input::placeholder{color:#8892b0}#og-chat-input button{background:linear-gradient(135deg,#00d4ff,#7c3aed);border:none;border-radius:8px;padding:10px 16px;color:#fff;font-size:13px;font-weight:600;cursor:pointer;transition:opacity .2s}#og-chat-input button:hover{opacity:.85}@media(max-width:480px){#og-chat-panel{width:calc(100vw - 32px);right:16px;bottom:84px;max-height:70vh}}';
  document.head.appendChild(style);
  var btn = document.createElement('button');
  btn.id = 'og-chat-btn';
  btn.setAttribute('aria-label', 'Chat with us');
  btn.innerHTML = '<svg viewBox="0 0 24 24"><path d="M20 2H4c-1.1 0-2 .9-2 2v18l4-4h14c1.1 0 2-.9 2-2V4c0-1.1-.9-2-2-2zm0 14H5.2L4 17.2V4h16v12z"/></svg>';
  document.body.appendChild(btn);
  var panel = document.createElement('div');
  panel.id = 'og-chat-panel';
  panel.innerHTML = '<div id="og-chat-hdr"><div class="dot"></div><span class="title">OmniaGuard Support</span><span class="subtitle">Online</span><button class="close-btn" id="og-close">\u00d7</button></div><div id="og-chat-msgs"></div><div id="og-chat-input"><input type="text" placeholder="Ask us anything..." id="og-input"><button id="og-send">Send</button></div>';
  document.body.appendChild(panel);
  var msgs = document.getElementById('og-chat-msgs');
  var input = document.getElementById('og-input');
  var sendBtn = document.getElementById('og-send');
  var closeBtn = document.getElementById('og-close');
  function addMsg(text, type) {
    var div = document.createElement('div');
    div.className = 'og-msg ' + type;
    div.textContent = text;
    msgs.appendChild(div);
    msgs.scrollTop = msgs.scrollHeight;
  }
  addMsg("Hi! I'm here to help you learn about OmniaGuard. Ask me about pricing, security features, how to get started, or anything else.", 'bot');
  btn.addEventListener('click', function() {
    panel.classList.toggle('open');
    if (panel.classList.contains('open')) input.focus();
  });
  closeBtn.addEventListener('click', function() {
    panel.classList.remove('open');
  });
  function handleSend() {
    var val = input.value.trim();
    if (!val) return;
    addMsg(val, 'user');
    input.value = '';
    var typing = document.createElement('div');
    typing.className = 'og-typing';
    typing.textContent = '...';
    msgs.appendChild(typing);
    msgs.scrollTop = msgs.scrollHeight;
    setTimeout(function() {
      if (typing.parentNode) msgs.removeChild(typing);
      addMsg(findResponse(val), 'bot');
    }, 600 + Math.random() * 400);
  }
  sendBtn.addEventListener('click', handleSend);
  input.addEventListener('keydown', function(e) {
    if (e.key === 'Enter') handleSend();
  });
})();
