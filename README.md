# OmniaGuard

**Autonomous Multi-Agent Cybersecurity Platform**

> 14 specialized AI agents working in consensus — not one tool, but a digital immune system that learns, adapts, and never sleeps.

---

## Architecture

OmniaGuard uses a **Multi-Agent Consensus Protocol** — no single agent decides. Every critical action requires cross-verification from multiple agents before execution.

| # | Agent | Function | Catches |
|---|---|---|---|
| 1 | Network Scanner | Port/service discovery | Hidden backdoors |
| 2 | Vulnerability Assessor | CVE matching | Known exploits |
| 3 | Threat Intel | OSINT feeds | Emerging attacks |
| 4 | Log Analyzer | SIEM parsing | Anomaly patterns |
| 5 | Incident Responder | Automated containment | Breach escalation |
| 6 | Phishing Detector | Email/URL analysis | Social engineering |
| 7 | Malware Analyzer | Static/dynamic analysis | Zero-day malware |
| 8 | Compliance Auditor | SOC2/ISO checks | Regulatory gaps |
| 9 | Access Controller | IAM enforcement | Privilege abuse |
| 10 | Data Loss Preventer | DLP monitoring | Insider threats |
| 11 | Endpoint Protector | EDR coverage | Device compromise |
| 12 | Cloud Guardian | AWS/GCP/Azure | Misconfiguration |
| 13 | Dark Web Monitor | Credential leaks | Stolen data |
| 14 | Report Generator | Executive summaries | Human-readable intel |

---

## Core Security Principles

### Zero-Trust Authorization Engine
Every agent action must prove its legitimacy. No implicit trust. No inherited permissions.
- Per-action authorization verification
- Time-bounded permission grants
- Automatic prompt injection detection
- Failed attempts logged and trigger alerts

### Multi-Agent Consensus Protocol
- Each agent votes on threat severity independently
- Critical/high classifications require 3+ agent agreement
- Dissenting opinions logged for audit trail
- Weighted confidence scoring by domain expertise

### Autonomous 24/7 Operation

| Time Block | Activity |
|---|---|
| 00:00–06:00 | Dark web scanning, threat intel updates |
| 06:00–12:00 | Log analysis, anomaly detection |
| 12:00–18:00 | Compliance checks, access reviews |
| 18:00–00:00 | Vulnerability scans, report generation |

Morning briefing via Telegram: what happened overnight, what needs your eyes.

---

## Tech Stack

| Component | Technology |
|---|---|
| AI Inference | Together AI (Llama 3.1 70B) |
| Database | Supabase (PostgreSQL) |
| Bot Interface | Telegram Bot API |
| Deployment | Docker / Supabase Edge Functions |
| Language | Python 3.11+ |
| DNS | Porkbun (omniaguard.com) |

---

## Quick Start

```bash
git clone https://github.com/franciscoderek7/omniaguard.git
cd omniaguard
pip install -r requirements.txt
cp .env.example .env
# Edit .env with your keys
python main.py --test    # Verify all 14 agents
python main.py           # Start Telegram bot
```

---

## Deployment Options

| Option | Cost | Best For |
|---|---|---|
| Local (polling) | $0 | Development, testing |
| Supabase Edge Functions | $0 | Production serverless |
| Docker on VPS | $5-10/mo | High-volume, dedicated |

See `docs/deployment.md` for full instructions.

---

## Telegram Commands

| Command | Function |
|---|---|
| `/start` | Initialize bot |
| `/scan <target>` | Full security scan |
| `/status` | System health check |
| `/alerts` | View active alerts |
| `/report` | Generate executive summary |
| `/breach <email>` | Check breach databases |
| `/monitor <domain>` | Add to continuous monitoring |

---

## SR&ED Eligible

This project qualifies for Canadian SR&ED tax incentives:
- Multi-agent consensus algorithms (experimental development)
- Zero-trust authorization for AI agents (systematic investigation)
- Prompt injection defense pipelines (applied research)
- Autonomous threat classification (technological uncertainty)

All commits prefixed with `R&D:` for audit trail compliance.

---

## License

MIT License

---

## Contact

- **Platform:** OmniaGuard
- **Organization:** Francisco Holdings
- **GitHub:** @franciscoderek7
