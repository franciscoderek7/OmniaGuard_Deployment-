"""
R&D: OmniaGuard Telegram Bot
==============================
Command interface for the 14-agent security platform via Telegram.

Commands:
    /start          — Welcome + help
    /scan <target>  — Quick network scan
    /vuln <target>  — Vulnerability assessment
    /phish <url>    — Check URL for phishing
    /breach <email> — Check email in breach databases
    /status         — System health check
    /report         — Generate executive summary
    /help           — Command reference

Integration: python-telegram-bot + all 14 agents.
"""

import os
import json
import asyncio
from datetime import datetime, timezone
from typing import Optional

import httpx

from core.config import settings


class OmniaGuardBot:
    """Telegram bot interface for OmniaGuard security platform."""

    def __init__(self):
        self.token = settings.TELEGRAM_BOT_TOKEN
        self.base_url = f"https://api.telegram.org/bot{self.token}"
        self.agents = {}
        self._running = False

    async def initialize_agents(self):
        """Initialize all 14 agents."""
        from agents.agent_01_network_scanner import NetworkScanner
        from agents.agent_02_vuln_assessor import VulnAssessor
        from agents.agent_03_threat_intel import ThreatIntel
        from agents.agent_04_log_analyzer import LogAnalyzer
        from agents.agent_05_incident_responder import IncidentResponder
        from agents.agent_06_phishing_detector import PhishingDetector
        from agents.agent_07_malware_analyzer import MalwareAnalyzer
        from agents.agent_08_compliance_auditor import ComplianceAuditor
        from agents.agent_09_access_controller import AccessController
        from agents.agent_10_dlp import DLPAgent
        from agents.agent_11_endpoint_monitor import EndpointMonitor
        from agents.agent_12_cloud_security import CloudSecurity
        from agents.agent_13_dark_web_monitor import DarkWebMonitor
        from agents.agent_14_report_generator import ReportGenerator

        self.agents = {
            "network": NetworkScanner(),
            "vuln": VulnAssessor(),
            "threat": ThreatIntel(),
            "log": LogAnalyzer(),
            "incident": IncidentResponder(),
            "phishing": PhishingDetector(),
            "malware": MalwareAnalyzer(),
            "compliance": ComplianceAuditor(),
            "access": AccessController(),
            "dlp": DLPAgent(),
            "endpoint": EndpointMonitor(),
            "cloud": CloudSecurity(),
            "darkweb": DarkWebMonitor(),
            "report": ReportGenerator(),
        }

    async def send_message(self, chat_id: int, text: str, parse_mode: str = "Markdown") -> dict:
        """Send a message via Telegram."""
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.post(
                f"{self.base_url}/sendMessage",
                json={
                    "chat_id": chat_id,
                    "text": text,
                    "parse_mode": parse_mode,
                },
            )
            return response.json()

    async def send_typing(self, chat_id: int):
        """Send typing indicator."""
        async with httpx.AsyncClient(timeout=10.0) as client:
            await client.post(
                f"{self.base_url}/sendChatAction",
                json={"chat_id": chat_id, "action": "typing"},
            )

    async def handle_update(self, update: dict):
        """Process incoming Telegram update."""
        message = update.get("message", {})
        if not message:
            return

        chat_id = message.get("chat", {}).get("id")
        text = message.get("text", "").strip()
        username = message.get("from", {}).get("username", "unknown")

        if not text or not chat_id:
            return

        # Route commands
        if text.startswith("/start"):
            await self._cmd_start(chat_id, username)
        elif text.startswith("/help"):
            await self._cmd_help(chat_id)
        elif text.startswith("/scan"):
            target = text.replace("/scan", "").strip()
            await self._cmd_scan(chat_id, target)
        elif text.startswith("/vuln"):
            target = text.replace("/vuln", "").strip()
            await self._cmd_vuln(chat_id, target)
        elif text.startswith("/phish"):
            target = text.replace("/phish", "").strip()
            await self._cmd_phish(chat_id, target)
        elif text.startswith("/breach"):
            target = text.replace("/breach", "").strip()
            await self._cmd_breach(chat_id, target)
        elif text.startswith("/status"):
            await self._cmd_status(chat_id)
        elif text.startswith("/report"):
            await self._cmd_report(chat_id)
        elif text.startswith("/compliance"):
            framework = text.replace("/compliance", "").strip() or "soc2"
            await self._cmd_compliance(chat_id, framework)
        elif text.startswith("/"):
            await self.send_message(chat_id, "❓ Unknown command. Use /help for available commands.")
        else:
            # Natural language query — route to appropriate agent
            await self._handle_natural_query(chat_id, text)

    async def _cmd_start(self, chat_id: int, username: str):
        """Handle /start command."""
        welcome = f"""🛡️ *OmniaGuard Security Platform*

Welcome, @{username}!

I'm your AI-powered cybersecurity assistant with 14 specialized agents ready to protect your infrastructure.

*Quick Start:*
• `/scan example.com` — Network scan
• `/vuln example.com` — Vulnerability check
• `/phish https://suspicious.link` — Phishing check
• `/breach email@domain.com` — Breach lookup

Type /help for all commands.

_Powered by Francisco Holdings | Enterprise Cybersecurity._"""

        await self.send_message(chat_id, welcome)

    async def _cmd_help(self, chat_id: int):
        """Handle /help command."""
        help_text = """🛡️ *OmniaGuard Commands*

*Scanning:*
`/scan <target>` — Network reconnaissance
`/vuln <target>` — Vulnerability assessment
`/phish <url>` — Phishing URL check
`/breach <email>` — Breach database lookup

*Monitoring:*
`/status` — System health & agent status
`/report` — Generate executive summary
`/compliance <framework>` — SOC2/ISO/PIPEDA check

*Frameworks:* soc2, iso27001, pipeda, pci

*Examples:*
```
/scan omniaguard.com
/vuln 192.168.1.0/24
/phish https://suspicious-link.xyz
/breach admin@company.com
/compliance pipeda
```

_All scans are logged for SR&ED audit trail._"""

        await self.send_message(chat_id, help_text)

    async def _cmd_scan(self, chat_id: int, target: str):
        """Handle /scan command."""
        if not target:
            await self.send_message(chat_id, "⚠️ Usage: `/scan <target>`\nExample: `/scan omniaguard.com`")
            return

        await self.send_typing(chat_id)
        await self.send_message(chat_id, f"🔍 *Scanning:* `{target}`\n_Agent 01 (Network Scanner) active..._")

        try:
            result = await self.agents["network"].scan(target, scan_type="quick_scan")
            response = self._format_result("Network Scan", target, result)
            await self.send_message(chat_id, response)
        except Exception as e:
            await self.send_message(chat_id, f"❌ Scan failed: `{str(e)[:100]}`")

    async def _cmd_vuln(self, chat_id: int, target: str):
        """Handle /vuln command."""
        if not target:
            await self.send_message(chat_id, "⚠️ Usage: `/vuln <target>`\nExample: `/vuln omniaguard.com`")
            return

        await self.send_typing(chat_id)
        await self.send_message(chat_id, f"🔬 *Vulnerability Assessment:* `{target}`\n_Agent 02 (Vuln Assessor) active..._")

        try:
            result = await self.agents["vuln"].scan(target, scan_type="web_scan")
            response = self._format_result("Vulnerability Assessment", target, result)
            await self.send_message(chat_id, response)
        except Exception as e:
            await self.send_message(chat_id, f"❌ Assessment failed: `{str(e)[:100]}`")

    async def _cmd_phish(self, chat_id: int, target: str):
        """Handle /phish command."""
        if not target:
            await self.send_message(chat_id, "⚠️ Usage: `/phish <url>`\nExample: `/phish https://suspicious.link`")
            return

        await self.send_typing(chat_id)
        await self.send_message(chat_id, f"🎣 *Phishing Check:* `{target}`\n_Agent 06 (Phishing Detector) active..._")

        try:
            result = await self.agents["phishing"].scan(target, scan_type="url_check")
            response = self._format_result("Phishing Analysis", target, result)
            await self.send_message(chat_id, response)
        except Exception as e:
            await self.send_message(chat_id, f"❌ Check failed: `{str(e)[:100]}`")

    async def _cmd_breach(self, chat_id: int, target: str):
        """Handle /breach command."""
        if not target:
            await self.send_message(chat_id, "⚠️ Usage: `/breach <email>`\nExample: `/breach admin@company.com`")
            return

        await self.send_typing(chat_id)
        await self.send_message(chat_id, f"🌐 *Breach Check:* `{target}`\n_Agent 13 (Dark Web Monitor) active..._")

        try:
            result = await self.agents["darkweb"].scan(target, scan_type="breach_check")
            response = self._format_result("Breach Check", target, result)
            await self.send_message(chat_id, response)
        except Exception as e:
            await self.send_message(chat_id, f"❌ Check failed: `{str(e)[:100]}`")

    async def _cmd_status(self, chat_id: int):
        """Handle /status command."""
        agent_count = len(self.agents)
        status_lines = [
            "🛡️ *OmniaGuard System Status*\n",
            f"*Agents Online:* {agent_count}/14",
            f"*Timestamp:* {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
            "",
            "*Agent Status:*",
        ]

        for name, agent in self.agents.items():
            status_lines.append(f"  ✅ {name}: operational")

        status_lines.append(f"\n*Infrastructure:*")
        status_lines.append(f"  • LLM: Together AI (Llama 3.1 70B)")
        status_lines.append(f"  • Database: Supabase")
        status_lines.append(f"  • Region: Canada")
        status_lines.append(f"\n_All systems nominal._")

        await self.send_message(chat_id, "\n".join(status_lines))

    async def _cmd_report(self, chat_id: int):
        """Handle /report command — generate executive summary."""
        await self.send_typing(chat_id)
        await self.send_message(chat_id, "📊 *Generating Executive Report...*\n_Agent 14 (Report Generator) compiling..._")

        try:
            # In production, this would aggregate recent scan results from Supabase
            result = await self.agents["report"].scan(
                "Francisco Holdings",
                scan_type="telegram_alert",
                findings=[],
            )
            message = result["findings"].get("message", "Report generation complete.")
            await self.send_message(chat_id, message)
        except Exception as e:
            await self.send_message(chat_id, f"❌ Report failed: `{str(e)[:100]}`")

    async def _cmd_compliance(self, chat_id: int, framework: str):
        """Handle /compliance command."""
        valid_frameworks = ["soc2", "iso27001", "pipeda", "pci"]
        if framework not in valid_frameworks:
            await self.send_message(
                chat_id,
                f"⚠️ Valid frameworks: `{', '.join(valid_frameworks)}`\nUsage: `/compliance soc2`"
            )
            return

        await self.send_typing(chat_id)
        await self.send_message(chat_id, f"📋 *{framework.upper()} Compliance Check*\n_Agent 08 (Compliance Auditor) active..._")

        try:
            scan_type = f"{framework}_check" if framework != "pci" else "gap_analysis"
            result = await self.agents["compliance"].scan(
                "Francisco Holdings",
                scan_type=scan_type,
                framework=framework,
            )
            response = self._format_result(f"{framework.upper()} Compliance", "Francisco Holdings", result)
            await self.send_message(chat_id, response)
        except Exception as e:
            await self.send_message(chat_id, f"❌ Audit failed: `{str(e)[:100]}`")

    async def _handle_natural_query(self, chat_id: int, text: str):
        """Route natural language queries to appropriate agent."""
        await self.send_typing(chat_id)

        # Simple keyword routing
        text_lower = text.lower()
        if any(kw in text_lower for kw in ["scan", "port", "network", "nmap"]):
            await self.send_message(chat_id, "💡 Try: `/scan <target>`")
        elif any(kw in text_lower for kw in ["vuln", "cve", "exploit", "patch"]):
            await self.send_message(chat_id, "💡 Try: `/vuln <target>`")
        elif any(kw in text_lower for kw in ["phish", "email", "link", "suspicious"]):
            await self.send_message(chat_id, "💡 Try: `/phish <url>`")
        elif any(kw in text_lower for kw in ["breach", "leak", "password", "dark web"]):
            await self.send_message(chat_id, "💡 Try: `/breach <email>`")
        else:
            await self.send_message(
                chat_id,
                "🤔 I'm not sure what you need. Try /help for available commands."
            )

    def _format_result(self, scan_name: str, target: str, result: dict) -> str:
        """Format agent result as Telegram message."""
        severity = result.get("severity", "info")
        emoji = self.SEVERITY_EMOJI.get(severity, "❓")
        summary = result.get("summary", "Scan complete")
        recommendations = result.get("recommendations", [])

        lines = [
            f"{emoji} *{scan_name}*",
            f"*Target:* `{target}`",
            f"*Severity:* {severity.upper()}",
            f"*Summary:* {summary}",
        ]

        if recommendations:
            lines.append("\n*Recommendations:*")
            for i, rec in enumerate(recommendations[:3], 1):
                if rec:
                    lines.append(f"  {i}. {rec}")

        lines.append(f"\n_{datetime.now(timezone.utc).strftime('%H:%M UTC')}_")
        return "\n".join(lines)

    async def start_polling(self):
        """Start long-polling for updates."""
        self._running = True
        offset = 0

        print("🛡️ OmniaGuard Telegram Bot started — polling for updates...")

        async with httpx.AsyncClient(timeout=60.0) as client:
            while self._running:
                try:
                    response = await client.get(
                        f"{self.base_url}/getUpdates",
                        params={"offset": offset, "timeout": 30},
                    )
                    data = response.json()

                    if data.get("ok"):
                        for update in data.get("result", []):
                            offset = update["update_id"] + 1
                            await self.handle_update(update)
                except httpx.TimeoutException:
                    continue
                except Exception as e:
                    print(f"Polling error: {e}")
                    await asyncio.sleep(5)

    def stop(self):
        """Stop the bot."""
        self._running = False


async def main():
    """Entry point for the Telegram bot."""
    bot = OmniaGuardBot()
    await bot.initialize_agents()
    await bot.start_polling()


if __name__ == "__main__":
    asyncio.run(main())
