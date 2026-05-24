"""
R&D: OmniaGuard Agent 14 — Report Generator
==============================================
Executive report generation and multi-agent result aggregation.

Capabilities:
- Aggregate findings from all 13 agents into unified reports
- Generate executive summaries (C-suite readable)
- Technical deep-dive reports for security teams
- Compliance report formatting (SOC2, ISO, PIPEDA)
- Trend analysis across scan history
- Risk scoring and prioritization
- Telegram-formatted alerts

Integration: Together AI for report writing + Supabase for historical data.
"""

import json
from datetime import datetime, timezone
from typing import Optional
from agents.base_agent import BaseAgent


class ReportGenerator(BaseAgent):
    """Agent 14: Report generation and multi-agent result aggregation."""

    @property
    def description(self) -> str:
        return "Aggregates findings from all OmniaGuard agents into executive reports, technical summaries, and compliance documents."

    @property
    def scan_types(self) -> list[str]:
        return ["executive_summary", "technical_report", "compliance_report", "telegram_alert", "trend_analysis"]

    # Report templates
    SEVERITY_EMOJI = {
        "critical": "🔴",
        "high": "🟠",
        "medium": "🟡",
        "low": "🟢",
        "info": "ℹ️",
    }

    async def scan(self, target: str, scan_type: str = "executive_summary", **kwargs) -> dict:
        """
        Generate reports from agent findings.

        Args:
            target: Organization or scan identifier
            scan_type: Type of report to generate
            kwargs: findings (list of agent results), timeframe (str), format (str)
        """
        findings = kwargs.get("findings", [])
        timeframe = kwargs.get("timeframe", "current")

        if scan_type == "executive_summary":
            return await self._executive_summary(target, findings)
        elif scan_type == "technical_report":
            return await self._technical_report(target, findings)
        elif scan_type == "compliance_report":
            framework = kwargs.get("framework", "soc2")
            return await self._compliance_report(target, findings, framework)
        elif scan_type == "telegram_alert":
            return await self._telegram_alert(target, findings)
        elif scan_type == "trend_analysis":
            history = kwargs.get("history", [])
            return await self._trend_analysis(target, history)
        else:
            return await self._executive_summary(target, findings)

    async def _executive_summary(self, target: str, findings: list) -> dict:
        """Generate executive-level security summary."""
        # Aggregate severity counts
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        all_recommendations = []

        for finding in findings:
            sev = finding.get("severity", "info")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
            recs = finding.get("recommendations", [])
            all_recommendations.extend(recs[:2])

        # Calculate overall risk score
        risk_score = (
            severity_counts["critical"] * 25 +
            severity_counts["high"] * 15 +
            severity_counts["medium"] * 5 +
            severity_counts["low"] * 1
        )
        risk_score = min(risk_score, 100)

        # LLM executive summary
        prompt = f"""Write a concise executive security summary for the board/C-suite:

Organization: {target}
Date: {datetime.now(timezone.utc).strftime('%Y-%m-%d')}
Findings: {json.dumps(severity_counts)}
Total Risk Score: {risk_score}/100
Top Findings: {json.dumps([f.get('summary', '') for f in findings[:10]])}
Key Recommendations: {json.dumps(all_recommendations[:10])}

Write in clear business language. No jargon. Focus on business impact and required actions.
Maximum 300 words. Include:
1. One-sentence overall status
2. Top 3 risks by business impact
3. Immediate actions required
4. 30-day priorities"""

        try:
            executive_text = await self.llm.analyze(prompt=prompt, max_tokens=1024)
        except Exception:
            executive_text = f"Security assessment complete. Risk score: {risk_score}/100. {severity_counts['critical']} critical findings require immediate attention."

        return {
            "findings": {
                "report_type": "executive_summary",
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "organization": target,
                "risk_score": risk_score,
                "severity_breakdown": severity_counts,
                "executive_summary": executive_text,
                "top_recommendations": all_recommendations[:5],
                "agents_reporting": len(findings),
            },
            "severity": "critical" if risk_score >= 70 else "high" if risk_score >= 40 else "medium",
            "summary": f"Executive Report: Risk Score {risk_score}/100 — {severity_counts['critical']} critical, {severity_counts['high']} high findings",
            "recommendations": all_recommendations[:5],
        }

    async def _technical_report(self, target: str, findings: list) -> dict:
        """Generate detailed technical security report."""
        prompt = f"""Generate a detailed technical security report:

Target: {target}
Date: {datetime.now(timezone.utc).strftime('%Y-%m-%d')}
Agent Findings ({len(findings)} agents reported):
{json.dumps([{{'agent': f.get('agent', 'unknown'), 'severity': f.get('severity'), 'summary': f.get('summary', ''), 'findings_count': len(f.get('findings', {{}}))}} for f in findings[:14]], indent=2)}

Structure the report as:
1. Scope and Methodology
2. Critical Findings (with technical details)
3. High-Priority Findings
4. Medium/Low Findings Summary
5. Attack Surface Analysis
6. Remediation Roadmap (prioritized)
7. Appendix: Full Finding Details

Write for a technical security audience. Include specific CVEs, MITRE ATT&CK references where applicable."""

        try:
            technical_text = await self.llm.analyze(prompt=prompt, max_tokens=4000)
        except Exception:
            technical_text = "Technical report generation failed — raw findings attached."

        return {
            "findings": {
                "report_type": "technical_report",
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "organization": target,
                "report_content": technical_text,
                "raw_findings": findings,
                "total_agents": len(findings),
            },
            "severity": "info",
            "summary": f"Technical report generated for {target} — {len(findings)} agent findings compiled",
            "recommendations": ["Distribute to security team", "Schedule remediation sprint"],
        }

    async def _compliance_report(self, target: str, findings: list, framework: str) -> dict:
        """Generate compliance-focused report."""
        prompt = f"""Generate a {framework.upper()} compliance report based on these security findings:

Organization: {target}
Framework: {framework.upper()}
Findings Summary: {json.dumps([{{'severity': f.get('severity'), 'summary': f.get('summary', '')}} for f in findings[:10]])}

Structure as:
1. Compliance Status Overview
2. Controls Assessed
3. Findings Mapped to {framework.upper()} Controls
4. Gap Analysis
5. Remediation Plan with Timelines
6. Evidence Requirements
7. Auditor Notes

Format for submission to compliance auditors."""

        try:
            compliance_text = await self.llm.analyze(prompt=prompt, max_tokens=3000)
        except Exception:
            compliance_text = f"{framework.upper()} compliance report generation failed."

        return {
            "findings": {
                "report_type": "compliance_report",
                "framework": framework,
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "organization": target,
                "report_content": compliance_text,
            },
            "severity": "info",
            "summary": f"{framework.upper()} compliance report generated for {target}",
            "recommendations": ["Submit to compliance officer", "Schedule auditor review"],
        }

    async def _telegram_alert(self, target: str, findings: list) -> dict:
        """Format findings as Telegram alert messages."""
        # Filter to critical and high only
        urgent = [f for f in findings if f.get("severity") in ("critical", "high")]

        if not urgent:
            message = f"✅ *OmniaGuard Status: {target}*\n\nAll clear — no critical or high findings.\n\n_{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}_"
        else:
            lines = [f"🛡️ *OmniaGuard Alert: {target}*\n"]
            lines.append(f"⚠️ *{len(urgent)} urgent findings detected*\n")

            for i, finding in enumerate(urgent[:5], 1):
                emoji = self.SEVERITY_EMOJI.get(finding.get("severity", "info"), "❓")
                lines.append(f"{emoji} *{i}.* {finding.get('summary', 'Unknown finding')}")

            if len(urgent) > 5:
                lines.append(f"\n_...and {len(urgent) - 5} more urgent findings_")

            lines.append(f"\n📋 *Top Actions:*")
            all_recs = []
            for f in urgent[:3]:
                all_recs.extend(f.get("recommendations", [])[:1])
            for i, rec in enumerate(all_recs[:3], 1):
                if rec:
                    lines.append(f"  {i}. {rec}")

            lines.append(f"\n_{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}_")
            message = "\n".join(lines)

        return {
            "findings": {
                "report_type": "telegram_alert",
                "message": message,
                "urgent_count": len(urgent) if urgent else 0,
                "parse_mode": "Markdown",
            },
            "severity": "critical" if urgent else "info",
            "summary": f"Telegram alert formatted: {len(urgent) if urgent else 0} urgent findings",
            "recommendations": ["Send via Telegram Bot API"],
        }

    async def _trend_analysis(self, target: str, history: list) -> dict:
        """Analyze security trends over time."""
        if not history:
            return {
                "findings": {"message": "No historical data available for trend analysis"},
                "severity": "info",
                "summary": "Trend analysis requires historical scan data",
                "recommendations": ["Run regular scans to build trend data"],
            }

        prompt = f"""Analyze security trends for this organization:

Organization: {target}
Historical Scan Data: {json.dumps(history[:30], indent=2, default=str)}

Identify:
1. Overall security posture trend (improving/stable/declining)
2. Recurring issues that aren't being fixed
3. New risks that appeared recently
4. Areas of improvement
5. Predicted next risks based on patterns

Respond with JSON:
{{
    "trend": "improving/stable/declining",
    "risk_score_trend": [{{"date": "...", "score": 0}}],
    "recurring_issues": ["..."],
    "new_risks": ["..."],
    "improvements": ["..."],
    "predictions": ["..."],
    "recommendations": ["..."]
}}"""

        try:
            result = await self.llm.analyze(prompt=prompt, json_mode=True, max_tokens=1024)
            analysis = json.loads(result)
        except Exception:
            analysis = {"trend": "unknown", "recommendations": ["Insufficient data for trend analysis"]}

        return {
            "findings": analysis,
            "severity": "high" if analysis.get("trend") == "declining" else "info",
            "summary": f"Security trend for {target}: {analysis.get('trend', 'unknown')}",
            "recommendations": analysis.get("recommendations", []),
        }
