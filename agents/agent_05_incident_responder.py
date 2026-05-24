"""
R&D: OmniaGuard Agent 05 — Incident Responder
================================================
Automated incident response and containment.

Capabilities:
- Automated playbook execution
- Threat containment recommendations
- Evidence preservation guidance
- Escalation decision making
- Post-incident report generation
- MITRE ATT&CK mapping

Integration: LLM-powered decision engine + Supabase incident tracking.
"""

import json
from datetime import datetime, timezone
from typing import Optional
from agents.base_agent import BaseAgent


class IncidentResponder(BaseAgent):
    """Agent 05: Automated incident response and containment."""

    @property
    def description(self) -> str:
        return "Executes incident response playbooks, recommends containment actions, and generates post-incident reports."

    @property
    def scan_types(self) -> list[str]:
        return ["triage", "contain", "investigate", "report", "playbook"]

    # Incident severity → response time SLA
    RESPONSE_SLA = {
        "critical": "15 minutes",
        "high": "1 hour",
        "medium": "4 hours",
        "low": "24 hours",
    }

    # Playbook templates
    PLAYBOOKS = {
        "brute_force": {
            "name": "Brute Force Response",
            "steps": [
                "Identify source IPs from logs",
                "Block attacking IPs at firewall",
                "Reset compromised account passwords",
                "Enable MFA on affected accounts",
                "Review access logs for successful unauthorized access",
                "Notify affected users",
            ],
        },
        "malware": {
            "name": "Malware Containment",
            "steps": [
                "Isolate affected system from network",
                "Preserve memory dump and disk image",
                "Identify malware family and IOCs",
                "Scan all systems for same IOCs",
                "Remove malware and restore from clean backup",
                "Update detection signatures",
                "Conduct root cause analysis",
            ],
        },
        "data_breach": {
            "name": "Data Breach Response",
            "steps": [
                "Identify scope of data exposure",
                "Contain the breach (revoke access, patch vuln)",
                "Preserve all evidence and logs",
                "Assess regulatory notification requirements (PIPEDA 72hr)",
                "Notify privacy officer and legal counsel",
                "Prepare breach notification for affected individuals",
                "Implement additional controls to prevent recurrence",
            ],
        },
        "ransomware": {
            "name": "Ransomware Response",
            "steps": [
                "IMMEDIATELY disconnect affected systems from network",
                "Do NOT pay ransom — contact law enforcement",
                "Identify ransomware variant and encryption method",
                "Check for available decryption tools (NoMoreRansom.org)",
                "Assess backup integrity and restoration options",
                "Preserve encrypted files as evidence",
                "Rebuild from clean backups",
                "Conduct full security audit post-recovery",
            ],
        },
        "phishing": {
            "name": "Phishing Incident Response",
            "steps": [
                "Identify all recipients of phishing email",
                "Block sender domain/IP at mail gateway",
                "Remove phishing emails from all mailboxes",
                "Identify users who clicked/submitted credentials",
                "Force password reset for compromised accounts",
                "Check for unauthorized access from compromised accounts",
                "Report phishing URL for takedown",
            ],
        },
    }

    async def scan(self, target: str, scan_type: str = "triage", **kwargs) -> dict:
        """
        Execute incident response actions.

        Args:
            target: Incident identifier or affected system
            scan_type: Response phase
            kwargs: incident_data (dict), severity, alert_data
        """
        incident_data = kwargs.get("incident_data", {})
        alert_data = kwargs.get("alert_data", {})

        if scan_type == "triage":
            return await self._triage_incident(target, incident_data, alert_data)
        elif scan_type == "contain":
            return await self._contain_threat(target, incident_data)
        elif scan_type == "investigate":
            return await self._investigate(target, incident_data)
        elif scan_type == "report":
            return await self._generate_report(target, incident_data)
        elif scan_type == "playbook":
            playbook_type = kwargs.get("playbook_type", "brute_force")
            return await self._execute_playbook(target, playbook_type, incident_data)
        else:
            return await self._triage_incident(target, incident_data, alert_data)

    async def _triage_incident(self, target: str, incident_data: dict, alert_data: dict) -> dict:
        """Triage an incoming security incident."""
        # Combine available data
        context = {**incident_data, **alert_data, "target": target}

        # LLM triage
        prompt = f"""Triage this security incident:

{json.dumps(context, indent=2, default=str)}

Determine:
1. Incident severity (critical/high/medium/low)
2. Incident category (brute_force, malware, data_breach, ransomware, phishing, unauthorized_access, dos, insider_threat)
3. Affected scope (single system, network segment, entire organization)
4. Immediate containment actions (top 3)
5. Recommended playbook
6. Escalation needed? (yes/no + reason)

Respond with JSON:
{{
    "severity": "critical/high/medium/low",
    "category": "category_name",
    "scope": "description",
    "immediate_actions": ["action1", "action2", "action3"],
    "playbook": "playbook_name",
    "escalate": true/false,
    "escalation_reason": "reason or null",
    "response_sla": "timeframe",
    "confidence": 0.0-1.0
}}"""

        try:
            result = await self.llm.analyze(prompt=prompt, json_mode=True)
            triage = json.loads(result)
        except Exception:
            triage = {
                "severity": "medium",
                "category": "unknown",
                "scope": "undetermined",
                "immediate_actions": ["Investigate manually", "Preserve logs", "Monitor for escalation"],
                "playbook": "brute_force",
                "escalate": False,
                "confidence": 0.0,
            }

        severity = triage.get("severity", "medium")
        triage["response_sla"] = self.RESPONSE_SLA.get(severity, "4 hours")

        return {
            "findings": {
                "triage": triage,
                "incident_id": f"INC-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}",
                "triaged_at": datetime.now(timezone.utc).isoformat(),
            },
            "severity": severity,
            "summary": f"Incident triaged: {triage['category']} ({severity}) — SLA: {triage['response_sla']}",
            "recommendations": triage.get("immediate_actions", []),
        }

    async def _contain_threat(self, target: str, incident_data: dict) -> dict:
        """Generate containment actions for an active threat."""
        prompt = f"""An active security threat has been detected on: {target}

Incident details:
{json.dumps(incident_data, indent=2, default=str)}

Generate specific containment actions that can be executed immediately.
Consider: network isolation, account lockdown, service shutdown, firewall rules.

Respond with JSON:
{{
    "containment_actions": [
        {{"action": "description", "command": "shell command if applicable", "risk": "low/medium/high", "reversible": true/false}}
    ],
    "estimated_containment_time": "X minutes/hours",
    "collateral_impact": "description of business impact",
    "verification_steps": ["how to verify containment worked"]
}}"""

        try:
            result = await self.llm.analyze(prompt=prompt, json_mode=True)
            containment = json.loads(result)
        except Exception:
            containment = {
                "containment_actions": [
                    {"action": "Isolate affected system from network", "command": "N/A — manual", "risk": "medium", "reversible": True}
                ],
                "estimated_containment_time": "Unknown",
                "verification_steps": ["Verify system is unreachable from network"],
            }

        return {
            "findings": containment,
            "severity": "high",
            "summary": f"Containment plan generated for {target} — {len(containment.get('containment_actions', []))} actions",
            "recommendations": [a["action"] for a in containment.get("containment_actions", [])],
        }

    async def _investigate(self, target: str, incident_data: dict) -> dict:
        """Deep investigation of an incident."""
        prompt = f"""Conduct a thorough investigation of this security incident:

Target: {target}
Data: {json.dumps(incident_data, indent=2, default=str)}

Provide:
1. Root cause analysis (what vulnerability/weakness was exploited)
2. Attack timeline reconstruction
3. Full scope assessment (what was accessed/modified/exfiltrated)
4. Attacker profile (skill level, motivation, possible attribution)
5. Evidence to preserve
6. Lessons learned

Respond with JSON:
{{
    "root_cause": "description",
    "attack_timeline": ["step1", "step2"],
    "scope": {{"systems_affected": 0, "data_at_risk": "description", "accounts_compromised": 0}},
    "attacker_profile": {{"skill_level": "novice/intermediate/advanced/nation-state", "motivation": "description"}},
    "evidence_to_preserve": ["item1", "item2"],
    "lessons_learned": ["lesson1", "lesson2"],
    "mitre_techniques": ["T####"]
}}"""

        try:
            result = await self.llm.analyze(prompt=prompt, json_mode=True, max_tokens=2048)
            investigation = json.loads(result)
        except Exception:
            investigation = {
                "root_cause": "Investigation requires additional data",
                "attack_timeline": [],
                "lessons_learned": ["Insufficient data for full investigation"],
            }

        return {
            "findings": investigation,
            "severity": incident_data.get("severity", "medium"),
            "summary": f"Investigation complete for {target}: {investigation.get('root_cause', 'Unknown')}",
            "recommendations": investigation.get("lessons_learned", []),
        }

    async def _generate_report(self, target: str, incident_data: dict) -> dict:
        """Generate post-incident report."""
        prompt = f"""Generate a professional post-incident report for:

Target: {target}
Incident Data: {json.dumps(incident_data, indent=2, default=str)}

Format as an executive-readable report with:
1. Executive Summary (2-3 sentences)
2. Incident Timeline
3. Impact Assessment
4. Root Cause
5. Actions Taken
6. Recommendations
7. Lessons Learned

Write in clear, professional language suitable for C-suite review."""

        try:
            report = await self.llm.analyze(prompt=prompt, max_tokens=3000)
        except Exception:
            report = "Report generation failed — manual compilation required."

        return {
            "findings": {
                "report": report,
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "classification": "CONFIDENTIAL",
            },
            "severity": "info",
            "summary": f"Post-incident report generated for {target}",
            "recommendations": ["Distribute report to stakeholders", "Schedule lessons-learned meeting"],
        }

    async def _execute_playbook(self, target: str, playbook_type: str, incident_data: dict) -> dict:
        """Execute a predefined incident response playbook."""
        playbook = self.PLAYBOOKS.get(playbook_type)
        if not playbook:
            return {
                "findings": {"error": f"Unknown playbook: {playbook_type}"},
                "severity": "info",
                "summary": f"Playbook '{playbook_type}' not found",
                "recommendations": [f"Available playbooks: {list(self.PLAYBOOKS.keys())}"],
            }

        # Customize playbook steps with LLM
        prompt = f"""Customize this incident response playbook for the specific situation:

Playbook: {playbook['name']}
Standard Steps: {json.dumps(playbook['steps'])}
Target: {target}
Incident Context: {json.dumps(incident_data, indent=2, default=str)}

For each step, provide:
- Specific command or action for this situation
- Expected outcome
- What to do if step fails

Respond with JSON:
{{
    "playbook_name": "{playbook['name']}",
    "customized_steps": [
        {{"step": 1, "action": "...", "command": "...", "expected_outcome": "...", "if_fails": "..."}}
    ],
    "estimated_duration": "X hours",
    "resources_needed": ["..."]
}}"""

        try:
            result = await self.llm.analyze(prompt=prompt, json_mode=True, max_tokens=2048)
            customized = json.loads(result)
        except Exception:
            customized = {
                "playbook_name": playbook["name"],
                "customized_steps": [
                    {"step": i + 1, "action": step, "command": "Manual", "expected_outcome": "Step completed"}
                    for i, step in enumerate(playbook["steps"])
                ],
                "estimated_duration": "2-4 hours",
            }

        return {
            "findings": customized,
            "severity": "high",
            "summary": f"Playbook '{playbook['name']}' ready for {target} — {len(customized.get('customized_steps', []))} steps",
            "recommendations": [s["action"] for s in customized.get("customized_steps", [])[:5]],
        }
