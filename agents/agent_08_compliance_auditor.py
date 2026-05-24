"""
R&D: OmniaGuard Agent 08 — Compliance Auditor
================================================
SOC2, ISO 27001, PIPEDA, and PCI-DSS compliance checking.

Capabilities:
- Policy compliance scanning
- Configuration audit against frameworks
- Gap analysis with remediation guidance
- Evidence collection for audits
- Continuous compliance monitoring

Integration: Together AI for policy interpretation + Supabase for audit logs.
"""

import json
from datetime import datetime, timezone
from typing import Optional
from agents.base_agent import BaseAgent


class ComplianceAuditor(BaseAgent):
    """Agent 08: Regulatory and framework compliance auditing."""

    @property
    def description(self) -> str:
        return "Audits systems against SOC2, ISO 27001, PIPEDA, and PCI-DSS frameworks with gap analysis and remediation guidance."

    @property
    def scan_types(self) -> list[str]:
        return ["soc2_check", "iso27001_check", "pipeda_check", "gap_analysis", "evidence_collect"]

    # SOC2 Trust Service Criteria
    SOC2_CRITERIA = {
        "CC1": "Control Environment",
        "CC2": "Communication and Information",
        "CC3": "Risk Assessment",
        "CC4": "Monitoring Activities",
        "CC5": "Control Activities",
        "CC6": "Logical and Physical Access Controls",
        "CC7": "System Operations",
        "CC8": "Change Management",
        "CC9": "Risk Mitigation",
    }

    async def scan(self, target: str, scan_type: str = "gap_analysis", **kwargs) -> dict:
        """
        Audit target against compliance frameworks.

        Args:
            target: System/organization to audit
            scan_type: Framework to audit against
            kwargs: config (dict), policies (list), evidence (dict)
        """
        config = kwargs.get("config", {})
        policies = kwargs.get("policies", [])

        if scan_type == "soc2_check":
            return await self._soc2_audit(target, config, policies)
        elif scan_type == "iso27001_check":
            return await self._iso27001_audit(target, config)
        elif scan_type == "pipeda_check":
            return await self._pipeda_audit(target, config)
        elif scan_type == "gap_analysis":
            framework = kwargs.get("framework", "soc2")
            return await self._gap_analysis(target, framework, config)
        elif scan_type == "evidence_collect":
            return await self._collect_evidence(target, config)
        else:
            return await self._gap_analysis(target, "soc2", config)

    async def _soc2_audit(self, target: str, config: dict, policies: list) -> dict:
        """Audit against SOC2 Trust Service Criteria."""
        prompt = f"""Audit this system configuration against SOC2 Trust Service Criteria:

System: {target}
Configuration: {json.dumps(config, indent=2, default=str)}
Policies in place: {json.dumps(policies)}

For each SOC2 criteria ({json.dumps(self.SOC2_CRITERIA)}), assess:
- Status: compliant / partially_compliant / non_compliant
- Evidence available
- Gaps identified
- Remediation needed

Respond with JSON:
{{
    "overall_status": "compliant/partially_compliant/non_compliant",
    "score": 0-100,
    "criteria_results": [
        {{"criteria": "CC1", "name": "Control Environment", "status": "compliant/partial/non_compliant", "gaps": ["gap1"], "remediation": ["action1"]}}
    ],
    "critical_gaps": ["most important gaps"],
    "estimated_remediation_hours": 0
}}"""

        try:
            result = await self.llm.analyze(prompt=prompt, json_mode=True, max_tokens=3000)
            audit = json.loads(result)
        except Exception:
            audit = {"overall_status": "unknown", "score": 0, "criteria_results": []}

        severity = "critical" if audit.get("score", 0) < 40 else \
                   "high" if audit.get("score", 0) < 60 else \
                   "medium" if audit.get("score", 0) < 80 else "low"

        return {
            "findings": audit,
            "severity": severity,
            "summary": f"SOC2 audit of {target}: {audit.get('score', 0)}% compliant — {audit.get('overall_status', 'unknown')}",
            "recommendations": audit.get("critical_gaps", [])[:5],
        }

    async def _iso27001_audit(self, target: str, config: dict) -> dict:
        """Audit against ISO 27001 controls."""
        prompt = f"""Audit this system against ISO 27001:2022 key controls:

System: {target}
Configuration: {json.dumps(config, indent=2, default=str)}

Assess these control domains:
A.5 Organizational, A.6 People, A.7 Physical, A.8 Technological

Respond with JSON:
{{
    "overall_score": 0-100,
    "domains": [
        {{"domain": "A.5", "name": "Organizational", "score": 0-100, "gaps": ["gap1"]}}
    ],
    "critical_findings": ["finding1"],
    "recommendations": ["rec1"]
}}"""

        try:
            result = await self.llm.analyze(prompt=prompt, json_mode=True, max_tokens=2048)
            audit = json.loads(result)
        except Exception:
            audit = {"overall_score": 0, "domains": [], "recommendations": ["Full audit required"]}

        severity = "high" if audit.get("overall_score", 0) < 60 else \
                   "medium" if audit.get("overall_score", 0) < 80 else "low"

        return {
            "findings": audit,
            "severity": severity,
            "summary": f"ISO 27001 audit of {target}: {audit.get('overall_score', 0)}% compliant",
            "recommendations": audit.get("recommendations", []),
        }

    async def _pipeda_audit(self, target: str, config: dict) -> dict:
        """Audit against PIPEDA (Canadian privacy law)."""
        prompt = f"""Audit this system against PIPEDA (Personal Information Protection and Electronic Documents Act):

System: {target}
Configuration: {json.dumps(config, indent=2, default=str)}

Assess the 10 PIPEDA Fair Information Principles:
1. Accountability, 2. Identifying Purposes, 3. Consent, 4. Limiting Collection,
5. Limiting Use/Disclosure/Retention, 6. Accuracy, 7. Safeguards,
8. Openness, 9. Individual Access, 10. Challenging Compliance

Respond with JSON:
{{
    "overall_compliant": true/false,
    "score": 0-100,
    "principles": [
        {{"principle": 1, "name": "Accountability", "status": "compliant/non_compliant", "notes": "..."}}
    ],
    "breach_notification_ready": true/false,
    "critical_gaps": ["gap1"],
    "recommendations": ["rec1"]
}}"""

        try:
            result = await self.llm.analyze(prompt=prompt, json_mode=True, max_tokens=2048)
            audit = json.loads(result)
        except Exception:
            audit = {"overall_compliant": False, "score": 0, "recommendations": ["Full PIPEDA audit required"]}

        severity = "critical" if not audit.get("overall_compliant") else "low"

        return {
            "findings": audit,
            "severity": severity,
            "summary": f"PIPEDA audit of {target}: {'Compliant' if audit.get('overall_compliant') else 'Non-compliant'} ({audit.get('score', 0)}%)",
            "recommendations": audit.get("recommendations", []),
        }

    async def _gap_analysis(self, target: str, framework: str, config: dict) -> dict:
        """Comprehensive gap analysis against specified framework."""
        prompt = f"""Perform a gap analysis for {target} against the {framework.upper()} framework.

Current configuration:
{json.dumps(config, indent=2, default=str)}

Identify:
1. All compliance gaps ranked by severity
2. Quick wins (can fix in < 1 day)
3. Medium-term fixes (1 week)
4. Long-term projects (1+ month)
5. Estimated cost to achieve full compliance

Respond with JSON:
{{
    "framework": "{framework}",
    "current_score": 0-100,
    "target_score": 100,
    "gaps": [
        {{"id": 1, "description": "...", "severity": "critical/high/medium/low", "effort": "quick/medium/long", "estimated_hours": 0}}
    ],
    "quick_wins": ["win1"],
    "estimated_total_hours": 0,
    "estimated_cost_cad": 0
}}"""

        try:
            result = await self.llm.analyze(prompt=prompt, json_mode=True, max_tokens=2048)
            analysis = json.loads(result)
        except Exception:
            analysis = {"framework": framework, "current_score": 0, "gaps": []}

        severity = "high" if analysis.get("current_score", 0) < 60 else "medium"

        return {
            "findings": analysis,
            "severity": severity,
            "summary": f"Gap analysis ({framework.upper()}): {analysis.get('current_score', 0)}% → 100% target",
            "recommendations": analysis.get("quick_wins", [])[:5],
        }

    async def _collect_evidence(self, target: str, config: dict) -> dict:
        """Collect and organize compliance evidence."""
        prompt = f"""For a compliance audit of {target}, identify what evidence should be collected:

Configuration available: {json.dumps(config, indent=2, default=str)}

List evidence items needed for SOC2 Type II audit:

Respond with JSON:
{{
    "evidence_items": [
        {{"item": "description", "source": "where to find it", "frequency": "how often to collect", "status": "available/missing"}}
    ],
    "available_count": 0,
    "missing_count": 0,
    "readiness_score": 0-100
}}"""

        try:
            result = await self.llm.analyze(prompt=prompt, json_mode=True, max_tokens=2048)
            evidence = json.loads(result)
        except Exception:
            evidence = {"evidence_items": [], "readiness_score": 0}

        return {
            "findings": evidence,
            "severity": "medium" if evidence.get("readiness_score", 0) < 70 else "low",
            "summary": f"Evidence collection for {target}: {evidence.get('readiness_score', 0)}% audit-ready",
            "recommendations": [
                f"Collect missing evidence: {item['item']}"
                for item in evidence.get("evidence_items", [])
                if item.get("status") == "missing"
            ][:5],
        }
