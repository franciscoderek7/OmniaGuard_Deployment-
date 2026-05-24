"""
R&D: OmniaGuard Agent 11 — Endpoint Monitor
==============================================
Endpoint security posture assessment.

Capabilities:
- OS patch level verification
- Antivirus/EDR status checking
- Firewall configuration audit
- Installed software inventory
- Unauthorized software detection
- Endpoint hardening score

Integration: Together AI for configuration analysis.
"""

import json
from datetime import datetime, timezone
from typing import Optional
from agents.base_agent import BaseAgent


class EndpointMonitor(BaseAgent):
    """Agent 11: Endpoint security monitoring and posture assessment."""

    @property
    def description(self) -> str:
        return "Monitors endpoint security posture — patches, AV status, firewall config, software inventory, and hardening compliance."

    @property
    def scan_types(self) -> list[str]:
        return ["posture_check", "patch_audit", "software_inventory", "hardening_score", "config_audit"]

    # CIS Benchmark categories
    CIS_CATEGORIES = [
        "Account Policies", "Local Policies", "Event Log",
        "System Services", "Registry", "File System",
        "Network Configuration", "Firewall", "Audit Policy",
    ]

    async def scan(self, target: str, scan_type: str = "posture_check", **kwargs) -> dict:
        """
        Assess endpoint security posture.

        Args:
            target: Hostname or endpoint identifier
            scan_type: Type of endpoint check
            kwargs: system_info (dict), installed_software (list), config (dict)
        """
        system_info = kwargs.get("system_info", {})
        config = kwargs.get("config", {})

        if scan_type == "posture_check":
            return await self._posture_check(target, system_info)
        elif scan_type == "patch_audit":
            return await self._patch_audit(target, system_info)
        elif scan_type == "software_inventory":
            software = kwargs.get("installed_software", [])
            return await self._software_inventory(target, software)
        elif scan_type == "hardening_score":
            return await self._hardening_score(target, config)
        elif scan_type == "config_audit":
            return await self._config_audit(target, config)
        else:
            return await self._posture_check(target, system_info)

    async def _posture_check(self, target: str, system_info: dict) -> dict:
        """Full endpoint security posture assessment."""
        prompt = f"""Assess the security posture of this endpoint:

Hostname: {target}
System Info: {json.dumps(system_info, indent=2, default=str)}

Evaluate:
1. OS version and patch status
2. Antivirus/EDR presence and status
3. Firewall enabled and configured
4. Disk encryption status
5. Auto-update enabled
6. Screen lock configured
7. USB/removable media policy
8. Remote access configuration

Respond with JSON:
{{
    "overall_score": 0-100,
    "risk_level": "critical/high/medium/low",
    "checks": [
        {{"check": "OS Patching", "status": "pass/fail/warning", "details": "...", "priority": 1-5}}
    ],
    "critical_issues": ["issue1"],
    "recommendations": ["rec1"]
}}"""

        try:
            result = await self.llm.analyze(prompt=prompt, json_mode=True, max_tokens=2048)
            posture = json.loads(result)
        except Exception:
            posture = {"overall_score": 0, "risk_level": "unknown", "checks": [], "recommendations": ["Manual assessment required"]}

        severity = posture.get("risk_level", "medium")

        return {
            "findings": posture,
            "severity": severity,
            "summary": f"Endpoint posture for {target}: {posture.get('overall_score', 0)}/100 ({posture.get('risk_level', 'unknown')} risk)",
            "recommendations": posture.get("recommendations", []),
        }

    async def _patch_audit(self, target: str, system_info: dict) -> dict:
        """Audit patch levels against known vulnerabilities."""
        os_version = system_info.get("os_version", "unknown")
        installed_patches = system_info.get("patches", [])

        prompt = f"""Audit the patch status of this system:

Hostname: {target}
OS: {os_version}
Installed patches: {json.dumps(installed_patches[:20])}
Last patch date: {system_info.get('last_patch_date', 'unknown')}

Identify:
1. Critical missing patches
2. Days since last security update
3. Known CVEs affecting this OS version
4. Patch compliance percentage

Respond with JSON:
{{
    "patch_compliance": 0-100,
    "days_since_last_patch": 0,
    "missing_critical": [{{"cve": "CVE-XXXX-XXXX", "severity": "critical/high", "description": "..."}}],
    "missing_count": 0,
    "os_eol": true/false,
    "recommendations": ["..."]
}}"""

        try:
            result = await self.llm.analyze(prompt=prompt, json_mode=True, max_tokens=1024)
            audit = json.loads(result)
        except Exception:
            audit = {"patch_compliance": 0, "missing_critical": [], "recommendations": ["Unable to assess — provide OS details"]}

        severity = "critical" if audit.get("os_eol") or len(audit.get("missing_critical", [])) > 3 else \
                   "high" if audit.get("patch_compliance", 100) < 80 else \
                   "medium" if audit.get("patch_compliance", 100) < 95 else "low"

        return {
            "findings": audit,
            "severity": severity,
            "summary": f"Patch audit for {target}: {audit.get('patch_compliance', 0)}% compliant, {len(audit.get('missing_critical', []))} critical missing",
            "recommendations": audit.get("recommendations", []),
        }

    async def _software_inventory(self, target: str, software: list) -> dict:
        """Inventory installed software and flag unauthorized items."""
        prompt = f"""Review this software inventory for security concerns:

Hostname: {target}
Installed Software: {json.dumps(software[:30], indent=2, default=str)}

Identify:
1. Known vulnerable software versions
2. Unauthorized/risky software (P2P, remote access tools, crypto miners)
3. End-of-life software
4. Software that should be updated
5. Potentially unwanted programs (PUPs)

Respond with JSON:
{{
    "total_installed": {len(software)},
    "vulnerable": [{{"name": "...", "version": "...", "cve": "...", "risk": "critical/high/medium"}}],
    "unauthorized": [{{"name": "...", "reason": "..."}}],
    "eol_software": [{{"name": "...", "eol_date": "..."}}],
    "update_needed": [{{"name": "...", "current": "...", "latest": "..."}}],
    "overall_risk": "critical/high/medium/low",
    "recommendations": ["..."]
}}"""

        try:
            result = await self.llm.analyze(prompt=prompt, json_mode=True, max_tokens=2048)
            inventory = json.loads(result)
        except Exception:
            inventory = {"total_installed": len(software), "overall_risk": "unknown", "recommendations": ["Manual review required"]}

        severity = inventory.get("overall_risk", "medium")

        return {
            "findings": inventory,
            "severity": severity,
            "summary": f"Software inventory for {target}: {inventory.get('total_installed', 0)} apps, {len(inventory.get('vulnerable', []))} vulnerable",
            "recommendations": inventory.get("recommendations", []),
        }

    async def _hardening_score(self, target: str, config: dict) -> dict:
        """Calculate CIS benchmark hardening score."""
        prompt = f"""Score this endpoint against CIS Benchmarks:

Hostname: {target}
Configuration: {json.dumps(config, indent=2, default=str)}

Score each CIS category (0-100):
{json.dumps(self.CIS_CATEGORIES)}

Respond with JSON:
{{
    "overall_score": 0-100,
    "categories": [
        {{"category": "...", "score": 0-100, "critical_gaps": ["..."]}}
    ],
    "hardening_level": "minimal/basic/intermediate/advanced/maximum",
    "quick_wins": ["..."],
    "recommendations": ["..."]
}}"""

        try:
            result = await self.llm.analyze(prompt=prompt, json_mode=True, max_tokens=1024)
            score = json.loads(result)
        except Exception:
            score = {"overall_score": 0, "hardening_level": "unknown", "recommendations": ["Provide system configuration for assessment"]}

        severity = "critical" if score.get("overall_score", 0) < 40 else \
                   "high" if score.get("overall_score", 0) < 60 else \
                   "medium" if score.get("overall_score", 0) < 80 else "low"

        return {
            "findings": score,
            "severity": severity,
            "summary": f"Hardening score for {target}: {score.get('overall_score', 0)}/100 ({score.get('hardening_level', 'unknown')})",
            "recommendations": score.get("quick_wins", [])[:5],
        }

    async def _config_audit(self, target: str, config: dict) -> dict:
        """Audit endpoint configuration for security issues."""
        prompt = f"""Audit this endpoint configuration for security misconfigurations:

Hostname: {target}
Configuration: {json.dumps(config, indent=2, default=str)}

Check for:
1. Default credentials still in use
2. Unnecessary services running
3. Insecure protocol usage (telnet, FTP, HTTP)
4. Weak encryption settings
5. Missing security headers
6. Open ports that should be closed
7. Logging/monitoring gaps

Respond with JSON:
{{
    "misconfigurations": [{{"issue": "...", "severity": "critical/high/medium/low", "fix": "..."}}],
    "total_issues": 0,
    "critical_count": 0,
    "recommendations": ["..."]
}}"""

        try:
            result = await self.llm.analyze(prompt=prompt, json_mode=True, max_tokens=1024)
            audit = json.loads(result)
        except Exception:
            audit = {"misconfigurations": [], "total_issues": 0, "recommendations": ["Provide configuration details"]}

        severity = "critical" if audit.get("critical_count", 0) > 0 else \
                   "high" if audit.get("total_issues", 0) > 5 else "medium"

        return {
            "findings": audit,
            "severity": severity,
            "summary": f"Config audit for {target}: {audit.get('total_issues', 0)} issues ({audit.get('critical_count', 0)} critical)",
            "recommendations": audit.get("recommendations", []),
        }
