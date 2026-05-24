"""
R&D: OmniaGuard Agent 10 — Data Loss Prevention
==================================================
Sensitive data detection and exfiltration prevention.

Capabilities:
- PII/PHI/PCI data detection in text and files
- Data classification (public/internal/confidential/restricted)
- Exfiltration pattern detection
- DLP policy enforcement
- Data flow mapping

Integration: Regex + LLM for context-aware classification.
"""

import json
import re
from typing import Optional
from agents.base_agent import BaseAgent


class DLPAgent(BaseAgent):
    """Agent 10: Data Loss Prevention — detect and protect sensitive data."""

    @property
    def description(self) -> str:
        return "Detects PII, PHI, PCI data in content, classifies data sensitivity, and monitors for exfiltration patterns."

    @property
    def scan_types(self) -> list[str]:
        return ["pii_scan", "classify", "exfiltration_check", "policy_check", "data_map"]

    # PII/PCI/PHI patterns
    PATTERNS = {
        "sin": r"\b\d{3}[-\s]?\d{3}[-\s]?\d{3}\b",  # Canadian SIN
        "ssn": r"\b\d{3}-\d{2}-\d{4}\b",  # US SSN
        "credit_card": r"\b(?:4\d{3}|5[1-5]\d{2}|3[47]\d{2}|6(?:011|5\d{2}))[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b",
        "email": r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b",
        "phone_ca": r"\b(?:\+1[-.]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b",
        "postal_code_ca": r"\b[A-Z]\d[A-Z]\s?\d[A-Z]\d\b",
        "date_of_birth": r"\b(?:19|20)\d{2}[-/](?:0[1-9]|1[0-2])[-/](?:0[1-9]|[12]\d|3[01])\b",
        "health_card_on": r"\b\d{4}[-\s]?\d{3}[-\s]?\d{3}[-\s]?[A-Z]{2}\b",
        "passport": r"\b[A-Z]{2}\d{6}\b",
        "bank_account": r"\b\d{5}[-\s]?\d{3}[-\s]?\d{7}\b",
        "ip_address": r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b",
        "api_key": r"\b(?:sk|pk|api|key|token)[-_][a-zA-Z0-9]{20,}\b",
    }

    async def scan(self, target: str, scan_type: str = "pii_scan", **kwargs) -> dict:
        """
        Scan for sensitive data.

        Args:
            target: Text content, file content, or system identifier
            scan_type: Type of DLP scan
            kwargs: content (str), policy (dict), threshold (str)
        """
        content = kwargs.get("content", target)

        if scan_type == "pii_scan":
            return await self._pii_scan(content)
        elif scan_type == "classify":
            return await self._classify_data(content)
        elif scan_type == "exfiltration_check":
            network_data = kwargs.get("network_data", {})
            return await self._exfiltration_check(target, network_data)
        elif scan_type == "policy_check":
            policy = kwargs.get("policy", {})
            return await self._policy_check(content, policy)
        elif scan_type == "data_map":
            return await self._data_map(target, kwargs.get("systems", []))
        else:
            return await self._pii_scan(content)

    async def _pii_scan(self, content: str) -> dict:
        """Scan content for PII/PHI/PCI data."""
        findings = {}
        total_matches = 0

        for data_type, pattern in self.PATTERNS.items():
            matches = re.findall(pattern, content, re.IGNORECASE)
            if matches:
                # Redact for safety
                redacted = [self._redact(m) for m in matches[:5]]
                findings[data_type] = {
                    "count": len(matches),
                    "samples_redacted": redacted,
                }
                total_matches += len(matches)

        # LLM context check for false positives
        if total_matches > 0:
            context_check = await self._llm_context_check(content[:1000], findings)
        else:
            context_check = {"false_positive_rate": 0.0, "confirmed_pii": []}

        severity = "critical" if total_matches > 10 else \
                   "high" if total_matches > 3 else \
                   "medium" if total_matches > 0 else "info"

        return {
            "findings": {
                "total_pii_found": total_matches,
                "by_type": findings,
                "context_analysis": context_check,
            },
            "severity": severity,
            "summary": f"PII scan: {total_matches} sensitive data items found across {len(findings)} categories",
            "recommendations": [
                "Encrypt or redact detected PII before storage/transmission" if total_matches > 0 else "No PII detected",
                f"Critical: {findings.get('credit_card', {}).get('count', 0)} credit card numbers exposed" if "credit_card" in findings else "",
                f"Critical: {findings.get('sin', {}).get('count', 0)} SIN numbers exposed" if "sin" in findings else "",
            ],
        }

    async def _classify_data(self, content: str) -> dict:
        """Classify data sensitivity level."""
        prompt = f"""Classify the sensitivity level of this data:

Content (first 500 chars): {content[:500]}

Classification levels:
- PUBLIC: Can be freely shared (marketing materials, public docs)
- INTERNAL: For internal use only (meeting notes, internal comms)
- CONFIDENTIAL: Business-sensitive (financials, strategy, contracts)
- RESTRICTED: Highest sensitivity (PII, health records, credentials)

Respond with JSON:
{{
    "classification": "PUBLIC/INTERNAL/CONFIDENTIAL/RESTRICTED",
    "confidence": 0.0-1.0,
    "reasoning": "why this classification",
    "data_types_detected": ["pii", "financial", "health", "credentials"],
    "handling_requirements": ["requirement1"],
    "retention_recommendation": "duration"
}}"""

        try:
            result = await self.llm.analyze(prompt=prompt, json_mode=True, max_tokens=512)
            classification = json.loads(result)
        except Exception:
            classification = {"classification": "INTERNAL", "confidence": 0.0}

        severity_map = {"PUBLIC": "info", "INTERNAL": "low", "CONFIDENTIAL": "medium", "RESTRICTED": "critical"}
        severity = severity_map.get(classification.get("classification", "INTERNAL"), "medium")

        return {
            "findings": classification,
            "severity": severity,
            "summary": f"Data classified as: {classification.get('classification', 'UNKNOWN')} (confidence: {classification.get('confidence', 0):.0%})",
            "recommendations": classification.get("handling_requirements", []),
        }

    async def _exfiltration_check(self, target: str, network_data: dict) -> dict:
        """Check for data exfiltration patterns."""
        prompt = f"""Analyze this network activity for data exfiltration indicators:

System: {target}
Network Data: {json.dumps(network_data, indent=2, default=str)}

Check for:
1. Unusual outbound data volumes (>normal baseline)
2. Data transfers to unknown/suspicious destinations
3. Encrypted channels to non-standard ports
4. DNS tunneling indicators
5. After-hours large transfers
6. Transfers to personal cloud storage

Respond with JSON:
{{
    "exfiltration_detected": true/false,
    "confidence": 0.0-1.0,
    "indicators": [{{"type": "...", "details": "...", "severity": "critical/high/medium"}}],
    "suspicious_destinations": ["ip/domain"],
    "data_volume_anomaly": true/false,
    "recommendations": ["..."]
}}"""

        try:
            result = await self.llm.analyze(prompt=prompt, json_mode=True, max_tokens=1024)
            analysis = json.loads(result)
        except Exception:
            analysis = {"exfiltration_detected": False, "confidence": 0.0, "indicators": []}

        severity = "critical" if analysis.get("exfiltration_detected") else "info"

        return {
            "findings": analysis,
            "severity": severity,
            "summary": f"Exfiltration check on {target}: {'ALERT — possible exfiltration' if analysis.get('exfiltration_detected') else 'No exfiltration detected'}",
            "recommendations": analysis.get("recommendations", []),
        }

    async def _policy_check(self, content: str, policy: dict) -> dict:
        """Check content against DLP policy."""
        # Run PII scan first
        pii_results = await self._pii_scan(content)
        pii_found = pii_results["findings"]["total_pii_found"]

        # Check against policy rules
        violations = []
        policy_rules = policy.get("rules", [])

        for rule in policy_rules:
            rule_type = rule.get("type", "")
            if rule_type == "no_pii" and pii_found > 0:
                violations.append({"rule": rule.get("name", "No PII"), "violation": f"{pii_found} PII items found"})
            elif rule_type == "max_classification":
                max_level = rule.get("level", "INTERNAL")
                # Would need classification result to check

        return {
            "findings": {
                "policy_violations": violations,
                "pii_scan": pii_results["findings"],
                "total_violations": len(violations),
            },
            "severity": "high" if violations else "info",
            "summary": f"DLP policy check: {len(violations)} violations found",
            "recommendations": [f"Fix violation: {v['rule']}" for v in violations],
        }

    async def _data_map(self, target: str, systems: list) -> dict:
        """Map data flows across systems."""
        prompt = f"""Map the data flows for this organization:

Organization: {target}
Systems: {json.dumps(systems, indent=2, default=str)}

Identify:
1. Where sensitive data is stored
2. How it flows between systems
3. External data sharing points
4. Potential leakage points
5. Data at rest vs. in transit encryption status

Respond with JSON:
{{
    "data_stores": [{{"system": "...", "data_types": ["..."], "encryption": "yes/no", "risk": "high/medium/low"}}],
    "data_flows": [{{"from": "...", "to": "...", "data_type": "...", "encrypted": true/false}}],
    "external_sharing": [{{"destination": "...", "data_type": "...", "authorized": true/false}}],
    "risk_points": ["..."],
    "recommendations": ["..."]
}}"""

        try:
            result = await self.llm.analyze(prompt=prompt, json_mode=True, max_tokens=2048)
            data_map = json.loads(result)
        except Exception:
            data_map = {"data_stores": [], "risk_points": ["Manual mapping required"]}

        return {
            "findings": data_map,
            "severity": "medium",
            "summary": f"Data map for {target}: {len(data_map.get('data_stores', []))} stores, {len(data_map.get('risk_points', []))} risk points",
            "recommendations": data_map.get("recommendations", []),
        }

    def _redact(self, value: str) -> str:
        """Redact sensitive value for safe display."""
        if len(value) <= 4:
            return "****"
        return value[:2] + "*" * (len(value) - 4) + value[-2:]

    async def _llm_context_check(self, content: str, findings: dict) -> dict:
        """Use LLM to check for false positives in PII detection."""
        prompt = f"""Review these PII detection results for false positives:

Content context (first 500 chars): {content[:500]}
Detected items: {json.dumps(findings, default=str)}

Are any of these likely false positives? (e.g., phone numbers that are actually order numbers, 
SIN patterns that are actually product codes)

Respond with JSON:
{{
    "false_positive_rate": 0.0-1.0,
    "confirmed_pii": ["type1", "type2"],
    "likely_false_positives": ["type1"],
    "notes": "explanation"
}}"""

        try:
            result = await self.llm.analyze(prompt=prompt, json_mode=True, max_tokens=512)
            return json.loads(result)
        except Exception:
            return {"false_positive_rate": 0.0, "confirmed_pii": list(findings.keys())}
