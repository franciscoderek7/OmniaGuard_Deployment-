"""
R&D: OmniaGuard Agent 03 — Threat Intelligence
=================================================
OSINT threat feed aggregation and correlation.

Capabilities:
- IP/domain reputation checking
- Threat feed aggregation (AbuseIPDB, VirusTotal, OTX)
- IOC (Indicator of Compromise) correlation
- Threat actor profiling via LLM
- Geolocation and ASN analysis

Integration: Free threat intel APIs + Together AI for correlation.
"""

import json
import httpx
from typing import Optional
from agents.base_agent import BaseAgent


class ThreatIntel(BaseAgent):
    """Agent 03: OSINT threat intelligence and IOC correlation."""

    # Free threat intel APIs
    ABUSEIPDB_API = "https://api.abuseipdb.com/api/v2"
    OTX_API = "https://otx.alienvault.com/api/v1"
    IPINFO_API = "https://ipinfo.io"

    @property
    def description(self) -> str:
        return "Aggregates threat intelligence from OSINT feeds and correlates IOCs across Francisco Holdings assets."

    @property
    def scan_types(self) -> list[str]:
        return ["ip_reputation", "domain_reputation", "ioc_check", "threat_landscape"]

    async def scan(self, target: str, scan_type: str = "ip_reputation", **kwargs) -> dict:
        """
        Gather threat intelligence for a target.

        Args:
            target: IP address, domain, or IOC to investigate
            scan_type: Type of intel gathering
        """
        if scan_type == "ip_reputation":
            return await self._check_ip_reputation(target)
        elif scan_type == "domain_reputation":
            return await self._check_domain_reputation(target)
        elif scan_type == "ioc_check":
            iocs = kwargs.get("iocs", [target])
            return await self._check_iocs(iocs)
        elif scan_type == "threat_landscape":
            return await self._threat_landscape(target)
        else:
            return await self._check_ip_reputation(target)

    async def _check_ip_reputation(self, ip: str) -> dict:
        """Check IP reputation across multiple sources."""
        results = {
            "ip": ip,
            "sources": {},
            "risk_score": 0,
            "categories": [],
        }

        # IPInfo (free, no key needed for basic)
        geo_data = await self._get_ip_info(ip)
        results["geolocation"] = geo_data

        # OTX AlienVault (free, no key for basic lookups)
        otx_data = await self._check_otx_ip(ip)
        results["sources"]["otx"] = otx_data

        # Calculate composite risk score
        risk_score = self._calculate_risk_score(results)
        results["risk_score"] = risk_score

        severity = "critical" if risk_score >= 80 else "high" if risk_score >= 60 else "medium" if risk_score >= 30 else "low"

        # LLM threat assessment
        assessment = await self._llm_threat_assessment(results)

        return {
            "findings": results,
            "severity": severity,
            "summary": f"IP {ip} risk score: {risk_score}/100 — {assessment.get('verdict', 'Unknown')}",
            "recommendations": assessment.get("recommendations", []),
        }

    async def _check_domain_reputation(self, domain: str) -> dict:
        """Check domain reputation and associated threats."""
        results = {
            "domain": domain,
            "sources": {},
        }

        # OTX domain check
        otx_data = await self._check_otx_domain(domain)
        results["sources"]["otx"] = otx_data

        # DNS resolution
        dns_data = await self._resolve_domain(domain)
        results["dns"] = dns_data

        # LLM analysis
        assessment = await self._llm_domain_assessment(domain, results)
        risk_score = assessment.get("risk_score", 0)

        severity = "critical" if risk_score >= 80 else "high" if risk_score >= 60 else "medium" if risk_score >= 30 else "low"

        return {
            "findings": results,
            "severity": severity,
            "summary": f"Domain {domain} risk score: {risk_score}/100",
            "recommendations": assessment.get("recommendations", []),
        }

    async def _check_iocs(self, iocs: list[str]) -> dict:
        """Check a list of IOCs against threat feeds."""
        results = []

        for ioc in iocs[:20]:  # Limit to 20 IOCs per batch
            ioc_type = self._identify_ioc_type(ioc)
            if ioc_type == "ip":
                check = await self._check_ip_reputation(ioc)
            elif ioc_type == "domain":
                check = await self._check_domain_reputation(ioc)
            else:
                check = await self._llm_ioc_check(ioc, ioc_type)

            results.append({
                "ioc": ioc,
                "type": ioc_type,
                "severity": check.get("severity", "info"),
                "summary": check.get("summary", ""),
            })

        malicious_count = len([r for r in results if r["severity"] in ("critical", "high")])
        severity = "critical" if malicious_count > 5 else "high" if malicious_count > 0 else "info"

        return {
            "findings": {
                "total_checked": len(results),
                "malicious": malicious_count,
                "results": results,
            },
            "severity": severity,
            "summary": f"Checked {len(results)} IOCs — {malicious_count} flagged as malicious",
            "recommendations": [
                f"Block IOC: {r['ioc']}" for r in results if r["severity"] in ("critical", "high")
            ][:10],
        }

    async def _threat_landscape(self, target: str) -> dict:
        """Generate threat landscape report for an organization."""
        prompt = f"""Generate a current threat landscape assessment for: {target}

Consider:
1. Industry-specific threats (if identifiable)
2. Current active threat actors targeting similar organizations
3. Most common attack vectors in 2024-2025
4. Emerging threats (AI-powered attacks, supply chain, etc.)

Respond with JSON:
{{
    "threat_actors": [{{"name": "...", "motivation": "...", "techniques": ["..."]}}],
    "top_attack_vectors": ["..."],
    "emerging_threats": ["..."],
    "risk_level": "critical/high/medium/low",
    "recommendations": ["..."]
}}"""

        try:
            result = await self.llm.analyze(prompt=prompt, json_mode=True, max_tokens=2048)
            landscape = json.loads(result)
        except Exception:
            landscape = {
                "threat_actors": [],
                "top_attack_vectors": ["Phishing", "Ransomware", "Supply chain"],
                "risk_level": "medium",
                "recommendations": ["Implement MFA", "Regular patching", "Security awareness training"],
            }

        return {
            "findings": landscape,
            "severity": landscape.get("risk_level", "medium"),
            "summary": f"Threat landscape for {target}: {landscape.get('risk_level', 'unknown')} risk",
            "recommendations": landscape.get("recommendations", []),
        }

    async def _get_ip_info(self, ip: str) -> dict:
        """Get geolocation and ASN info for an IP."""
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.get(f"{self.IPINFO_API}/{ip}/json")
                if response.status_code == 200:
                    return response.json()
        except Exception:
            pass
        return {"ip": ip, "error": "lookup_failed"}

    async def _check_otx_ip(self, ip: str) -> dict:
        """Check IP against OTX AlienVault."""
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                response = await client.get(
                    f"{self.OTX_API}/indicators/IPv4/{ip}/general"
                )
                if response.status_code == 200:
                    data = response.json()
                    return {
                        "pulse_count": data.get("pulse_info", {}).get("count", 0),
                        "reputation": data.get("reputation", 0),
                        "country": data.get("country_name", "Unknown"),
                    }
        except Exception:
            pass
        return {"pulse_count": 0, "reputation": 0, "error": "otx_unavailable"}

    async def _check_otx_domain(self, domain: str) -> dict:
        """Check domain against OTX AlienVault."""
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                response = await client.get(
                    f"{self.OTX_API}/indicators/domain/{domain}/general"
                )
                if response.status_code == 200:
                    data = response.json()
                    return {
                        "pulse_count": data.get("pulse_info", {}).get("count", 0),
                        "alexa_rank": data.get("alexa", "Unknown"),
                        "whois": data.get("whois", ""),
                    }
        except Exception:
            pass
        return {"pulse_count": 0, "error": "otx_unavailable"}

    async def _resolve_domain(self, domain: str) -> dict:
        """Resolve domain DNS records."""
        import socket
        try:
            ips = socket.gethostbyname_ex(domain)
            return {"hostname": ips[0], "aliases": ips[1], "addresses": ips[2]}
        except Exception:
            return {"error": "resolution_failed"}

    def _identify_ioc_type(self, ioc: str) -> str:
        """Identify the type of IOC."""
        import re
        if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ioc):
            return "ip"
        elif re.match(r"^[a-f0-9]{32}$", ioc, re.IGNORECASE):
            return "md5"
        elif re.match(r"^[a-f0-9]{64}$", ioc, re.IGNORECASE):
            return "sha256"
        elif "." in ioc and not ioc.startswith("http"):
            return "domain"
        elif ioc.startswith("http"):
            return "url"
        return "unknown"

    def _calculate_risk_score(self, results: dict) -> int:
        """Calculate composite risk score 0-100."""
        score = 0
        otx = results.get("sources", {}).get("otx", {})
        if otx.get("pulse_count", 0) > 0:
            score += min(otx["pulse_count"] * 10, 50)
        if otx.get("reputation", 0) > 0:
            score += otx["reputation"]
        return min(score, 100)

    async def _llm_threat_assessment(self, data: dict) -> dict:
        """LLM-powered threat assessment."""
        prompt = f"""Assess this IP/target based on gathered intelligence:

{json.dumps(data, indent=2, default=str)}

Respond with JSON:
{{
    "verdict": "malicious/suspicious/clean/unknown",
    "confidence": 0.0-1.0,
    "threat_type": "description or null",
    "recommendations": ["action1", "action2"]
}}"""

        try:
            result = await self.llm.analyze(prompt=prompt, json_mode=True, max_tokens=512)
            return json.loads(result)
        except Exception:
            return {"verdict": "unknown", "confidence": 0.0, "recommendations": []}

    async def _llm_domain_assessment(self, domain: str, data: dict) -> dict:
        """LLM domain threat assessment."""
        prompt = f"""Assess domain security risk: {domain}

Data: {json.dumps(data, indent=2, default=str)}

Respond with JSON:
{{
    "risk_score": 0-100,
    "verdict": "malicious/suspicious/clean",
    "reasons": ["..."],
    "recommendations": ["..."]
}}"""

        try:
            result = await self.llm.analyze(prompt=prompt, json_mode=True, max_tokens=512)
            return json.loads(result)
        except Exception:
            return {"risk_score": 0, "verdict": "unknown", "recommendations": []}

    async def _llm_ioc_check(self, ioc: str, ioc_type: str) -> dict:
        """LLM fallback for IOC types we can't check via API."""
        prompt = f"""Is this IOC known to be malicious?
Type: {ioc_type}
Value: {ioc}

Respond with JSON: {{"severity": "critical/high/medium/low/info", "summary": "brief assessment"}}"""

        try:
            result = await self.llm.analyze(prompt=prompt, json_mode=True, max_tokens=256)
            return json.loads(result)
        except Exception:
            return {"severity": "info", "summary": f"Unable to assess {ioc_type}: {ioc}"}
