"""
R&D: OmniaGuard Agent 02 — Vulnerability Assessor
====================================================
CVE matching, vulnerability scoring, and remediation guidance.

Capabilities:
- Service version → CVE database lookup
- CVSS score analysis
- Exploit availability checking
- Patch priority ranking
- Remediation guidance via LLM

Integration: NVD API (free) + Together AI for contextual analysis.
"""

import json
import httpx
from typing import Optional
from agents.base_agent import BaseAgent


class VulnAssessor(BaseAgent):
    """Agent 02: Vulnerability assessment and CVE matching."""

    NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    @property
    def description(self) -> str:
        return "Identifies known vulnerabilities (CVEs) in detected services and provides remediation guidance."

    @property
    def scan_types(self) -> list[str]:
        return ["service_check", "cve_lookup", "full_assessment", "patch_priority"]

    async def scan(self, target: str, scan_type: str = "service_check", **kwargs) -> dict:
        """
        Assess vulnerabilities for a target.

        Args:
            target: Service identifier (e.g., "nginx/1.18.0", "openssh/8.2")
                    or IP/domain for full assessment
            scan_type: Type of assessment
            kwargs: services (list of service dicts from Agent 01)
        """
        if scan_type == "cve_lookup":
            return await self._cve_lookup(target)
        elif scan_type == "service_check":
            services = kwargs.get("services", [])
            return await self._check_services(target, services)
        elif scan_type == "full_assessment":
            services = kwargs.get("services", [])
            return await self._full_assessment(target, services)
        elif scan_type == "patch_priority":
            vulns = kwargs.get("vulnerabilities", [])
            return await self._prioritize_patches(target, vulns)
        else:
            return await self._cve_lookup(target)

    async def _cve_lookup(self, keyword: str) -> dict:
        """Look up CVEs for a specific software/version."""
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.get(
                    self.NVD_API_BASE,
                    params={
                        "keywordSearch": keyword,
                        "resultsPerPage": 20,
                    },
                )
                if response.status_code == 200:
                    data = response.json()
                    vulns = self._parse_nvd_response(data)
                    severity = self._calculate_max_severity(vulns)

                    return {
                        "findings": {
                            "keyword": keyword,
                            "total_cves": len(vulns),
                            "vulnerabilities": vulns[:10],  # Top 10
                        },
                        "severity": severity,
                        "summary": f"Found {len(vulns)} CVEs for '{keyword}'",
                        "recommendations": self._generate_recommendations(vulns),
                    }
                else:
                    return await self._llm_fallback_lookup(keyword)
        except Exception as e:
            return await self._llm_fallback_lookup(keyword)

    async def _check_services(self, target: str, services: list[dict]) -> dict:
        """Check vulnerabilities for a list of detected services."""
        all_vulns = []

        for service in services:
            service_name = service.get("service", "")
            version = service.get("version", "")
            port = service.get("port", 0)

            if service_name and service_name != "unknown":
                keyword = f"{service_name} {version}".strip()
                result = await self._cve_lookup(keyword)
                vulns = result.get("findings", {}).get("vulnerabilities", [])
                for v in vulns:
                    v["affected_port"] = port
                    v["affected_service"] = service_name
                all_vulns.extend(vulns)

        # Sort by CVSS score descending
        all_vulns.sort(key=lambda x: x.get("cvss_score", 0), reverse=True)
        severity = self._calculate_max_severity(all_vulns)

        return {
            "findings": {
                "target": target,
                "services_checked": len(services),
                "total_vulnerabilities": len(all_vulns),
                "critical": len([v for v in all_vulns if v.get("cvss_score", 0) >= 9.0]),
                "high": len([v for v in all_vulns if 7.0 <= v.get("cvss_score", 0) < 9.0]),
                "medium": len([v for v in all_vulns if 4.0 <= v.get("cvss_score", 0) < 7.0]),
                "low": len([v for v in all_vulns if v.get("cvss_score", 0) < 4.0]),
                "vulnerabilities": all_vulns[:20],
            },
            "severity": severity,
            "summary": f"Found {len(all_vulns)} vulnerabilities across {len(services)} services on {target}",
            "recommendations": self._generate_recommendations(all_vulns),
        }

    async def _full_assessment(self, target: str, services: list[dict]) -> dict:
        """Complete vulnerability assessment with LLM-powered analysis."""
        # Get raw CVE data
        service_result = await self._check_services(target, services)
        vulns = service_result["findings"]["vulnerabilities"]

        # LLM deep analysis
        if vulns:
            analysis = await self._llm_deep_analysis(target, vulns)
            service_result["findings"]["llm_analysis"] = analysis
            service_result["recommendations"] = analysis.get("prioritized_actions", [])

        return service_result

    async def _prioritize_patches(self, target: str, vulnerabilities: list[dict]) -> dict:
        """Rank patches by business impact and exploitability."""
        prompt = f"""Prioritize these vulnerabilities for patching on {target}:

{json.dumps(vulnerabilities[:10], indent=2)}

Consider:
1. CVSS score
2. Known exploits in the wild
3. Network exposure (internet-facing vs internal)
4. Business impact if exploited

Respond with JSON:
{{
    "patch_order": [
        {{"cve_id": "CVE-...", "priority": 1, "reason": "...", "effort": "low/medium/high"}}
    ],
    "estimated_total_hours": 0,
    "risk_if_unpatched": "description"
}}"""

        try:
            result = await self.llm.analyze(prompt=prompt, json_mode=True)
            priority_data = json.loads(result)
        except Exception:
            priority_data = {"patch_order": [], "estimated_total_hours": 0}

        return {
            "findings": priority_data,
            "severity": self._calculate_max_severity(vulnerabilities),
            "summary": f"Patch priority plan for {len(vulnerabilities)} vulnerabilities on {target}",
            "recommendations": [
                item.get("reason", "") for item in priority_data.get("patch_order", [])[:5]
            ],
        }

    def _parse_nvd_response(self, data: dict) -> list[dict]:
        """Parse NVD API response into simplified vulnerability list."""
        vulns = []
        for item in data.get("vulnerabilities", []):
            cve = item.get("cve", {})
            cve_id = cve.get("id", "Unknown")

            # Get CVSS score
            metrics = cve.get("metrics", {})
            cvss_score = 0.0
            if "cvssMetricV31" in metrics:
                cvss_score = metrics["cvssMetricV31"][0].get("cvssData", {}).get("baseScore", 0.0)
            elif "cvssMetricV2" in metrics:
                cvss_score = metrics["cvssMetricV2"][0].get("cvssData", {}).get("baseScore", 0.0)

            # Get description
            descriptions = cve.get("descriptions", [])
            desc = next(
                (d["value"] for d in descriptions if d.get("lang") == "en"),
                "No description available",
            )

            vulns.append({
                "cve_id": cve_id,
                "cvss_score": cvss_score,
                "description": desc[:200],
                "published": cve.get("published", ""),
            })

        return sorted(vulns, key=lambda x: x["cvss_score"], reverse=True)

    def _calculate_max_severity(self, vulns: list[dict]) -> str:
        """Determine overall severity from vulnerability list."""
        if not vulns:
            return "info"
        max_cvss = max(v.get("cvss_score", 0) for v in vulns)
        if max_cvss >= 9.0:
            return "critical"
        elif max_cvss >= 7.0:
            return "high"
        elif max_cvss >= 4.0:
            return "medium"
        return "low"

    def _generate_recommendations(self, vulns: list[dict]) -> list[str]:
        """Generate basic recommendations from vulnerability data."""
        recs = []
        critical = [v for v in vulns if v.get("cvss_score", 0) >= 9.0]
        high = [v for v in vulns if 7.0 <= v.get("cvss_score", 0) < 9.0]

        if critical:
            recs.append(f"URGENT: Patch {len(critical)} critical vulnerabilities immediately")
        if high:
            recs.append(f"HIGH: Address {len(high)} high-severity vulnerabilities within 48 hours")
        if len(vulns) > 10:
            recs.append("Consider automated patch management to handle volume")
        if not vulns:
            recs.append("No known vulnerabilities detected — maintain update schedule")

        return recs[:5]

    async def _llm_fallback_lookup(self, keyword: str) -> dict:
        """Use LLM when NVD API is unavailable."""
        prompt = f"""What are the most critical known vulnerabilities for: {keyword}

List top 5 CVEs with:
- CVE ID
- CVSS score
- Brief description
- Whether exploits exist in the wild

Respond with JSON:
{{
    "vulnerabilities": [{{"cve_id": "...", "cvss_score": 0.0, "description": "...", "exploit_available": true/false}}]
}}"""

        try:
            result = await self.llm.analyze(prompt=prompt, json_mode=True)
            data = json.loads(result)
            vulns = data.get("vulnerabilities", [])
        except Exception:
            vulns = []

        return {
            "findings": {"keyword": keyword, "total_cves": len(vulns), "vulnerabilities": vulns, "source": "llm_knowledge"},
            "severity": self._calculate_max_severity(vulns),
            "summary": f"LLM analysis: {len(vulns)} known CVEs for '{keyword}'",
            "recommendations": self._generate_recommendations(vulns),
        }

    async def _llm_deep_analysis(self, target: str, vulns: list[dict]) -> dict:
        """Deep LLM analysis of vulnerability landscape."""
        prompt = f"""Analyze this vulnerability landscape for {target}:

{json.dumps(vulns[:10], indent=2)}

Provide:
1. Attack surface summary
2. Most likely attack vector
3. Prioritized remediation actions (top 5)
4. Estimated risk score (1-10)
5. Time to remediate estimate

Respond with JSON:
{{
    "attack_surface": "summary",
    "likely_attack_vector": "description",
    "prioritized_actions": ["action1", "action2"],
    "risk_score": 0,
    "remediation_hours": 0
}}"""

        try:
            result = await self.llm.analyze(prompt=prompt, json_mode=True)
            return json.loads(result)
        except Exception:
            return {"attack_surface": "Analysis unavailable", "prioritized_actions": []}
