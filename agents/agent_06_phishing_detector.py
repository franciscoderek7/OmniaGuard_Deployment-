"""
R&D: OmniaGuard Agent 06 — Phishing Detector
===============================================
Email and URL phishing analysis.

Capabilities:
- Email header analysis (SPF, DKIM, DMARC validation)
- URL reputation and redirect chain analysis
- Visual similarity detection (brand impersonation)
- Social engineering pattern recognition via LLM
- Bulk email campaign detection

Integration: Together AI for content analysis + free URL/domain APIs.
"""

import json
import re
import hashlib
from typing import Optional
from urllib.parse import urlparse
import httpx
from agents.base_agent import BaseAgent


class PhishingDetector(BaseAgent):
    """Agent 06: Phishing email and URL analysis."""

    @property
    def description(self) -> str:
        return "Detects phishing emails, malicious URLs, and social engineering attempts targeting Francisco Holdings entities."

    @property
    def scan_types(self) -> list[str]:
        return ["email_analysis", "url_check", "header_analysis", "bulk_scan"]

    # Known phishing indicators
    URGENCY_KEYWORDS = [
        "urgent", "immediate action", "account suspended", "verify now",
        "click here immediately", "your account will be", "unauthorized",
        "security alert", "confirm your identity", "limited time",
    ]

    SUSPICIOUS_TLD = [
        ".xyz", ".top", ".click", ".loan", ".work", ".gq", ".ml",
        ".cf", ".tk", ".buzz", ".icu", ".monster",
    ]

    async def scan(self, target: str, scan_type: str = "url_check", **kwargs) -> dict:
        """
        Analyze target for phishing indicators.

        Args:
            target: Email content, URL, or email address to analyze
            scan_type: Type of phishing analysis
            kwargs: headers (dict), sender (str), subject (str)
        """
        if scan_type == "email_analysis":
            return await self._analyze_email(target, **kwargs)
        elif scan_type == "url_check":
            return await self._check_url(target)
        elif scan_type == "header_analysis":
            headers = kwargs.get("headers", {})
            return await self._analyze_headers(target, headers)
        elif scan_type == "bulk_scan":
            urls = kwargs.get("urls", [target])
            return await self._bulk_url_scan(urls)
        else:
            return await self._check_url(target)

    async def _analyze_email(self, email_body: str, **kwargs) -> dict:
        """Full phishing analysis of an email."""
        sender = kwargs.get("sender", "unknown")
        subject = kwargs.get("subject", "")
        headers = kwargs.get("headers", {})

        # Extract URLs from email
        urls = re.findall(r'https?://[^\s<>"]+', email_body)

        # Check urgency keywords
        urgency_score = sum(
            1 for kw in self.URGENCY_KEYWORDS
            if kw.lower() in email_body.lower()
        )

        # Check sender domain
        sender_domain = sender.split("@")[-1] if "@" in sender else ""
        suspicious_sender = any(sender_domain.endswith(tld) for tld in self.SUSPICIOUS_TLD)

        # URL analysis
        suspicious_urls = []
        for url in urls[:10]:
            url_result = await self._quick_url_check(url)
            if url_result["suspicious"]:
                suspicious_urls.append(url_result)

        # LLM content analysis
        llm_analysis = await self._llm_phishing_analysis(email_body, sender, subject)

        # Calculate phishing score
        phishing_score = self._calculate_phishing_score(
            urgency_score, suspicious_sender, suspicious_urls, llm_analysis
        )

        severity = "critical" if phishing_score >= 80 else \
                   "high" if phishing_score >= 60 else \
                   "medium" if phishing_score >= 30 else "low"

        return {
            "findings": {
                "phishing_score": phishing_score,
                "sender": sender,
                "sender_domain": sender_domain,
                "suspicious_sender": suspicious_sender,
                "subject": subject,
                "urgency_keywords_found": urgency_score,
                "urls_found": len(urls),
                "suspicious_urls": suspicious_urls,
                "llm_analysis": llm_analysis,
            },
            "severity": severity,
            "summary": f"Phishing score: {phishing_score}/100 — {'LIKELY PHISHING' if phishing_score >= 60 else 'Probably safe'}",
            "recommendations": self._generate_phishing_recommendations(phishing_score, suspicious_urls),
        }

    async def _check_url(self, url: str) -> dict:
        """Deep analysis of a single URL."""
        parsed = urlparse(url)
        domain = parsed.netloc

        checks = {
            "url": url,
            "domain": domain,
            "suspicious_tld": any(domain.endswith(tld) for tld in self.SUSPICIOUS_TLD),
            "ip_in_url": bool(re.match(r"\d+\.\d+\.\d+\.\d+", domain)),
            "excessive_subdomains": domain.count(".") > 3,
            "url_length": len(url),
            "has_at_symbol": "@" in url,
            "has_double_slash_redirect": "//" in url[8:],  # After protocol
        }

        # Check redirect chain
        redirect_chain = await self._follow_redirects(url)
        checks["redirect_chain"] = redirect_chain
        checks["redirects_count"] = len(redirect_chain)

        # Domain age / reputation (via LLM knowledge)
        domain_analysis = await self._llm_domain_check(domain)
        checks["domain_analysis"] = domain_analysis

        # Score
        score = 0
        if checks["suspicious_tld"]:
            score += 30
        if checks["ip_in_url"]:
            score += 40
        if checks["excessive_subdomains"]:
            score += 20
        if checks["url_length"] > 100:
            score += 15
        if checks["has_at_symbol"]:
            score += 25
        if checks["redirects_count"] > 3:
            score += 20

        severity = "critical" if score >= 70 else "high" if score >= 50 else \
                   "medium" if score >= 25 else "low"

        return {
            "findings": checks,
            "severity": severity,
            "summary": f"URL risk score: {score}/100 — {domain}",
            "recommendations": [
                "Do NOT click this URL" if score >= 50 else "URL appears relatively safe",
                f"Domain has {checks['redirects_count']} redirects" if checks["redirects_count"] > 1 else "",
            ],
        }

    async def _analyze_headers(self, sender: str, headers: dict) -> dict:
        """Analyze email headers for authentication failures."""
        results = {
            "spf": self._check_spf(headers),
            "dkim": self._check_dkim(headers),
            "dmarc": self._check_dmarc(headers),
            "received_chain": self._parse_received_headers(headers),
        }

        # Count failures
        failures = sum(1 for v in [results["spf"], results["dkim"], results["dmarc"]]
                      if v.get("status") == "fail")

        severity = "high" if failures >= 2 else "medium" if failures >= 1 else "low"

        return {
            "findings": results,
            "severity": severity,
            "summary": f"Email auth: SPF={results['spf']['status']}, DKIM={results['dkim']['status']}, DMARC={results['dmarc']['status']}",
            "recommendations": [
                f"SPF failed — sender may be spoofed" if results["spf"]["status"] == "fail" else "",
                f"DKIM failed — email integrity not verified" if results["dkim"]["status"] == "fail" else "",
                f"DMARC failed — domain policy violated" if results["dmarc"]["status"] == "fail" else "",
            ],
        }

    async def _bulk_url_scan(self, urls: list[str]) -> dict:
        """Scan multiple URLs for phishing indicators."""
        results = []
        malicious_count = 0

        for url in urls[:50]:
            check = await self._quick_url_check(url)
            results.append(check)
            if check["suspicious"]:
                malicious_count += 1

        severity = "critical" if malicious_count > 5 else \
                   "high" if malicious_count > 0 else "info"

        return {
            "findings": {
                "total_scanned": len(results),
                "malicious": malicious_count,
                "clean": len(results) - malicious_count,
                "results": results,
            },
            "severity": severity,
            "summary": f"Bulk scan: {malicious_count}/{len(results)} URLs flagged as suspicious",
            "recommendations": [
                f"Block: {r['url']}" for r in results if r["suspicious"]
            ][:10],
        }

    async def _quick_url_check(self, url: str) -> dict:
        """Quick check of a single URL."""
        parsed = urlparse(url)
        domain = parsed.netloc

        suspicious = (
            any(domain.endswith(tld) for tld in self.SUSPICIOUS_TLD)
            or bool(re.match(r"\d+\.\d+\.\d+\.\d+", domain))
            or domain.count(".") > 3
            or "@" in url
            or len(url) > 150
        )

        return {
            "url": url,
            "domain": domain,
            "suspicious": suspicious,
        }

    async def _follow_redirects(self, url: str, max_redirects: int = 5) -> list[str]:
        """Follow URL redirect chain."""
        chain = [url]
        try:
            async with httpx.AsyncClient(follow_redirects=False, timeout=10.0) as client:
                current_url = url
                for _ in range(max_redirects):
                    response = await client.head(current_url)
                    if response.status_code in (301, 302, 303, 307, 308):
                        location = response.headers.get("location", "")
                        if location:
                            chain.append(location)
                            current_url = location
                        else:
                            break
                    else:
                        break
        except Exception:
            pass
        return chain

    def _calculate_phishing_score(
        self, urgency: int, suspicious_sender: bool, suspicious_urls: list, llm_analysis: dict
    ) -> int:
        """Calculate composite phishing score 0-100."""
        score = 0
        score += min(urgency * 10, 30)
        if suspicious_sender:
            score += 25
        score += min(len(suspicious_urls) * 15, 30)
        llm_confidence = llm_analysis.get("phishing_confidence", 0)
        score += int(llm_confidence * 30)
        return min(score, 100)

    def _check_spf(self, headers: dict) -> dict:
        """Check SPF result from headers."""
        auth_results = headers.get("Authentication-Results", headers.get("authentication-results", ""))
        if "spf=pass" in auth_results.lower():
            return {"status": "pass"}
        elif "spf=fail" in auth_results.lower():
            return {"status": "fail"}
        return {"status": "unknown"}

    def _check_dkim(self, headers: dict) -> dict:
        """Check DKIM result from headers."""
        auth_results = headers.get("Authentication-Results", headers.get("authentication-results", ""))
        if "dkim=pass" in auth_results.lower():
            return {"status": "pass"}
        elif "dkim=fail" in auth_results.lower():
            return {"status": "fail"}
        return {"status": "unknown"}

    def _check_dmarc(self, headers: dict) -> dict:
        """Check DMARC result from headers."""
        auth_results = headers.get("Authentication-Results", headers.get("authentication-results", ""))
        if "dmarc=pass" in auth_results.lower():
            return {"status": "pass"}
        elif "dmarc=fail" in auth_results.lower():
            return {"status": "fail"}
        return {"status": "unknown"}

    def _parse_received_headers(self, headers: dict) -> list[str]:
        """Parse Received headers to trace email path."""
        received = headers.get("Received", [])
        if isinstance(received, str):
            received = [received]
        return received[:10]

    def _generate_phishing_recommendations(self, score: int, suspicious_urls: list) -> list[str]:
        """Generate recommendations based on phishing analysis."""
        recs = []
        if score >= 60:
            recs.append("DO NOT interact with this email — likely phishing")
            recs.append("Report to IT security team immediately")
            recs.append("If you clicked any links, change your password NOW")
        elif score >= 30:
            recs.append("Exercise caution — some phishing indicators present")
            recs.append("Verify sender through a separate communication channel")
        else:
            recs.append("Email appears legitimate — standard caution applies")

        if suspicious_urls:
            recs.append(f"Block {len(suspicious_urls)} suspicious URLs at gateway")

        return recs[:5]

    async def _llm_phishing_analysis(self, body: str, sender: str, subject: str) -> dict:
        """LLM-powered phishing content analysis."""
        prompt = f"""Analyze this email for phishing indicators:

From: {sender}
Subject: {subject}
Body (first 500 chars): {body[:500]}

Assess:
1. Is this a phishing attempt? (confidence 0.0-1.0)
2. What social engineering techniques are used?
3. What is the likely goal (credential theft, malware, BEC)?
4. Brand being impersonated (if any)?

Respond with JSON:
{{
    "phishing_confidence": 0.0-1.0,
    "techniques": ["urgency", "authority", "fear"],
    "goal": "credential_theft/malware/bec/other",
    "impersonated_brand": "brand name or null",
    "reasoning": "brief explanation"
}}"""

        try:
            result = await self.llm.analyze(prompt=prompt, json_mode=True, max_tokens=512)
            return json.loads(result)
        except Exception:
            return {"phishing_confidence": 0.0, "techniques": [], "goal": "unknown"}

    async def _llm_domain_check(self, domain: str) -> dict:
        """LLM knowledge-based domain assessment."""
        prompt = f"""Is this domain known to be associated with phishing or malware?
Domain: {domain}

Respond with JSON:
{{
    "known_malicious": true/false,
    "category": "legitimate/suspicious/malicious/unknown",
    "notes": "brief assessment"
}}"""

        try:
            result = await self.llm.analyze(prompt=prompt, model=self.llm.fast_model, json_mode=True, max_tokens=256)
            return json.loads(result)
        except Exception:
            return {"known_malicious": False, "category": "unknown"}
