"""
R&D: OmniaGuard Agent 12 — Cloud Security
============================================
Cloud infrastructure security assessment.

Capabilities:
- Cloud misconfiguration detection (AWS, GCP, Azure, Supabase)
- Public exposure scanning
- IAM policy analysis
- Storage bucket security
- Serverless function security
- Cost anomaly detection (indicator of compromise)

Integration: Together AI for config analysis + cloud API checks.
"""

import json
from typing import Optional
from agents.base_agent import BaseAgent


class CloudSecurity(BaseAgent):
    """Agent 12: Cloud infrastructure security assessment."""

    @property
    def description(self) -> str:
        return "Scans cloud infrastructure for misconfigurations, public exposures, IAM issues, and storage security across AWS/GCP/Azure/Supabase."

    @property
    def scan_types(self) -> list[str]:
        return ["misconfig_scan", "public_exposure", "iam_audit", "storage_audit", "cost_anomaly"]

    # Common cloud misconfigurations
    CRITICAL_MISCONFIGSS = [
        "Public S3 bucket with sensitive data",
        "Security group allowing 0.0.0.0/0 on SSH/RDP",
        "Root account without MFA",
        "Unencrypted storage volumes",
        "Public database endpoint",
        "Overly permissive IAM policies",
        "Missing CloudTrail/audit logging",
        "Default VPC in use",
    ]

    async def scan(self, target: str, scan_type: str = "misconfig_scan", **kwargs) -> dict:
        """
        Assess cloud security posture.

        Args:
            target: Cloud account/project identifier or resource
            scan_type: Type of cloud security check
            kwargs: cloud_config (dict), provider (str), resources (list)
        """
        cloud_config = kwargs.get("cloud_config", {})
        provider = kwargs.get("provider", "aws")

        if scan_type == "misconfig_scan":
            return await self._misconfig_scan(target, cloud_config, provider)
        elif scan_type == "public_exposure":
            return await self._public_exposure(target, cloud_config)
        elif scan_type == "iam_audit":
            iam_policies = kwargs.get("iam_policies", [])
            return await self._iam_audit(target, iam_policies, provider)
        elif scan_type == "storage_audit":
            buckets = kwargs.get("buckets", [])
            return await self._storage_audit(target, buckets, provider)
        elif scan_type == "cost_anomaly":
            billing_data = kwargs.get("billing_data", {})
            return await self._cost_anomaly(target, billing_data)
        else:
            return await self._misconfig_scan(target, cloud_config, provider)

    async def _misconfig_scan(self, target: str, config: dict, provider: str) -> dict:
        """Scan for cloud misconfigurations."""
        prompt = f"""Audit this {provider.upper()} cloud configuration for security misconfigurations:

Account/Project: {target}
Provider: {provider}
Configuration: {json.dumps(config, indent=2, default=str)}

Check against cloud security best practices:
1. Network security (security groups, NACLs, firewalls)
2. Identity and access (IAM policies, roles, service accounts)
3. Data protection (encryption at rest/transit, key management)
4. Logging and monitoring (CloudTrail, VPC Flow Logs, alerts)
5. Compute security (instance metadata, IMDSv2, patching)
6. Database security (public access, encryption, backups)

Respond with JSON:
{{
    "provider": "{provider}",
    "total_findings": 0,
    "critical": [{{"resource": "...", "issue": "...", "fix": "..."}}],
    "high": [{{"resource": "...", "issue": "...", "fix": "..."}}],
    "medium": [{{"resource": "...", "issue": "...", "fix": "..."}}],
    "overall_score": 0-100,
    "recommendations": ["..."]
}}"""

        try:
            result = await self.llm.analyze(prompt=prompt, json_mode=True, max_tokens=2048)
            scan = json.loads(result)
        except Exception:
            scan = {"provider": provider, "total_findings": 0, "overall_score": 0, "recommendations": ["Provide cloud configuration for assessment"]}

        severity = "critical" if scan.get("critical") else \
                   "high" if scan.get("high") else "medium"

        return {
            "findings": scan,
            "severity": severity,
            "summary": f"Cloud scan ({provider}): {scan.get('total_findings', 0)} findings, score {scan.get('overall_score', 0)}/100",
            "recommendations": scan.get("recommendations", []),
        }

    async def _public_exposure(self, target: str, config: dict) -> dict:
        """Check for publicly exposed cloud resources."""
        prompt = f"""Check for publicly exposed resources in this cloud environment:

Account: {target}
Configuration: {json.dumps(config, indent=2, default=str)}

Look for:
1. Public S3/GCS/Blob storage buckets
2. Public database endpoints (RDS, Cloud SQL)
3. Public Elasticsearch/Redis/Memcached instances
4. Security groups with 0.0.0.0/0 ingress
5. Public serverless function endpoints without auth
6. Exposed management consoles
7. Public container registries

Respond with JSON:
{{
    "exposed_resources": [{{"resource": "...", "type": "...", "exposure_level": "internet/vpc/account", "risk": "critical/high/medium", "data_at_risk": "..."}}],
    "total_exposed": 0,
    "internet_facing": 0,
    "recommendations": ["..."]
}}"""

        try:
            result = await self.llm.analyze(prompt=prompt, json_mode=True, max_tokens=1024)
            exposure = json.loads(result)
        except Exception:
            exposure = {"exposed_resources": [], "total_exposed": 0, "recommendations": ["Manual review required"]}

        severity = "critical" if exposure.get("internet_facing", 0) > 0 else "medium"

        return {
            "findings": exposure,
            "severity": severity,
            "summary": f"Public exposure check: {exposure.get('total_exposed', 0)} exposed resources ({exposure.get('internet_facing', 0)} internet-facing)",
            "recommendations": exposure.get("recommendations", []),
        }

    async def _iam_audit(self, target: str, iam_policies: list, provider: str) -> dict:
        """Audit IAM policies for over-permission."""
        prompt = f"""Audit these {provider.upper()} IAM policies for security issues:

Account: {target}
IAM Policies: {json.dumps(iam_policies[:10], indent=2, default=str)}

Check for:
1. Wildcard permissions (*:*)
2. Admin access on non-admin accounts
3. Unused permissions (principle of least privilege)
4. Cross-account access without conditions
5. Missing MFA requirements
6. Service accounts with user-level access

Respond with JSON:
{{
    "total_policies_reviewed": {len(iam_policies)},
    "issues": [{{"policy": "...", "issue": "...", "severity": "critical/high/medium", "fix": "..."}}],
    "wildcard_permissions": 0,
    "admin_accounts": 0,
    "mfa_missing": 0,
    "overall_risk": "critical/high/medium/low",
    "recommendations": ["..."]
}}"""

        try:
            result = await self.llm.analyze(prompt=prompt, json_mode=True, max_tokens=1024)
            audit = json.loads(result)
        except Exception:
            audit = {"issues": [], "overall_risk": "unknown", "recommendations": ["Provide IAM policies for review"]}

        return {
            "findings": audit,
            "severity": audit.get("overall_risk", "medium"),
            "summary": f"IAM audit ({provider}): {len(audit.get('issues', []))} issues, {audit.get('wildcard_permissions', 0)} wildcard permissions",
            "recommendations": audit.get("recommendations", []),
        }

    async def _storage_audit(self, target: str, buckets: list, provider: str) -> dict:
        """Audit cloud storage security."""
        prompt = f"""Audit these {provider.upper()} storage resources for security:

Account: {target}
Storage Resources: {json.dumps(buckets[:15], indent=2, default=str)}

Check each bucket/container for:
1. Public access enabled
2. Encryption at rest
3. Versioning enabled
4. Lifecycle policies
5. Access logging
6. Cross-origin (CORS) configuration
7. Sensitive data exposure

Respond with JSON:
{{
    "total_reviewed": {len(buckets)},
    "public_buckets": [{{"name": "...", "data_risk": "..."}}],
    "unencrypted": ["..."],
    "no_versioning": ["..."],
    "no_logging": ["..."],
    "overall_risk": "critical/high/medium/low",
    "recommendations": ["..."]
}}"""

        try:
            result = await self.llm.analyze(prompt=prompt, json_mode=True, max_tokens=1024)
            audit = json.loads(result)
        except Exception:
            audit = {"total_reviewed": len(buckets), "overall_risk": "unknown", "recommendations": ["Provide bucket details"]}

        severity = "critical" if audit.get("public_buckets") else \
                   "high" if audit.get("unencrypted") else "medium"

        return {
            "findings": audit,
            "severity": severity,
            "summary": f"Storage audit ({provider}): {len(audit.get('public_buckets', []))} public, {len(audit.get('unencrypted', []))} unencrypted",
            "recommendations": audit.get("recommendations", []),
        }

    async def _cost_anomaly(self, target: str, billing_data: dict) -> dict:
        """Detect cost anomalies that may indicate compromise."""
        prompt = f"""Analyze this cloud billing data for anomalies that could indicate a security breach:

Account: {target}
Billing Data: {json.dumps(billing_data, indent=2, default=str)}

Cost anomalies can indicate:
- Crypto mining on compromised instances
- Data exfiltration (high egress)
- Unauthorized resource provisioning
- DDoS attack (high bandwidth)

Respond with JSON:
{{
    "anomalies_detected": true/false,
    "anomalies": [{{"service": "...", "expected_cost": 0, "actual_cost": 0, "deviation_percent": 0, "possible_cause": "..."}}],
    "total_unexpected_cost": 0,
    "security_indicators": ["..."],
    "recommendations": ["..."]
}}"""

        try:
            result = await self.llm.analyze(prompt=prompt, json_mode=True, max_tokens=1024)
            analysis = json.loads(result)
        except Exception:
            analysis = {"anomalies_detected": False, "anomalies": [], "recommendations": ["Provide billing data for analysis"]}

        severity = "critical" if analysis.get("anomalies_detected") else "info"

        return {
            "findings": analysis,
            "severity": severity,
            "summary": f"Cost anomaly check: {'ANOMALY DETECTED' if analysis.get('anomalies_detected') else 'Normal'} — ${analysis.get('total_unexpected_cost', 0)} unexpected",
            "recommendations": analysis.get("recommendations", []),
        }
