"""
R&D: OmniaGuard Agent 09 — Access Controller
===============================================
IAM policy enforcement and access review.

Capabilities:
- Least privilege analysis
- Dormant account detection
- Permission drift monitoring
- Role-based access validation
- Separation of duties enforcement
- Access certification campaigns

Integration: Together AI for policy analysis + Supabase for access logs.
"""

import json
from datetime import datetime, timezone, timedelta
from typing import Optional
from agents.base_agent import BaseAgent


class AccessController(BaseAgent):
    """Agent 09: Identity and Access Management enforcement."""

    @property
    def description(self) -> str:
        return "Enforces least-privilege access, detects dormant accounts, monitors permission drift, and validates RBAC policies."

    @property
    def scan_types(self) -> list[str]:
        return ["privilege_audit", "dormant_accounts", "permission_drift", "rbac_validate", "separation_of_duties"]

    async def scan(self, target: str, scan_type: str = "privilege_audit", **kwargs) -> dict:
        """
        Audit access controls.

        Args:
            target: System or organization to audit
            scan_type: Type of access audit
            kwargs: users (list), roles (list), policies (list), access_logs (list)
        """
        users = kwargs.get("users", [])
        roles = kwargs.get("roles", [])
        policies = kwargs.get("policies", [])
        access_logs = kwargs.get("access_logs", [])

        if scan_type == "privilege_audit":
            return await self._privilege_audit(target, users, roles)
        elif scan_type == "dormant_accounts":
            return await self._find_dormant_accounts(target, users, access_logs)
        elif scan_type == "permission_drift":
            return await self._detect_permission_drift(target, users, roles)
        elif scan_type == "rbac_validate":
            return await self._validate_rbac(target, users, roles, policies)
        elif scan_type == "separation_of_duties":
            return await self._check_sod(target, users, roles)
        else:
            return await self._privilege_audit(target, users, roles)

    async def _privilege_audit(self, target: str, users: list, roles: list) -> dict:
        """Audit for over-privileged accounts."""
        prompt = f"""Audit these user accounts for excessive privileges:

System: {target}
Users: {json.dumps(users[:20], indent=2, default=str)}
Available Roles: {json.dumps(roles, indent=2, default=str)}

Identify:
1. Over-privileged accounts (have more access than needed)
2. Admin accounts that should be regular users
3. Service accounts with excessive permissions
4. Shared accounts (security risk)
5. Accounts without MFA

Respond with JSON:
{{
    "over_privileged": [{{"user": "...", "current_role": "...", "recommended_role": "...", "risk": "high/medium/low"}}],
    "admin_review": [{{"user": "...", "reason": "..."}}],
    "shared_accounts": ["..."],
    "no_mfa": ["..."],
    "overall_risk": "critical/high/medium/low",
    "recommendations": ["..."]
}}"""

        try:
            result = await self.llm.analyze(prompt=prompt, json_mode=True, max_tokens=2048)
            audit = json.loads(result)
        except Exception:
            audit = {"over_privileged": [], "overall_risk": "unknown", "recommendations": ["Manual audit required"]}

        severity = audit.get("overall_risk", "medium")

        return {
            "findings": audit,
            "severity": severity,
            "summary": f"Privilege audit of {target}: {len(audit.get('over_privileged', []))} over-privileged accounts",
            "recommendations": audit.get("recommendations", []),
        }

    async def _find_dormant_accounts(self, target: str, users: list, access_logs: list) -> dict:
        """Identify dormant/inactive accounts."""
        dormant_threshold = timedelta(days=90)
        now = datetime.now(timezone.utc)

        dormant = []
        active = []

        for user in users:
            last_login = user.get("last_login")
            if last_login:
                try:
                    last_dt = datetime.fromisoformat(last_login.replace("Z", "+00:00"))
                    if now - last_dt > dormant_threshold:
                        dormant.append({
                            "user": user.get("username", user.get("email", "unknown")),
                            "last_login": last_login,
                            "days_inactive": (now - last_dt).days,
                            "role": user.get("role", "unknown"),
                        })
                    else:
                        active.append(user.get("username", user.get("email")))
                except Exception:
                    dormant.append({"user": user.get("username", "unknown"), "last_login": "parse_error"})
            else:
                dormant.append({
                    "user": user.get("username", user.get("email", "unknown")),
                    "last_login": "never",
                    "days_inactive": 999,
                    "role": user.get("role", "unknown"),
                })

        # High-risk dormant = dormant + admin/elevated role
        high_risk = [d for d in dormant if d.get("role") in ("admin", "superadmin", "owner")]

        severity = "critical" if high_risk else "high" if dormant else "info"

        return {
            "findings": {
                "total_users": len(users),
                "dormant_count": len(dormant),
                "active_count": len(active),
                "high_risk_dormant": high_risk,
                "dormant_accounts": dormant[:20],
                "threshold_days": 90,
            },
            "severity": severity,
            "summary": f"Dormant accounts on {target}: {len(dormant)}/{len(users)} inactive >90 days ({len(high_risk)} high-risk)",
            "recommendations": [
                f"Disable {len(high_risk)} high-risk dormant admin accounts immediately" if high_risk else "",
                f"Review and disable {len(dormant)} dormant accounts" if dormant else "No dormant accounts found",
                "Implement automated account deprovisioning policy",
            ],
        }

    async def _detect_permission_drift(self, target: str, users: list, roles: list) -> dict:
        """Detect permission drift from baseline."""
        prompt = f"""Analyze these user permissions for drift from expected baselines:

System: {target}
Users with current permissions: {json.dumps(users[:15], indent=2, default=str)}
Expected role definitions: {json.dumps(roles, indent=2, default=str)}

Identify users whose actual permissions exceed their assigned role definition.

Respond with JSON:
{{
    "drift_detected": [{{"user": "...", "assigned_role": "...", "extra_permissions": ["..."], "risk": "high/medium/low"}}],
    "total_drift_count": 0,
    "highest_risk": "description",
    "recommendations": ["..."]
}}"""

        try:
            result = await self.llm.analyze(prompt=prompt, json_mode=True, max_tokens=1024)
            drift = json.loads(result)
        except Exception:
            drift = {"drift_detected": [], "total_drift_count": 0, "recommendations": ["Manual review required"]}

        severity = "high" if drift.get("total_drift_count", 0) > 3 else \
                   "medium" if drift.get("total_drift_count", 0) > 0 else "info"

        return {
            "findings": drift,
            "severity": severity,
            "summary": f"Permission drift on {target}: {drift.get('total_drift_count', 0)} accounts with excess permissions",
            "recommendations": drift.get("recommendations", []),
        }

    async def _validate_rbac(self, target: str, users: list, roles: list, policies: list) -> dict:
        """Validate RBAC implementation."""
        prompt = f"""Validate this RBAC implementation:

System: {target}
Roles defined: {json.dumps(roles, indent=2, default=str)}
Policies: {json.dumps(policies, indent=2, default=str)}
Sample users: {json.dumps(users[:10], indent=2, default=str)}

Check:
1. Are roles properly defined with least privilege?
2. Are there any role hierarchy issues?
3. Are policies correctly enforcing role boundaries?
4. Any users without proper role assignment?

Respond with JSON:
{{
    "rbac_valid": true/false,
    "issues": [{{"issue": "...", "severity": "high/medium/low", "fix": "..."}}],
    "score": 0-100,
    "recommendations": ["..."]
}}"""

        try:
            result = await self.llm.analyze(prompt=prompt, json_mode=True, max_tokens=1024)
            validation = json.loads(result)
        except Exception:
            validation = {"rbac_valid": False, "score": 0, "recommendations": ["Manual RBAC review required"]}

        severity = "high" if not validation.get("rbac_valid") else "low"

        return {
            "findings": validation,
            "severity": severity,
            "summary": f"RBAC validation for {target}: {'Valid' if validation.get('rbac_valid') else 'Issues found'} ({validation.get('score', 0)}%)",
            "recommendations": validation.get("recommendations", []),
        }

    async def _check_sod(self, target: str, users: list, roles: list) -> dict:
        """Check separation of duties violations."""
        prompt = f"""Check for Separation of Duties (SoD) violations:

System: {target}
Users and their roles: {json.dumps(users[:15], indent=2, default=str)}
Role definitions: {json.dumps(roles, indent=2, default=str)}

Common SoD conflicts:
- Same person can create AND approve transactions
- Same person manages users AND audits access
- Developer has production deployment access
- DBA has both read and delete on sensitive data

Respond with JSON:
{{
    "violations": [{{"user": "...", "conflict": "...", "risk": "critical/high/medium", "remediation": "..."}}],
    "total_violations": 0,
    "recommendations": ["..."]
}}"""

        try:
            result = await self.llm.analyze(prompt=prompt, json_mode=True, max_tokens=1024)
            sod = json.loads(result)
        except Exception:
            sod = {"violations": [], "total_violations": 0, "recommendations": ["Manual SoD review required"]}

        severity = "critical" if sod.get("total_violations", 0) > 3 else \
                   "high" if sod.get("total_violations", 0) > 0 else "info"

        return {
            "findings": sod,
            "severity": severity,
            "summary": f"SoD check on {target}: {sod.get('total_violations', 0)} violations found",
            "recommendations": sod.get("recommendations", []),
        }
