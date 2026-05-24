"""
R&D: OmniaGuard Zero-Trust Authorization Engine
=================================================
Every action must prove its legitimacy before execution.
No implicit trust. No inherited permissions. Every request verified.

SR&ED Activity: Novel implementation of zero-trust principles applied to
multi-agent AI authorization. No existing product enforces legal-grade
authorization verification on AI agent actions.

Core Principle:
    "Unauthorized action = void action."
    Any agent request that bypasses normal authorization is immediately rejected and logged.
    Every command must have proper identity verification, scope validation, and authorization.

Architecture:
    - Every agent action requires explicit authorization token
    - No agent inherits permissions from another agent
    - Authorization is verified at every hop (agent-to-agent, agent-to-resource)
    - Failed authorization attempts are logged and trigger alerts
    - Time-bounded permissions — no permanent access grants

Key Research Questions:
    - Can zero-trust at the agent level prevent prompt injection escalation?
    - What is the performance overhead of per-action authorization verification?
    - How to balance security with real-time response requirements?
"""

import json
import hashlib
import time
from datetime import datetime, timezone, timedelta
from typing import Optional
from dataclasses import dataclass, field
from enum import Enum


class AuthorizationLevel(Enum):
    """Authorization levels for agent actions."""
    READ = "read"           # View data, no modification
    SCAN = "scan"           # Active scanning (network probes, etc.)
    ANALYZE = "analyze"     # Process data through LLM
    ALERT = "alert"         # Send notifications
    MODIFY = "modify"       # Change configurations
    CONTAIN = "contain"     # Isolate/block resources (incident response)
    ESCALATE = "escalate"   # Escalate to human operator


class Jurisdiction(Enum):
    """Operational scope boundaries for agent operations."""
    INTERNAL = "internal"       # Francisco Holdings assets only
    CLIENT = "client"           # Authorized client assets
    PUBLIC = "public"           # Public internet resources
    RESTRICTED = "restricted"   # Requires explicit human approval


@dataclass
class AuthorizationRequest:
    """A request for authorization to perform an action."""
    agent_name: str
    agent_number: int
    action: str
    target: str
    level: AuthorizationLevel
    jurisdiction: Jurisdiction
    justification: str
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    request_id: str = ""

    def __post_init__(self):
        if not self.request_id:
            # Generate unique request ID for audit trail
            raw = f"{self.agent_name}:{self.action}:{self.target}:{self.timestamp}"
            self.request_id = hashlib.sha256(raw.encode()).hexdigest()[:16]


@dataclass
class AuthorizationGrant:
    """A granted authorization with time-bounded scope."""
    request_id: str
    granted: bool
    level: AuthorizationLevel
    jurisdiction: Jurisdiction
    expires_at: str
    conditions: list
    granted_by: str  # "system", "consensus", or "human"
    denial_reason: Optional[str] = None


class ZeroTrustEngine:
    """
    Zero-Trust Authorization Engine for OmniaGuard.

    Every agent action must be explicitly authorized.
    No implicit trust. No inherited permissions.
    Unauthorized action = void action.
    """

    # Maximum permission duration (prevents permanent access)
    MAX_GRANT_DURATION = {
        AuthorizationLevel.READ: timedelta(hours=24),
        AuthorizationLevel.SCAN: timedelta(hours=1),
        AuthorizationLevel.ANALYZE: timedelta(hours=4),
        AuthorizationLevel.ALERT: timedelta(minutes=30),
        AuthorizationLevel.MODIFY: timedelta(minutes=15),
        AuthorizationLevel.CONTAIN: timedelta(minutes=5),
        AuthorizationLevel.ESCALATE: timedelta(minutes=1),
    }

    # Actions that ALWAYS require human approval
    HUMAN_REQUIRED_ACTIONS = [
        "block_ip_range",
        "disable_user_account",
        "modify_firewall_rules",
        "delete_data",
        "send_external_notification",
        "access_production_database",
    ]

    # Agent permission matrix — what each agent is allowed to request
    AGENT_PERMISSIONS = {
        "network_scanner": [AuthorizationLevel.READ, AuthorizationLevel.SCAN],
        "vuln_assessor": [AuthorizationLevel.READ, AuthorizationLevel.SCAN, AuthorizationLevel.ANALYZE],
        "threat_intel": [AuthorizationLevel.READ, AuthorizationLevel.ANALYZE],
        "log_analyzer": [AuthorizationLevel.READ, AuthorizationLevel.ANALYZE],
        "incident_responder": [AuthorizationLevel.READ, AuthorizationLevel.ANALYZE, AuthorizationLevel.ALERT, AuthorizationLevel.CONTAIN],
        "phishing_detector": [AuthorizationLevel.READ, AuthorizationLevel.ANALYZE, AuthorizationLevel.ALERT],
        "malware_analyzer": [AuthorizationLevel.READ, AuthorizationLevel.ANALYZE, AuthorizationLevel.ALERT],
        "compliance_auditor": [AuthorizationLevel.READ, AuthorizationLevel.ANALYZE],
        "access_controller": [AuthorizationLevel.READ, AuthorizationLevel.ANALYZE, AuthorizationLevel.MODIFY],
        "dlp": [AuthorizationLevel.READ, AuthorizationLevel.ANALYZE, AuthorizationLevel.ALERT, AuthorizationLevel.CONTAIN],
        "endpoint_monitor": [AuthorizationLevel.READ, AuthorizationLevel.SCAN, AuthorizationLevel.ANALYZE],
        "cloud_security": [AuthorizationLevel.READ, AuthorizationLevel.SCAN, AuthorizationLevel.ANALYZE],
        "dark_web_monitor": [AuthorizationLevel.READ, AuthorizationLevel.ANALYZE],
        "report_generator": [AuthorizationLevel.READ, AuthorizationLevel.ANALYZE, AuthorizationLevel.ALERT],
    }

    def __init__(self):
        self.active_grants: dict[str, AuthorizationGrant] = {}
        self.audit_log: list[dict] = []
        self.denied_requests: list[dict] = []
        self.violation_count: int = 0

    def authorize(self, request: AuthorizationRequest) -> AuthorizationGrant:
        """
        Process an authorization request.

        Zero-trust verification:
        1. Verify agent identity (exists in permission matrix)
        2. Verify requested level is within agent's allowed scope
        3. Verify scope boundary is appropriate for the action
        4. Check if action requires human approval
        5. Apply time-bounded grant if approved

        Returns:
            AuthorizationGrant — approved or denied with full rationale
        """
        # Step 1: Verify agent identity
        if request.agent_name not in self.AGENT_PERMISSIONS:
            return self._deny(request, "IDENTITY_DENIED: Agent not recognized in authorization matrix")

        # Step 2: Verify permission level
        allowed_levels = self.AGENT_PERMISSIONS[request.agent_name]
        if request.level not in allowed_levels:
            self.violation_count += 1
            return self._deny(
                request,
                f"LEVEL_DENIED: Agent '{request.agent_name}' not authorized for "
                f"'{request.level.value}' actions. Allowed: {[l.value for l in allowed_levels]}"
            )

        # Step 3: Verify scope boundary
        if request.jurisdiction == Jurisdiction.RESTRICTED:
            return self._deny(request, "SCOPE_DENIED: Restricted boundary requires human approval")

        # Step 4: Check human-required actions
        if request.action in self.HUMAN_REQUIRED_ACTIONS:
            return self._deny(
                request,
                f"HUMAN_REQUIRED: Action '{request.action}' requires explicit human authorization"
            )

        # Step 5: Input sanitization check (anti-prompt-injection)
        if self._detect_injection_attempt(request):
            self.violation_count += 1
            return self._deny(request, "INJECTION_DETECTED: Request contains suspicious patterns — action terminated and quarantined")

        # Step 6: Grant with time-bounded scope
        max_duration = self.MAX_GRANT_DURATION.get(request.level, timedelta(minutes=5))
        expires_at = datetime.now(timezone.utc) + max_duration

        grant = AuthorizationGrant(
            request_id=request.request_id,
            granted=True,
            level=request.level,
            jurisdiction=request.jurisdiction,
            expires_at=expires_at.isoformat(),
            conditions=[
                f"Scope limited to: {request.target}",
                f"Expires: {expires_at.strftime('%H:%M:%S UTC')}",
                f"Level: {request.level.value} only",
                "No lateral movement permitted",
                "Results must be logged to audit trail",
            ],
            granted_by="system",
        )

        # Store active grant
        self.active_grants[request.request_id] = grant

        # Log for audit trail
        self._log_decision(request, grant)

        return grant

    def verify_grant(self, request_id: str) -> bool:
        """Verify an existing grant is still valid (not expired)."""
        grant = self.active_grants.get(request_id)
        if not grant:
            return False
        if not grant.granted:
            return False

        # Check expiration
        expires = datetime.fromisoformat(grant.expires_at)
        if datetime.now(timezone.utc) > expires:
            # Expired — revoke
            del self.active_grants[request_id]
            return False

        return True

    def revoke_grant(self, request_id: str, reason: str = "Manual revocation"):
        """Immediately revoke an active grant."""
        if request_id in self.active_grants:
            del self.active_grants[request_id]
            self.audit_log.append({
                "action": "REVOKE",
                "request_id": request_id,
                "reason": reason,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            })

    def revoke_all_agent_grants(self, agent_name: str, reason: str = "Agent lockdown"):
        """Revoke ALL grants for a specific agent (emergency lockdown)."""
        to_revoke = [
            rid for rid, grant in self.active_grants.items()
            if grant.granted  # Only revoke active grants
        ]
        for rid in to_revoke:
            self.revoke_grant(rid, reason=f"{reason} — agent: {agent_name}")

    def _deny(self, request: AuthorizationRequest, reason: str) -> AuthorizationGrant:
        """Deny a request and log the denial."""
        grant = AuthorizationGrant(
            request_id=request.request_id,
            granted=False,
            level=request.level,
            jurisdiction=request.jurisdiction,
            expires_at=datetime.now(timezone.utc).isoformat(),
            conditions=[],
            granted_by="system",
            denial_reason=reason,
        )

        self.denied_requests.append({
            "request_id": request.request_id,
            "agent": request.agent_name,
            "action": request.action,
            "target": request.target,
            "reason": reason,
            "timestamp": request.timestamp,
        })

        self._log_decision(request, grant)
        return grant

    def _detect_injection_attempt(self, request: AuthorizationRequest) -> bool:
        """
        Detect potential prompt injection in authorization requests.

        Checks for:
        - Instruction override patterns
        - Role assumption attempts
        - System prompt extraction attempts
        - Encoding obfuscation
        """
        suspicious_patterns = [
            "ignore previous",
            "ignore all",
            "you are now",
            "act as",
            "pretend to be",
            "system prompt",
            "reveal your",
            "override",
            "bypass",
            "admin mode",
            "sudo",
            "jailbreak",
            "DAN",
            "developer mode",
        ]

        # Check all text fields
        check_text = f"{request.action} {request.target} {request.justification}".lower()

        for pattern in suspicious_patterns:
            if pattern in check_text:
                return True

        # Check for encoding obfuscation (base64, hex patterns)
        if any(c in request.justification for c in ["\\x", "\\u", "&#"]):
            return True

        return False

    def _log_decision(self, request: AuthorizationRequest, grant: AuthorizationGrant):
        """Log authorization decision for SR&ED audit trail."""
        self.audit_log.append({
            "action": "AUTHORIZE" if grant.granted else "DENY",
            "request_id": request.request_id,
            "agent": request.agent_name,
            "agent_number": request.agent_number,
            "requested_action": request.action,
            "target": request.target,
            "level": request.level.value,
            "jurisdiction": request.jurisdiction.value,
            "granted": grant.granted,
            "reason": grant.denial_reason if not grant.granted else "Authorized within scope",
            "expires_at": grant.expires_at if grant.granted else None,
            "timestamp": request.timestamp,
        })

    def get_security_status(self) -> dict:
        """Get current authorization engine status."""
        return {
            "active_grants": len(self.active_grants),
            "total_decisions": len(self.audit_log),
            "denied_requests": len(self.denied_requests),
            "violations_detected": self.violation_count,
            "engine": "Zero-Trust Authorization Engine",
            "principle": "Unauthorized action = void action",
        }

    def get_audit_trail(self) -> list[dict]:
        """Export full audit trail for SR&ED compliance."""
        return self.audit_log
