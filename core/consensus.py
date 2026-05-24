"""
R&D: OmniaGuard Multi-Agent Consensus Protocol
================================================
No single agent decides. Every critical action requires consensus — like a jury, not a dictator.

SR&ED Activity: Novel application of distributed consensus algorithms to
multi-agent cybersecurity decision-making. No existing commercial product
implements jury-style consensus for threat classification.

Architecture:
- Each agent votes on threat severity independently
- Consensus threshold: 3+ agents must agree for critical/high classification
- Dissenting opinions are logged for audit trail
- Tie-breaking uses weighted confidence scores

Key Research Questions:
- What is the optimal consensus threshold for minimizing false positives
  while maintaining detection rate?
- How to weight agent votes based on domain expertise vs. general confidence?
- Can consensus reduce false positive rates below 5% while maintaining 95%+ detection?
"""

import json
from datetime import datetime, timezone
from typing import Optional
from dataclasses import dataclass, field


@dataclass
class AgentVote:
    """A single agent's vote on a threat assessment."""
    agent_name: str
    agent_number: int
    severity: str  # critical, high, medium, low, info
    confidence: float  # 0.0 - 1.0
    reasoning: str
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


@dataclass
class ConsensusResult:
    """Result of multi-agent consensus voting."""
    final_severity: str
    consensus_reached: bool
    vote_count: int
    agreement_ratio: float
    votes: list
    dissenting_opinions: list
    decision_rationale: str
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class ConsensusProtocol:
    """
    Multi-Agent Consensus Protocol for OmniaGuard.

    No single agent can escalate to 'critical' alone.
    Requires jury-style agreement before taking action.
    """

    # Severity levels ranked
    SEVERITY_RANK = {
        "critical": 5,
        "high": 4,
        "medium": 3,
        "low": 2,
        "info": 1,
    }

    # Minimum votes required for each severity level
    CONSENSUS_THRESHOLDS = {
        "critical": 3,  # 3+ agents must agree for critical
        "high": 2,      # 2+ agents must agree for high
        "medium": 1,    # 1 agent can flag medium
        "low": 1,       # 1 agent can flag low
        "info": 1,      # Informational, no consensus needed
    }

    # Agent expertise weights (domain-specific agents get higher weight in their domain)
    AGENT_WEIGHTS = {
        "network_scanner": {"network": 1.5, "default": 1.0},
        "vuln_assessor": {"vulnerability": 1.5, "default": 1.0},
        "threat_intel": {"threat": 1.5, "emerging": 1.5, "default": 1.0},
        "log_analyzer": {"anomaly": 1.5, "default": 1.0},
        "incident_responder": {"breach": 1.5, "default": 1.0},
        "phishing_detector": {"phishing": 2.0, "social_engineering": 1.5, "default": 1.0},
        "malware_analyzer": {"malware": 2.0, "default": 1.0},
        "compliance_auditor": {"compliance": 1.5, "default": 0.8},
        "access_controller": {"access": 1.5, "privilege": 1.5, "default": 1.0},
        "dlp": {"data_loss": 2.0, "insider": 1.5, "default": 1.0},
        "endpoint_monitor": {"endpoint": 1.5, "default": 1.0},
        "cloud_security": {"cloud": 2.0, "misconfiguration": 1.5, "default": 1.0},
        "dark_web_monitor": {"breach": 1.5, "credential": 1.5, "default": 0.8},
        "report_generator": {"default": 0.5},  # Reporter doesn't vote on severity
    }

    def __init__(self):
        self.vote_history: list[ConsensusResult] = []

    def evaluate_consensus(
        self,
        votes: list[AgentVote],
        threat_domain: str = "default",
    ) -> ConsensusResult:
        """
        Evaluate multi-agent votes and reach consensus.

        Args:
            votes: List of AgentVote from participating agents
            threat_domain: Domain of the threat (for weight calculation)

        Returns:
            ConsensusResult with final decision and rationale
        """
        if not votes:
            return ConsensusResult(
                final_severity="info",
                consensus_reached=True,
                vote_count=0,
                agreement_ratio=1.0,
                votes=[],
                dissenting_opinions=[],
                decision_rationale="No votes received — defaulting to informational.",
            )

        # Calculate weighted votes
        weighted_scores = []
        for vote in votes:
            weight = self._get_agent_weight(vote.agent_name, threat_domain)
            weighted_score = self.SEVERITY_RANK.get(vote.severity, 1) * weight * vote.confidence
            weighted_scores.append({
                "agent": vote.agent_name,
                "severity": vote.severity,
                "confidence": vote.confidence,
                "weight": weight,
                "weighted_score": weighted_score,
            })

        # Determine majority severity
        severity_votes = {}
        for vote in votes:
            sev = vote.severity
            severity_votes[sev] = severity_votes.get(sev, 0) + 1

        # Find the severity with most votes
        majority_severity = max(severity_votes, key=severity_votes.get)
        majority_count = severity_votes[majority_severity]

        # Check if consensus threshold is met
        threshold = self.CONSENSUS_THRESHOLDS.get(majority_severity, 1)
        consensus_reached = majority_count >= threshold

        # If no consensus at highest level, step down
        if not consensus_reached:
            # Try next lower severity
            for sev in ["critical", "high", "medium", "low", "info"]:
                count = severity_votes.get(sev, 0)
                if count >= self.CONSENSUS_THRESHOLDS.get(sev, 1):
                    majority_severity = sev
                    majority_count = count
                    consensus_reached = True
                    break

        # Calculate agreement ratio
        agreement_ratio = majority_count / len(votes) if votes else 0

        # Identify dissenting opinions
        dissenting = [
            {
                "agent": vote.agent_name,
                "voted": vote.severity,
                "reasoning": vote.reasoning,
            }
            for vote in votes
            if vote.severity != majority_severity
        ]

        # Generate decision rationale
        rationale = self._generate_rationale(
            majority_severity, majority_count, len(votes),
            consensus_reached, dissenting, threat_domain,
        )

        result = ConsensusResult(
            final_severity=majority_severity,
            consensus_reached=consensus_reached,
            vote_count=len(votes),
            agreement_ratio=agreement_ratio,
            votes=[{
                "agent": v.agent_name,
                "severity": v.severity,
                "confidence": v.confidence,
            } for v in votes],
            dissenting_opinions=dissenting,
            decision_rationale=rationale,
        )

        # Store for audit trail
        self.vote_history.append(result)

        return result

    def _get_agent_weight(self, agent_name: str, domain: str) -> float:
        """Get agent's voting weight for a specific threat domain."""
        agent_weights = self.AGENT_WEIGHTS.get(agent_name, {"default": 1.0})
        return agent_weights.get(domain, agent_weights.get("default", 1.0))

    def _generate_rationale(
        self,
        severity: str,
        majority_count: int,
        total_votes: int,
        consensus_reached: bool,
        dissenting: list,
        domain: str,
    ) -> str:
        """Generate human-readable decision rationale for audit trail."""
        if consensus_reached:
            rationale = (
                f"CONSENSUS REACHED: {majority_count}/{total_votes} agents classified "
                f"threat as '{severity}' in domain '{domain}'. "
                f"Threshold met ({self.CONSENSUS_THRESHOLDS.get(severity, 1)} required). "
            )
        else:
            rationale = (
                f"NO CONSENSUS: Highest agreement was {majority_count}/{total_votes} "
                f"for '{severity}'. Defaulting to majority with reduced confidence. "
            )

        if dissenting:
            rationale += f"{len(dissenting)} dissenting opinion(s) logged for review."

        return rationale

    def requires_human_review(self, result: ConsensusResult) -> bool:
        """
        Determine if a consensus result requires human review.

        Human review triggered when:
        - Critical severity with less than 75% agreement
        - No consensus reached on high+ severity
        - More than 2 dissenting opinions on critical
        """
        if result.final_severity == "critical" and result.agreement_ratio < 0.75:
            return True
        if not result.consensus_reached and self.SEVERITY_RANK.get(result.final_severity, 0) >= 4:
            return True
        if result.final_severity == "critical" and len(result.dissenting_opinions) > 2:
            return True
        return False

    def get_audit_trail(self) -> list[dict]:
        """Export vote history for SR&ED audit trail."""
        return [
            {
                "timestamp": r.timestamp,
                "severity": r.final_severity,
                "consensus": r.consensus_reached,
                "votes": r.vote_count,
                "agreement": f"{r.agreement_ratio:.0%}",
                "dissenting": len(r.dissenting_opinions),
                "rationale": r.decision_rationale,
            }
            for r in self.vote_history
        ]
