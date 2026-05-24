"""
R&D: OmniaGuard Base Agent
============================
Abstract base class for all 14 security agents.

Provides:
- Together AI LLM access
- Supabase database logging
- Telegram alert dispatch
- Standardized scan/report interface
- Health monitoring
"""

import asyncio
import traceback
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Any, Optional

from core.config import config
from core.supabase_client import db
from core.together_client import llm


class BaseAgent(ABC):
    """Base class for all OmniaGuard security agents."""

    def __init__(self):
        self.name: str = self.__class__.__name__
        self.agent_id: str = self.name.lower().replace(" ", "_")
        self.version: str = "1.0.0"
        self.status: str = "idle"
        self.last_run: Optional[str] = None
        self.llm = llm
        self.db = db

    @property
    @abstractmethod
    def description(self) -> str:
        """Human-readable description of what this agent does."""
        ...

    @property
    @abstractmethod
    def scan_types(self) -> list[str]:
        """List of scan types this agent can perform."""
        ...

    @abstractmethod
    async def scan(self, target: str, scan_type: str = "full", **kwargs) -> dict:
        """
        Execute a security scan against the target.

        Args:
            target: The asset to scan (IP, domain, URL, email, etc.)
            scan_type: Type of scan to perform (agent-specific)
            **kwargs: Additional scan parameters

        Returns:
            dict with keys: findings, severity, summary, recommendations
        """
        ...

    async def run(self, target: str, scan_type: str = "full", **kwargs) -> dict:
        """
        Execute scan with logging, error handling, and status updates.
        This is the public interface — wraps self.scan() with infrastructure.
        """
        self.status = "running"
        start_time = datetime.now(timezone.utc)

        try:
            # Update agent status
            await self.db.update_agent_status(self.agent_id, "running")

            # Execute the scan
            results = await self.scan(target, scan_type, **kwargs)

            # Determine severity
            severity = results.get("severity", "info")

            # Log to database
            await self.db.log_scan(
                agent_name=self.agent_id,
                target=target,
                scan_type=scan_type,
                results=results,
                severity=severity,
            )

            # Create alert if severity warrants it
            if severity in ("critical", "high"):
                await self.db.create_alert(
                    agent_name=self.agent_id,
                    title=f"[{severity.upper()}] {self.name}: {results.get('summary', 'Alert')}",
                    description=results.get("summary", "Security issue detected"),
                    severity=severity,
                    target=target,
                    evidence=results.get("findings", {}),
                )

            # Update status
            self.status = "idle"
            self.last_run = start_time.isoformat()
            await self.db.update_agent_status(
                self.agent_id, "idle", last_run=self.last_run
            )

            return {
                "agent": self.agent_id,
                "target": target,
                "scan_type": scan_type,
                "status": "complete",
                "duration_ms": int(
                    (datetime.now(timezone.utc) - start_time).total_seconds() * 1000
                ),
                **results,
            }

        except Exception as e:
            self.status = "error"
            error_msg = f"{self.name} error scanning {target}: {str(e)}"
            await self.db.update_agent_status(self.agent_id, "error")
            await self.db.log_scan(
                agent_name=self.agent_id,
                target=target,
                scan_type=scan_type,
                results={"error": str(e), "traceback": traceback.format_exc()},
                severity="error",
            )
            return {
                "agent": self.agent_id,
                "target": target,
                "status": "error",
                "error": error_msg,
            }

    async def health_check(self) -> dict:
        """Return agent health status."""
        return {
            "agent": self.agent_id,
            "name": self.name,
            "version": self.version,
            "status": self.status,
            "last_run": self.last_run,
            "scan_types": self.scan_types,
            "description": self.description,
        }

    def __repr__(self) -> str:
        return f"<{self.name} v{self.version} [{self.status}]>"
