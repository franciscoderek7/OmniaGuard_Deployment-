"""
R&D: OmniaGuard Supabase Client
=================================
Database operations for scan results, alerts, logs, and agent state.

Tables (created via Supabase dashboard or migration):
- scans: All security scan records
- alerts: Triggered security alerts
- agents: Agent health/status tracking
- targets: Monitored assets (domains, IPs, endpoints)
- reports: Generated security reports
- users: Telegram-linked user accounts
"""

from datetime import datetime, timezone
from typing import Any, Optional
from supabase import create_client, Client
from core.config import config


def get_client() -> Client:
    """Get authenticated Supabase client."""
    return create_client(config.supabase_url, config.supabase_service_key)


class OmniaDB:
    """OmniaGuard database operations."""

    def __init__(self):
        self.client = get_client()

    # --- Scans ---

    async def log_scan(
        self,
        agent_name: str,
        target: str,
        scan_type: str,
        results: dict,
        severity: str = "info",
    ) -> dict:
        """Log a completed scan to the database."""
        record = {
            "agent_name": agent_name,
            "target": target,
            "scan_type": scan_type,
            "results": results,
            "severity": severity,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        response = self.client.table("scans").insert(record).execute()
        return response.data[0] if response.data else record

    async def get_recent_scans(
        self, agent_name: Optional[str] = None, limit: int = 50
    ) -> list[dict]:
        """Get recent scan results, optionally filtered by agent."""
        query = self.client.table("scans").select("*").order(
            "timestamp", desc=True
        ).limit(limit)
        if agent_name:
            query = query.eq("agent_name", agent_name)
        response = query.execute()
        return response.data or []

    # --- Alerts ---

    async def create_alert(
        self,
        agent_name: str,
        title: str,
        description: str,
        severity: str,
        target: str,
        evidence: dict,
    ) -> dict:
        """Create a security alert."""
        record = {
            "agent_name": agent_name,
            "title": title,
            "description": description,
            "severity": severity,
            "target": target,
            "evidence": evidence,
            "status": "open",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        response = self.client.table("alerts").insert(record).execute()
        return response.data[0] if response.data else record

    async def get_open_alerts(self, severity: Optional[str] = None) -> list[dict]:
        """Get all open alerts, optionally filtered by severity."""
        query = (
            self.client.table("alerts")
            .select("*")
            .eq("status", "open")
            .order("timestamp", desc=True)
        )
        if severity:
            query = query.eq("severity", severity)
        response = query.execute()
        return response.data or []

    async def resolve_alert(self, alert_id: str, resolution: str) -> dict:
        """Mark an alert as resolved."""
        response = (
            self.client.table("alerts")
            .update({
                "status": "resolved",
                "resolution": resolution,
                "resolved_at": datetime.now(timezone.utc).isoformat(),
            })
            .eq("id", alert_id)
            .execute()
        )
        return response.data[0] if response.data else {}

    # --- Targets ---

    async def get_targets(self, active_only: bool = True) -> list[dict]:
        """Get monitored targets."""
        query = self.client.table("targets").select("*")
        if active_only:
            query = query.eq("active", True)
        response = query.execute()
        return response.data or []

    async def add_target(
        self, name: str, target_type: str, value: str, owner: str = "Francisco Holdings"
    ) -> dict:
        """Add a new target to monitor."""
        record = {
            "name": name,
            "target_type": target_type,
            "value": value,
            "owner": owner,
            "active": True,
            "added_at": datetime.now(timezone.utc).isoformat(),
        }
        response = self.client.table("targets").insert(record).execute()
        return response.data[0] if response.data else record

    # --- Agent Health ---

    async def update_agent_status(
        self, agent_name: str, status: str, last_run: Optional[str] = None
    ) -> dict:
        """Update agent health status."""
        record = {
            "agent_name": agent_name,
            "status": status,
            "last_heartbeat": datetime.now(timezone.utc).isoformat(),
        }
        if last_run:
            record["last_run"] = last_run
        response = (
            self.client.table("agents")
            .upsert(record, on_conflict="agent_name")
            .execute()
        )
        return response.data[0] if response.data else record

    async def get_all_agent_statuses(self) -> list[dict]:
        """Get health status of all agents."""
        response = self.client.table("agents").select("*").execute()
        return response.data or []


# Singleton instance
db = OmniaDB()
