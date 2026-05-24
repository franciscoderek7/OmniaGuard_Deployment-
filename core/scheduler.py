"""
R&D: OmniaGuard Autonomous Scheduler
======================================
24/7 automated security operations — time-block scanning with
morning briefings via Telegram.

SR&ED Activity: Experimental development of autonomous scheduling
algorithms for multi-agent cybersecurity operations. Research into
optimal scan timing to minimize detection evasion.

Schedule:
    00:00-06:00 — Dark web scanning, threat intel updates
    06:00-12:00 — Log analysis, anomaly detection
    12:00-18:00 — Compliance checks, access reviews
    18:00-00:00 — Vulnerability scans, report generation
    07:00 daily  — Morning briefing (Telegram summary)
"""

import asyncio
from datetime import datetime, timezone, time as dt_time
from typing import Callable, Optional
from dataclasses import dataclass


@dataclass
class ScheduledTask:
    """A scheduled security operation."""
    name: str
    agent_names: list[str]
    start_hour: int
    end_hour: int
    frequency_minutes: int  # How often within the window
    enabled: bool = True
    last_run: Optional[str] = None


class AutonomousScheduler:
    """
    R&D: Autonomous 24/7 security operations scheduler.

    Manages time-block scanning, ensuring continuous coverage
    while respecting rate limits and resource constraints.
    """

    # Default schedule — agents grouped by time block
    DEFAULT_SCHEDULE = [
        ScheduledTask(
            name="dark_web_sweep",
            agent_names=["dark_web_monitor", "threat_intel"],
            start_hour=0,
            end_hour=6,
            frequency_minutes=120,  # Every 2 hours
        ),
        ScheduledTask(
            name="log_analysis",
            agent_names=["log_analyzer", "incident_responder"],
            start_hour=6,
            end_hour=12,
            frequency_minutes=60,  # Every hour
        ),
        ScheduledTask(
            name="compliance_review",
            agent_names=["compliance_auditor", "access_controller", "dlp"],
            start_hour=12,
            end_hour=18,
            frequency_minutes=180,  # Every 3 hours
        ),
        ScheduledTask(
            name="vulnerability_scan",
            agent_names=["network_scanner", "vuln_assessor", "endpoint_monitor", "cloud_security"],
            start_hour=18,
            end_hour=24,
            frequency_minutes=90,  # Every 90 minutes
        ),
        ScheduledTask(
            name="continuous_phishing",
            agent_names=["phishing_detector", "malware_analyzer"],
            start_hour=0,
            end_hour=24,
            frequency_minutes=30,  # Every 30 minutes (always active)
        ),
    ]

    MORNING_BRIEFING_HOUR = 7  # 07:00 UTC

    def __init__(self):
        self.schedule = self.DEFAULT_SCHEDULE.copy()
        self.running = False
        self._tasks: list[asyncio.Task] = []
        self.briefing_callback: Optional[Callable] = None
        self.scan_callback: Optional[Callable] = None

    def set_scan_callback(self, callback: Callable):
        """Set the function to call when a scheduled scan should execute."""
        self.scan_callback = callback

    def set_briefing_callback(self, callback: Callable):
        """Set the function to call for morning briefing."""
        self.briefing_callback = callback

    def get_current_tasks(self) -> list[ScheduledTask]:
        """Get tasks that should be running in the current time block."""
        now = datetime.now(timezone.utc)
        current_hour = now.hour

        active = []
        for task in self.schedule:
            if not task.enabled:
                continue
            # Handle wrap-around (e.g., 18-24 means 18:00 to 23:59)
            if task.start_hour <= current_hour < task.end_hour:
                active.append(task)
            # Handle 0-24 (always active)
            elif task.start_hour == 0 and task.end_hour == 24:
                active.append(task)

        return active

    async def start(self):
        """Start the autonomous scheduler loop."""
        self.running = True
        self._tasks.append(asyncio.create_task(self._scheduler_loop()))
        self._tasks.append(asyncio.create_task(self._briefing_loop()))

    async def stop(self):
        """Stop the scheduler gracefully."""
        self.running = False
        for task in self._tasks:
            task.cancel()
        self._tasks.clear()

    async def _scheduler_loop(self):
        """Main scheduler loop — checks every minute for tasks to run."""
        while self.running:
            try:
                active_tasks = self.get_current_tasks()

                for task in active_tasks:
                    # Check if enough time has passed since last run
                    if self._should_run(task):
                        if self.scan_callback:
                            await self.scan_callback(task.name, task.agent_names)
                        task.last_run = datetime.now(timezone.utc).isoformat()

                # Sleep 60 seconds before next check
                await asyncio.sleep(60)

            except asyncio.CancelledError:
                break
            except Exception as e:
                # Log error but don't crash the scheduler
                print(f"Scheduler error: {e}")
                await asyncio.sleep(60)

    async def _briefing_loop(self):
        """Morning briefing loop — sends daily summary at 07:00 UTC."""
        while self.running:
            try:
                now = datetime.now(timezone.utc)

                # Check if it's briefing time (07:00 UTC, within first minute)
                if now.hour == self.MORNING_BRIEFING_HOUR and now.minute == 0:
                    if self.briefing_callback:
                        await self.briefing_callback()
                    # Sleep 61 minutes to avoid double-trigger
                    await asyncio.sleep(3660)
                else:
                    # Check every 30 seconds
                    await asyncio.sleep(30)

            except asyncio.CancelledError:
                break
            except Exception as e:
                print(f"Briefing loop error: {e}")
                await asyncio.sleep(60)

    def _should_run(self, task: ScheduledTask) -> bool:
        """Check if enough time has elapsed since last run."""
        if task.last_run is None:
            return True

        last = datetime.fromisoformat(task.last_run)
        now = datetime.now(timezone.utc)
        elapsed_minutes = (now - last).total_seconds() / 60

        return elapsed_minutes >= task.frequency_minutes

    def get_status(self) -> dict:
        """Get scheduler status for health checks."""
        active = self.get_current_tasks()
        return {
            "running": self.running,
            "total_tasks": len(self.schedule),
            "active_tasks": len(active),
            "active_names": [t.name for t in active],
            "next_briefing_hour": f"{self.MORNING_BRIEFING_HOUR}:00 UTC",
        }
