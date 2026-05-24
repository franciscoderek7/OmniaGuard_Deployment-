"""
R&D: OmniaGuard Agent 04 — Log Analyzer
==========================================
SIEM-style log parsing, anomaly detection, and threat hunting.

Capabilities:
- Multi-format log parsing (syslog, JSON, Apache, nginx, auth)
- Pattern-based anomaly detection
- Brute force attempt identification
- Privilege escalation detection
- Timeline reconstruction for incidents
- LLM-powered log correlation

Integration: Reads logs from Supabase or direct file input.
"""

import json
import re
from datetime import datetime, timezone, timedelta
from typing import Optional
from collections import Counter
from agents.base_agent import BaseAgent


class LogAnalyzer(BaseAgent):
    """Agent 04: Security log analysis and anomaly detection."""

    @property
    def description(self) -> str:
        return "Analyzes security logs for anomalies, brute force attempts, privilege escalation, and threat indicators."

    @property
    def scan_types(self) -> list[str]:
        return ["analyze_batch", "hunt_bruteforce", "hunt_privesc", "timeline", "anomaly_detect"]

    # Known attack patterns
    BRUTE_FORCE_PATTERNS = [
        r"Failed password for .+ from (\d+\.\d+\.\d+\.\d+)",
        r"authentication failure.*rhost=(\d+\.\d+\.\d+\.\d+)",
        r"Invalid user .+ from (\d+\.\d+\.\d+\.\d+)",
        r"Connection closed by authenticating user .+ (\d+\.\d+\.\d+\.\d+)",
    ]

    PRIVESC_PATTERNS = [
        r"sudo:.+COMMAND=",
        r"su\[\d+\]: .+ to root",
        r"pkexec.+executed",
        r"setuid|setgid",
        r"chmod.+[47][0-7]{2}",
    ]

    SUSPICIOUS_PATTERNS = [
        r"reverse shell|nc -e|bash -i|/dev/tcp",
        r"wget.+\|.+sh|curl.+\|.+bash",
        r"base64.+decode|eval\(",
        r"crontab -e|/etc/cron",
        r"iptables -F|ufw disable",
        r"/etc/shadow|/etc/passwd",
    ]

    async def scan(self, target: str, scan_type: str = "analyze_batch", **kwargs) -> dict:
        """
        Analyze logs for security events.

        Args:
            target: Log source identifier or description
            scan_type: Type of analysis
            kwargs: logs (list of log lines), timeframe (hours)
        """
        logs = kwargs.get("logs", [])

        if scan_type == "analyze_batch":
            return await self._analyze_batch(target, logs)
        elif scan_type == "hunt_bruteforce":
            return await self._hunt_bruteforce(target, logs)
        elif scan_type == "hunt_privesc":
            return await self._hunt_privesc(target, logs)
        elif scan_type == "timeline":
            return await self._build_timeline(target, logs)
        elif scan_type == "anomaly_detect":
            return await self._detect_anomalies(target, logs)
        else:
            return await self._analyze_batch(target, logs)

    async def _analyze_batch(self, target: str, logs: list[str]) -> dict:
        """Comprehensive analysis of a batch of log entries."""
        if not logs:
            return {
                "findings": {"error": "No logs provided"},
                "severity": "info",
                "summary": "No logs to analyze",
                "recommendations": ["Provide log data for analysis"],
            }

        # Pattern matching
        brute_force = self._find_pattern_matches(logs, self.BRUTE_FORCE_PATTERNS)
        privesc = self._find_pattern_matches(logs, self.PRIVESC_PATTERNS)
        suspicious = self._find_pattern_matches(logs, self.SUSPICIOUS_PATTERNS)

        # Statistics
        stats = {
            "total_lines": len(logs),
            "brute_force_events": len(brute_force),
            "privilege_escalation_events": len(privesc),
            "suspicious_commands": len(suspicious),
        }

        # Determine severity
        if suspicious:
            severity = "critical"
        elif privesc:
            severity = "high"
        elif len(brute_force) > 10:
            severity = "high"
        elif brute_force:
            severity = "medium"
        else:
            severity = "info"

        # LLM analysis for complex patterns
        llm_analysis = {}
        if severity in ("critical", "high"):
            llm_analysis = await self._llm_log_analysis(
                target, brute_force[:5] + privesc[:5] + suspicious[:5]
            )

        return {
            "findings": {
                "statistics": stats,
                "brute_force_attempts": brute_force[:20],
                "privilege_escalation": privesc[:10],
                "suspicious_activity": suspicious[:10],
                "llm_analysis": llm_analysis,
            },
            "severity": severity,
            "summary": f"Analyzed {len(logs)} log entries from {target}: {stats['brute_force_events']} brute force, {stats['privilege_escalation_events']} privesc, {stats['suspicious_commands']} suspicious",
            "recommendations": self._generate_log_recommendations(stats, severity),
        }

    async def _hunt_bruteforce(self, target: str, logs: list[str]) -> dict:
        """Specifically hunt for brute force attacks."""
        matches = self._find_pattern_matches(logs, self.BRUTE_FORCE_PATTERNS)

        # Extract source IPs and count attempts
        ip_counter = Counter()
        for match in matches:
            ips = re.findall(r"\d+\.\d+\.\d+\.\d+", match)
            for ip in ips:
                ip_counter[ip] += 1

        # Flag IPs with > 5 attempts
        attackers = [
            {"ip": ip, "attempts": count, "blocked": False}
            for ip, count in ip_counter.most_common(20)
            if count >= 5
        ]

        severity = "critical" if any(a["attempts"] > 50 for a in attackers) else \
                   "high" if attackers else "info"

        return {
            "findings": {
                "total_failed_auths": len(matches),
                "unique_source_ips": len(ip_counter),
                "top_attackers": attackers,
                "attack_window": f"Across {len(logs)} log entries",
            },
            "severity": severity,
            "summary": f"Brute force hunt on {target}: {len(attackers)} attacking IPs, {len(matches)} failed attempts",
            "recommendations": [
                f"Block IP {a['ip']} ({a['attempts']} attempts)" for a in attackers[:5]
            ] + ["Enable fail2ban or equivalent", "Enforce MFA on all accounts"],
        }

    async def _hunt_privesc(self, target: str, logs: list[str]) -> dict:
        """Hunt for privilege escalation attempts."""
        matches = self._find_pattern_matches(logs, self.PRIVESC_PATTERNS)

        # Categorize
        sudo_events = [m for m in matches if "sudo" in m.lower()]
        su_events = [m for m in matches if "su[" in m.lower() or "su:" in m.lower()]
        setuid_events = [m for m in matches if "setuid" in m.lower() or "chmod" in m.lower()]

        severity = "critical" if setuid_events else "high" if matches else "info"

        return {
            "findings": {
                "total_privesc_events": len(matches),
                "sudo_usage": len(sudo_events),
                "su_usage": len(su_events),
                "setuid_changes": len(setuid_events),
                "events": matches[:20],
            },
            "severity": severity,
            "summary": f"Privilege escalation hunt on {target}: {len(matches)} events detected",
            "recommendations": [
                "Audit all sudo commands for legitimacy",
                "Review setuid binary changes immediately",
                "Implement least-privilege access model",
            ] if matches else ["No privilege escalation detected"],
        }

    async def _build_timeline(self, target: str, logs: list[str]) -> dict:
        """Build incident timeline from logs."""
        events = []
        for line in logs:
            timestamp = self._extract_timestamp(line)
            event_type = self._classify_event(line)
            if event_type != "normal":
                events.append({
                    "timestamp": timestamp,
                    "type": event_type,
                    "raw": line[:200],
                })

        # Sort by timestamp
        events.sort(key=lambda x: x["timestamp"] or "")

        # LLM narrative
        if events:
            narrative = await self._llm_timeline_narrative(target, events[:30])
        else:
            narrative = "No security events found in provided logs."

        return {
            "findings": {
                "total_events": len(events),
                "timeline": events[:50],
                "narrative": narrative,
            },
            "severity": "high" if len(events) > 10 else "medium" if events else "info",
            "summary": f"Timeline for {target}: {len(events)} security events reconstructed",
            "recommendations": ["Review timeline for attack chain indicators"],
        }

    async def _detect_anomalies(self, target: str, logs: list[str]) -> dict:
        """Statistical anomaly detection in log patterns."""
        # Hourly event distribution
        hourly_counts = Counter()
        for line in logs:
            ts = self._extract_timestamp(line)
            if ts:
                try:
                    hour = ts[:13]  # YYYY-MM-DDTHH
                    hourly_counts[hour] += 1
                except Exception:
                    pass

        # Detect spikes (> 2x average)
        if hourly_counts:
            avg = sum(hourly_counts.values()) / len(hourly_counts)
            spikes = {h: c for h, c in hourly_counts.items() if c > avg * 2.5}
        else:
            avg = 0
            spikes = {}

        # Event type distribution
        event_types = Counter()
        for line in logs:
            event_types[self._classify_event(line)] += 1

        severity = "high" if spikes else "info"

        return {
            "findings": {
                "hourly_average": round(avg, 1),
                "spike_hours": spikes,
                "event_distribution": dict(event_types.most_common(10)),
                "anomaly_count": len(spikes),
            },
            "severity": severity,
            "summary": f"Anomaly detection on {target}: {len(spikes)} time-based anomalies detected",
            "recommendations": [
                f"Investigate spike at {h} ({c} events, avg={avg:.0f})"
                for h, c in list(spikes.items())[:5]
            ] if spikes else ["No statistical anomalies detected"],
        }

    def _find_pattern_matches(self, logs: list[str], patterns: list[str]) -> list[str]:
        """Find log lines matching any of the given patterns."""
        matches = []
        compiled = [re.compile(p, re.IGNORECASE) for p in patterns]
        for line in logs:
            for pattern in compiled:
                if pattern.search(line):
                    matches.append(line.strip())
                    break
        return matches

    def _extract_timestamp(self, log_line: str) -> Optional[str]:
        """Extract timestamp from various log formats."""
        patterns = [
            r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})",  # ISO
            r"(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})",  # Syslog
            r"(\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2})",  # Apache
        ]
        for pattern in patterns:
            match = re.search(pattern, log_line)
            if match:
                return match.group(1)
        return None

    def _classify_event(self, log_line: str) -> str:
        """Classify a log line into event categories."""
        line_lower = log_line.lower()
        if any(re.search(p, log_line, re.IGNORECASE) for p in self.BRUTE_FORCE_PATTERNS):
            return "brute_force"
        elif any(re.search(p, log_line, re.IGNORECASE) for p in self.PRIVESC_PATTERNS):
            return "privilege_escalation"
        elif any(re.search(p, log_line, re.IGNORECASE) for p in self.SUSPICIOUS_PATTERNS):
            return "suspicious"
        elif "error" in line_lower or "fail" in line_lower:
            return "error"
        elif "warn" in line_lower:
            return "warning"
        return "normal"

    def _generate_log_recommendations(self, stats: dict, severity: str) -> list[str]:
        """Generate recommendations based on log analysis."""
        recs = []
        if stats["brute_force_events"] > 0:
            recs.append("Enable rate limiting and account lockout policies")
            recs.append("Deploy fail2ban or similar IP blocking")
        if stats["privilege_escalation_events"] > 0:
            recs.append("Audit all privilege escalation events for legitimacy")
            recs.append("Review sudoers file and remove unnecessary permissions")
        if stats["suspicious_commands"] > 0:
            recs.append("URGENT: Investigate suspicious commands — possible active compromise")
            recs.append("Isolate affected systems and preserve evidence")
        if severity == "info":
            recs.append("No immediate threats detected — maintain monitoring")
        return recs[:5]

    async def _llm_log_analysis(self, target: str, events: list[str]) -> dict:
        """LLM-powered deep log analysis."""
        prompt = f"""Analyze these security log events from {target}:

{chr(10).join(events[:15])}

Identify:
1. Attack type/technique (MITRE ATT&CK if applicable)
2. Attack stage (recon, initial access, execution, persistence, etc.)
3. Severity assessment
4. Recommended immediate actions

Respond with JSON:
{{
    "attack_type": "description",
    "mitre_technique": "T####",
    "attack_stage": "stage",
    "severity": "critical/high/medium/low",
    "immediate_actions": ["action1", "action2"]
}}"""

        try:
            result = await self.llm.analyze(prompt=prompt, json_mode=True)
            return json.loads(result)
        except Exception:
            return {"attack_type": "unknown", "immediate_actions": ["Manual review required"]}

    async def _llm_timeline_narrative(self, target: str, events: list[dict]) -> str:
        """Generate human-readable timeline narrative."""
        prompt = f"""Create a concise incident timeline narrative for {target}:

Events:
{json.dumps(events[:20], indent=2)}

Write a 3-5 sentence narrative describing what happened, in chronological order.
Focus on the attack chain and impact."""

        try:
            return await self.llm.analyze(prompt=prompt, max_tokens=512)
        except Exception:
            return "Timeline narrative generation failed — review events manually."
