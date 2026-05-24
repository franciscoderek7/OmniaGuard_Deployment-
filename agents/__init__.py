"""
R&D: OmniaGuard Agent Package
===============================
14 specialized cybersecurity agents protecting Francisco Holdings
and all subsidiary entities.

Agent Registry:
01. Network Scanner — Port/service discovery
02. Vulnerability Assessor — CVE matching
03. Threat Intelligence — OSINT threat feeds
04. Log Analyzer — SIEM log parsing
05. Incident Responder — Automated containment
06. Phishing Detector — Email/URL analysis
07. Malware Analyzer — Static/dynamic analysis
08. Compliance Auditor — SOC2/ISO27001 checks
09. Access Controller — IAM policy enforcement
10. Data Loss Preventer — DLP monitoring
11. Endpoint Protector — EDR agent
12. Cloud Guardian — AWS/GCP/Azure misconfig
13. Dark Web Monitor — Credential leak detection
14. Report Generator — Executive summaries
"""

from agents.base_agent import BaseAgent

__all__ = ["BaseAgent"]
