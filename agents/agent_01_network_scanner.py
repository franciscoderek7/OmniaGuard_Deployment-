"""
R&D: OmniaGuard Agent 01 — Network Scanner
=============================================
Port/service discovery and network mapping.

Capabilities:
- TCP/UDP port scanning (top 1000 or full 65535)
- Service version detection
- OS fingerprinting via TTL/window analysis
- Banner grabbing
- Network topology mapping

Integration: Uses Python sockets + LLM for intelligent service identification.
"""

import asyncio
import socket
import json
from typing import Optional
from agents.base_agent import BaseAgent


class NetworkScanner(BaseAgent):
    """Agent 01: Network reconnaissance and service discovery."""

    @property
    def description(self) -> str:
        return "Discovers open ports, running services, and network topology for monitored assets."

    @property
    def scan_types(self) -> list[str]:
        return ["quick", "full", "service_detect", "banner_grab"]

    # Common ports for quick scan
    COMMON_PORTS = [
        21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
        993, 995, 1723, 3306, 3389, 5432, 5900, 8080, 8443, 8888, 9090,
    ]

    async def scan(self, target: str, scan_type: str = "quick", **kwargs) -> dict:
        """
        Scan target for open ports and services.

        Args:
            target: IP address or hostname
            scan_type: 'quick' (top ports), 'full' (all 65535), 'service_detect', 'banner_grab'
        """
        if scan_type == "quick":
            return await self._quick_scan(target)
        elif scan_type == "full":
            return await self._full_scan(target)
        elif scan_type == "service_detect":
            return await self._service_detect(target)
        elif scan_type == "banner_grab":
            return await self._banner_grab(target)
        else:
            return await self._quick_scan(target)

    async def _quick_scan(self, target: str) -> dict:
        """Scan common ports (top 24)."""
        open_ports = []
        closed_ports = []

        tasks = [self._check_port(target, port) for port in self.COMMON_PORTS]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for port, result in zip(self.COMMON_PORTS, results):
            if isinstance(result, bool) and result:
                open_ports.append(port)
            else:
                closed_ports.append(port)

        # LLM analysis of findings
        severity = "info"
        if any(p in open_ports for p in [23, 21, 135, 139, 445]):
            severity = "high"  # Dangerous services exposed
        elif any(p in open_ports for p in [3306, 5432, 3389]):
            severity = "medium"  # DB/RDP exposed

        analysis = await self._analyze_ports(target, open_ports)

        return {
            "findings": {
                "open_ports": open_ports,
                "total_scanned": len(self.COMMON_PORTS),
                "open_count": len(open_ports),
                "services": analysis.get("services", []),
            },
            "severity": severity,
            "summary": f"Found {len(open_ports)} open ports on {target}",
            "recommendations": analysis.get("recommendations", []),
        }

    async def _full_scan(self, target: str) -> dict:
        """Scan all 65535 ports (batched for performance)."""
        open_ports = []
        batch_size = 500

        for start in range(1, 65536, batch_size):
            end = min(start + batch_size, 65536)
            ports = range(start, end)
            tasks = [self._check_port(target, port) for port in ports]
            results = await asyncio.gather(*tasks, return_exceptions=True)

            for port, result in zip(ports, results):
                if isinstance(result, bool) and result:
                    open_ports.append(port)

        severity = "high" if len(open_ports) > 20 else "medium" if len(open_ports) > 5 else "info"

        return {
            "findings": {
                "open_ports": open_ports,
                "total_scanned": 65535,
                "open_count": len(open_ports),
            },
            "severity": severity,
            "summary": f"Full scan: {len(open_ports)} open ports on {target}",
            "recommendations": [
                f"Close unnecessary port {p}" for p in open_ports
                if p not in [80, 443, 22]
            ][:10],
        }

    async def _service_detect(self, target: str) -> dict:
        """Detect services on open ports via banner grabbing + LLM."""
        # First find open ports
        quick_result = await self._quick_scan(target)
        open_ports = quick_result["findings"]["open_ports"]

        services = []
        for port in open_ports:
            banner = await self._grab_banner(target, port)
            service = self._identify_service(port, banner)
            services.append({
                "port": port,
                "banner": banner,
                "service": service,
            })

        return {
            "findings": {"services": services, "open_ports": open_ports},
            "severity": quick_result["severity"],
            "summary": f"Identified {len(services)} services on {target}",
            "recommendations": quick_result["recommendations"],
        }

    async def _banner_grab(self, target: str, **kwargs) -> dict:
        """Grab banners from all open ports."""
        ports = kwargs.get("ports", self.COMMON_PORTS)
        banners = {}

        for port in ports:
            banner = await self._grab_banner(target, port)
            if banner:
                banners[port] = banner

        return {
            "findings": {"banners": banners, "total_grabbed": len(banners)},
            "severity": "info",
            "summary": f"Grabbed {len(banners)} banners from {target}",
            "recommendations": [],
        }

    async def _check_port(self, host: str, port: int, timeout: float = 1.0) -> bool:
        """Check if a single port is open."""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=timeout,
            )
            writer.close()
            await writer.wait_closed()
            return True
        except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
            return False

    async def _grab_banner(self, host: str, port: int, timeout: float = 2.0) -> str:
        """Attempt to grab service banner."""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=timeout,
            )
            # Send probe for HTTP
            if port in [80, 8080, 8443, 443]:
                writer.write(b"HEAD / HTTP/1.0\r\nHost: " + host.encode() + b"\r\n\r\n")
                await writer.drain()

            data = await asyncio.wait_for(reader.read(1024), timeout=timeout)
            writer.close()
            await writer.wait_closed()
            return data.decode("utf-8", errors="ignore").strip()[:256]
        except Exception:
            return ""

    def _identify_service(self, port: int, banner: str) -> str:
        """Identify service from port number and banner."""
        known_ports = {
            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
            80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS",
            445: "SMB", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
            8080: "HTTP-Proxy", 8443: "HTTPS-Alt", 27017: "MongoDB",
        }
        if port in known_ports:
            return known_ports[port]
        if "SSH" in banner:
            return "SSH"
        if "HTTP" in banner:
            return "HTTP"
        if "FTP" in banner:
            return "FTP"
        return "unknown"

    async def _analyze_ports(self, target: str, open_ports: list[int]) -> dict:
        """Use LLM to analyze port findings and generate recommendations."""
        if not open_ports:
            return {"services": [], "recommendations": ["No open ports found — verify target is reachable."]}

        prompt = f"""Analyze these open ports on {target}: {open_ports}

For each port, identify:
1. Likely service
2. Security risk level
3. Whether it should be exposed to the internet

Respond with JSON:
{{
    "services": [{{"port": 80, "service": "HTTP", "risk": "low"}}],
    "recommendations": ["list of security recommendations"]
}}"""

        try:
            result = await self.llm.analyze(prompt=prompt, json_mode=True, max_tokens=1024)
            return json.loads(result)
        except Exception:
            return {
                "services": [{"port": p, "service": self._identify_service(p, ""), "risk": "unknown"} for p in open_ports],
                "recommendations": ["Review all open ports and close unnecessary services."],
            }
