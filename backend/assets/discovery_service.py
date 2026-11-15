import ipaddress
import re
import subprocess

from backend.assets.asset_service import AssetService
from backend.core.logger import logger


class AssetDiscoveryService:
    """
    Defensive local-network asset discovery using Nmap host discovery.
    Only host discovery (-sn) is performed; no port scanning.
    """

    def __init__(self):
        self.asset_service = AssetService()

    def validate_network(self, network):
        try:
            parsed = ipaddress.ip_network(
                str(network).strip(),
                strict=False
            )
        except ValueError as exc:
            raise ValueError("Invalid network range") from exc

        if parsed.version != 4:
            raise ValueError("Only IPv4 networks are supported")

        # Only scan explicitly authorized private IPv4 networks.
        private_blocks = (
            ipaddress.ip_network("10.0.0.0/8"),
            ipaddress.ip_network("172.16.0.0/12"),
            ipaddress.ip_network("192.168.0.0/16"),
        )
        if not any(parsed.subnet_of(block) for block in private_blocks):
            raise ValueError("Only private RFC1918 IPv4 networks are allowed")

        if parsed.prefixlen < 24:
            raise ValueError(
                "Discovery is limited to /24 or smaller networks"
            )

        return str(parsed)

    def discover(self, network):
        network = self.validate_network(network)

        command = [
            "nmap",
            "-sn",
            network
        ]

        logger.info(
            f"ASSET_DISCOVERY | started | network={network}"
        )

        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=120,
            check=False
        )

        if result.returncode != 0:
            logger.error(
                f"ASSET_DISCOVERY | nmap_failed | "
                f"returncode={result.returncode}"
            )
            raise RuntimeError(
                result.stderr.strip() or "Nmap discovery failed"
            )

        discovered = []
        current = None

        for line in result.stdout.splitlines():
            line = line.strip()

            host_match = re.match(
                r"Nmap scan report for (.+)",
                line
            )

            if host_match:
                if current:
                    discovered.append(current)

                host_value = host_match.group(1)

                if " (" in host_value and host_value.endswith(")"):
                    hostname, ip_address = host_value.rsplit(" (", 1)
                    ip_address = ip_address.rstrip(")")
                else:
                    hostname = None
                    ip_address = host_value

                current = {
                    "ip_address": ip_address,
                    "hostname": hostname,
                    "mac_address": None,
                    "vendor": None
                }
                continue

            mac_match = re.match(
                r"MAC Address: ([0-9A-Fa-f:]{17})(?: \((.+)\))?",
                line
            )

            if mac_match and current:
                current["mac_address"] = mac_match.group(1).upper()
                current["vendor"] = mac_match.group(2)

        if current:
            discovered.append(current)

        registered = []

        for asset in discovered:
            ip_address = asset["ip_address"]

            try:
                ipaddress.ip_address(ip_address)
            except ValueError:
                continue

            registered_asset = self.asset_service.register_asset(
                ip_address=ip_address,
                hostname=asset["hostname"],
                mac_address=asset["mac_address"],
                asset_type="NETWORK_HOST",
                risk_score=0,
                status="ACTIVE"
            )

            registered.append(dict(registered_asset))

        logger.info(
            f"ASSET_DISCOVERY | completed | "
            f"network={network} | discovered={len(registered)}"
        )

        return {
            "network": network,
            "discovered_count": len(registered),
            "assets": registered
        }


asset_discovery_service = AssetDiscoveryService()
