"""
Network Pools Manager - IP Range Configuration

Manages configurable IP ranges (pools) that can be used in senders:
- CIDR notation: 192.168.1.0/24
- Range notation: 192.168.1.1-192.168.1.254

Supports categories: internal, external, malicious, etc.
"""

import ipaddress
import random
from pathlib import Path
from store import JsonStore


class NetworkPoolManager(JsonStore):
    """Manages network IP pools - CIDR and range formats."""

    def __init__(self, config_file="network_pools.json"):
        super().__init__(config_file)
        if not self._data:
            self._initialize_defaults()

    def _initialize_defaults(self):
        """Initialize with default pools if file is empty."""
        self._data = {
            "internal": [
                {"name": "corporate_internal", "range": "192.168.1.0/24", "type": "cidr"},
                {"name": "datacenter_1", "range": "10.0.0.0/8", "type": "cidr"},
                {"name": "datacenter_2", "range": "172.16.0.0/12", "type": "cidr"},
            ],
            "external": [
                {"name": "cloud_providers", "range": "8.8.8.0/24", "type": "cidr"},
                {"name": "isp_range", "range": "1.1.1.1-1.1.1.254", "type": "range"},
            ],
            "malicious": [
                {
                    "name": "threat_actors",
                    "range": "185.220.101.0/24",
                    "type": "cidr",
                },
            ],
        }
        self._save()

    def _parse_range(self, range_str: str) -> list:
        """Parse CIDR or range notation into list of IPs."""
        try:
            # Try CIDR
            if "/" in range_str:
                network = ipaddress.ip_network(range_str, strict=False)
                return [str(ip) for ip in network.hosts()]  # Exclude network/broadcast
            # Try range (start-end)
            elif "-" in range_str:
                start_ip, end_ip = range_str.split("-")
                start = ipaddress.ip_address(start_ip.strip())
                end = ipaddress.ip_address(end_ip.strip())
                return [str(ip) for ip in ipaddress.summarize_address_range(start, end)]
            else:
                # Single IP
                ipaddress.ip_address(range_str)
                return [range_str]
        except ValueError as e:
            raise ValueError(f"Invalid IP range format: {range_str}") from e

    def get_pool(self, category: str, pool_name: str) -> list:
        """Get all IPs from a specific pool."""
        if category not in self._data:
            raise ValueError(f"Category '{category}' not found")
        pools = self._data[category]
        for pool in pools:
            if pool["name"] == pool_name:
                return self._parse_range(pool["range"])
        raise ValueError(f"Pool '{pool_name}' not found in category '{category}'")

    def get_random_ip(self, category: str, pool_name: str) -> str:
        """Get a random IP from a pool."""
        ips = self.get_pool(category, pool_name)
        return random.choice(ips) if ips else None

    def list_categories(self) -> list:
        """List all categories."""
        return list(self._data.keys())

    def list_pools(self, category: str) -> list:
        """List all pools in a category."""
        if category not in self._data:
            raise ValueError(f"Category '{category}' not found")
        return self._data[category]

    def create_pool(
        self, category: str, name: str, range_str: str, type_: str = "cidr"
    ):
        """Create a new pool."""
        # Validate range format
        self._parse_range(range_str)

        if category not in self._data:
            self._data[category] = []

        # Check for duplicates
        for pool in self._data[category]:
            if pool["name"] == name:
                raise ValueError(f"Pool '{name}' already exists in category '{category}'")

        self._data[category].append(
            {"name": name, "range": range_str, "type": type_}
        )
        self._save()

    def update_pool(self, category: str, name: str, range_str: str, type_: str):
        """Update an existing pool."""
        # Validate format
        self._parse_range(range_str)

        if category not in self._data:
            raise ValueError(f"Category '{category}' not found")

        for pool in self._data[category]:
            if pool["name"] == name:
                pool["range"] = range_str
                pool["type"] = type_
                self._save()
                return

        raise ValueError(f"Pool '{name}' not found in category '{category}'")

    def delete_pool(self, category: str, name: str):
        """Delete a pool."""
        if category not in self._data:
            raise ValueError(f"Category '{category}' not found")

        self._data[category] = [
            p for p in self._data[category] if p["name"] != name
        ]
        self._save()

    def get_stats(self) -> dict:
        """Get statistics on all pools."""
        stats = {}
        for category, pools in self._data.items():
            stats[category] = {
                "count": len(pools),
                "pools": [p["name"] for p in pools],
            }
        return stats
