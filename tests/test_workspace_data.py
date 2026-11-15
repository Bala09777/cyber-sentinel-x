"""Unit tests that run without Flask, Scapy, Nmap, or network access."""
import sqlite3
from contextlib import closing
import unittest
from backend.database.schema import SCHEMA
from backend.assets.discovery_service import asset_discovery_service


class TestWorkspaceData(unittest.TestCase):
    def test_network_metrics_table_created(self):
        with closing(sqlite3.connect(":memory:")) as db:
            db.executescript(SCHEMA)
            db.execute("SELECT * FROM network_metrics LIMIT 1")
            db.execute("SELECT * FROM alerts LIMIT 1")

    def test_private_host_discovery_range(self):
        self.assertEqual(
            asset_discovery_service.validate_network("192.168.1.42/24"),
            "192.168.1.0/24"
        )

    def test_refuse_public_loopback_and_large_ranges(self):
        for network in ("8.8.8.0/24", "127.0.0.0/24", "192.168.0.0/16"):
            with self.subTest(network=network):
                with self.assertRaises(ValueError):
                    asset_discovery_service.validate_network(network)


if __name__ == "__main__":
    unittest.main()
