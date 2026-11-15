"""Offline premium UI contract tests. Requires Jinja2 (installed with Flask)."""
from pathlib import Path
import re
import unittest
from jinja2 import Environment, FileSystemLoader

ROOT = Path(__file__).resolve().parents[1]
TEMPLATES = ROOT / "frontend" / "templates"
STATIC = ROOT / "frontend" / "static"


class TestPremiumUI(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.jinja = Environment(loader=FileSystemLoader(str(TEMPLATES)), autoescape=True)
        cls.jinja.globals["url_for"] = lambda endpoint, filename, **kwargs: "/static/" + filename

    def render(self, name, view):
        return self.jinja.get_template(name).render(
            view=view, title="Cyber Sentinel X", breadcrumb="TEST", subtitle="Offline QA"
        )

    def test_dashboard_extends_common_shell_and_has_no_duplicate_ids(self):
        html = self.render("dashboard_new.html", "dashboard")
        ids = re.findall(r'\bid="([a-zA-Z][\w-]*)"', html)
        self.assertEqual(len(ids), len(set(ids)))
        for important in ("kpiEvents", "kpiAlerts", "kpiIncidents", "riskRing",
                          "activityChart", "mlStatusPill", "networkStatus", "dashAlerts"):
            self.assertIn(important, ids)

    def test_workspaces_use_single_navigation_and_unique_ids(self):
        views = (("alerts.html", "alerts"), ("rules.html", "rules"),
                 ("pcap.html", "pcap"), ("incidents.html", "incidents"),
                 ("assets.html", "assets"), ("live_network.html", "network"),
                 ("reports.html", "reports"), ("threat_sources.html", "sources"))
        for template, view in views:
            with self.subTest(template=template):
                html = self.render(template, view)
                ids = re.findall(r'\bid="([a-zA-Z][\w-]*)"', html)
                self.assertEqual(len(ids), len(set(ids)))
                self.assertIn('href="/alerts"', html)
                self.assertIn('href="/incidents"', html)
                self.assertIn('href="/"', html)

    def test_local_assets_and_no_hardcoded_kpi_numbers(self):
        for file in ("css/csx-workspaces.css", "css/csx-dashboard.css",
                     "js/csx-workspaces.js", "js/csx-dashboard.js"):
            self.assertTrue((STATIC / file).is_file(), file)
        dashboard = (TEMPLATES / "dashboard_new.html").read_text()
        self.assertIn('id="kpiEvents"', dashboard)
        self.assertIn('id="kpiAnomalies"', dashboard)
        self.assertIn('id="trendNumber"', dashboard)
        self.assertNotIn("24,892", dashboard)  # Demonstration image values must not ship.
        self.assertNotIn("IsolationForest", dashboard)  # Cannot claim a trained model is loaded.


if __name__ == "__main__":
    unittest.main()
