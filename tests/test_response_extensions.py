"""Offline regression tests for Cyber Sentinel X V3.1 extensions."""
import ast
import os
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from backend.database.manager import db
from backend.database.schema import SCHEMA
from backend.intelligence.geo_service import geo_lookup
from backend.response.firewall import action, _validate
from backend.response.notifications import enqueue_alert, dispatch_once

ROOT = Path(__file__).resolve().parents[1]


class SecurityExtensionsTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.original_db = db.db_file
        db.db_file = Path(self.temp.name) / 'isolated_tests.db'
        conn = sqlite3.connect(db.db_file)
        try:
            conn.executescript(SCHEMA)
        finally:
            conn.close()

    def tearDown(self):
        db.db_file = self.original_db
        self.temp.cleanup()

    def test_network_route_is_in_application_factory(self):
        tree = ast.parse((ROOT / 'backend/app.py').read_text())
        factory = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name=='create_app')
        function_names = [n.name for n in factory.body if isinstance(n, ast.FunctionDef)]
        self.assertIn('soc_network', function_names)
        self.assertIn('firewall_change', function_names)

    def test_geoip_never_fabricates_private_location(self):
        result = geo_lookup('192.168.56.1')
        self.assertEqual(result['scope'], 'NON_PUBLIC')
        self.assertIsNone(result['latitude'])
        self.assertIsNone(result['country'])

    def test_firewall_stays_preview_by_default(self):
        with patch.dict(os.environ, {'CSX_FIREWALL_EXECUTE':'0',
                                     'CSX_FIREWALL_ALLOW_PRIVATE':'0'}):
            result = action('8.8.8.8','block','unit-test')
            self.assertEqual(result['status'], 'DRY_RUN')
            for ip in ('127.0.0.1','192.168.0.1','203.0.113.44','bad-ip'):
                with self.assertRaises(ValueError):
                    _validate(ip)
        self.assertEqual(db.count('firewall_actions'), 0)

    def test_firewall_confirmation_required(self):
        with patch.dict(os.environ, {
            'CSX_FIREWALL_EXECUTE': '1',
            'CSX_FIREWALL_ALLOWLIST': ''
        }), patch('backend.response.firewall._ensure_chain') as chain:
            with self.assertRaises(ValueError):
                action('8.8.8.8', 'block', 'admin', confirmed=False)
            chain.assert_not_called()

    def test_firewall_block_and_unblock(self):
        with patch.dict(os.environ, {
            'CSX_FIREWALL_EXECUTE': '1',
            'CSX_FIREWALL_ALLOWLIST': ''
        }), patch('backend.response.firewall._ensure_chain'), patch('backend.response.firewall._run') as run:
            self.assertEqual(
                action('8.8.8.8', 'block', 'admin', True)['status'],
                'APPLIED'
            )
            self.assertEqual(
                action('8.8.8.8', 'unblock', 'admin', True)['status'],
                'APPLIED'
            )
            self.assertEqual(run.call_count, 2)
            self.assertEqual(db.count('firewall_actions'), 2)

    def test_firewall_allowlist_protection(self):
        with patch.dict(os.environ, {
            'CSX_FIREWALL_ALLOWLIST': '8.8.8.8'
        }):
            with self.assertRaises(ValueError):
                _validate('8.8.8.8')

    def test_firewall_failure_audit(self):
        with patch.dict(os.environ, {
            'CSX_FIREWALL_EXECUTE': '1',
            'CSX_FIREWALL_ALLOWLIST': ''
        }), patch('backend.response.firewall._ensure_chain'), patch(
            'backend.response.firewall._run',
            side_effect=RuntimeError('Mock firewall failure')
        ):
            with self.assertRaises(RuntimeError):
                action('8.8.8.8', 'block', 'admin', True)

        rows = db.fetch_all("SELECT status FROM firewall_actions")
        self.assertEqual(rows[0]['status'], 'FAILED')

    def test_local_voice_alert(self):
        with patch.dict(os.environ, {
            'CSX_EMAIL_ENABLED': '0',
            'CSX_VOICE_ENABLED': '0',
            'CSX_LOCAL_VOICE_ENABLED': '1'
        }), patch('backend.response.notifications.shutil.which',
                  return_value='/usr/bin/espeak-ng'), patch(
            'backend.response.notifications.subprocess.run'
        ) as speaker:

            alert = {
                'alert_id': 'LOCAL-TEST',
                'severity': 'CRITICAL',
                'source_ip': '192.0.2.10',
                'risk_score': 85,
                'message': 'Simulated brute force attack'
            }

            self.assertEqual(enqueue_alert(alert), 1)
            self.assertEqual(enqueue_alert(alert), 0)
            self.assertEqual(dispatch_once(), 1)
            speaker.assert_called_once()

            self.assertIn(
                'Simulated brute force attack',
                speaker.call_args.kwargs['input']
            )
            rows = db.fetch_all("SELECT status FROM notification_outbox")
            self.assertEqual(rows[0]['status'], 'PLAYBACK_COMPLETED')

    def test_alert_outbox_and_cooldown(self):
        conf = {'CSX_LOCAL_VOICE_ENABLED':'0', 'CSX_EMAIL_ENABLED':'1', 'CSX_SMTP_HOST':'smtp.local',
                'CSX_ALERT_EMAIL_FROM':'csx@example.test',
                'CSX_ALERT_EMAIL_TO':'admin@example.test',
                'CSX_VOICE_ENABLED':'1', 'CSX_TWILIO_SID':'sid',
                'CSX_TWILIO_TOKEN':'token','CSX_TWILIO_FROM':'+10000000000',
                'CSX_ALERT_PHONE':'+19999999999'}
        alert = {'alert_id':'ALT-test', 'severity':'CRITICAL',
                 'source_ip':'8.8.8.8', 'risk_score':95,
                 'message':'Synthetic unit test; no real attack'}
        with patch.dict(os.environ, conf):
            self.assertEqual(enqueue_alert(alert), 2)
            self.assertEqual(enqueue_alert(alert), 0)
            self.assertEqual(db.count('notification_outbox'), 2)
            # Mock actual external transports: zero mail or calls performed.
            with patch('backend.response.notifications.deliver_email') as email, \
                 patch('backend.response.notifications.deliver_voice') as voice:
                self.assertEqual(dispatch_once(), 2)
                email.assert_called_once()
                voice.assert_called_once()
        statuses = {r['status'] for r in db.fetch_all('SELECT status FROM notification_outbox')}
        self.assertEqual(statuses, {'ACCEPTED_BY_PROVIDER'})


if __name__ == '__main__':
    unittest.main()
