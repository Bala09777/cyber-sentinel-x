"""Small, read-only local Flask factory route smoke check (no login secrets)."""
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from backend.app import create_app


def main():
    app = create_app()
    client = app.test_client()
    routes = [
        ('/api/health', 200),
        ('/login', 200),
        ('/api/soc/network', 401),
        ('/api/soc/summary', 401),
        ('/api/soc/notifications', 401),
        ('/api/soc/firewall', 401),
        ('/api/soc/threat-sources/8.8.8.8/investigate', 401),
    ]
    errors = 0
    for url, expected in routes:
        response = client.get(url)
        ok = response.status_code == expected
        print(('PASS' if ok else 'FAIL'), response.status_code, url,
              '(expected %d)' % expected)
        errors += not ok
    print('Smoke checks:', len(routes)-errors, '/', len(routes))
    return 1 if errors else 0

if __name__ == '__main__':
    raise SystemExit(main())
