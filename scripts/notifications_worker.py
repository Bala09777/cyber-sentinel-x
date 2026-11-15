"""Run separately to deliver configured alerts: python scripts/notifications_worker.py"""
import os
import sys
import time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from backend.database.schema import initialize_database
from backend.response.notifications import dispatch_once, configured

if __name__ == '__main__':
    initialize_database()
    print('Cyber Sentinel X Notification Worker:', configured(), flush=True)
    while True:
        try:
            sent = dispatch_once()
            if sent:
                print(f'Successfully processed {sent} notification jobs', flush=True)
        except Exception as exc:
            print('Worker error:', type(exc).__name__, flush=True)
        time.sleep(max(3, int(os.getenv('CSX_NOTIFY_POLL_SECONDS', '10'))))
