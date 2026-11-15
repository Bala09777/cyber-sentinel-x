# Cyber Sentinel X — Incident Correlation V3.2 Safe Update

**Scope:** Incremental improvement to the existing V3.1 incident correlation engine. No dashboard redesign, schema migration, or modifications to `.env`, email/voice provider setup, firewall, capture, ML artifacts, credentials, logs, or actual SQLite data files.

## What the patch changes

- Existing 5-minute correlation window / two suspicious-events minimum retained.
- Two or more related suspicious/HIGH/CRITICAL events can create a case with linked evidence; NORMAL events do not trigger a case.
- New events for an active case refresh **actual** severity, risk, counts and first/last event time. CRITICAL evidence escalates an existing HIGH case.
- Evidence already assigned to CLOSED/RESOLVED cases is not reused for new cases.
- A stale open case is not silently revived outside the correlation window.
- Repeated checks do not duplicate incident-event links.
- SQLite `BEGIN IMMEDIATE` prevents competing correlation processes from creating duplicate cases from the same window (subject to SQLite locking). Existing analyst-assigned statuses remain unchanged.
- Correlation obeys `CORRELATION_ENABLED`. No automatic firewall blocking.

## Verify on Kali

From the **already installed** project folder:

```bash
.venv/bin/python -m unittest discover -s tests -v
.venv/bin/python scripts/demo_incident_correlation_v32.py
```

The demo uses **only a temporary SQLite database** and documentation-address test events, then cleans up. The demo does not send email, initiate calls, modify firewall rules, or write fake incidents into the active SOC database. Existing live capture and Gmail worker remain separate.

## Remaining actual-device verification

Use your existing authenticated SOC dashboard to verify that **real monitored events**, once legitimately classified as suspicious, correlate into incidents, appear in `/incidents`, and open an actual `/investigation?id=...` timeline. The two-event demo only proves correlation logic, not attack detection accuracy or email delivery. Keep `STATISTICAL_BASELINE` vs experimental ML labels honest.
