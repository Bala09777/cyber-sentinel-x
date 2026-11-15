# Premium UI v3 (additional update)

The live dashboard has now been **actually redesigned**, with real API-driven animations, a unified workspace shell and updated login/Alerts/Rules/PCAP pages. Read `PREMIUM_UI_V3.md` for current UI changes and `UPGRADE_NOTES.md` below for the earlier backend upgrade.

---

# Cyber Sentinel X — Portfolio Upgrade Notes (14 Nov 2026)

This is an **edited copy of the uploaded existing project**, not a new replacement architecture. Keep your existing project and databases backed up before testing or merging.

## Fixed/implemented

- `/alerts` and `/incidents` are no longer missing page routes.
- Alert Center acknowledge/close buttons now have authenticated POST handlers and use the stable database alert ID internally. A closed alert cannot be acknowledged.
- New premium dark SOC pages: `/incidents`, `/live-network`, `/assets`, `/threat-sources`, `/reports`. The original dashboard/other app pages remain intact.
- Incident investigation uses the selected URL ID (`/investigation?id=...`) instead of a hardcoded historical case ID.
- Active dashboard now uses `dashboard_new.html` and correctly binds its alert/incident/asset counters to SOC summary; the KPI named "Events / Min" counts events created in the last 60 seconds (UTC).
- ML dashboard distinguishes **production model available** from **statistical baseline active** and shows the real stored anomaly count.
- Live capture API reports STOPPED when the latest metrics are stale (>20 sec), rather than perpetually displaying a past RUNNING value; dashboard and network page use this distinction.
- Core schema includes the missing `network_metrics` table and is created idempotently on app startup; existing data is preserved.
- Asset discovery limited to private RFC1918 IPv4 /24-or-smaller networks with user confirmation in the new Assets UI.
- Threat-source risk analytics are based on local events. CSV exports have a fixed table allowlist and basic spreadsheet-formula injection protection.
- Old raw HTML interpolations in alert and asset cards are HTML-escaped to reduce XSS exposure.
- Model/UI status placeholders updated, visual polish and motion-reduction support added.
- 5 additional tests (16 total) run with Python unittest. Active backend syntax, inline JS syntax, shared workspace JS syntax and Jinja page rendering passed.

## Not claimed complete / not tested here

- The full Flask/Scapy server **was not run** in the editing environment because those packages were unavailable and network package installation was blocked. Confirm integration in your Kali VM.
- Actual packet capture requires a **separate process**, a valid interface, OS permissions and real authorized traffic. The graph only visualizes records received from that process.
- The trained production `network_anomaly_model.pkl` remains unavailable; statistical baseline is functional but should not be called a trained AI model. The experimental UNSW `.joblib` uses a different feature schema and is intentionally **not** promoted to production.
- Report export is CSV, not PDF. External reputation feeds, fully automated incident response and production SIEM hardening are not implemented.
- File upload, asset discovery, authentication flows and browser layout still require an end-to-end run on the target machine.
- The dashboard network-map graphic is decorative/illustrative; captured packet/flow figures are backend telemetry.

## Use safely

1. **Do not delete or overwrite your original project automatically.** Keep a backup before comparing or merging files.
2. Extract this ZIP to a separate folder, then review the changed backend, frontend, tests and documentation against your original project.
3. Keep your existing `data/*.db`, `.env`, credentials and other private files; the updated package intentionally excludes those files.
4. Install dependencies from `requirements.txt` in Kali's own `.venv`; the project requires `nmap` only for its optional host discovery feature.
5. Run unit tests, then test login, alert triage, incident investigation, capture service and dashboard manually on Kali.

## Known data semantics

- `active_alerts` counts OPEN + ACKNOWLEDGED alerts, excluding CLOSED.
- `events_per_minute` is a one-minute **database event count**, not network packets per minute.
- `anomaly_count` is the cumulative number of events whose stored `anomaly_score` meets configured threshold, not a one-minute rate.
- The Assets API limits its displayed list to 50 rows, while total/active counters come from the full database.

## Premium V3.1 Defensive Operations Add-on (2026-11-14)

See [CSX_V3_1_ADDON.md](CSX_V3_1_ADDON.md) for new module explanations, opt-in flags, safety scope, test results, limitations and startup instructions. This release is a non-destructive extension of Premium V3 and does not reset authentication, databases or existing project data.
