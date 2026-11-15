# Cyber Sentinel X — Premium V3.1 Defensive Operations Add-on

This update continues **the existing Premium V3 project**, not a rebuild. Active dashboard: `frontend/templates/dashboard_new.html`. The original database, accounts, Git history, virtual environment, user rules, logs and packet captures must remain in the **active Kali project**. The archive deliberately excludes private state.

## Verified in the packaging environment

- Python source files parse and compile.
- JavaScript passes `node --check`; Jinja2 Premium UI contract tests passed.
- Extension tests (outbox + cooldown, firewall dry-run, private-IP geo handling, factory registration) passed.
- UNSW-NB15 new **experimental** Random Forest trained on user-supplied splits, using only TCP/UDP/ICMP records. Test results in `models/unsw_nb15_validation.json`. This is **not** live production performance or a replacement for the statistical baseline.

**Not verified here:** full Flask/Scapy end-to-end behavior on Kali, actual email/voice delivery, installed nftables compatibility, packet capture on the selected VM interface, external GeoLite2 database availability. The packaging environment cannot install Flask/Scapy, so these must be tested on the user's Kali VM.

## Key fixes and modules

1. Network API `/api/soc/network` now registered **inside `create_app`**; previously module-global registration caused 404 when Flask CLI selected the factory. Running the API still requires a logged-in session (401 without login is expected).
2. The separate live capture process now writes heartbeat metrics every five seconds, including when no flows have completed, and writes STOPPED status at shutdown.
3. Authentication failures in the `audit_logs` table now correlate by source IP: 5 LOGIN_FAILURE entries within 5 minutes create one CRITICAL threat event/alert; repeats are suppressed 15 minutes. Application login lockout remains unchanged. Only the authenticated app's observed remote IP is trusted (trusted reverse proxies must be explicitly configured).
4. High/critical alerts can queue **email** and critical alerts can additionally queue **voice calls**, if independently configured. `notification_outbox` tracks pending, accepted, retry and failed states. Dispatch happens only in the **separate worker**; no external network operations happen in the detection pipeline. Provider acceptance is not the same as delivery or an answered call.
5. `/threat-sources` now provides source investigation drill-down, events, target/registered asset details and approximate country from an optional, local GeoLite2 database. It never guesses identity or locations for private/reserved IPs.
6. `/firewall` adds manually confirmed, ADMIN-only, nftables actions for the **Kali VM INPUT chain only**. It is **dry-run by default** and changes nothing without an explicit opt-in. No automatic blocking of suspected traffic is enabled.
7. Experimental ML shadow predictions may be persisted to `shadow_ml_predictions`; they do **not** influence production scoring or alerts. New validated experimental model is supplied separately, leaving the existing `unsw_nb15_experimental.joblib` unchanged.
8. Health UI now distinguishes an online Flask database from STOPPED network capture, instead of claiming all systems are connected.

## Kali start and tests

From the existing `~/cyber-sentinel/cyber-sentinel-x` project, after safe patch installation:

```
.venv/bin/python -m unittest discover -s tests -v
.venv/bin/python -m flask --app backend.app:create_app run --host 127.0.0.1 --port 8000
```

Use an existing account to log in via Firefox at `http://127.0.0.1:8000`. Visit `/live-network` and `/api/soc/network`. `401` before login is correct; after login, `200` is expected. No preexisting alerts/assets were removed.

Separate terminal for passive capture (authorized traffic only, correct interface must be selected):

```
CSX_INTERFACE=eth0 .venv/bin/python -m backend.pcap.live_capture
```

This capture process requires appropriate packet-capture privileges. VirtualBox networking mode and interface choice constrain visibility. A heartbeat means the capture **process is reporting**; it does not prove it sees your whole LAN.

## Real email / optional Twilio voice delivery

Set these as environment variables (keep passwords and tokens in a private local environment / secrets manager; do NOT commit `.env`):

```
CSX_EMAIL_ENABLED=1
CSX_SMTP_HOST=smtp.example.com
CSX_SMTP_PORT=587
CSX_SMTP_USER=your_smtp_username
CSX_SMTP_PASSWORD=your_smtp_app_password
CSX_ALERT_EMAIL_FROM=alerts@example.com
CSX_ALERT_EMAIL_TO=admin@example.com
```

For critical calls, **optional** (provider fees and verified-number rules may apply):

```
CSX_VOICE_ENABLED=1
CSX_TWILIO_SID=your_account_sid
CSX_TWILIO_TOKEN=your_auth_token
CSX_TWILIO_FROM=your_provider_phone_number
CSX_ALERT_PHONE=your_admin_phone_number
```

Then start a **separate** notification worker with the same environment variables:

```
.venv/bin/python scripts/notifications_worker.py
```

Email requires working SMTP TLS. The worker does not send when unconfigured; `/notifications` shows exactly which channels are ready and the outbox status. Do not test with real administrator calls until recipients opt in.

## Geolocation / device intelligence

Optional offline MaxMind GeoLite2 databases and Python `geoip2` dependency (obtain databases under their applicable terms):

```
CSX_GEOIP_CITY_DB=/private/path/GeoLite2-City.mmdb
CSX_GEOIP_ASN_DB=/private/path/GeoLite2-ASN.mmdb
```

GeoIP2 (optional) can be installed using `.venv/bin/python -m pip install geoip2`. Without the databases, location is **Unknown**. Geolocation is approximate and does not identify attackers. Device MAC/hostname are populated only if an asset already exists; internet IP addresses do not reveal remote MAC/device identity. **No public IP lookup is sent to third parties by this add-on.**

## Firewall opt-in and scope

Default: `/firewall` previews actions as `DRY_RUN`. Nothing is blocked.

For an authorized, isolated Kali lab where nftables is installed, operators can deliberately set:

```
CSX_FIREWALL_EXECUTE=1
CSX_FIREWALL_ALLOWLIST=203.0.113.1,8.8.8.8
```

The allowlist must be adjusted to your legitimate management addresses. The tool creates only `inet csx_guard` with an accept-policy **input** hook and a source-IP set. The user must be logged in as ADMIN and type `CONFIRM` for execution. By default only global IPv4 addresses can be blocked; private address blocking requires `CSX_FIREWALL_ALLOW_PRIVATE=1` in a lab and is dangerous around local routers/VM networks. It does not inspect or filter traffic on other LAN devices. Never expose the Flask development server publicly or treat these firewall controls as a network perimeter firewall. Test nftables interactions offline before enabling.

To inspect or manually remove the add-on's isolated table **only if you intentionally enabled it**, use standard nftables administration with trusted local admin procedures. Unblock directly via the `/firewall` interface if possible.

## Experimental validation model

- Bundled original experimental model: `models/unsw_nb15_experimental.joblib` — preserved.
- Newly trained, held-out evaluated artifact: `models/unsw_nb15_validated.joblib`.
- Test metrics: `models/unsw_nb15_validation.json`.
- To reproduce validation: `.venv/bin/python scripts/validate_unsw_nb15.py --train path/to/UNSW_NB15_training-set.csv --test path/to/UNSW_NB15_testing-set.csv`.
- **No dataset CSVs** bundled in the public release. Do not commit the private lab captures or `.env`.
- Default `ml_prediction_mode` remains **STATISTICAL_BASELINE** until a genuinely feature-compatible production model has been developed, tested and reviewed.

## Important limitations before an interview demo

- End-to-end browser/API tests on Kali still required. An API response or unit test pass is not proof every UI action works.
- Authentication correlation detects failed logins **to this app**; host SSH monitoring is not included yet. New/unfamiliar IP activity needs a deliberately maintained asset trust baseline; a new IP alone is not proof of attack.
- Firewall is manual, Kali-host-only and disabled until opted in. No automatic prevention of arbitrary network attacks is claimed.
- Email and calls are not configured or delivered in the ZIP. Valid provider credentials, admin consent, and the worker are required.
- The model evaluation uses the supplied benchmark splits; distribution shift and false positives on a real enterprise network are unknown.
- Risk scoring and incidents remain the existing defensive workflow. Controlled, authorized scenarios should be used for demos.

Factory/API smoke checks (unauthenticated `401` on protected APIs is expected):

```
.venv/bin/python scripts/smoke_check.py
```

This checks the factory's route registration without requiring admin passwords; it does not prove that a logged-in API call, live packet capture or notification provider works end to end.
