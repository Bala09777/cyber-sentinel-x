# Cyber Sentinel X — Premium UI v3

This revision replaces the **actual active Flask dashboard template** (`frontend/templates/dashboard_new.html`) with a modern, responsive SOC interface, rather than merely producing a promotional video of a possible design. It continues the existing project, uses the previous portfolio upgrade's backend, and does not include private databases or credentials.

## New visual design and working bindings

- `soc_shell.html` provides one coherent sidebar, accessible navigation, live clock, backend health indicator and sign-out button for the SOC workspaces.
- `dashboard_new.html` now has an independently styled overview, five live KPI cards, radial environment-risk gauge, animated event-history chart, ML engine state, network topology illustration, recent alert queue, detection-event table and observed source-risk list.
- All numerical dashboard counters are fetched from existing local API endpoints. **No sample metrics are shipped.** A blank database shows zero or empty states, and unavailable endpoints show an error instead of invented readings.
- The animated event chart uses **actual `/api/soc/summary` samples** from the time the page opens, on a 5-second interval. It cannot show historical samples before the page was opened without a separate historical time-series API.
- The animated network topology is **explicitly labeled a conceptual diagram**; moving dots appear only when `/api/soc/network` reports a fresh RUNNING capture. It does not claim to plot actual packet trajectories.
- The ML card uses `/api/health` to distinguish trained model availability, statistical baseline operation, disabled state and current configured threshold. The experimental UNSW model has NOT been promoted to production.
- A toast appears for **newly observed alert IDs** after the initial alert feed is loaded (not as simulated attacks).
- Alerts, Detection Rules, PCAP Analysis, login and the other shared workspaces use the premium color system. Existing backend APIs and features are retained; the investigation page has navigation links back to Dashboard and Incident Queue.
- Includes keyboard focus states, responsive mobile sidebar, cached-asset busting (`?v=3`) and reduced-motion behavior.
- Unauthenticated browser requests for protected HTML pages now redirect to `/login`, while `/api/...` continues to return HTTP 401 JSON (without leaking data).

## Files changed for this UI revision

| File | Purpose |
| --- | --- |
| `frontend/templates/dashboard_new.html` | Rebuilt active overview template; no duplicate IDs |
| `frontend/templates/soc_shell.html` | Common premium sidebar, header, icon sprite and layout |
| `frontend/static/css/csx-dashboard.css` | Dashboard visuals, responsive grids and animations |
| `frontend/static/css/csx-workspaces.css` | Shared design system for the app workspaces |
| `frontend/static/js/csx-dashboard.js` | Real API dashboard counters, charts, alerts, ML/capture status |
| `frontend/static/js/csx-workspaces.js` | Shared health/nav and functional alerts/rules/PCAP/workspaces |
| `frontend/templates/alerts.html` | Premium alert filtering and action layout |
| `frontend/templates/rules.html` | Premium CRUD detection-rule manager |
| `frontend/templates/pcap.html` | Premium offline capture analysis UI |
| `frontend/templates/login.html` | Premium existing username/password authentication form |
| `frontend/templates/investigation.html` | Back links and typography polish, existing analysis retained |
| `backend/app.py` | Page metadata (title, active nav, descriptions) |
| `backend/security/auth_service.py` | Browser login redirect with API 401 preserved |
| `tests/test_premium_ui.py` | Jinja templates and duplicate ID checks |

## Keep your original data safe

**Always back up the working project before copying.** Integrate the changed code without overwriting `.env`, `.venv`, Git history, `data/`, `instance/`, `logs/`, `pcaps/`, or `reports/`. Never use `rsync --delete` or delete the old project. Old backups may be retained safely.

To run in Kali after updating files, restart the Flask server and hard-refresh the browser (`Ctrl+Shift+R`). If the active dashboard still looks old, make sure the server is using `backend/app.py` from the intended project folder and `render_template("dashboard_new.html")`.

## Quality checks and limitations

- 19 Python unit tests pass in the editing environment. Browser rendering, duplicate IDs, JavaScript syntax and standard/mobile layout were inspected with Chromium using *test-only simulated API responses*, not live Kali capture.
- **The final Flask + Scapy authenticated end-to-end run and real network capture must be verified in your own Kali VM.** This environment does not have Flask or Scapy installed.
- The trained production ML model remains unavailable unless you supply and validate a feature-compatible model. This package does not claim a completed production AI classifier.
- For the premium chart to show movement, the application must actually record network events; when no new events arrive, the chart correctly stays flat.
- The responsive dashboard is a production *portfolio design*, not a claim of commercial SOC/SIEM production readiness.
