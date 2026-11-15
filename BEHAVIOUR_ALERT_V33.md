# Cyber Sentinel X V3.3 — Behaviour Alert Reliability

An incremental fix for real traffic **heuristics** (not an IDS accuracy guarantee).

- Count distinct valid TCP/UDP destination ports **on one destination host**
  within the existing behavioural time window (default 60 s).
- Ten distinct target ports (default `PORT_SCAN_THRESHOLD=10`): SUSPICIOUS
  risk floor 40. Creates an alert; no external email under the current policy.
- Same source with >=30 events (default `RAPID_PACKET_THRESHOLD=30`)
  and at least ten ports on one target: HIGH risk floor 60. Creates an alert,
  and queues Gmail only when enabled. Worker is separate; no blocking.
- Repeated hits on just one port, or one port on ten unrelated destinations,
  do not trigger the port-scan heuristic.
- Existing stronger rules/ML/threat-intel scores remain intact.
- Adds explanatory evidence in event activity, logging and returned risk data.
- Cannot prove maliciousness; many connections may be legitimate. Tune for
  your authorized network, rate-limit/suppress alerts as appropriate.
- No new network scanning or firewall action. No database schema changes.
- Run all tests after installation. Restart Flask and live capture processes
  afterward to load the updated source; Gmail worker unchanged.
- Test code uses ephemeral SQLite and mocks external notifications; SMTP
  delivery was verified separately before this upgrade.
