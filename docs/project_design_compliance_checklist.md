# HoneyDash Project Design Compliance Checklist

This checklist maps HoneyDash against the STIZK3993 Project Design functional requirements.

## Functional Requirements

| ID | Requirement | Implementation Evidence | Verification |
| --- | --- | --- | --- |
| HD_UC_01 | Admin/Analyst login | `/auth/login`, `frontend/login.html`, JWT auth guards | Login with seeded/admin user and verify token-protected pages load |
| HD_UC_02 | Public viewer dashboard | `/api/public/*`, `frontend/public.html` | Open `public.html` without login and confirm charts/map load |
| HD_UC_03 | Connect/ingest live honeypot logs | Cowrie log tailer, Dionaea collector, `/api/ingest/event`, `/api/ingest/batch` | Run mocks and send a manual remote event with `sensor=remote` |
| HD_UC_04 | Process and normalise logs | `process_line()` maps Cowrie/Dionaea/remote events to `Session` and `Event` | Confirm Cowrie, Dionaea, and remote rows exist in PostgreSQL |
| HD_UC_05 | Upload static log file | `/api/upload/logs`, `frontend/configuration.html` upload panel | Upload a Cowrie JSON log and confirm processed/skipped counts |
| HD_UC_06 | Attack timeline chart | `/api/dashboard/timeline`, dashboard timeline chart | Change dashboard range and verify populated chart |
| HD_UC_07 | Attack geo-map | `/api/dashboard/map`, `/api/public/map`, Leaflet map | Confirm enriched IPs appear on map |
| HD_UC_08 | Session viewer/search | `/api/sessions`, `/api/events/search`, `frontend/sessions.html` | Search/filter sessions and open details |
| HD_UC_09 | GeoIP enrichment | `backend/services/enrichment.py` using ip-api.com | Confirm `ip_enrichments` rows contain country/city/lat/lng |
| HD_UC_10 | VirusTotal enrichment | Optional VT API support in enrichment and malware paths | Set `VIRUSTOTAL_API_KEY` and verify VT fields populate |
| HD_UC_11 | Configure alert rules | `/api/alert-rules`, configuration alert-rules panel | Create/update/disable/delete a rule |
| HD_UC_12 | Alert notification | Rule checks in `log_collector.py`, notifications service, dashboard/alerts UI | Trigger threshold and confirm high-severity notification appears |
| HD_UC_13 | Remediation suggestions | `/api/remediation`, `frontend/alerts.html` | Open alert remediation and verify playbook steps |
| HD_UC_14 | Persist telemetry | PostgreSQL models `events`, `sessions`, `ip_enrichments`, `malware_samples` | Query row counts after ingest |
| HD_UC_15 | Data retention | `/api/retention`, retention scheduler, configuration page | Update retention policy and run manual purge |

## Deployment Checks

- Keep `backend/.env` private and use `backend/.env.example` for fresh deployments.
- For remote friend honeypot data, send events to `/api/ingest/event` with `X-Sensor-Key` and `"sensor": "remote"`.
- For Google Cloud/VPS static frontend on `:8090`, `frontend/config.js` automatically points API calls to the same host on `:8000`.
- `mock-dionaea` reads `SENSOR_API_KEY` from `backend/.env`, so it must match the backend ingest key.

## Smoke Test Commands

```bash
python -m compileall backend
docker compose --profile dev up -d --build
curl http://localhost:8000/health
curl http://localhost:8000/api/public/stats
```

Authenticated endpoints require a token:

```bash
TOKEN=$(curl -s -X POST http://localhost:8000/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"admin@honeydash.local","password":"admin"}' \
  | python -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

curl -H "Authorization: Bearer $TOKEN" http://localhost:8000/api/dashboard/stats
curl -H "Authorization: Bearer $TOKEN" http://localhost:8000/api/alert-rules
curl -H "Authorization: Bearer $TOKEN" "http://localhost:8000/api/remediation?attack_type=SSH%20Brute%20Force"
```
