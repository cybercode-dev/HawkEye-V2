# HawkEye v2 — Mini SIEM Platform

A Linux authentication log analyzer upgraded into a working mini-SIEM: streaming
multi-format log parsing, rule-based attack detection, alert correlation, MITRE
ATT&CK mapping, IOC extraction, incident-response playbooks, PDF/CSV/HTML
reporting, scan history, and a context-aware AI security assistant.

## Setup
```bash
pip install -r requirements.txt
python app.py
```
Open http://127.0.0.1:5000

Optional: set `ANTHROPIC_API_KEY` in your environment to upgrade the AI
Assistant from rule-based answers to free-form LLM answers (it works fully
without this — see Module 7 below).

## Pages
- `/` — Upload & analyze (.log, .txt, .csv, .json, .gz)
- `/history` — Scan history (persisted to SQLite)
- `/mitre` — MITRE ATT&CK Explorer
- `/assistant` — AI Security Assistant chat
- `/settings` — Live configuration view

## Module map

| Module | File(s) | What it does |
|---|---|---|
| 1. Smart Log Processing | `parser.py`, `utils.py` | Streaming (never `file.read()`-the-whole-thing) parser for `.log/.txt/.csv/.json/.gz`, auto-detects format, extracts timestamp/user/IP/event type/result/hostname/process |
| 2. Detection Engine | `detector.py` | 10 rule-based detectors, each with severity/confidence/risk score/evidence |
| 3. Correlation Engine | `correlation.py` | Chains related alerts (same IP/username, time-windowed) into escalated incidents |
| 4. MITRE ATT&CK Mapping | `mitre.py` | Every detection rule mapped to a real technique ID/tactic/description/reference |
| 5. IOC Extraction | `ioc.py` | Source IPs, usernames, hostnames, processes — with attempt counts and first/last seen |
| 6. Incident Response | `incident_response.py` | Description, root cause, business impact, real Linux mitigation commands, recovery steps, prevention, and recommended controls per rule |
| 7. AI Security Assistant | `ai_assistant.py` | Context-grounded Q&A (rule-based, always works) + optional Claude API enhancement |
| 8. Dashboard | `templates/result.html`, `templates/history.html` | Threat score, risk level, alerts, incidents, IOC table, charts |
| 9. Report Generation | `reports.py`, `report_generator.py` | PDF (ReportLab) + CSV + HTML reports, all including MITRE/IOC/recommendations |
| 10. Database | `history.py`, `database.py` | SQLite scan history: filename, alerts, incidents, MITRE results, threat score, report paths |
| 11. Project structure | (all of the above) | Modular file layout per the target structure |
| 12. UI | all templates, `static/css/style.css` | Dark SOC theme, responsive, new pages (MITRE Explorer, AI Assistant, Settings) |

## Backward compatibility
- `.log`/`.txt` uploads still use the original, tested `analyzer.py` regex
  path for the summary numbers (failed/success/threat score/etc.) — those
  numbers are unchanged from the original HawkEye.
- `.csv`/`.json`/`.gz` uploads (new formats) get the same summary shape via
  `engine.summary_from_events()`, computed from the new parser's normalized
  events, so every format gets the exact same dashboard.
- All original routes, download links, and history behavior still work.

## Known limitations (documented, not hidden)
- Uploaded file bytes are still buffered in memory (`file.read()` in
  `app.py`) before being handed to the streaming parser — the *parser*
  itself never materializes the whole file as one string, but true
  constant-memory handling of multi-GB uploads would need to stream
  directly from Werkzeug's temp file on disk. Fine for the 20 MB cap
  currently configured; raise `MAX_CONTENT_LENGTH` and switch to
  disk-backed streaming if you need bigger files.
- Geolocation (`geolocation.py`, used for the IOC/top-IP location columns)
  calls the free `ip-api.com` batch endpoint over plain HTTP with a 45
  req/min limit and no key — fine for demo/personal use, swap in a paid
  provider for production volume.
- The AI Assistant's rule-based tier is intent-pattern matching over a
  fixed set of question types (explain alert / why high risk / explain
  MITRE / how to fix / how to prevent / explain IP), not a general chatbot.
  It's honest and grounded rather than fluent — set `ANTHROPIC_API_KEY` for
  more natural free-form answers over the same real data.

## Testing performed
Every module was tested standalone as it was built, and a full 24-check
regression suite was run against the final integrated app via Flask's test
client, covering: all 5 file formats, PDF/CSV/HTML report generation,
alert/incident/IOC rendering, MITRE mapping, incident-response playbooks,
error handling (bad extension/empty/garbage file), scan history persistence
+ archived-report reconstruction after an in-memory "restart", and all new
pages (assistant/mitre/settings). All 24 checks passed.

To re-run a quick smoke test yourself:
```bash
python3 -c "
import app as hawkeye_app
client = hawkeye_app.app.test_client()
print(client.get('/').status_code)          # 200
print(client.get('/mitre').status_code)     # 200
print(client.get('/assistant').status_code) # 200
print(client.get('/settings').status_code)  # 200
"
```
