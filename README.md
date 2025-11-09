# Port Scan Detection Lab — Suricata → Filebeat → Elasticsearch → Kibana

[![Docs (EN)](https://img.shields.io/badge/docs-EN-blue)](README.md)
[![Docs (pt‑BR)](https://img.shields.io/badge/docs-pt%E2%80%91BR-blue)](README.pt-BR.md)

Modern, reproducible lab to detect TCP SYN port scanning with Suricata, ship events via Filebeat to Elasticsearch, and visualize everything inside Kibana Lens. Includes local detection rules, Saved Objects export (NDJSON), health/backup/export/screenshot scripts, and bilingual docs.

> 🇧🇷 Leia este conteúdo em português: [README.pt-BR.md](README.pt-BR.md)

![Dashboard Overview](docs/screenshots/dashboard_overview.png)

## Contents

- [What I Built & Why](#what-i-built--why)
- [Architecture & Flow](#architecture--flow)
- [Design Decisions](#design-decisions)
- [Components and Versions](#components-and-versions)
- [Detection Rules (local)](#detection-rules-local)
- [Runbook (Setup → Health → Traffic → Teardown)](#runbook-setup--health--traffic--teardown)
- [Automation Scripts](#automation-scripts)
- [Traffic Generation (Nmap)](#traffic-generation-nmap)
- [Kibana Dashboard & KQL](#kibana-dashboard--kql)
- [Evidence & Screenshots](#evidence--screenshots)
- [Exports (NDJSON) & Reproducibility](#exports-ndjson--reproducibility)
- [Backup & Snapshots](#backup--snapshots)
- [Hardening & Ops Notes](#hardening--ops-notes)
- [Troubleshooting](#troubleshooting)
- [Project Layout](#project-layout)
- [Evidence & Screenshots (gallery)](#evidence--screenshots-gallery)
- [Results & Evidence](#results--evidence)
- [License, Conduct, Security](#license-conduct-security)
- [Acknowledgements](#acknowledgements)

## What I Built & Why
- Containerised Suricata → Filebeat → Elasticsearch → Kibana lab focused on TCP SYN scan detection. It complements the offensive [Pentest Lab](https://github.com/fantasmagorikus/pentest-lab) so you can showcase both sides of the story.
- Local Suricata rules: baseline SYN (sid 9900001) + threshold rule (sid 9901001) to flag Nmap sweeps.
- EVE JSON shipped via Filebeat Suricata module into ECS data streams, visualised with a curated Kibana dashboard.
- Operational scripts cover health checks, snapshots/backups, screenshot capture, and NDJSON exports for portability.
- `.env` toggles single-host (`lo`) and LAN interfaces; OWASP Juice Shop (3000/tcp) provides deterministic traffic.

Detect TCP SYN port scans, correlate them with Juice Shop traffic, and present the story in Kibana Lens. This mirrors the documentation style of the [Pentest Lab](https://github.com/fantasmagorikus/pentest-lab) to keep both repos uniform.

## Architecture & Flow

```
┌──────────────────────────────┐           ┌────────────────────────────┐
│ Suricata (EVE JSON)          │           │ Filebeat Suricata module   │
│ network_mode: host           │──────────▶│ ECS data streams / ES      │
│ Local rules 9900001 / 9901001│ alerts    └────────────┬────────────────┘
└─────────────┬────────────────┘                        │
              │ HTTP / ECS                              ▼
      ┌───────────────┐                          ┌───────────────┐
      │ Juice Shop    │◀───────────── traffic ──▶│ Kibana Lens   │
      └───────────────┘                          └───────────────┘
```

- Suricata: mature IDS that emits structured EVE JSON (alerts, flows, stats)
- Filebeat Suricata module: ECS mapping + data streams simplify ingestion
- Elasticsearch/Kibana: fast search, KQL, and Lens-based visualizations
- Local rules: tailored detections for SYN and scan thresholds to highlight Nmap activity

## Design Decisions

- Suricata + EVE JSON: mature IDS with structured output (alerts, flows, stats) that fits ELK ingestion well.
- Filebeat Suricata module: automatic ECS mapping and data streams reduce custom parsing/schema work.
- Host networking for Suricata: required to see host traffic on Linux; toggled via `.env` for single‑host (lo) or LAN (NIC).
- Local rules: baseline SYN + threshold rule produce clear scan signals without heavy rulepacks; easy to explain and reproduce.
- Kibana Lens + Saved Objects: fast iteration and portable visuals; NDJSON export attached to the release.
- Snapshots + backup scripts: preserve state and artifacts for repeatable demonstrations and audits.
- Headless screenshots: consistent portfolio evidence without manual capture steps.

## Components and Versions

- Suricata 8.x (container `jasonish/suricata:latest`)
- Filebeat 8.14.3 (container)
- Elasticsearch 8.14.3 (single node, security off for lab)
- Kibana 8.14.3
- OWASP Juice Shop (target app) on `:3000`

## Detection Rules (local)

Defined in `local-rules/local.rules`:

```
alert tcp any any -> $HOME_NET any (msg:"LAB - TCP SYN"; flags:S; flow:stateless; sid:9900001; rev:2;)
alert tcp any any -> $HOME_NET any (msg:"LAB - Port Scan (SYN threshold)"; flags:S; flow:stateless; detection_filter: track by_src, count 20, seconds 60; classtype:attempted-recon; sid:9901001; rev:1;)
```

- 9900001: baseline SYN detection
- 9901001: raises an alert when a source sends ≥20 SYNs within 60s (by_src)

## Runbook (Setup → Health → Traffic → Teardown)

Prereqs (Linux): Docker, Docker Compose, `curl`, `jq`, `nmap`.

```bash
cd homelab-security/suricata-elk-lab

# 1) Configure interface (single host = lo, LAN = your NIC)
cp .env.example .env
# edit SURICATA_IFACE if needed

# 2) Start the stack
docker compose up -d

# 3) Health check + log capture
bash scripts/retomada_check.sh

# 4) Generate traffic (single-host example)
sudo nmap -sS -p 1-10000 127.0.0.1 -T4 --reason

# 5) Explore dashboard
open http://localhost:5601

# 6) Tear down
docker compose down -v
```

Makefile shortcuts (single host):
`make up | make health | make nmap-local | make dashboard | make screenshots | make backup | make down`

## Automation Scripts

- `scripts/retomada_check.sh` — one-shot health checklist (services, logs, curl checks) with timestamped report.
- `scripts/backup.sh` — ES snapshot + Suricata logs + config tarball + next-steps checklist.
- `scripts/kibana_export_dashboard.sh` / `scripts/kibana_rename_dashboard.sh` — Saved Objects operations.
- `scripts/capture_screenshots.sh` — headless Chromium captures dashboard panels for docs/portfolio.
- `scripts/publish_github.sh` — mirrors repo to GitHub via `gh` CLI (SSH).

## Traffic Generation (Nmap)

- Single-host loopback:
  ```bash
  sudo nmap -sS -p 1-10000 127.0.0.1 -T4 --reason
  ```
- LAN demo (execute from attacker host):
  ```bash
  sudo nmap -sS -p 1-1000 <VICTIM_IP> -T4 --reason
  ```

## Kibana Dashboard & KQL

Open Kibana at `http://localhost:5601`.

- Create Data View (if prompted):
  - Name: `filebeat-*`
  - Time field: `@timestamp`

- Dashboard: “Port Scan Detection (Suricata)”
  - Alerts over time (stacked by signature)
  - Top source IPs (alerts)
  - Top destination ports (alerts)
  - Destination port ranges (well-known/registered/dynamic)
  - Alert details (saved search)

- Useful KQL filters:
```
event.module: "suricata" and suricata.eve.event_type: "flow"
event.module: "suricata" and suricata.eve.event_type: "alert"
suricata.eve.alert.signature_id: 9901001
```

## Evidence & Screenshots

- Kibana captures live under `docs/screenshots/` (PNG) and can be regenerated via `make screenshots`.
- `scripts/capture_screenshots.sh` stores raw PNGs in `docs/screenshots/` for README embedding and interviews.
- Combine with [Pentest Lab](https://github.com/fantasmagorikus/pentest-lab) evidence to tell the offensive + defensive story (e.g., Suricata alert screenshot mirrors ZAP findings).

## Exports (NDJSON) & Reproducibility

Saved Objects export is provided under `kibana_exports/` as NDJSON (newline-delimited JSON). Import it to recreate dashboard and related objects.

- Export (script):
```bash
bash scripts/kibana_export_dashboard.sh "Port Scan Detection (Suricata)"
```

- Import (UI): Kibana → Stack Management → Saved Objects → Import → select `.ndjson` and confirm.

## Backup & Snapshots

Create an Elasticsearch snapshot and archive lab configs with a single script:
```bash
bash scripts/backup.sh
```
Outputs under `backups/<timestamp>/` include snapshot response, Suricata logs (if available), and a tarball of key configs.

## Hardening & Ops Notes
- Suricata runs with `network_mode: host`; adjust `.env` carefully (no default NIC assumptions).
- Filebeat runs as root with `-strict.perms=false` to avoid permission spamming when mounting configs.
- Elasticsearch stack disables security for lab purposes—never expose to untrusted networks. Enable `xpack.security` if turning this into a long-lived SIEM.
- Store snapshots (`es-snapshots` volume) and backups (`backups/`) outside of ephemeral disks if running in the cloud.

## Troubleshooting

- No alerts after Nmap
  - Ensure the capture interface matches your scenario (`lo` for single-host, your NIC for LAN)
  - Confirm rules are loaded and Suricata is healthy (`docker logs suricata-lab-suricata`)
  - Increase scan intensity (e.g. `-p 1-10000`)

- No data in Kibana
  - Verify Filebeat config/output:
    - `docker exec suricata-lab-filebeat filebeat -e -strict.perms=false test config`
    - `docker exec suricata-lab-filebeat filebeat -e -strict.perms=false test output`
  - Check Elasticsearch/Kibana reachability (`curl` 9200/5601)

- Time alignment issues
  - In Kibana, set timezone to “Browser” and enlarge the time window

## Project Layout

- `docker-compose.yml` — containers and volumes
- `.env` — capture interface (`SURICATA_IFACE`)
- `suricata/suricata.yaml` — EVE JSON outputs (alerts, flows)
- `local-rules/local.rules` — lab detection rules (9900001 / 9901001)
- `filebeat/filebeat.yml` — module suricata → Elasticsearch
- `scripts/` — backup, health check, export/rename helpers
- `kibana_exports/` — saved objects export (.ndjson)
- `Makefile` — common tasks: `make up|down|health|backup|export|screenshots`

## Evidence & Screenshots (gallery)

Dashboard overview (last 15 minutes):

![Dashboard Overview](docs/screenshots/dashboard_overview.png)

Recent activity (last 5 minutes):

![Dashboard Last 5m](docs/screenshots/dashboard_overview_last5.png)

Alerts over time (stacked by signature):

![Alerts Over Time](docs/screenshots/alerts_over_time.png)

Top sources (alerts):

![Top Sources](docs/screenshots/top_sources.png)

Top destination ports (alerts):

![Top Ports](docs/screenshots/top_ports.png)

Top destination ports (close-up):

![Top Ports Close-up](docs/screenshots/top_ports_closeup.png)

Alert details (Discover):

![Discover Alerts](docs/screenshots/discover_alerts.png)

## Changelog

See CHANGELOG.md for versioned history and highlights.

## Results and Evidence

- Ingested flow events (last 10 min): 109
- Alerts (last 10 min): total 473
  - sid=9901001 (Port Scan threshold): 224
  - sid=9900001 (TCP SYN): 249
- Dashboard and Saved Objects export available in `kibana_exports/`

## License, Conduct, Security

- MIT License (LICENSE)
- Code of Conduct (CODE_OF_CONDUCT.md)
- Security policy and vulnerability reporting (SECURITY.md)

## Acknowledgements

- Suricata IDS, Elastic Beats, Elasticsearch, Kibana
- OWASP Juice Shop
