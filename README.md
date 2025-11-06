# Port Scan Detection Lab — Suricata → Filebeat → Elasticsearch → Kibana

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Release](https://img.shields.io/github/v/release/fantasmagorikus/suricata-port-scan-detection-lab)](https://github.com/fantasmagorikus/suricata-port-scan-detection-lab/releases)
[![Docs](https://img.shields.io/badge/docs-README-blue)](README.md)

What I built
- A containerized detection lab that identifies TCP SYN port scanning and visualizes results in Kibana.
- Suricata rule engineering: baseline SYN (sid 9900001) and a scan-threshold rule (sid 9901001) with detection_filter.
- EVE → ECS pipeline using Filebeat’s Suricata module, landing in Elasticsearch data streams.
- A Kibana dashboard (“Port Scan Detection (Suricata)”) with Lens panels (alerts over time, top sources/ports, port ranges, details).
- Operational scripts for health checks, reproducible exports (NDJSON), snapshots/backups, and headless screenshot capture.
- Single-host and network modes via `.env` (`SURICATA_IFACE=lo` or your NIC).

Detect TCP SYN port scans and visualize them with Kibana Lens. This lab uses Suricata to generate EVE JSON, Filebeat (suricata module) to ship data into Elasticsearch, and a Kibana dashboard to analyze and present results. An OWASP Juice Shop service is included as a convenient target on port 3000.

## Architecture and Rationale

```mermaid
flowchart LR
  A[Suricata (EVE.json)] -->|Filebeat Suricata module| B[Elasticsearch]
  B --> C[Kibana]
  A <--> D[Local Rules\n9900001 / 9901001]
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

## Setup and Health Checks

Prerequisites: Linux with Docker + Docker Compose, `curl`, `jq`, and `nmap` for traffic generation.

1) Change into the lab directory
```
cd homelab-security/suricata-elk-lab
```

2) Prepare environment
- Copy the example env and adjust interface if needed:
```
cp .env.example .env
# default is SURICATA_IFACE=lo (single-host). For LAN, set SURICATA_IFACE to your NIC (e.g. wlp3s0)
```

3) Start the stack
```
docker compose up -d
```

4) Run the one-shot health check (prints and logs results)
```
bash scripts/retomada_check.sh
```
Artifacts are saved as `retomada_check-YYYY-MM-DD-HHMMSS.txt` and symlinked to `retomada_check-latest.txt`.

## Demo TL;DR (single host)

```
git clone <this repo>
cd suricata-port-scan-detection-lab/homelab-security/suricata-elk-lab
cp .env.example .env
docker compose up -d
bash scripts/retomada_check.sh
sudo nmap -sS -p 1-10000 127.0.0.1 -T4 --reason
open http://localhost:5601 (Dashboard: "Port Scan Detection (Suricata)")
```

## Traffic Generation (Nmap)

- Single-host demo (loopback):
```
sudo nmap -sS -p 1-10000 127.0.0.1 -T4 --reason
```

- Network demo (from another host on the LAN, scanning this machine):
```
sudo nmap -sS -p 1-1000 <VICTIM_IP> -T4 --reason
```

## Kibana Dashboard and KQL

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

## Exports (NDJSON) and Reproducibility

Saved Objects export is provided under `kibana_exports/` as NDJSON (newline-delimited JSON). Import it to recreate dashboard and related objects.

- Export (script):
```
bash scripts/kibana_export_dashboard.sh "Port Scan Detection (Suricata)"
```

- Import (UI): Kibana → Stack Management → Saved Objects → Import → select `.ndjson` and confirm.

## Backup and Snapshots

Create an Elasticsearch snapshot and archive lab configs with a single script:
```
bash scripts/backup.sh
```
Outputs under `backups/<timestamp>/` include snapshot response, Suricata logs (if available), and a tarball of key configs.

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

## Screenshots

Dashboard overview (last 15 minutes):

![Dashboard Overview](docs/screenshots/dashboard_overview.png)

Recent activity (last 5 minutes):

![Dashboard Last 5m](docs/screenshots/dashboard_overview_last5.png)

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
