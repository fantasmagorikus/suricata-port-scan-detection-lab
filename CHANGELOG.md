# Changelog

All notable changes to this project will be documented in this file.

The format is based on Keep a Changelog, and this project adheres to
Semantic Versioning (SemVer).

## [Unreleased]
- Add MIT license file and refine troubleshooting with ES|QL examples
- Add more screenshots (Discover view, Top ports panel zoom)

## [1.0.0] - 2025-11-06
### Added
- Docker Compose stack: Elasticsearch 8.14.3, Kibana 8.14.3, Filebeat 8.14.3 (suricata module), Suricata 8.x, Juice Shop target
- Suricata local rules:
  - `9900001` LAB - TCP SYN (baseline)
  - `9901001` LAB - Port Scan (SYN threshold) with `detection_filter: by_src, count 20, seconds 60`
- Filebeat configuration (`filebeat/filebeat.yml`) with `strict.perms: false` and Kibana setup
- Kibana dashboard: “Port Scan Detection (Suricata)” with Lens panels
- Saved Objects export (NDJSON) under `kibana_exports/`
- Scripts:
  - `scripts/retomada_check.sh` — one-shot health checklist and log capture
  - `scripts/backup.sh` — ES snapshot + config archive + optional Suricata logs
  - `scripts/kibana_export_dashboard.sh` — export dashboard to NDJSON
  - `scripts/kibana_rename_dashboard.sh` — rename a dashboard by title
  - `scripts/capture_screenshots.sh` — headless Chrome screenshots of the dashboard
- Documentation:
  - English-first `README.md` + `README.pt-BR.md`
  - Screenshots embedded and stored in `docs/screenshots/`

### Changed
- Dashboard renamed from “SIEM LAB NOVO” to “Port Scan Detection (Suricata)”
- `.env` made explicit for single-host (`SURICATA_IFACE=lo`) and network modes

### Fixed
- Ensured Suricata loads local rules and captures on the intended interface

