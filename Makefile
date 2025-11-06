.PHONY: up down restart health nmap-local export backup screenshots

up:
	docker compose up -d

down:
	docker compose down

restart:
	docker compose up -d --force-recreate --no-deps suricata

health:
	bash scripts/retomada_check.sh

nmap-local:
	sudo nmap -sS -p 1-10000 127.0.0.1 -T4 --reason

export:
	bash scripts/kibana_export_dashboard.sh "Port Scan Detection (Suricata)"

backup:
	bash scripts/backup.sh

screenshots:
	bash scripts/capture_screenshots.sh

