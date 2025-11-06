#!/usr/bin/env bash
set -euo pipefail

# One-shot backup for SOC/SIEM lab (excludes Kibana Saved Objects export)
# - Copies Suricata logs from container (if running)
# - Creates Elasticsearch snapshot (registers repo if missing)
# - Archives the whole lab directory (excluding backups)

LAB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TS="$(date +%F-%H%M%S)"
OUT_DIR="$LAB_DIR/backups/$TS"
mkdir -p "$OUT_DIR"

echo "[1/5] docker compose ps > $OUT_DIR/compose-ps.txt"
(
  cd "$LAB_DIR"
  docker compose ps || true
) > "$OUT_DIR/compose-ps.txt" 2>&1 || true

echo "[2/5] Copy Suricata logs to $OUT_DIR/suricata-logs (if container exists)"
if docker ps -a --format '{{.Names}}' | grep -q '^suricata-lab-suricata$'; then
  docker cp suricata-lab-suricata:/var/log/suricata "$OUT_DIR/suricata-logs" >/dev/null 2>&1 || true
else
  echo "suricata-lab-suricata container not found; skipping logs" > "$OUT_DIR/suricata-logs.skipped"
fi

echo "[3/5] Elasticsearch snapshot (lab_repo)"
SNAP="snap-$TS"
if curl -sSf http://localhost:9200 >/dev/null 2>&1; then
  # Register repo if missing
  curl -sS -X PUT 'http://localhost:9200/_snapshot/lab_repo' \
       -H 'Content-Type: application/json' \
       -d '{"type":"fs","settings":{"location":"/usr/share/elasticsearch/snapshots"}}' \
       >/dev/null 2>&1 || true
  # Create snapshot and wait for completion
  curl -sS -X PUT "http://localhost:9200/_snapshot/lab_repo/$SNAP?wait_for_completion=true" \
       > "$OUT_DIR/es-snapshot-$SNAP.json" 2>&1 || echo "SNAPSHOT_FAILED" > "$OUT_DIR/es-snapshot-$SNAP.failed"
else
  echo "Elasticsearch not reachable on localhost:9200" > "$OUT_DIR/es-snapshot.skipped"
fi

echo "[4/5] Archive selected lab files to $OUT_DIR/lab-config-$TS.tgz"
STAGE_DIR="$OUT_DIR/lab-config"
mkdir -p "$STAGE_DIR"

# Copy only the needed project files (avoid unreadable defaults under suricata/)
cp -a "$LAB_DIR/docker-compose.yml" "$STAGE_DIR/" || true
[ -f "$LAB_DIR/.env" ] && cp -a "$LAB_DIR/.env" "$STAGE_DIR/" || true
[ -f "$LAB_DIR/agent.md" ] && echo "(skipping legacy agent.md)" >/dev/null || true
[ -f "$LAB_DIR/README.md" ] && cp -a "$LAB_DIR/README.md" "$STAGE_DIR/" || true
[ -d "$LAB_DIR/scripts" ] && cp -a "$LAB_DIR/scripts" "$STAGE_DIR/" || true
mkdir -p "$STAGE_DIR/filebeat" "$STAGE_DIR/local-rules" "$STAGE_DIR/suricata"
[ -f "$LAB_DIR/filebeat/filebeat.yml" ] && cp -a "$LAB_DIR/filebeat/filebeat.yml" "$STAGE_DIR/filebeat/" || true
[ -f "$LAB_DIR/local-rules/local.rules" ] && cp -a "$LAB_DIR/local-rules/local.rules" "$STAGE_DIR/local-rules/" || true
[ -f "$LAB_DIR/suricata/suricata.yaml" ] && cp -a "$LAB_DIR/suricata/suricata.yaml" "$STAGE_DIR/suricata/" || true

tar -C "$OUT_DIR" -czf "$OUT_DIR/lab-config-$TS.tgz" "$(basename "$STAGE_DIR")"

echo "[5/5] Write manifest"
cat > "$OUT_DIR/manifest.txt" <<EOF
Timestamp: $TS
Lab dir: $LAB_DIR
Compose ps: $OUT_DIR/compose-ps.txt
Suricata logs: $OUT_DIR/suricata-logs (if present)
ES snapshot repo: lab_repo
ES snapshot name: $SNAP (if created)
Lab archive: $OUT_DIR/lab-config-$TS.tgz
EOF

echo "Backup completed at: $OUT_DIR"
