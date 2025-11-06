#!/usr/bin/env bash
set -euo pipefail

# Capture Kibana screenshots via headless Chrome with robust waits and data checks.
# Requires: google-chrome (headless) and a running stack.

LAB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="$LAB_DIR/docs/screenshots"
mkdir -p "$OUT_DIR"

DASH_ID="9f4b2337-ab9c-4229-a5c7-ae72c82bbfbf"  # Port Scan Detection (Suricata)
BASE_URL="http://localhost:5601/app/dashboards#/view/$DASH_ID"

# Saved objects (from export NDJSON)
LENS_TOP_SOURCES_ID="5616f594-2e9b-475e-a9dd-b86556c09599"
DISCOVER_ALERTS_ID="4327c594-332b-4c48-a098-3c1dfd6fabc6"

CHROME_BIN="${CHROME_BIN:-google-chrome}"
CHROME_ARGS=(
  --headless=new
  --disable-gpu
  --no-sandbox
  --disable-dev-shm-usage
  --hide-scrollbars
  --window-size=1920,1080
  --force-device-scale-factor=1.25
  --enable-features=NetworkService,NetworkServiceInProcess
  --no-first-run
  --no-default-browser-check
  --virtual-time-budget=60000
)

echo "Using Chrome: $CHROME_BIN"

ensure_alerts() {
  local tries=6
  local wait=5
  for i in $(seq 1 $tries); do
    local cnt
    cnt=$(curl -s --max-time 5 'http://localhost:9200/.ds-filebeat-*/_count' \
      -H 'Content-Type: application/json' \
      -d '{"query":{"bool":{"filter":[{"term":{"event.module":"suricata"}},{"term":{"suricata.eve.event_type":"alert"}},{"range":{"@timestamp":{"gte":"now-1h"}}}]}}}' | jq -r '.count' 2>/dev/null || echo 0)
    if [ "${cnt:-0}" -gt 0 ]; then
      echo "[ok] Alerts present in last 1h: $cnt"
      return 0
    fi
    echo "[wait] No alerts yet (try $i/$tries). Generate traffic (nmap) and retrying in ${wait}s..."
    sleep "$wait"
  done
  echo "[warn] Proceeding without positive alert count; screenshots may be empty."
}

capture() {
  local url="$1" out="$2" label="$3"
  echo "[*] Warm-up load for $label"
  "$CHROME_BIN" "${CHROME_ARGS[@]}" "$url" >/dev/null 2>&1 || true
  sleep 3
  echo "[+] Capturing: $out"
  "$CHROME_BIN" "${CHROME_ARGS[@]}" --screenshot="$out" "$url" >/dev/null 2>&1 || {
    echo "Failed to capture $out"; return 1;
  }
}

capture_viewport() {
  local url="$1" out="$2" label="$3" width="$4" height="$5"
  echo "[*] Warm-up (viewport) for $label"
  "$CHROME_BIN" "${CHROME_ARGS[@]}" --window-size="${width},${height}" "$url" >/dev/null 2>&1 || true
  sleep 2
  echo "[+] Capturing viewport ${width}x${height}: $out"
  "$CHROME_BIN" "${CHROME_ARGS[@]}" --window-size="${width},${height}" --screenshot="$out" "$url" >/dev/null 2>&1 || {
    echo "Failed to capture $out"; return 1;
  }
}

ensure_alerts

# 1) Dashboard overview (last 1 hour)
URL1="$BASE_URL?_g=(time:(from:now-1h,to:now))&kiosk=true&embed=true"
OUT1="$OUT_DIR/dashboard_overview.png"
capture "$URL1" "$OUT1" "last 1h overview"

# 2) Dashboard overview (last 10 minutes)
URL2="$BASE_URL?_g=(time:(from:now-10m,to:now))&kiosk=true&embed=true"
OUT2="$OUT_DIR/dashboard_overview_last5.png"
capture "$URL2" "$OUT2" "last 10m overview"

# 3) Lens: Top source IPs (alerts)
URL3="http://localhost:5601/app/lens#/edit/${LENS_TOP_SOURCES_ID}?embed=true&kiosk=true&_g=(time:(from:now-1h,to:now))"
OUT3="$OUT_DIR/top_sources.png"
capture "$URL3" "$OUT3" "Top source IPs (alerts)"

# 4) Discover: Alert details saved search
URL4="http://localhost:5601/app/discover#/view/${DISCOVER_ALERTS_ID}?embed=true&kiosk=true&_g=(time:(from:now-1h,to:now))"
OUT4="$OUT_DIR/discover_alerts.png"
capture "$URL4" "$OUT4" "Discover alert details"

# 5) Alerts over time close-up (viewport tuned to show top-left panel)
OUT5="$OUT_DIR/alerts_over_time.png"
capture_viewport "$URL2" "$OUT5" "Alerts over time close-up" 1024 640

echo "Done. Screenshots saved under $OUT_DIR"
