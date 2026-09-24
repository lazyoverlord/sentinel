#!/usr/bin/env bash
# Start the API (owns models + state) and the Streamlit UI (thin client). Ctrl+C stops both.
set -euo pipefail
cd "$(dirname "$0")"
HOST="${BIND_HOST:-127.0.0.1}"
uv run uvicorn api.server:app --host "$HOST" --port 8000 &
API_PID=$!
trap 'kill $API_PID 2>/dev/null || true' EXIT INT TERM
echo "waiting for API (classifiers load on first start)..."
for i in $(seq 1 120); do curl -sf "http://$HOST:8000/health" >/dev/null && break; sleep 1; done
uv run streamlit run ui/app.py --server.address "$HOST" --server.headless true
