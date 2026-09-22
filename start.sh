#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# Keep the Mac awake for the lifetime of the demo (prevents idle standby, which
# would drop the Cloudflare tunnel + ngrok and take the public URLs down).
# -d display, -i idle, -m disk, -s on AC. Killed automatically when this script exits.
caffeinate -dims &
CAFFEINATE_PID=$!
echo "caffeinate PID: $CAFFEINATE_PID (Mac will not idle-sleep while demo runs)"
trap 'kill $CAFFEINATE_PID 2>/dev/null' EXIT

# Ollama — required locally on :11434 (direct attack path + exposed via ngrok for the gateway)
if ! curl -sf -o /dev/null http://localhost:11434/api/tags; then
  echo "Starting Ollama..."
  ollama serve > /tmp/ollama.log 2>&1 &
  OLLAMA_PID=$!
  echo "Ollama PID: $OLLAMA_PID"
  for i in $(seq 1 15); do curl -sf -o /dev/null http://localhost:11434/api/tags && break; sleep 1; done
else
  echo "Ollama already running"
fi
for m in dolphin-llama3:8b llama3.1:8b; do
  ollama list 2>/dev/null | grep -q "$m" || echo "WARNING: required model missing: $m (run: ollama pull $m)"
done

# ngrok — exposes local Ollama to Portkey's cloud so the Local+Portkey gateway route works.
# host-header=localhost because Ollama rejects non-local Host headers.
if ! curl -sf -o /dev/null http://127.0.0.1:4040/api/tunnels; then
  echo "Starting ngrok tunnel for Ollama..."
  ngrok http 11434 --url=https://kisser-droplet-snowflake.ngrok-free.dev --host-header=localhost --log=stdout > /tmp/ngrok.log 2>&1 &
  NGROK_PID=$!
  echo "ngrok PID: $NGROK_PID"
  for i in $(seq 1 15); do curl -sf -o /dev/null https://kisser-droplet-snowflake.ngrok-free.dev/api/version && break; sleep 1; done
else
  echo "ngrok already running"
fi

cd "$SCRIPT_DIR/backend"
source venv/bin/activate
python -m uvicorn main:app --host 127.0.0.1 --port 8000 --reload &
BACKEND_PID=$!
echo "Backend PID: $BACKEND_PID"

cd "$SCRIPT_DIR/frontend"
npm run dev &
FRONTEND_PID=$!
echo "Frontend PID: $FRONTEND_PID"

cloudflared tunnel run b724113c-73e8-4b79-81b5-fcbf50204547 &
TUNNEL_PID=$!
echo "Tunnel PID: $TUNNEL_PID"

echo "All services started. Backend: $BACKEND_PID, Frontend: $FRONTEND_PID, Tunnel: $TUNNEL_PID"

# Health check — wait for backend, then verify local + public endpoints
echo "Running health checks..."
for i in $(seq 1 30); do curl -sf -o /dev/null http://127.0.0.1:8000/health && break; sleep 1; done
check() { curl -sf -o /dev/null -w "  %-40s HTTP %{http_code}\n" "$1" || echo "  $1  FAILED"; }
check http://localhost:11434/api/tags
check https://kisser-droplet-snowflake.ngrok-free.dev/api/version
check http://127.0.0.1:8000/health
check http://localhost:5173/
check https://airs-demo.shekitout.uk/
check https://airs-api.shekitout.uk/health
echo "Health checks complete."

wait
