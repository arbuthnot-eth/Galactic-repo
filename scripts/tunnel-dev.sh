#!/usr/bin/env bash
set -euo pipefail

# vWallet dev helper: starts Cloudflare Tunnel (if needed) and Vite dev server.
# Usage:
#   CLOUDFLARE_TUNNEL_TOKEN=... npm run tunnel-dev
#
# Behavior:
# - If systemd cloudflared service is active, uses it.
# - Else, if CLOUDFLARE_TUNNEL_TOKEN is set, runs a connector in the background.
# - Then runs `npm run dev` in the foreground.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"

info() { echo -e "[tunnel-dev] $*"; }
err() { echo -e "[tunnel-dev][ERROR] $*" >&2; }

# Auto-load environment variables from .env files in repo root
for ENV_FILE in "$REPO_ROOT/.env" "$REPO_ROOT/.env.local"; do
  if [ -f "$ENV_FILE" ]; then
    info "Loading env from $(basename "$ENV_FILE")"
    set -a
    # shellcheck disable=SC1090
    source "$ENV_FILE"
    set +a
  fi
done

ensure_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    err "Missing dependency: $1"
    exit 1
  fi
}

ensure_cmd npm
ensure_cmd cloudflared

CF_BG_PID=""
VITE_PID=""

# Always ensure no previous cloudflared is running so we attach to the right tunnel
if command -v systemctl >/dev/null 2>&1; then
  if systemctl is-active --quiet cloudflared; then
    info "Stopping systemd service: cloudflared"
    # Try non-interactive sudo; if it fails, print a hint but continue to kill processes
    if sudo -n systemctl stop cloudflared >/dev/null 2>&1; then
      info "Stopped cloudflared service"
    else
      err "Could not stop cloudflared service without sudo password. If it restarts, run: sudo systemctl stop cloudflared"
    fi
  fi
fi

if pgrep -x cloudflared >/dev/null 2>&1; then
  info "Killing existing cloudflared processes"
  pkill -x cloudflared || true
  # Wait up to 5s for processes to exit
  for i in 1 2 3 4 5; do
    if pgrep -x cloudflared >/dev/null 2>&1; then
      sleep 1
    else
      break
    fi
  done
fi

cleanup() {
  info "🧹 Cleaning up processes..."
  
  # Kill Vite process
  if [ -n "$VITE_PID" ] && kill -0 "$VITE_PID" >/dev/null 2>&1; then
    info "Stopping Vite dev server (pid $VITE_PID)"
    kill "$VITE_PID" 2>/dev/null || true
    wait "$VITE_PID" 2>/dev/null || true
  fi
  
  # Kill any remaining processes on port 5173
  if command -v lsof >/dev/null 2>&1 && lsof -ti:5173 >/dev/null 2>&1; then
    info "Killing processes on port 5173"
    kill -9 $(lsof -ti:5173) 2>/dev/null || true
  fi
  
  # Kill cloudflared process
  if [ -n "$CF_BG_PID" ] && kill -0 "$CF_BG_PID" >/dev/null 2>&1; then
    info "Stopping background cloudflared (pid $CF_BG_PID)"
    kill "$CF_BG_PID" 2>/dev/null || true
    wait "$CF_BG_PID" 2>/dev/null || true
  fi
  
  # Final cleanup of any remaining cloudflared processes
  if pgrep -x cloudflared >/dev/null 2>&1; then
    info "Killing any remaining cloudflared processes"
    pkill -x cloudflared 2>/dev/null || true
  fi
  
  info "✅ Cleanup complete"
}
trap cleanup EXIT INT TERM

if [ -z "${CLOUDFLARE_TUNNEL_TOKEN:-}" ]; then
  err "CLOUDFLARE_TUNNEL_TOKEN is not set. Add it to .env or export it."
  exit 1
fi
info "Starting Cloudflare tunnel (quiet mode)..."
# Run cloudflared quietly in background, only showing errors
cloudflared tunnel run --token "$CLOUDFLARE_TUNNEL_TOKEN" >/dev/null 2>&1 &
CF_BG_PID=$!
sleep 2
if ! kill -0 "$CF_BG_PID" >/dev/null 2>&1; then
  err "Cloudflare tunnel failed to start. Check your token."
  # Show last few lines of error output
  echo "Recent cloudflared errors:"
  cloudflared tunnel run --token "$CLOUDFLARE_TUNNEL_TOKEN" 2>&1 | tail -5
  exit 1
fi

# Show the public URL where the app will be available through Cloudflare
PUBLIC_HOSTNAME="${VWALLET_PUBLIC_HOSTNAME:-${PUBLIC_HOSTNAME:-dev.vwallet.red}}"
PUBLIC_PATH="${VWALLET_PUBLIC_PATH:-/}"
PUBLIC_URL="https://$PUBLIC_HOSTNAME"
info "Cloudflare public URL: $PUBLIC_URL"

# Auto-open browser when ready
auto_open() {
  local vv_url="$PUBLIC_URL"
  local sw_url="$PUBLIC_URL/src/smartwallet-dev.html"
  local open_sw="${VWALLET_OPEN_SMARTWALLET:-true}"
  # Normalize boolean-like values
  case "${open_sw,,}" in
    false|0|no) open_sw=false ;;
    *) open_sw=true ;;
  esac
  # Quick wait for Vite
  sleep 1.5

  # Open browser quietly (Linux first, macOS fallback)
  if command -v xdg-open >/dev/null 2>&1; then
    xdg-open "$vv_url" >/dev/null 2>&1 &
    if [ "$open_sw" = true ]; then
      # Open SmartWallet after a brief delay so vWallet gets focus
      sleep 0.75
      xdg-open "$sw_url" >/dev/null 2>&1 &
    fi
  elif command -v open >/dev/null 2>&1; then
    open "$vv_url" >/dev/null 2>&1 &
    if [ "$open_sw" = true ]; then
      # Open SmartWallet after a brief delay so vWallet gets focus
      sleep 0.75
      open "$sw_url" >/dev/null 2>&1 &
    fi
  fi
}

auto_open &

# Clean up any existing Vite processes on port 5173
if command -v lsof >/dev/null 2>&1 && lsof -ti:5173 >/dev/null 2>&1; then
  info "🧹 Cleaning up existing Vite process on port 5173..."
  kill -9 $(lsof -ti:5173) 2>/dev/null || true
  sleep 1
elif command -v netstat >/dev/null 2>&1 && netstat -tlnp 2>/dev/null | grep -q ":5173 "; then
  info "🧹 Cleaning up existing process on port 5173..."
  # Try to find and kill process using netstat
  pkill -f "vite.*5173" 2>/dev/null || true
  sleep 1
fi

# Start Vite with minimal output
info "🚀 Starting Vite dev server..."
npm run dev &
VITE_PID=$!
sleep 2

# Check if Vite started successfully
if ! kill -0 "$VITE_PID" >/dev/null 2>&1; then
  err "Vite dev server failed to start"
  exit 1
fi

# Show final clean summary
echo ""
echo "╔════════════════════════════════════════════════════════════╗"
echo "║                      🍷vWallet Ready!                      "
echo "╠════════════════════════════════════════════════════════════╝"
echo "║ 🌐 Tunnel URLs:"
echo "║       - $PUBLIC_URL"
echo "║       - $PUBLIC_URL/src/smartwallet-dev.html"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""
info "Press Ctrl+C to stop both servers..."

# Wait for either process to exit
wait
