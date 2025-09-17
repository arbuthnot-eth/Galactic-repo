#!/usr/bin/env bash
set -euo pipefail

# Helper script to request Sui testnet faucet funds for the active address or a provided identifier.
# Usage:
#   npm run faucet                # Uses `sui client active-address`
#   npm run faucet addr 0xABC...  # Uses provided 0x-prefixed address
#   npm run faucet name your.sui  # Resolves SuiNS name before requesting
#   npm run faucet 0xABC...       # Positional address works
#   npm run faucet yourname       # Positional SuiNS name works (.sui optional)

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"

info() { echo "[faucet] $*"; }
err() { echo "[faucet][ERROR] $*" >&2; }

usage() {
  cat <<USAGE
Usage: npm run faucet [addr|name] [VALUE]

Without arguments, the script requests faucet funds for the active Sui CLI address.
Provide an address or SuiNS name either positionally or via the addr/name keywords.
When using a SuiNS name, the .sui suffix is optional.
USAGE
}

ensure_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    err "Missing dependency: $1"
    exit 1
  fi
}

ensure_cmd sui
ensure_cmd curl

normalize_address() {
  echo "$1" | tr '[:upper:]' '[:lower:]'
}

trim() {
  tr -d '\r' | tr -d '\n'
}

normalize_name() {
  local input="$1"
  if [[ "$input" == *.* ]]; then
    if [[ "$input" == *.sui ]]; then
      echo "$input"
    else
      echo "$input.sui"
    fi
  else
    echo "$input.sui"
  fi
}

resolve_suins_name() {
  local name="$1"
  local network_url="https://fullnode.testnet.sui.io:443"

  info "Resolving SuiNS name: $name via API" >&2

  local response
  if ! response=$(curl -s -X POST "$network_url" \
    -H "Content-Type: application/json" \
    -d '{
      "jsonrpc": "2.0",
      "id": 1,
      "method": "suix_resolveNameServiceAddress",
      "params": ["'"$name"'"]
    }' 2>/dev/null); then
    return 1
  fi

  # Extract result from JSON response using a simpler approach
  local address
  address=$(echo "$response" | sed -n 's/.*"result":"\([^"]*\)".*/\1/p')

  if [[ -z "$address" || "$address" == "null" ]]; then
    return 1
  fi

  echo "$address"
  return 0
}

determine_target() {
  local mode="$1"
  local value="$2"

  if [[ "$mode" == "addr" ]]; then
    if [[ ! "$value" =~ ^0x[0-9a-fA-F]{40,}$ ]]; then
      err "Invalid Sui address: $value"
      exit 1
    fi
    normalize_address "$value"
    return
  fi

  if [[ "$mode" == "name" ]]; then
    local name=$(normalize_name "$value")
    local resolved
    if ! resolved=$(resolve_suins_name "$name"); then
      err "Failed to resolve SuiNS name: $name"
      exit 1
    fi
    if [[ ! "$resolved" =~ ^0x[0-9a-fA-F]{40,}$ ]]; then
      err "Resolver returned unexpected value: $resolved"
      exit 1
    fi
    normalize_address "$resolved"
    return
  fi

  # Auto-detect positional value
  if [[ "$mode" =~ ^0x[0-9a-fA-F]{40,}$ ]]; then
    normalize_address "$mode"
    return
  fi

  local name=$(normalize_name "$mode")
  local resolved
  if ! resolved=$(resolve_suins_name "$name"); then
    err "Failed to resolve SuiNS name: $name"
    exit 1
  fi
  if [[ ! "$resolved" =~ ^0x[0-9a-fA-F]{40,}$ ]]; then
    err "Resolver returned unexpected value: $resolved"
    exit 1
  fi
  normalize_address "$resolved"
}

# Parse arguments
case $# in
  0)
    info "Using active Sui CLI address"
    ADDRESS=$(sui client active-address | trim)
    ;;
  1)
    if [[ "$1" == "-h" || "$1" == "--help" ]]; then
      usage
      exit 0
    fi
    ADDRESS=$(determine_target "$1" "")
    ;;
  2)
    ADDRESS=$(determine_target "$1" "$2")
    ;;
  *)
    err "Too many arguments"
    usage
    exit 1
    ;;
esac

info "Requesting faucet funds for $ADDRESS"

# Try the web faucet API first
info "Trying web faucet API..."
set +e
FAUCET_RESPONSE=$(curl -s -X POST "https://faucet.testnet.sui.io/v2/gas" \
  -H "Content-Type: application/json" \
  -d "{\"FixedAmountRequest\":{\"recipient\":\"$ADDRESS\"}}" 2>/dev/null)
CURL_STATUS=$?
set -e

if [[ $CURL_STATUS -eq 0 && ! "$FAUCET_RESPONSE" =~ "Too Many Requests" && ! "$FAUCET_RESPONSE" =~ "error" ]]; then
  info "✅ Faucet request submitted via web API"
  echo "Response: $FAUCET_RESPONSE"
else
  info "Web faucet API failed or rate limited. Trying CLI faucet..."

  # Fallback to CLI faucet
  set +e
  FAUCET_OUTPUT=$(sui client faucet --address "$ADDRESS" 2>&1)
  CLI_STATUS=$?
  set -e

  echo "$FAUCET_OUTPUT"

  if [[ $CLI_STATUS -ne 0 ]]; then
    info "All automated faucets failed. Here are your options:"
    info ""
    info "🔥 RECOMMENDED - Discord Faucet (Most Reliable):"
    info "   1. Join: https://discord.com/invite/sui"
    info "   2. Go to #testnet-faucet channel"
    info "   3. Send: !faucet $ADDRESS"
    info ""
    info "🌐 Alternative Web Faucets:"
    info "   • Official: https://faucet.sui.io/?address=$ADDRESS"
    info "   • Stakely: https://stakely.io/faucet/sui-testnet-sui"
    info "   • BlockBolt: https://faucet.blockbolt.io"
    info ""
    exit 1
  else
    info "✅ Faucet request submitted via CLI"
  fi
fi
