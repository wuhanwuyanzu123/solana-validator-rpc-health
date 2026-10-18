#!/usr/bin/env bash
# Mint a registry API key manually — no on-chain payment needed.
#
# Use this when the member paid you out of band, or while PAY_TO is unset.
#
#   ./mint_key.sh alice 30
#   ./mint_key.sh bob 90
#   ./mint_key.sh            # 30 days, label "manual"
set -euo pipefail

URL="${REGISTRY_URL:-https://solana-rpc-registry.lwhch888.workers.dev}"
TOKEN_FILE="${REGISTRY_ADMIN_FILE:-/root/.cf-admin-token}"

LABEL="${1:-manual}"
DAYS="${2:-30}"

if [ ! -s "$TOKEN_FILE" ]; then
  echo "admin token not found at $TOKEN_FILE" >&2
  echo "set REGISTRY_ADMIN_FILE=<path> or create it with the ADMIN_TOKEN" >&2
  exit 2
fi

ADMIN=$(cat "$TOKEN_FILE")
RESP=$(curl -sS -m 30 -X POST \
  -H "Authorization: Bearer ${ADMIN}" \
  -H "Content-Type: application/json" \
  --data "{\"label\":\"${LABEL}\",\"days\":${DAYS}}" \
  "${URL}/admin/keys")

KEY=$(printf '%s' "$RESP" | python3 -c 'import sys,json; print(json.load(sys.stdin).get("key",""))' 2>/dev/null || true)

if [ -z "$KEY" ]; then
  echo "failed to mint key:" >&2
  printf '%s\n' "$RESP" >&2
  exit 1
fi

echo "label: ${LABEL}"
echo "days:  ${DAYS}"
echo "key:   ${KEY}"
echo
echo "把这个 key 给会员，网页登录或调接口时用:"
echo "  Authorization: Bearer ${KEY}"
