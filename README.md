# Solana Validator RPC Health

Small CLI for probing Solana validator-advertised RPC endpoints.

It reads `getClusterNodes`, filters nodes whose advertised `rpc` field ends with `:8899` by default, then checks common RPC methods and optionally probes `getMultipleAccounts` plus the same host's gRPC port, usually `:10000`.

## Features

- Discovers advertised validator RPC endpoints from any Solana RPC.
- Checks `getHealth`, `getVersion`, `getSlot`, `getBlockHeight`, `getLatestBlockhash`, and `getGenesisHash`.
- Optionally checks `getMultipleAccounts` for a supplied account pubkey, including 64-character hex input.
- Can probe all advertised RPC endpoints, not only `:8899`.
- Measures RPC latency and writes a CSV report.
- Probes gRPC TCP reachability on the same host and port.
- Optional h2c gRPC check through `curl --http2-prior-knowledge`, useful for seeing responses like `grpc-status=16 grpc-message=No valid auth token`.
- Scans a single authorized validator host across a port range and highlights ports that look like h2c gRPC.
- No Python package dependencies.

## Quick Start

Linux/macOS:

```bash
bin/probe.sh --cluster-rpc http://YOUR_RPC_HOST:8899 --grpc-h2c
```

Windows PowerShell:

```powershell
.\bin\probe.ps1 --cluster-rpc http://YOUR_RPC_HOST:8899 --grpc-h2c
```

Direct Python:

```bash
python3 bin/solana-validator-rpc-health.py --cluster-rpc https://api.mainnet-beta.solana.com
```

Scan one validator host for likely gRPC ports:

```bash
python3 bin/solana-validator-rpc-health.py --scan-host YOUR_VALIDATOR_HOST --port-range 1-10000
```

Scan and verify whether a Yellowstone/Solana gRPC endpoint is actually usable:

```bash
python3 bin/solana-validator-rpc-health.py --scan-host YOUR_VALIDATOR_HOST --port-range 1-10000 --grpc-token YOUR_TOKEN
```

## Registry (scan host + Cloudflare)

The scanner and the API are two separate things.

```text
82.23.138.51   runs the scan every 600s and publishes the snapshot
      ↓ push
Cloudflare     serves the console and the JSON endpoints to members
```

`bin/rpc_grpc_registry.py --no-serve` scans and pushes but binds no port — members
read the Cloudflare Worker, so the scan host publishes nothing itself. That also
matters on a box with no firewall, where any `0.0.0.0` listener is immediately
internet-facing. Stdlib only, no package dependencies.

```bash
python3 bin/rpc_grpc_registry.py --no-serve --interval 600   --push-race-seconds 10   --push-url https://solana-rpc-registry.lwhch888.workers.dev   --push-token-file /root/.cf-ingest-token
```

### Worker routes

All member routes are behind an account session or an API key.

| Route | Returns |
|---|---|
| `GET /` | HTML dashboard (overview, sign up, sign in, payment, console) |
| `GET /health` | freshness and pricing only — no scan internals |
| `GET /rpc?limit=10` | ranked usable JSON-RPC endpoints |
| `GET /grpc?limit=10` | ranked Yellowstone gRPC endpoints |
| `GET /all` | both lists plus detailed scan counters |
| `POST /ingest` | scanner publishes a snapshot (`INGEST_TOKEN`) |
| `POST /register` `/login` | account lifecycle |
| `POST /pay` | redeem an on-chain payment for the signed-in account |
| `POST /admin/accounts/activate` | grant access without payment (`ADMIN_TOKEN`) |

```bash
curl -H "Authorization: Bearer <session-or-key>"   https://solana-rpc-registry.lwhch888.workers.dev/grpc?limit=5
```

Each row carries the measurements needed to pick an endpoint: `latency_ms`,
`push_lag_ms`, `tcp_ms`, reported `version`, and `stream_messages`.

Filters applied so a row is only reported when it can actually be used:

- **RPC** — `getHealth` answers, `getLatestBlockhash` succeeds, and
  `getMultipleAccounts` returns the probe account. Endpoints that only serve
  `getHealth`/`getSlot` fall into `partial_endpoints` instead.
- **gRPC** — HTTP/2 preface accepted, `geyser.Geyser/GetVersion` returns a
  Yellowstone version, and an anonymous `geyser.Geyser/Subscribe` actually
  receives stream data. A server that answers `GetVersion` but refuses the
  stream is not counted, and endpoints requiring a token are dropped rather
  than listed.
- **Ordering** — ranked by `push_lag_ms` (server `createdAt` to local receive),
  with kernel-stamped `tcp_ms` as the tie-break.

Discovery sweeps the whole `getClusterNodes` address set, not just the nodes
that advertise an RPC port — most nodes advertise no RPC yet still run gRPC.

Other useful flags:

```text
--interval 600           Seconds between scans (default 600 = 10 min)
--no-serve               Scan and push without binding an HTTP port
--no-scan                Serve only the persisted snapshot
--once                   Run one scan, print it, exit
--push-url URL           Worker base URL to publish each snapshot to
--push-token-file PATH   File holding the INGEST_TOKEN (mode 600)
--grpc-ports 10000,...   Ports swept for gRPC
--grpc-proto-dir DIR     Directory holding geyser.proto
--push-race-seconds 10   Window for sampling push lag; 0 disables
--probe-account PUBKEY    Account used for the getMultipleAccounts check
--state-file PATH        Where the last snapshot is persisted
```

The last snapshot is persisted, so a restart publishes the previous results
immediately instead of starting empty.

## Handover

Read [docs/HANDOVER.md](docs/HANDOVER.md) before changing anything — it records
the architecture, where credentials live, the operational commands, and the
findings that are not obvious from the code. In particular it covers why this
scan cannot be moved to a Worker, and which mistakes have already been made
here once.

## Useful Options

```text
--cluster-rpc URL       RPC used for getClusterNodes
--rpc-suffix :8899      Advertised RPC suffix to filter
--all-advertised-rpc    Probe every advertised RPC endpoint instead of filtering by suffix
--get-multiple-accounts ACCOUNT
                         Probe getMultipleAccounts for this pubkey; 64-char hex is converted to base58
--account-encoding base64
                         Account encoding used for getMultipleAccounts
--timeout 2             Per-RPC request timeout in seconds
--parallel 48           Concurrent RPC probes
--print-first 50        Rows printed per section
--out-dir logs          Directory for CSV reports
--probe-grpc            Probe same host's gRPC TCP port, enabled by default
--grpc-port 10000       gRPC port to test
--grpc-h2c              Use curl HTTP/2 prior knowledge to inspect h2c gRPC response
--grpc-for-all          Probe gRPC even if RPC is not usable
--scan-host HOST        Scan one authorized validator host for open ports
--port-range 1-10000    Port range used with --scan-host
--scan-timeout 0.35     TCP timeout per scanned port
--scan-parallel 256     Concurrent workers for --scan-host
--test-solana-grpc      Call geyser.Geyser/GetVersion on likely gRPC ports, enabled by default
--grpc-token TOKEN      Token sent as x-token for Yellowstone gRPC
--grpc-token-header x-token
--grpc-transport auto   Use auto, plaintext, or tls for grpcurl
--grpcurl PATH          Path to grpcurl if it is not on PATH
--grpc-proto-dir DIR    Directory for Yellowstone proto files
--no-download-protos    Do not auto-download Yellowstone proto files
```

Environment variables are also supported:

```bash
CLUSTER_RPC=http://YOUR_RPC_HOST:8899 \
TIMEOUT_SECONDS=1.5 \
MAX_PARALLEL=64 \
GRPC_PORT=10000 \
bin/probe.sh --grpc-h2c
```

## Example Output

```json
{
  "totalNodes": 4357,
  "advertisedRpcSuffix": ":8899",
  "advertisedRpcCount": 202,
  "rpcUsable": 42,
  "rpcHealthy": 41,
  "grpcPort": 10000,
  "grpcTcpOpenAmongUsableRpc": 2,
  "rpcLatencyMs": {
    "min": 2,
    "p50": 205,
    "p95": 427,
    "max": 472
  }
}
```

Rows are also written to `logs/solana_validator_rpc_health_YYYYMMDD_HHMMSS.csv`.

## Notes

`getClusterNodes` includes many validators, but only a smaller subset advertises a public `rpc` address. A gRPC TCP port being open does not mean it is usable without authentication; many endpoints return a valid gRPC response such as `grpc-status=16` with `No valid auth token`.

When scanning a port range, `grpc-status=...` or `application/grpc` is the strongest signal. If local `curl` does not support HTTP/2, the scanner falls back to raw protocol checks. `http2-settings` means the port speaks cleartext HTTP/2 and `tls-http2` means TLS ALPN negotiated HTTP/2; both are likely gRPC candidates.

For Solana gRPC usability, the scanner uses `grpcurl` and Yellowstone proto files to call `geyser.Geyser/GetVersion` on likely gRPC ports. A row under `SOLANA_GRPC_USABLE` means the endpoint accepted the call. `auth-failed:...` means it appears to be Yellowstone/Solana gRPC, but the supplied token is missing or not accepted.
