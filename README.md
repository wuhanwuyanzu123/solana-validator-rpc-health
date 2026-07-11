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
