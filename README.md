# Solana Validator RPC Health

Small CLI for probing Solana validator-advertised RPC endpoints.

It reads `getClusterNodes`, filters nodes whose advertised `rpc` field ends with `:8899`, then checks common RPC methods and optionally probes the same host's gRPC port, usually `:10000`.

## Features

- Discovers advertised validator RPC endpoints from any Solana RPC.
- Checks `getHealth`, `getVersion`, `getSlot`, `getBlockHeight`, `getLatestBlockhash`, and `getGenesisHash`.
- Measures RPC latency and writes a CSV report.
- Probes gRPC TCP reachability on the same host and port.
- Optional h2c gRPC check through `curl --http2-prior-knowledge`, useful for seeing responses like `grpc-status=16 grpc-message=No valid auth token`.
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

## Useful Options

```text
--cluster-rpc URL       RPC used for getClusterNodes
--rpc-suffix :8899      Advertised RPC suffix to filter
--timeout 2             Per-RPC request timeout in seconds
--parallel 48           Concurrent RPC probes
--print-first 50        Rows printed per section
--out-dir logs          Directory for CSV reports
--probe-grpc            Probe same host's gRPC TCP port, enabled by default
--grpc-port 10000       gRPC port to test
--grpc-h2c              Use curl HTTP/2 prior knowledge to inspect h2c gRPC response
--grpc-for-all          Probe gRPC even if RPC is not usable
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
