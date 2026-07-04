#!/usr/bin/env python3
"""Probe advertised Solana validator RPC endpoints and nearby gRPC ports."""

from __future__ import annotations

import argparse
import concurrent.futures
import csv
import json
import os
import shutil
import socket
import subprocess
import sys
import time
from dataclasses import dataclass, asdict
from datetime import datetime
from typing import Any
from urllib import request


MAINNET_GENESIS_HASH = "5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d"


@dataclass
class ProbeResult:
    ok: bool
    rpc: str
    rpc_url: str
    rpc_latency_ms: int | str
    health: str
    node_version: str
    slot: int | str
    block_height: int | str
    latest_blockhash_ok: bool
    genesis_hash: str
    genesis_ok: bool
    grpc_host: str
    grpc_port: int
    grpc_tcp_open: bool
    grpc_tcp_latency_ms: int | str
    grpc_h2c_status: str
    client_id: str
    pubkey: str
    gossip: str
    advertised_version: str
    error: str


def rpc_post(url: str, method: str, timeout: float, params: list[Any] | None = None) -> tuple[dict[str, Any], int]:
    payload: dict[str, Any] = {"jsonrpc": "2.0", "id": 1, "method": method}
    if params is not None:
        payload["params"] = params

    data = json.dumps(payload).encode("utf-8")
    req = request.Request(
        url,
        data=data,
        headers={"content-type": "application/json"},
        method="POST",
    )
    start = time.perf_counter()
    with request.urlopen(req, timeout=timeout) as resp:
        body = resp.read()
    elapsed_ms = int((time.perf_counter() - start) * 1000)
    return json.loads(body.decode("utf-8")), elapsed_ms


def tcp_probe(host: str, port: int, timeout: float) -> tuple[bool, int | str]:
    start = time.perf_counter()
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True, int((time.perf_counter() - start) * 1000)
    except OSError:
        return False, ""


def h2c_grpc_probe(host: str, port: int, timeout: float) -> str:
    curl = shutil.which("curl")
    if not curl:
        return "skipped:curl-not-found"

    url = f"http://{host}:{port}/"
    cmd = [
        curl,
        "-sS",
        "-m",
        str(timeout),
        "--http2-prior-knowledge",
        "-i",
        url,
    ]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 1)
    except Exception as exc:
        return f"error:{exc}"

    text = (proc.stdout + proc.stderr).replace("\r", "")
    for line in text.splitlines():
        lower = line.lower()
        if lower.startswith("grpc-status:"):
            status = line.split(":", 1)[1].strip()
            message = ""
            for msg_line in text.splitlines():
                if msg_line.lower().startswith("grpc-message:"):
                    message = msg_line.split(":", 1)[1].strip()
                    break
            return f"grpc-status={status}" + (f" grpc-message={message}" if message else "")
    if "content-type: application/grpc" in text.lower():
        return "application/grpc"
    if proc.returncode == 0:
        return "open-no-grpc-status"
    return f"error:{text.splitlines()[-1][:120] if text.splitlines() else proc.returncode}"


def probe_node(node: dict[str, Any], args: argparse.Namespace) -> ProbeResult:
    rpc = str(node.get("rpc") or "")
    rpc_url = rpc if rpc.startswith(("http://", "https://")) else f"{args.rpc_scheme}://{rpc}"
    host = rpc.rsplit(":", 1)[0]

    row = ProbeResult(
        ok=False,
        rpc=rpc,
        rpc_url=rpc_url,
        rpc_latency_ms="",
        health="",
        node_version="",
        slot="",
        block_height="",
        latest_blockhash_ok=False,
        genesis_hash="",
        genesis_ok=False,
        grpc_host=host,
        grpc_port=args.grpc_port,
        grpc_tcp_open=False,
        grpc_tcp_latency_ms="",
        grpc_h2c_status="",
        client_id=str(node.get("clientId") or ""),
        pubkey=str(node.get("pubkey") or ""),
        gossip=str(node.get("gossip") or ""),
        advertised_version=str(node.get("version") or ""),
        error="",
    )

    try:
        health, latency_ms = rpc_post(rpc_url, "getHealth", args.timeout)
        row.rpc_latency_ms = latency_ms
        row.health = health.get("result") or (health.get("error") or {}).get("message") or json.dumps(health, separators=(",", ":"))

        version, _ = rpc_post(rpc_url, "getVersion", args.timeout)
        row.node_version = (version.get("result") or {}).get("solana-core") or ""

        slot, _ = rpc_post(rpc_url, "getSlot", args.timeout)
        row.slot = slot.get("result") or ""

        block_height, _ = rpc_post(rpc_url, "getBlockHeight", args.timeout)
        row.block_height = block_height.get("result") or ""

        latest_blockhash, _ = rpc_post(rpc_url, "getLatestBlockhash", args.timeout)
        row.latest_blockhash_ok = bool(((latest_blockhash.get("result") or {}).get("value") or {}).get("blockhash"))

        genesis, _ = rpc_post(rpc_url, "getGenesisHash", args.timeout)
        row.genesis_hash = genesis.get("result") or ""
        row.genesis_ok = row.genesis_hash == args.expected_genesis_hash

        row.ok = bool(row.node_version or row.slot)
    except Exception as exc:
        row.error = str(exc)

    if args.probe_grpc and (row.ok or args.grpc_for_all):
        row.grpc_tcp_open, row.grpc_tcp_latency_ms = tcp_probe(host, args.grpc_port, args.grpc_timeout)
        if row.grpc_tcp_open and args.grpc_h2c:
            row.grpc_h2c_status = h2c_grpc_probe(host, args.grpc_port, args.grpc_timeout)

    return row


def load_nodes(args: argparse.Namespace) -> tuple[list[dict[str, Any]], int]:
    cluster, elapsed_ms = rpc_post(args.cluster_rpc, "getClusterNodes", args.timeout)
    return cluster.get("result") or [], elapsed_ms


def percentile(values: list[int], ratio: float) -> int | str:
    if not values:
        return ""
    idx = max(0, min(len(values) - 1, int(len(values) * ratio) - 1))
    return sorted(values)[idx]


def print_table(title: str, rows: list[ProbeResult], limit: int) -> None:
    if not rows:
        return
    print(f"\n{title}")
    for row in rows[:limit]:
        grpc = ""
        if row.grpc_tcp_open:
            grpc = f" grpc{row.grpc_port}=open/{row.grpc_tcp_latency_ms}ms"
            if row.grpc_h2c_status:
                grpc += f" h2c={row.grpc_h2c_status}"
        print(
            f"{row.rpc:<22} rpc={row.rpc_latency_ms}ms health={row.health} "
            f"slot={row.slot} ver={row.node_version}{grpc} pubkey={row.pubkey}"
        )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cluster-rpc", default=os.environ.get("CLUSTER_RPC", "https://api.mainnet-beta.solana.com"))
    parser.add_argument("--rpc-suffix", default=os.environ.get("RPC_SUFFIX", ":8899"))
    parser.add_argument("--rpc-scheme", default=os.environ.get("RPC_SCHEME", "http"))
    parser.add_argument("--timeout", type=float, default=float(os.environ.get("TIMEOUT_SECONDS", "2")))
    parser.add_argument("--parallel", type=int, default=int(os.environ.get("MAX_PARALLEL", "48")))
    parser.add_argument("--print-first", type=int, default=int(os.environ.get("PRINT_FIRST", "50")))
    parser.add_argument("--out-dir", default=os.environ.get("OUT_DIR", "logs"))
    parser.add_argument("--expected-genesis-hash", default=os.environ.get("EXPECTED_GENESIS_HASH", MAINNET_GENESIS_HASH))
    parser.add_argument("--probe-grpc", action=argparse.BooleanOptionalAction, default=True)
    parser.add_argument("--grpc-port", type=int, default=int(os.environ.get("GRPC_PORT", "10000")))
    parser.add_argument("--grpc-timeout", type=float, default=float(os.environ.get("GRPC_TIMEOUT_SECONDS", "1")))
    parser.add_argument("--grpc-for-all", action="store_true", help="Probe gRPC port even if RPC did not respond.")
    parser.add_argument("--grpc-h2c", action="store_true", help="Use curl --http2-prior-knowledge to identify h2c gRPC status.")
    args = parser.parse_args()

    os.makedirs(args.out_dir, exist_ok=True)

    nodes, cluster_latency_ms = load_nodes(args)
    candidates = [node for node in nodes if str(node.get("rpc") or "").endswith(args.rpc_suffix)]

    start = time.perf_counter()
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.parallel) as pool:
        results = list(pool.map(lambda node: probe_node(node, args), candidates))
    elapsed = round(time.perf_counter() - start, 2)

    results.sort(key=lambda r: (not r.ok, int(r.rpc_latency_ms or 10**12), r.rpc))
    alive = [row for row in results if row.ok]
    healthy = [row for row in alive if row.health == "ok"]
    not_healthy = [row for row in alive if row.health != "ok"]
    grpc_open = [row for row in alive if row.grpc_tcp_open]
    latencies = [int(row.rpc_latency_ms) for row in alive if row.rpc_latency_ms != ""]

    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    csv_path = os.path.abspath(os.path.join(args.out_dir, f"solana_validator_rpc_health_{stamp}.csv"))
    fields = list(asdict(results[0]).keys()) if results else list(ProbeResult.__dataclass_fields__.keys())
    with open(csv_path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields)
        writer.writeheader()
        writer.writerows(asdict(row) for row in results)

    summary = {
        "clusterRpc": args.cluster_rpc,
        "clusterRpcLatencyMs": cluster_latency_ms,
        "totalNodes": len(nodes),
        "advertisedRpcSuffix": args.rpc_suffix,
        "advertisedRpcCount": len(candidates),
        "rpcUsable": len(alive),
        "rpcHealthy": len(healthy),
        "rpcRespondingButNotHealthy": len(not_healthy),
        "grpcPort": args.grpc_port,
        "grpcTcpOpenAmongUsableRpc": len(grpc_open),
        "scanElapsedSeconds": elapsed,
        "rpcLatencyMs": {
            "min": min(latencies) if latencies else "",
            "p50": percentile(latencies, 0.50),
            "p95": percentile(latencies, 0.95),
            "max": max(latencies) if latencies else "",
        },
        "csv": csv_path,
    }
    print(json.dumps(summary, ensure_ascii=False, indent=2))

    print_table("HEALTHY_RPC", healthy, args.print_first)
    print_table(f"GRPC_{args.grpc_port}_TCP_OPEN", grpc_open, args.print_first)
    print_table("RESPONDING_BUT_NOT_HEALTHY", not_healthy, args.print_first)
    return 0


if __name__ == "__main__":
    sys.exit(main())
