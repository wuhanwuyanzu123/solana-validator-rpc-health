#!/usr/bin/env python3
"""Probe advertised Solana validator RPC endpoints and nearby gRPC ports."""

from __future__ import annotations

import argparse
import concurrent.futures
import csv
import json
import os
import re
import shutil
import socket
import ssl
import subprocess
import sys
import time
from dataclasses import dataclass, asdict
from datetime import datetime
from typing import Any
from urllib import request


MAINNET_GENESIS_HASH = "5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d"
YELLOWSTONE_PROTO_BASE_URL = "https://raw.githubusercontent.com/rpcpool/yellowstone-grpc/master/yellowstone-grpc-proto/proto"
BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
CURL_HTTP2_SUPPORTED: bool | None = None


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
    get_multiple_accounts_ok: bool
    get_multiple_accounts_latency_ms: int | str
    get_multiple_accounts_error: str
    grpc_host: str
    grpc_port: int
    grpc_tcp_open: bool
    grpc_tcp_latency_ms: int | str
    grpc_h2c_status: str
    solana_grpc_usable: bool
    solana_grpc_status: str
    client_id: str
    pubkey: str
    gossip: str
    advertised_version: str
    error: str


@dataclass
class PortScanResult:
    host: str
    port: int
    tcp_open: bool
    tcp_latency_ms: int | str
    grpc_h2c_status: str
    grpc_like: bool
    solana_grpc_usable: bool
    solana_grpc_status: str


def normalize_pubkey(value: str) -> str:
    if re.fullmatch(r"[0-9a-fA-F]{64}", value):
        raw = bytes.fromhex(value)
        number = int.from_bytes(raw, "big")
        encoded = ""
        while number:
            number, remainder = divmod(number, 58)
            encoded = BASE58_ALPHABET[remainder] + encoded
        zero_prefix = len(raw) - len(raw.lstrip(b"\0"))
        return "1" * zero_prefix + (encoded or "1")
    return value


def rpc_post(url: str, method: str, timeout: float, params: list[Any] | None = None) -> tuple[dict[str, Any], int]:
    payload: dict[str, Any] = {"jsonrpc": "2.0", "id": 1, "method": method}
    if params is not None:
        payload["params"] = params

    data = json.dumps(payload).encode("utf-8")
    req = request.Request(
        url,
        data=data,
        headers={"content-type": "application/json", "user-agent": "curl/8.0"},
        method="POST",
    )
    start = time.perf_counter()
    with request.urlopen(req, timeout=timeout) as resp:
        body = resp.read()
    elapsed_ms = int((time.perf_counter() - start) * 1000)
    return json.loads(body.decode("utf-8")), elapsed_ms


def download_file(url: str, path: str, timeout: float) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with request.urlopen(url, timeout=timeout) as resp:
        data = resp.read()
    with open(path, "wb") as fh:
        fh.write(data)


def tcp_probe(host: str, port: int, timeout: float) -> tuple[bool, int | str]:
    start = time.perf_counter()
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True, int((time.perf_counter() - start) * 1000)
    except OSError:
        return False, ""


def h2c_grpc_probe(host: str, port: int, timeout: float) -> str:
    curl = shutil.which("curl")
    if not curl or not curl_supports_http2(curl):
        return http2_probe(host, port, timeout)

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
    fallback = http2_probe(host, port, timeout)
    if fallback.startswith("http2-"):
        return fallback
    if fallback == "tls-http2":
        return fallback
    return f"error:{text.splitlines()[-1][:120] if text.splitlines() else proc.returncode}"


def curl_supports_http2(curl: str) -> bool:
    global CURL_HTTP2_SUPPORTED
    if CURL_HTTP2_SUPPORTED is not None:
        return CURL_HTTP2_SUPPORTED

    try:
        proc = subprocess.run([curl, "--version"], capture_output=True, text=True, timeout=2)
        CURL_HTTP2_SUPPORTED = "HTTP2" in proc.stdout
    except Exception:
        CURL_HTTP2_SUPPORTED = False
    return CURL_HTTP2_SUPPORTED


def h2c_preface_probe(host: str, port: int, timeout: float) -> str:
    preface = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
    empty_settings = b"\x00\x00\x00\x04\x00\x00\x00\x00\x00"
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            sock.sendall(preface + empty_settings)
            data = sock.recv(32)
    except OSError as exc:
        return f"error:{exc}"

    if data.startswith(b"HTTP/"):
        return "http1-response"
    if len(data) >= 9:
        frame_type = data[3]
        if frame_type == 0x04:
            return "http2-settings"
        return f"http2-frame-type={frame_type}"
    if data:
        return f"unexpected-bytes={data[:8].hex()}"
    return "no-response"


def tls_http2_probe(host: str, port: int, timeout: float) -> str:
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    context.set_alpn_protocols(["h2", "http/1.1"])

    try:
        with socket.create_connection((host, port), timeout=timeout) as raw_sock:
            raw_sock.settimeout(timeout)
            with context.wrap_socket(raw_sock, server_hostname=host) as tls_sock:
                selected = tls_sock.selected_alpn_protocol()
    except OSError as exc:
        return f"error:{exc}"

    if selected == "h2":
        return "tls-http2"
    if selected:
        return f"tls-alpn={selected}"
    return "tls-no-alpn"


def http2_probe(host: str, port: int, timeout: float) -> str:
    h2c_status = h2c_preface_probe(host, port, timeout)
    if h2c_status.startswith("http2-"):
        return h2c_status

    tls_status = tls_http2_probe(host, port, timeout)
    if tls_status == "tls-http2":
        return tls_status
    return h2c_status


def is_grpc_like(status: str) -> bool:
    lower = status.lower()
    return lower.startswith("grpc-status=") or lower == "application/grpc" or lower in {"http2-settings", "tls-http2"}


def parse_port_range(value: str) -> tuple[int, int]:
    if "-" in value:
        start_text, end_text = value.split("-", 1)
        start, end = int(start_text), int(end_text)
    else:
        start = end = int(value)

    if start < 1 or end > 65535 or start > end:
        raise argparse.ArgumentTypeError("port range must be within 1-65535, for example 1-10000")
    return start, end


def ensure_yellowstone_protos(args: argparse.Namespace) -> str | None:
    proto_dir = os.path.abspath(args.grpc_proto_dir)
    geyser_proto = os.path.join(proto_dir, "geyser.proto")
    storage_proto = os.path.join(proto_dir, "solana-storage.proto")
    if os.path.exists(geyser_proto) and os.path.exists(storage_proto):
        return proto_dir
    if args.no_download_protos:
        return None

    try:
        download_file(f"{YELLOWSTONE_PROTO_BASE_URL}/geyser.proto", geyser_proto, args.timeout)
        download_file(f"{YELLOWSTONE_PROTO_BASE_URL}/solana-storage.proto", storage_proto, args.timeout)
    except Exception:
        return None
    return proto_dir


def grpcurl_transport_args(transport: str) -> list[str]:
    if transport == "plaintext":
        return ["-plaintext"]
    if transport == "tls":
        return ["-insecure"]
    return []


def find_grpcurl(explicit_path: str) -> str | None:
    if explicit_path:
        return explicit_path
    found = shutil.which("grpcurl")
    if found:
        return found

    winget_root = os.path.join(os.environ.get("LOCALAPPDATA", ""), "Microsoft", "WinGet", "Packages")
    if os.path.isdir(winget_root):
        for root, _, files in os.walk(winget_root):
            if "grpcurl.exe" in files and "fullstorydev.grpcurl" in root:
                return os.path.join(root, "grpcurl.exe")
    return None


def run_grpcurl(
    args: argparse.Namespace,
    host: str,
    port: int,
    proto_dir: str,
    transport: str,
) -> tuple[bool, str]:
    grpcurl = find_grpcurl(args.grpcurl)
    if not grpcurl:
        return False, "skipped:grpcurl-not-found"

    cmd = [
        grpcurl,
        "-max-time",
        str(args.grpc_timeout),
        *grpcurl_transport_args(transport),
        "-import-path",
        proto_dir,
        "-proto",
        "geyser.proto",
    ]
    if args.grpc_token:
        cmd.extend(["-H", f"{args.grpc_token_header}: {args.grpc_token}"])
    cmd.extend([f"{host}:{port}", args.solana_grpc_method])

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=args.grpc_timeout + 2)
    except Exception as exc:
        return False, f"error:{exc}"

    text = (proc.stdout + proc.stderr).replace("\r", " ").replace("\n", " ").strip()
    compact = " ".join(text.split())
    if proc.returncode == 0:
        return True, compact[:240] or "ok"

    lower = compact.lower()
    if "unauthenticated" in lower or "permissiondenied" in lower or "permission denied" in lower:
        return False, f"auth-failed:{compact[:220]}"
    if "unknown service" in lower or "unknown method" in lower or "unimplemented" in lower:
        return False, f"not-yellowstone:{compact[:220]}"
    return False, f"error:{compact[:240] if compact else proc.returncode}"


def solana_grpc_probe(args: argparse.Namespace, host: str, port: int, grpc_status: str) -> tuple[bool, str]:
    proto_dir = ensure_yellowstone_protos(args)
    if not proto_dir:
        return False, "skipped:yellowstone-protos-unavailable"

    if args.grpc_transport != "auto":
        return run_grpcurl(args, host, port, proto_dir, args.grpc_transport)

    first_transport = "tls" if grpc_status == "tls-http2" else "plaintext"
    usable, status = run_grpcurl(args, host, port, proto_dir, first_transport)
    if usable or status.startswith(("auth-failed:", "not-yellowstone:", "skipped:")):
        return usable, status

    second_transport = "plaintext" if first_transport == "tls" else "tls"
    second_usable, second_status = run_grpcurl(args, host, port, proto_dir, second_transport)
    if second_usable:
        return second_usable, second_status
    if second_status.startswith(("auth-failed:", "not-yellowstone:")):
        return second_usable, second_status
    return usable, status


def scan_port(host: str, port: int, args: argparse.Namespace) -> PortScanResult:
    tcp_open, latency_ms = tcp_probe(host, port, args.scan_timeout)
    grpc_status = ""
    if tcp_open and (args.grpc_h2c or args.scan_host):
        grpc_status = h2c_grpc_probe(host, port, args.grpc_timeout)
    solana_usable = False
    solana_status = ""
    if args.test_solana_grpc and is_grpc_like(grpc_status):
        solana_usable, solana_status = solana_grpc_probe(args, host, port, grpc_status)

    return PortScanResult(
        host=host,
        port=port,
        tcp_open=tcp_open,
        tcp_latency_ms=latency_ms,
        grpc_h2c_status=grpc_status,
        grpc_like=is_grpc_like(grpc_status),
        solana_grpc_usable=solana_usable,
        solana_grpc_status=solana_status,
    )


def scan_host_ports(args: argparse.Namespace) -> int:
    start_port, end_port = args.port_range
    ports = range(start_port, end_port + 1)
    started = time.perf_counter()

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.scan_parallel) as pool:
        results = list(pool.map(lambda port: scan_port(args.scan_host, port, args), ports))

    open_ports = [row for row in results if row.tcp_open]
    grpc_like = [row for row in open_ports if row.grpc_like]
    solana_usable = [row for row in grpc_like if row.solana_grpc_usable]

    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_host = "".join(ch if ch.isalnum() or ch in ".-_" else "_" for ch in args.scan_host)
    csv_path = os.path.abspath(os.path.join(args.out_dir, f"port_scan_{safe_host}_{start_port}_{end_port}_{stamp}.csv"))
    with open(csv_path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(PortScanResult.__dataclass_fields__.keys()))
        writer.writeheader()
        writer.writerows(asdict(row) for row in open_ports)

    summary = {
        "host": args.scan_host,
        "portRange": f"{start_port}-{end_port}",
        "tcpOpen": len(open_ports),
        "grpcLike": len(grpc_like),
        "solanaGrpcUsable": len(solana_usable),
        "scanElapsedSeconds": round(time.perf_counter() - started, 2),
        "csv": csv_path,
    }
    print(json.dumps(summary, ensure_ascii=False, indent=2))

    if solana_usable:
        print("\nSOLANA_GRPC_USABLE")
        for row in solana_usable[: args.print_first]:
            print(f"{row.host}:{row.port} tcp={row.tcp_latency_ms}ms status={row.solana_grpc_status}")

    if grpc_like:
        print("\nGRPC_LIKE")
        for row in grpc_like[: args.print_first]:
            solana = f" solana={row.solana_grpc_status}" if row.solana_grpc_status else ""
            print(f"{row.host}:{row.port} tcp={row.tcp_latency_ms}ms h2c={row.grpc_h2c_status}{solana}")

    if open_ports:
        print("\nTCP_OPEN")
        for row in open_ports[: args.print_first]:
            h2c = f" h2c={row.grpc_h2c_status}" if row.grpc_h2c_status else ""
            print(f"{row.host}:{row.port} tcp={row.tcp_latency_ms}ms{h2c}")

    return 0


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
        get_multiple_accounts_ok=False,
        get_multiple_accounts_latency_ms="",
        get_multiple_accounts_error="",
        grpc_host=host,
        grpc_port=args.grpc_port,
        grpc_tcp_open=False,
        grpc_tcp_latency_ms="",
        grpc_h2c_status="",
        solana_grpc_usable=False,
        solana_grpc_status="",
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

        if args.get_multiple_accounts:
            account_params = [[args.get_multiple_accounts], {"encoding": args.account_encoding}]
            accounts, accounts_latency_ms = rpc_post(rpc_url, "getMultipleAccounts", args.timeout, account_params)
            row.get_multiple_accounts_latency_ms = accounts_latency_ms
            if "error" in accounts:
                row.get_multiple_accounts_error = json.dumps(accounts["error"], separators=(",", ":"))
            else:
                value = (accounts.get("result") or {}).get("value")
                row.get_multiple_accounts_ok = isinstance(value, list) and len(value) == 1
                if not row.get_multiple_accounts_ok:
                    row.get_multiple_accounts_error = json.dumps(accounts, separators=(",", ":"))

        row.ok = bool(row.node_version or row.slot)
    except Exception as exc:
        row.error = str(exc)

    if args.probe_grpc and (row.ok or args.grpc_for_all):
        row.grpc_tcp_open, row.grpc_tcp_latency_ms = tcp_probe(host, args.grpc_port, args.grpc_timeout)
        if row.grpc_tcp_open and args.grpc_h2c:
            row.grpc_h2c_status = h2c_grpc_probe(host, args.grpc_port, args.grpc_timeout)
        if row.grpc_tcp_open and args.test_solana_grpc and (not args.grpc_h2c or is_grpc_like(row.grpc_h2c_status)):
            row.solana_grpc_usable, row.solana_grpc_status = solana_grpc_probe(args, host, args.grpc_port, row.grpc_h2c_status)

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
            if row.solana_grpc_status:
                grpc += f" solana={row.solana_grpc_status}"
        accounts = ""
        if row.get_multiple_accounts_ok:
            accounts = f" getMultipleAccounts={row.get_multiple_accounts_latency_ms}ms"
        elif row.get_multiple_accounts_error:
            accounts = f" getMultipleAccountsError={row.get_multiple_accounts_error[:80]}"
        print(
            f"{row.rpc:<22} rpc={row.rpc_latency_ms}ms health={row.health} "
            f"slot={row.slot} ver={row.node_version}{accounts}{grpc} pubkey={row.pubkey}"
        )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cluster-rpc", default=os.environ.get("CLUSTER_RPC", "https://api.mainnet-beta.solana.com"))
    parser.add_argument("--rpc-suffix", default=os.environ.get("RPC_SUFFIX", ":8899"))
    parser.add_argument("--all-advertised-rpc", action="store_true", help="Probe every advertised RPC endpoint instead of filtering by --rpc-suffix.")
    parser.add_argument("--rpc-scheme", default=os.environ.get("RPC_SCHEME", "http"))
    parser.add_argument("--timeout", type=float, default=float(os.environ.get("TIMEOUT_SECONDS", "2")))
    parser.add_argument("--parallel", type=int, default=int(os.environ.get("MAX_PARALLEL", "48")))
    parser.add_argument("--print-first", type=int, default=int(os.environ.get("PRINT_FIRST", "50")))
    parser.add_argument("--out-dir", default=os.environ.get("OUT_DIR", "logs"))
    parser.add_argument("--expected-genesis-hash", default=os.environ.get("EXPECTED_GENESIS_HASH", MAINNET_GENESIS_HASH))
    parser.add_argument("--get-multiple-accounts", default=os.environ.get("GET_MULTIPLE_ACCOUNTS"), help="Account pubkey to probe with getMultipleAccounts; 64-char hex is converted to base58.")
    parser.add_argument("--account-encoding", default=os.environ.get("ACCOUNT_ENCODING", "base64"))
    parser.add_argument("--probe-grpc", action=argparse.BooleanOptionalAction, default=True)
    parser.add_argument("--grpc-port", type=int, default=int(os.environ.get("GRPC_PORT", "10000")))
    parser.add_argument("--grpc-timeout", type=float, default=float(os.environ.get("GRPC_TIMEOUT_SECONDS", "1")))
    parser.add_argument("--grpc-for-all", action="store_true", help="Probe gRPC port even if RPC did not respond.")
    parser.add_argument("--grpc-h2c", action="store_true", help="Use curl --http2-prior-knowledge to identify h2c gRPC status.")
    parser.add_argument("--scan-host", help="Scan a single authorized validator host for open ports.")
    parser.add_argument("--port-range", type=parse_port_range, default=parse_port_range(os.environ.get("PORT_RANGE", "1-10000")))
    parser.add_argument("--scan-timeout", type=float, default=float(os.environ.get("SCAN_TIMEOUT_SECONDS", "0.35")))
    parser.add_argument("--scan-parallel", type=int, default=int(os.environ.get("SCAN_PARALLEL", "256")))
    parser.add_argument("--test-solana-grpc", action=argparse.BooleanOptionalAction, default=True)
    parser.add_argument("--grpcurl", default=os.environ.get("GRPCURL_PATH", ""), help="Path to grpcurl; defaults to PATH lookup.")
    parser.add_argument("--grpc-token", default=os.environ.get("GRPC_TOKEN", ""), help="Auth token for Solana Yellowstone gRPC.")
    parser.add_argument("--grpc-token-header", default=os.environ.get("GRPC_TOKEN_HEADER", "x-token"))
    parser.add_argument("--grpc-transport", choices=["auto", "plaintext", "tls"], default=os.environ.get("GRPC_TRANSPORT", "auto"))
    parser.add_argument("--grpc-proto-dir", default=os.environ.get("GRPC_PROTO_DIR", os.path.join("logs", "yellowstone-proto")))
    parser.add_argument("--no-download-protos", action="store_true", help="Do not download Yellowstone proto files automatically.")
    parser.add_argument("--solana-grpc-method", default=os.environ.get("SOLANA_GRPC_METHOD", "geyser.Geyser/GetVersion"))
    args = parser.parse_args()
    if args.get_multiple_accounts:
        args.get_multiple_accounts = normalize_pubkey(args.get_multiple_accounts)

    os.makedirs(args.out_dir, exist_ok=True)

    if args.scan_host:
        return scan_host_ports(args)

    nodes, cluster_latency_ms = load_nodes(args)
    candidates = [node for node in nodes if str(node.get("rpc") or "")]
    if not args.all_advertised_rpc:
        candidates = [node for node in candidates if str(node.get("rpc") or "").endswith(args.rpc_suffix)]

    start = time.perf_counter()
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.parallel) as pool:
        results = list(pool.map(lambda node: probe_node(node, args), candidates))
    elapsed = round(time.perf_counter() - start, 2)

    if args.get_multiple_accounts:
        results.sort(key=lambda r: (not r.get_multiple_accounts_ok, int(r.get_multiple_accounts_latency_ms or 10**12), r.rpc))
    else:
        results.sort(key=lambda r: (not r.ok, int(r.rpc_latency_ms or 10**12), r.rpc))
    alive = [row for row in results if row.ok]
    healthy = [row for row in alive if row.health == "ok"]
    not_healthy = [row for row in alive if row.health != "ok"]
    grpc_open = [row for row in alive if row.grpc_tcp_open]
    get_multiple_accounts_supported = [row for row in results if row.get_multiple_accounts_ok]
    latencies = [int(row.rpc_latency_ms) for row in alive if row.rpc_latency_ms != ""]
    get_multiple_accounts_latencies = [int(row.get_multiple_accounts_latency_ms) for row in get_multiple_accounts_supported if row.get_multiple_accounts_latency_ms != ""]

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
        "advertisedRpcSuffix": "*" if args.all_advertised_rpc else args.rpc_suffix,
        "advertisedRpcCount": len(candidates),
        "rpcUsable": len(alive),
        "rpcHealthy": len(healthy),
        "rpcRespondingButNotHealthy": len(not_healthy),
        "getMultipleAccountsAccount": args.get_multiple_accounts or "",
        "getMultipleAccountsSupported": len(get_multiple_accounts_supported),
        "grpcPort": args.grpc_port,
        "grpcTcpOpenAmongUsableRpc": len(grpc_open),
        "scanElapsedSeconds": elapsed,
        "rpcLatencyMs": {
            "min": min(latencies) if latencies else "",
            "p50": percentile(latencies, 0.50),
            "p95": percentile(latencies, 0.95),
            "max": max(latencies) if latencies else "",
        },
        "getMultipleAccountsLatencyMs": {
            "min": min(get_multiple_accounts_latencies) if get_multiple_accounts_latencies else "",
            "p50": percentile(get_multiple_accounts_latencies, 0.50),
            "p95": percentile(get_multiple_accounts_latencies, 0.95),
            "max": max(get_multiple_accounts_latencies) if get_multiple_accounts_latencies else "",
        },
        "csv": csv_path,
    }
    print(json.dumps(summary, ensure_ascii=False, indent=2))

    print_table("GET_MULTIPLE_ACCOUNTS_RPC", get_multiple_accounts_supported, args.print_first)
    print_table("HEALTHY_RPC", healthy, args.print_first)
    print_table(f"GRPC_{args.grpc_port}_TCP_OPEN", grpc_open, args.print_first)
    print_table("RESPONDING_BUT_NOT_HEALTHY", not_healthy, args.print_first)
    return 0


if __name__ == "__main__":
    sys.exit(main())
