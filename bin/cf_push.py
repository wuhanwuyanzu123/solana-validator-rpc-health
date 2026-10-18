#!/usr/bin/env python3
"""Push the local registry snapshot to a Cloudflare Worker.

Runs on the scanning host. The Worker is the read side that members hit, so the
scan box never serves member traffic — it only publishes. Reads the ingest
credential from a file (mode 600) so the token stays out of the process list.

    python3 cf_push.py --token-file /root/.cf-ingest-token \
        --url https://solana-rpc-registry.lwhch888.workers.dev

Exit codes: 0 pushed (or nothing to do), 1 push failed, 2 misconfiguration.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time


def load_token(path: str) -> str:
    with open(path, encoding="utf-8") as fh:
        token = fh.read().strip()
    if not token:
        raise ValueError(f"{path} is empty")
    return token


def read_state(path: str) -> dict:
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--url", required=True, help="Worker base URL")
    parser.add_argument("--state-file", default="/tmp/rpc-grpc-registry/last-scan.json",
                        help="snapshot written by the registry service")
    parser.add_argument("--token-file", default="/root/.cf-ingest-token",
                        help="file holding the INGEST_TOKEN (mode 600)")
    parser.add_argument("--timeout", type=float, default=30.0)
    parser.add_argument("--min-bytes", type=int, default=1000,
                        help="refuse to push a snapshot smaller than this; guards "
                             "against publishing a truncated scrape")
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args(argv)

    try:
        token = load_token(args.token_file)
    except (OSError, ValueError) as exc:
        print(f"[push] cannot read token: {exc}", file=sys.stderr)
        return 2

    if not os.path.isfile(args.state_file):
        print(f"[push] no snapshot at {args.state_file} yet", file=sys.stderr)
        return 0

    try:
        snapshot = read_state(args.state_file)
    except (OSError, json.JSONDecodeError) as exc:
        print(f"[push] unreadable snapshot: {exc}", file=sys.stderr)
        return 1

    totals = snapshot.get("totals") or {}
    if not totals:
        print("[push] snapshot has no totals; skipping", file=sys.stderr)
        return 0

    # The scanner writes this file atomically, but a scan interrupted mid-write
    # or an upstream failure can still leave a thin payload. Publishing that
    # would replace good data with bad, so refuse.
    body = json.dumps(snapshot).encode("utf-8")
    if len(body) < args.min_bytes:
        print(f"[push] snapshot only {len(body)} bytes (< {args.min_bytes}); skipping",
              file=sys.stderr)
        return 0

    started = time.perf_counter()
    # curl, not urllib: Cloudflare rejects urllib with a browser-fingerprinting
    # 403 (error 1010) while accepting curl, and this endpoint sits behind that.
    cmd = [
        "curl", "-sS", "-m", str(args.timeout),
        "-o", os.devnull, "-w", "%{http_code}",
        "-X", "POST",
        "-H", f"Authorization: Bearer {token}",
        "-H", "Content-Type: application/json",
        "--data-binary", "@-",
        args.url.rstrip("/") + "/ingest",
    ]
    try:
        proc = subprocess.run(cmd, input=body.decode("utf-8"), capture_output=True, text=True,
                              timeout=args.timeout + 10)
    except (subprocess.TimeoutExpired, OSError) as exc:
        print(f"[push] failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1

    elapsed = (time.perf_counter() - started) * 1000
    code = (proc.stdout or "").strip()
    if code != "200":
        tail = (proc.stderr or code or "").strip()[:200]
        print(f"[push] http={code or 'none'} {tail}", file=sys.stderr)
        return 1

    if args.verbose:
        print(f"[push] {len(body)} bytes in {elapsed:.0f}ms -> http 200")
    else:
        print(
            f"[push] ok {len(body)}B {elapsed:.0f}ms "
            f"rpc={totals.get('rpc_usable')} grpc={totals.get('grpc_usable')}",
            flush=True,
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
