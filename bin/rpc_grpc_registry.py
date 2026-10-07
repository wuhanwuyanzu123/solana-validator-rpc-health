#!/usr/bin/env python3
"""Solana RPC / Yellowstone gRPC registry service.

Scans the cluster on a fixed interval and serves the latest snapshot over HTTP
so other services can discover endpoints that actually work.

Endpoints
    GET /          HTML dashboard (auto-refreshing)
    GET /index.json index of available routes
    GET /health    service liveness + scan bookkeeping
    GET /ready     200 once a fresh snapshot exists, else 503
    GET /rpc       usable JSON-RPC endpoints (ranked)
    GET /grpc      usable Yellowstone gRPC endpoints (ranked)
    GET /all       both lists in one response

Nothing here publishes credentials. Only endpoint reachability and latency.
"""

from __future__ import annotations

import argparse
import base64
import csv
import hmac
import importlib.util
import json
import os
import re
import socket
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlparse, parse_qs

DEFAULT_CLUSTER_RPC = os.environ.get("CLUSTER_RPC", "https://api.mainnet-beta.solana.com")
DEFAULT_GRPC_PORTS = "10000,10001,10002,8080,8000,8001"
DEFAULT_PROTO_DIR = os.environ.get(
    "GRPC_PROTO_DIR",
    "/root/solana-validator-rpc-health/logs/yellowstone-proto",
)

# Run the gRPC filters through a real Subscribe call. GetVersion succeeding does
# not prove a server will accept a stream, so this is what makes a row "usable".
SUBSCRIBE_PAYLOAD = json.dumps({"slots": {"registry": {}}, "commitment": "PROCESSED"})

# Solana returns this method-not-found for endpoints fronted by a method
# whitelist. Useful as a capability signal, not a failure of the probe itself.
METHOD_NOT_FOUND = -32601

DEFAULT_PASSWORD = "777888"
AUTH_REALM = "Solana RPC/gRPC Registry"


DASHBOARD_HTML = r"""<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Solana RPC / gRPC Registry</title>
<style>
  :root {
    --bg: #0f1115; --panel: #161a21; --panel2: #1c212a; --line: #262c37;
    --fg: #e6e9ef; --dim: #8b95a7; --faint: #5d667a;
    --ok: #4ade80; --warn: #fbbf24; --bad: #f87171; --accent: #60a5fa;
  }
  * { box-sizing: border-box; }
  body {
    margin: 0; background: var(--bg); color: var(--fg);
    font: 14px/1.5 -apple-system, BlinkMacSystemFont, "Segoe UI", "PingFang SC",
          "Microsoft YaHei", Roboto, Helvetica, Arial, sans-serif;
  }
  code, .mono { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }
  .wrap { max-width: 1240px; margin: 0 auto; padding: 28px 20px 64px; }
  header { display: flex; flex-wrap: wrap; gap: 16px; align-items: baseline;
           justify-content: space-between; margin-bottom: 22px; }
  h1 { font-size: 20px; margin: 0; font-weight: 650; letter-spacing: .2px; }
  h1 span { color: var(--dim); font-weight: 400; }
  .status { display: flex; gap: 10px; align-items: center; font-size: 13px; color: var(--dim); }
  .dot { width: 8px; height: 8px; border-radius: 50%; background: var(--dim); }
  .dot.fresh { background: var(--ok); box-shadow: 0 0 0 3px rgba(74,222,128,.15); }
  .dot.stale { background: var(--warn); box-shadow: 0 0 0 3px rgba(251,191,36,.15); }
  button {
    background: var(--panel2); color: var(--fg); border: 1px solid var(--line);
    border-radius: 6px; padding: 6px 12px; font-size: 13px; cursor: pointer;
  }
  button:hover { border-color: var(--accent); }
  .cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
           gap: 12px; margin-bottom: 24px; }
  .card { background: var(--panel); border: 1px solid var(--line); border-radius: 10px;
          padding: 14px 16px; }
  .card .k { color: var(--dim); font-size: 12px; margin-bottom: 6px; }
  .card .v { font-size: 26px; font-weight: 650; letter-spacing: -.5px; }
  .card .s { color: var(--faint); font-size: 11px; margin-top: 4px; }
  section { background: var(--panel); border: 1px solid var(--line);
            border-radius: 10px; margin-bottom: 20px; overflow: hidden; }
  .sec-head { display: flex; flex-wrap: wrap; gap: 12px; align-items: center;
              justify-content: space-between; padding: 14px 16px;
              border-bottom: 1px solid var(--line); }
  .sec-head h2 { font-size: 15px; margin: 0; font-weight: 600; }
  .sec-head .meta { color: var(--dim); font-size: 12px; }
  input[type=search] {
    background: var(--panel2); border: 1px solid var(--line); color: var(--fg);
    border-radius: 6px; padding: 6px 10px; font-size: 13px; width: 200px;
  }
  input[type=search]:focus { outline: none; border-color: var(--accent); }
  .scroll { overflow-x: auto; }
  table { width: 100%; border-collapse: collapse; font-size: 13px; }
  th { text-align: left; color: var(--dim); font-weight: 500; font-size: 11px;
       text-transform: uppercase; letter-spacing: .6px; padding: 10px 16px;
       border-bottom: 1px solid var(--line); white-space: nowrap; }
  td { padding: 9px 16px; border-bottom: 1px solid rgba(38,44,55,.55); white-space: nowrap; }
  tbody tr:hover { background: rgba(96,165,250,.05); }
  tbody tr:last-child td { border-bottom: none; }
  .rank { color: var(--faint); width: 34px; }
  .ep { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }
  .num { text-align: right; font-variant-numeric: tabular-nums;
         font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }
  .good { color: var(--ok); } .mid { color: var(--warn); } .slow { color: var(--bad); }
  .muted { color: var(--faint); }
  .badge { display: inline-block; font-size: 10px; padding: 1px 6px; border-radius: 4px;
           background: var(--panel2); border: 1px solid var(--line); color: var(--dim);
           margin-left: 6px; vertical-align: middle; }
  .copy { background: transparent; border: 1px solid var(--line); padding: 3px 8px;
          font-size: 11px; border-radius: 5px; color: var(--dim); }
  .copy:hover { color: var(--fg); }
  .empty { padding: 26px 16px; color: var(--dim); text-align: center; }
  .note { color: var(--faint); font-size: 12px; margin-top: 6px; padding: 0 4px; }
  .note b { color: var(--dim); font-weight: 500; }
  code.inline { background: var(--panel2); border: 1px solid var(--line);
                padding: 1px 5px; border-radius: 4px; color: var(--dim); }
  .overlay { position: fixed; inset: 0; background: rgba(10,12,16,.86);
             display: flex; align-items: center; justify-content: center; z-index: 50; }
  .overlay[hidden] { display: none; }
  .dialog { background: var(--panel); border: 1px solid var(--line); border-radius: 12px;
            padding: 26px 28px; width: 320px; }
  .dialog h3 { margin: 0 0 6px; font-size: 16px; }
  .dialog p { margin: 0 0 16px; color: var(--dim); font-size: 13px; }
  .dialog input { width: 100%; background: var(--panel2); border: 1px solid var(--line);
                  color: var(--fg); border-radius: 6px; padding: 9px 11px;
                  font-size: 14px; margin-bottom: 12px; }
  .dialog input:focus { outline: none; border-color: var(--accent); }
  .dialog button { width: 100%; background: var(--accent); border: none; color: #0b1220;
                   font-weight: 600; padding: 9px; }
  .dialog button:hover { filter: brightness(1.08); border: none; }
  .err { color: var(--bad); font-size: 12px; margin-top: 10px; min-height: 15px; }
  @media (max-width: 720px) { .wrap { padding: 18px 12px 48px; } h1 { font-size: 17px; } }
</style>
</head>
<body>
<div class="wrap">
  <header>
    <h1>Solana RPC / gRPC Registry <span>· 端点可用性</span></h1>
    <div class="status">
      <span class="dot" id="dot"></span>
      <span id="age">载入中…</span>
      <button id="refresh">刷新</button>
    </div>
  </header>

  <div class="cards" id="cards"></div>

  <section>
    <div class="sec-head">
      <div>
        <h2>JSON-RPC</h2>
        <div class="meta" id="rpcMeta">—</div>
      </div>
      <input type="search" id="rpcFilter" placeholder="过滤地址…">
    </div>
    <div class="scroll">
      <table>
        <thead><tr>
          <th class="rank">#</th><th>Endpoint</th><th style="text-align:right">延迟</th>
          <th>版本</th><th style="text-align:right">Slot</th><th>能力</th><th></th>
        </tr></thead>
        <tbody id="rpcBody"><tr><td colspan="7" class="empty">载入中…</td></tr></tbody>
      </table>
    </div>
  </section>
  <div class="note">
    <b>可用判定</b>： <code class="inline">getHealth</code> +
    <code class="inline">getLatestBlockhash</code> +
    <code class="inline">getMultipleAccounts</code> 三项全部通过。
    只能查 slot 的阉割节点计入「部分」，不进此表。
  </div>

  <section style="margin-top:24px">
    <div class="sec-head">
      <div>
        <h2>Yellowstone gRPC</h2>
        <div class="meta" id="grpcMeta">—</div>
      </div>
      <input type="search" id="grpcFilter" placeholder="过滤地址…">
    </div>
    <div class="scroll">
      <table>
        <thead><tr>
          <th class="rank">#</th><th>Endpoint</th>
          <th style="text-align:right">TCP</th><th style="text-align:right">GetVersion</th>
          <th>版本</th><th style="text-align:right">流消息</th><th></th>
        </tr></thead>
        <tbody id="grpcBody"><tr><td colspan="7" class="empty">载入中…</td></tr></tbody>
      </table>
    </div>
  </section>
  <div class="note">
    <b>可用判定</b>： HTTP/2 前导通过 →
    <code class="inline">geyser.Geyser/GetVersion</code> 返回版本 →
    匿名 <code class="inline">geyser.Geyser/Subscribe</code> 实际收到流数据。
    只握手不推流的不计入。
  </div>
</div>

<div class="overlay" id="login" hidden>
  <div class="dialog">
    <h3>需要登录</h3>
    <p>请输入控制台密码以查看端点列表。</p>
    <input type="password" id="pw" placeholder="密码" autocomplete="current-password">
    <button id="loginBtn">登录</button>
    <div class="err" id="loginErr"></div>
  </div>
</div>

<script>
var DATA = null;
var TOKEN = null;   // set after a successful inline login; sent as Bearer

function esc(s) {
  return String(s == null ? '' : s).replace(/[&<>"]/g, function (c) {
    return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c];
  });
}
function cls(ms, a, b) { return ms == null ? 'muted' : (ms <= a ? 'good' : (ms <= b ? 'mid' : 'slow')); }
function age(sec) {
  if (sec < 60) return Math.round(sec) + ' 秒前';
  if (sec < 3600) return Math.round(sec / 60) + ' 分钟前';
  return (sec / 3600).toFixed(1) + ' 小时前';
}
function copyText(text, btn) {
  var done = function () { var o = btn.textContent; btn.textContent = '已复制';
    setTimeout(function () { btn.textContent = o; }, 1200); };
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(text).then(done, function () { fallback(text, done); });
  } else { fallback(text, done); }
}
function fallback(text, done) {
  var ta = document.createElement('textarea');
  ta.value = text; ta.style.position = 'fixed'; ta.style.opacity = '0';
  document.body.appendChild(ta); ta.select();
  try { document.execCommand('copy'); done(); } catch (e) {}
  document.body.removeChild(ta);
}

function card(k, v, s) {
  return '<div class="card"><div class="k">' + esc(k) + '</div>' +
         '<div class="v">' + esc(v) + '</div>' +
         (s ? '<div class="s">' + esc(s) + '</div>' : '') + '</div>';
}

function render() {
  if (!DATA) return;
  var scanned = DATA.scanned_at, now = Date.now() / 1000;
  var ageSec = Math.max(0, now - scanned);
  var fresh = !!DATA.fresh;
  var dot = document.getElementById('dot');
  dot.className = 'dot ' + (fresh ? 'fresh' : 'stale');
  document.getElementById('age').textContent =
    (fresh ? '新鲜 · ' : '已过期 · ') + '扫描于 ' + age(ageSec) +
    ' · 每 ' + Math.round(DATA.interval_seconds / 60) + ' 分钟';

  var t = DATA.totals || {};
  var r = DATA.rpc || {}, g = DATA.grpc || {};
  var rl = r.latency_ms || {}, gl = g.latency_ms || {};
  document.getElementById('cards').innerHTML =
    card('可用 RPC', t.rpc_usable != null ? t.rpc_usable : '—',
         '部分可用 ' + (t.rpc_partial || 0)) +
    card('可用 gRPC', t.grpc_usable != null ? t.grpc_usable : '—',
         'h2c 候选 ' + ((g.counts || {}).h2c || 0)) +
    card('RPC P50', rl.p50 != null ? rl.p50 + 'ms' : '—',
         'min ' + (rl.min != null ? rl.min + 'ms' : '—')) +
    card('gRPC P50', gl.p50 != null ? gl.p50 + 'ms' : '—',
         'min ' + (gl.min != null ? gl.min + 'ms' : '—'));

  var rc = r.counts || {};
  document.getElementById('rpcMeta').textContent =
    rc.usable + ' 可用 / ' + rc.healthy + ' 健康 / ' + rc.advertised + ' 广告 · 扫描 ' +
    (r.scan_seconds || 0) + 's';
  var gc = g.counts || {};
  document.getElementById('grpcMeta').textContent =
    (gc.subscribe_ok || 0) + ' 订阅通过 / ' + (gc.getversion_ok || 0) + ' GetVersion / ' +
    (gc.h2c || 0) + ' h2c / ' + (gc.cluster_ips || 0) + ' 节点 · 扫描 ' +
    (g.scan_seconds || 0) + 's';

  renderRpc(r.endpoints || []);
  renderGrpc(g.endpoints || []);
}

function renderRpc(rows) {
  var q = document.getElementById('rpcFilter').value.toLowerCase();
  var out = rows.filter(function (e) { return !q || e.endpoint.toLowerCase().indexOf(q) >= 0; });
  if (!out.length) {
    document.getElementById('rpcBody').innerHTML =
      '<tr><td colspan="7" class="empty">没有匹配的可用 RPC</td></tr>';
    return;
  }
  document.getElementById('rpcBody').innerHTML = out.map(function (e, i) {
    var caps = [];
    if (e.getLatestBlockhash) caps.push('blockhash');
    if (e.getMultipleAccounts) caps.push('accounts');
    return '<tr>' +
      '<td class="rank">' + (i + 1) + '</td>' +
      '<td class="ep">' + esc(e.endpoint) + '</td>' +
      '<td class="num ' + cls(e.latency_ms, 50, 250) + '">' +
        (e.latency_ms != null ? e.latency_ms + 'ms' : '—') + '</td>' +
      '<td>' + esc(e.version || '—') +
        (e.healthy ? '' : '<span class="badge">异常</span>') + '</td>' +
      '<td class="num muted">' + esc(e.slot || '—') + '</td>' +
      '<td class="muted">' + esc(caps.join(', ') || '—') + '</td>' +
      '<td><button class="copy" data-v="' + esc(e.endpoint) + '">复制</button></td>' +
      '</tr>';
  }).join('');
}

function renderGrpc(rows) {
  var q = document.getElementById('grpcFilter').value.toLowerCase();
  var out = rows.filter(function (e) { return !q || e.endpoint.toLowerCase().indexOf(q) >= 0; });
  if (!out.length) {
    document.getElementById('grpcBody').innerHTML =
      '<tr><td colspan="7" class="empty">没有匹配的可用 gRPC</td></tr>';
    return;
  }
  document.getElementById('grpcBody').innerHTML = out.map(function (e, i) {
    return '<tr>' +
      '<td class="rank">' + (i + 1) + '</td>' +
      '<td class="ep">' + esc(e.endpoint) + '</td>' +
      '<td class="num ' + cls(e.tcp_ms, 5, 30) + '">' +
        (e.tcp_ms != null ? e.tcp_ms + 'ms' : '—') + '</td>' +
      '<td class="num ' + cls(e.getversion_ms, 60, 200) + '">' +
        (e.getversion_ms != null ? e.getversion_ms + 'ms' : '—') + '</td>' +
      '<td>' + esc(e.version || '—') + '</td>' +
      '<td class="num muted">' + esc(e.stream_messages != null ? e.stream_messages : '—') + '</td>' +
      '<td><button class="copy" data-v="' + esc(e.endpoint) + '">复制</button></td>' +
      '</tr>';
  }).join('');
}

function load() {
  var headers = { 'cache': 'no-store' };
  if (TOKEN) headers['Authorization'] = 'Bearer ' + TOKEN;
  return fetch('/all', { headers: headers, cache: 'no-store' })
    .then(function (r) {
      if (r.status === 401) {
        // The browser normally replays Basic credentials for same-origin
        // fetches; this is the fallback when it does not.
        showLogin('');
        throw new Error('401');
      }
      if (!r.ok) throw new Error('HTTP ' + r.status);
      return r.json();
    })
    .then(function (d) { DATA = d; hideLogin(); render(); })
    .catch(function (e) {
      if (e && e.message !== '401') {
        document.getElementById('age').textContent = '加载失败: ' + e;
      }
    });
}

function showLogin(msg) {
  document.getElementById('login').hidden = false;
  document.getElementById('loginErr').textContent = msg || '';
  document.getElementById('pw').focus();
}
function hideLogin() { document.getElementById('login').hidden = true; }

function submitLogin() {
  var value = document.getElementById('pw').value;
  if (!value) { document.getElementById('loginErr').textContent = '请输入密码'; return; }
  fetch('/health', {
    headers: { 'Authorization': 'Bearer ' + value },
    cache: 'no-store'
  }).then(function (r) {
    if (r.ok) {
      TOKEN = value;
      document.getElementById('pw').value = '';
      load();
    } else {
      document.getElementById('loginErr').textContent = '密码错误';
      document.getElementById('pw').select();
    }
  }).catch(function () {
    document.getElementById('loginErr').textContent = '网络错误';
  });
}

document.getElementById('refresh').addEventListener('click', load);
document.getElementById('loginBtn').addEventListener('click', submitLogin);
document.getElementById('pw').addEventListener('keydown', function (ev) {
  if (ev.key === 'Enter') submitLogin();
});
document.getElementById('rpcFilter').addEventListener('input', function () {
  if (DATA) renderRpc(DATA.rpc.endpoints || []);
});
document.getElementById('grpcFilter').addEventListener('input', function () {
  if (DATA) renderGrpc(DATA.grpc.endpoints || []);
});
document.addEventListener('click', function (ev) {
  var b = ev.target.closest && ev.target.closest('.copy');
  if (b) copyText(b.getAttribute('data-v'), b);
});

load();
setInterval(load, 30000);
setInterval(function () { if (DATA) render(); }, 1000);
</script>
</body>
</html>
"""


# --------------------------------------------------------------------------
# shared snapshot
# --------------------------------------------------------------------------


class Snapshot:
    """Thread-safe holder for the most recent scan result."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._data: dict[str, Any] = {}
        self._scanning = False
        self._last_error: str | None = None

    def publish(self, data: dict[str, Any]) -> None:
        with self._lock:
            self._data = data
            self._last_error = None

    def get(self) -> dict[str, Any]:
        with self._lock:
            return dict(self._data)

    def set_scanning(self, value: bool) -> None:
        with self._lock:
            self._scanning = value

    def set_error(self, message: str) -> None:
        with self._lock:
            self._last_error = message

    @property
    def scanning(self) -> bool:
        with self._lock:
            return self._scanning

    @property
    def last_error(self) -> str | None:
        with self._lock:
            return self._last_error


# --------------------------------------------------------------------------
# tool loading
# --------------------------------------------------------------------------


def load_probe_tool(path: str):
    """Import bin/solana-validator-rpc-health.py by path (dashes block import)."""
    spec = importlib.util.spec_from_file_location("solana_probe_tool", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load probe tool from {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def find_proto_file(proto_dir: str) -> str | None:
    for name in ("geyser.proto", "yellowstone.proto", "geyser_grpc.proto"):
        if os.path.isfile(os.path.join(proto_dir, name)):
            return name
    return None


# --------------------------------------------------------------------------
# JSON-RPC scan
# --------------------------------------------------------------------------


def scan_rpc(tool_path: str, out_dir: str, args: argparse.Namespace) -> dict[str, Any]:
    """Run the existing probe tool and turn its CSV into a ranked endpoint list."""
    os.makedirs(out_dir, exist_ok=True)
    cmd = [
        sys.executable, tool_path,
        "--all-advertised-rpc",
        "--timeout", str(args.rpc_timeout),
        "--parallel", str(args.rpc_parallel),
        "--print-first", "0",
        "--out-dir", out_dir,
        "--grpc-h2c",
        "--grpc-for-all",
        "--get-multiple-accounts", args.probe_account,
        "--cluster-rpc", args.cluster_rpc,
    ]
    started = time.time()
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=args.scan_timeout)

    summary: dict[str, Any] = {}
    stdout = (proc.stdout or "").strip()
    if stdout.startswith("{"):
        try:
            summary, _ = json.JSONDecoder().raw_decode(stdout)
        except json.JSONDecodeError:
            summary = {}

    csv_path = summary.get("csv")
    if not csv_path or not os.path.isfile(csv_path):
        raise RuntimeError(
            f"probe tool produced no CSV (rc={proc.returncode}): "
            f"{(proc.stderr or '').strip()[:400]}"
        )

    rows: list[dict[str, Any]] = []
    with open(csv_path, newline="", encoding="utf-8", errors="replace") as fh:
        for row in csv.DictReader(fh):
            if str(row.get("ok", "")).lower() != "true":
                continue
            gma_err = row.get("get_multiple_accounts_error") or ""
            gma_ok = str(row.get("get_multiple_accounts_ok", "")).lower() == "true"
            latency = row.get("rpc_latency_ms") or ""
            try:
                latency_ms: int | None = int(float(latency))
            except ValueError:
                latency_ms = None

            # Only endpoints that answer the two transaction-critical methods are
            # usable by a trading service; the rest are health/slot monitors.
            has_blockhash = str(row.get("latest_blockhash_ok", "")).lower() == "true"
            errors: list[str] = []
            if not has_blockhash:
                errors.append("getLatestBlockhash_unsupported")
            if args.probe_account and not gma_ok:
                errors.append(
                    "getMultipleAccounts_unsupported"
                    if METHOD_NOT_FOUND.__str__() in gma_err
                    else f"getMultipleAccounts_error:{gma_err[:120]}"
                )

            rows.append({
                "endpoint": row.get("rpc_url") or row.get("rpc"),
                "host": (row.get("rpc") or "").split(":")[0],
                "latency_ms": latency_ms,
                "health": row.get("health") or "",
                "healthy": (row.get("health") or "").lower() == "ok",
                "version": row.get("node_version") or "",
                "slot": row.get("slot") or "",
                "getLatestBlockhash": has_blockhash,
                "getMultipleAccounts": gma_ok,
                "usable": not errors,
                "unsupported": errors,
                "genesis_ok": str(row.get("genesis_ok", "")).lower() == "true",
            })

    usable = [r for r in rows if r["usable"]]
    usable.sort(key=lambda r: (r["latency_ms"] is None, r["latency_ms"] or 0))
    partial = [r for r in rows if not r["usable"]]
    partial.sort(key=lambda r: (r["latency_ms"] is None, r["latency_ms"] or 0))

    latencies = [r["latency_ms"] for r in usable if r["latency_ms"] is not None]
    return {
        "scanned_at": time.time(),
        "scan_seconds": round(time.time() - started, 1),
        "cluster_rpc": args.cluster_rpc,
        "probe_csv": csv_path,
        "summary": summary,
        "counts": {
            "advertised": summary.get("advertisedRpcCount"),
            "healthy": summary.get("rpcHealthy"),
            "usable": len(usable),
            "partial": len(partial),
        },
        "latency_ms": _percentiles(latencies),
        "endpoints": usable,
        "partial_endpoints": partial[:50],
        "tool_stderr": (proc.stderr or "").strip()[:400] or None,
        "tool_returncode": proc.returncode,
    }


def _percentiles(values: list[int]) -> dict[str, int | None]:
    if not values:
        return {"min": None, "p50": None, "p95": None, "max": None}
    ordered = sorted(values)
    return {
        "min": ordered[0],
        "p50": ordered[len(ordered) // 2],
        "p95": ordered[min(len(ordered) - 1, int(len(ordered) * 0.95))],
        "max": ordered[-1],
    }


# --------------------------------------------------------------------------
# gRPC scan
# --------------------------------------------------------------------------


def cluster_ips(cluster_rpc: str, timeout: float) -> list[str]:
    """Unique IPs advertised by getClusterNodes (gossip / rpc / tpu)."""
    payload = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "getClusterNodes"}).encode()
    from urllib.request import Request, urlopen

    req = Request(cluster_rpc, data=payload, headers={"content-type": "application/json"})
    with urlopen(req, timeout=timeout) as resp:
        nodes = json.load(resp).get("result") or []

    seen: dict[str, None] = {}
    for node in nodes:
        for field in ("gossip", "rpc", "tpu"):
            value = node.get(field) or ""
            if not value:
                continue
            ip = value.rsplit(":", 1)[0]
            if ip:
                seen.setdefault(ip, None)
    return list(seen)


def tcp_connect_ms(ip: str, port: int, timeout: float) -> float | None:
    sock = socket.socket()
    sock.settimeout(timeout)
    started = time.perf_counter()
    try:
        sock.connect((ip, port))
        return round((time.perf_counter() - started) * 1000, 1)
    except OSError:
        return None
    finally:
        sock.close()


def h2c_probe(ip: str, port: int, timeout: float) -> bool:
    """True when the port answers an HTTP/2 connection preface with SETTINGS."""
    try:
        sock = socket.socket()
        sock.settimeout(timeout)
        sock.connect((ip, port))
        sock.sendall(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n\x00\x04\x00\x00\x00\x00")
        data = sock.recv(64)
        sock.close()
        return len(data) >= 4 and data[3] == 0x04
    except OSError:
        return False


def grpc_get_version(ip: str, port: int, proto_dir: str, proto_file: str, timeout: float) -> dict[str, Any]:
    try:
        proc = subprocess.run(
            [
                "grpcurl", "-plaintext",
                "-import-path", proto_dir,
                "-proto", proto_file,
                "-max-time", str(timeout),
                f"{ip}:{port}",
                "geyser.Geyser/GetVersion",
            ],
            capture_output=True, text=True, timeout=timeout + 6,
        )
    except (subprocess.TimeoutExpired, OSError) as exc:
        return {"status": "ERROR", "detail": type(exc).__name__}

    out = ((proc.stdout or "") + (proc.stderr or "")).strip()
    low = out.lower()
    if proc.returncode == 0 and "yellowstone" in low:
        version = ""
        match = re.search(r'yellowstone-grpc-geyser","version":"([^"]+)"', out.replace('\\"', '"'))
        if match:
            version = match.group(1)
        if not version:
            match = re.search(r'"version\\":\\"([0-9][^"\\]+)', out)
            if match:
                version = match.group(1)
        return {"status": "OK", "version": version}
    if "unauthenticated" in low or "auth token" in low or "grpc-status: 16" in low:
        return {"status": "AUTH_REQUIRED"}
    if "unimplemented" in low or "grpc-status: 12" in low:
        return {"status": "NOT_YELLOWSTONE"}
    if "deadline" in low or "timeout" in low:
        return {"status": "TIMEOUT"}
    if "403" in low or "forbidden" in low:
        return {"status": "HTTP_403"}
    if "unavailable" in low or "connection refused" in low:
        return {"status": "UNAVAILABLE"}
    return {"status": "OTHER", "detail": out[:200]}


def grpc_subscribe(ip: str, port: int, proto_dir: str, proto_file: str, timeout: float) -> dict[str, Any]:
    """Confirm an anonymous stream is accepted, not just that GetVersion answers."""
    try:
        proc = subprocess.run(
            [
                "grpcurl", "-plaintext",
                "-import-path", proto_dir,
                "-proto", proto_file,
                "-max-time", str(timeout),
                "-d", SUBSCRIBE_PAYLOAD,
                f"{ip}:{port}",
                "geyser.Geyser/Subscribe",
            ],
            capture_output=True, text=True, timeout=timeout + 6,
        )
    except (subprocess.TimeoutExpired, OSError) as exc:
        return {"status": "ERROR", "detail": type(exc).__name__}

    out = ((proc.stdout or "") + (proc.stderr or "")).strip()
    low = out.lower()
    # Subscribe never ends on its own, so grpcurl always exits via -max-time with
    # DeadlineExceeded. Evidence of a live stream must win over that trailing
    # deadline, otherwise every healthy endpoint is misread as a timeout.
    if "filter" in low or '"slot"' in low or "ping" in low:
        return {"status": "OK", "messages": out.count('"slot"')}
    if "unauthenticated" in low or "auth token" in low:
        return {"status": "AUTH_REQUIRED"}
    if "unimplemented" in low:
        return {"status": "NOT_IMPL"}
    if "deadline" in low or "timeout" in low:
        return {"status": "TIMEOUT"}
    return {"status": "FAIL", "detail": out[:200]}


def scan_grpc(args: argparse.Namespace, proto_dir: str, proto_file: str) -> dict[str, Any]:
    started = time.time()
    ports = [int(p) for p in args.grpc_ports.split(",") if p.strip().isdigit()]
    ips = cluster_ips(args.cluster_rpc, args.rpc_timeout)

    open_pairs: list[tuple[str, int]] = []
    with ThreadPoolExecutor(max_workers=args.sweep_parallel) as pool:
        futures = {
            pool.submit(tcp_connect_ms, ip, port, args.tcp_timeout): (ip, port)
            for ip in ips
            for port in ports
        }
        for future in as_completed(futures):
            if future.result() is not None:
                open_pairs.append(futures[future])

    candidates: list[tuple[str, int]] = []
    with ThreadPoolExecutor(max_workers=args.sweep_parallel) as pool:
        futures = {
            pool.submit(h2c_probe, ip, port, args.tcp_timeout): (ip, port)
            for ip, port in open_pairs
        }
        for future in as_completed(futures):
            if future.result():
                candidates.append(futures[future])

    versioned: list[dict[str, Any]] = []
    with ThreadPoolExecutor(max_workers=args.grpc_parallel) as pool:
        futures = {
            pool.submit(grpc_get_version, ip, port, proto_dir, proto_file, args.grpc_timeout): (ip, port)
            for ip, port in candidates
        }
        for future in as_completed(futures):
            ip, port = futures[future]
            result = future.result()
            if result["status"] != "OK":
                continue
            versioned.append({"host": ip, "port": port, "version": result.get("version", "")})

    # GetVersion gates the expensive part; only stream-verified rows are usable.
    verified: list[dict[str, Any]] = []
    with ThreadPoolExecutor(max_workers=args.grpc_parallel) as pool:
        futures = {
            pool.submit(_verify_grpc, entry, proto_dir, proto_file, args): entry
            for entry in versioned
        }
        for future in as_completed(futures):
            entry = future.result()
            if entry is not None:
                verified.append(entry)

    verified.sort(key=lambda r: (r["getversion_ms"] is None, r["getversion_ms"] or 0))
    latencies = [r["getversion_ms"] for r in verified if r["getversion_ms"] is not None]

    return {
        "scanned_at": time.time(),
        "scan_seconds": round(time.time() - started, 1),
        "counts": {
            "cluster_ips": len(ips),
            "tcp_open": len(open_pairs),
            "h2c": len(candidates),
            "getversion_ok": len(versioned),
            "subscribe_ok": len(verified),
        },
        "latency_ms": _percentiles(latencies),
        "endpoints": verified,
        "auth_required": [f"{ip}:{port}" for ip, port in candidates],
        "ports": ports,
    }


def _verify_grpc(
    entry: dict[str, Any],
    proto_dir: str,
    proto_file: str,
    args: argparse.Namespace,
) -> dict[str, Any] | None:
    ip, port = entry["host"], entry["port"]
    tcp = tcp_connect_ms(ip, port, args.tcp_timeout)
    if tcp is None:
        return None

    started = time.perf_counter()
    version = grpc_get_version(ip, port, proto_dir, proto_file, args.grpc_timeout)
    gv_ms = round((time.perf_counter() - started) * 1000, 1)
    if version["status"] != "OK":
        return None

    subscribe = grpc_subscribe(ip, port, proto_dir, proto_file, args.subscribe_timeout)
    if subscribe["status"] != "OK":
        return None

    return {
        "endpoint": f"{ip}:{port}",
        "host": ip,
        "port": port,
        "tcp_ms": tcp,
        "getversion_ms": gv_ms,
        "version": entry.get("version") or version.get("version", ""),
        "subscribe": subscribe["status"],
        "stream_messages": subscribe.get("messages", 0),
        "usable": True,
    }


# --------------------------------------------------------------------------
# scan loop
# --------------------------------------------------------------------------


def run_scan(args: argparse.Namespace, snapshot: Snapshot, proto_dir: str, proto_file: str) -> None:
    snapshot.set_scanning(True)
    try:
        rpc_result = scan_rpc(args.tool_path, args.out_dir, args)
        grpc_result = scan_grpc(args, proto_dir, proto_file)
        now = time.time()
        payload = {
            "scanned_at": now,
            "interval_seconds": args.interval,
            "expires_at": now + args.interval * 2,
            "rpc": rpc_result,
            "grpc": grpc_result,
            "totals": {
                "rpc_usable": len(rpc_result["endpoints"]),
                "rpc_partial": len(rpc_result["partial_endpoints"]),
                "grpc_usable": len(grpc_result["endpoints"]),
            },
        }
        snapshot.publish(payload)
        _persist(args.state_file, payload)
        print(
            f"[scan] done in {rpc_result['scan_seconds'] + grpc_result['scan_seconds']}s "
            f"rpc_usable={payload['totals']['rpc_usable']} "
            f"grpc_usable={payload['totals']['grpc_usable']}",
            flush=True,
        )
    except Exception as exc:  # noqa: BLE001 - scan must not kill the server
        snapshot.set_error(f"{type(exc).__name__}: {exc}")
        print(f"[scan] failed: {type(exc).__name__}: {exc}", flush=True)
    finally:
        snapshot.set_scanning(False)


def _persist(path: str, payload: dict[str, Any]) -> None:
    try:
        tmp = f"{path}.tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2)
        os.replace(tmp, path)
    except OSError as exc:
        print(f"[persist] {exc}", flush=True)


def _restore(path: str) -> dict[str, Any] | None:
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, json.JSONDecodeError):
        return None


def scan_loop(args: argparse.Namespace, snapshot: Snapshot, proto_dir: str, proto_file: str) -> None:
    while True:
        run_scan(args, snapshot, proto_dir, proto_file)
        time.sleep(max(30, args.interval))


# --------------------------------------------------------------------------
# HTTP
# --------------------------------------------------------------------------


def check_auth(header: str | None, user: str, password: str) -> bool:
    """Accept either HTTP Basic or a bare Bearer token.

    Bearer keeps things simple for service clients that do not want to build a
    Basic header; both carry the same credential.
    """
    if not header:
        return False
    parts = header.split(None, 1)
    if len(parts) != 2:
        return False
    scheme, value = parts[0].lower(), parts[1].strip()
    if scheme == "bearer":
        return hmac.compare_digest(value, password)
    if scheme != "basic":
        return False
    try:
        decoded = base64.b64decode(value, validate=True).decode("utf-8")
    except (ValueError, UnicodeDecodeError):
        return False
    supplied_user, sep, supplied_password = decoded.partition(":")
    if not sep:
        return False
    # Compare both halves in constant time so neither leaks through timing.
    return hmac.compare_digest(supplied_user, user) and hmac.compare_digest(
        supplied_password, password
    )


def make_handler(snapshot: Snapshot, args: argparse.Namespace):
    class RegistryHandler(BaseHTTPRequestHandler):
        server_version = "RpcGrpcRegistry/1.0"

        def log_message(self, fmt: str, *rest: Any) -> None:  # noqa: A003
            if args.verbose:
                sys.stderr.write("%s - %s\n" % (self.address_string(), fmt % rest))

        def _send(self, code: int, body: bytes, content_type: str = "application/json") -> None:
            self.send_response(code)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Cache-Control", "no-store")
            if code == 401:
                self.send_header(
                    "WWW-Authenticate",
                    f'Basic realm="{AUTH_REALM}", charset="UTF-8"',
                )
            self.end_headers()
            self.wfile.write(body)

        def _json(self, code: int, payload: Any) -> None:
            self._send(code, json.dumps(payload, indent=2).encode("utf-8"))

        def do_OPTIONS(self) -> None:  # noqa: N802
            self.send_response(204)
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Access-Control-Allow-Methods", "GET, OPTIONS")
            self.send_header("Access-Control-Allow-Headers", "Authorization, Content-Type")
            self.send_header("Access-Control-Max-Age", "600")
            self.send_header("Content-Length", "0")
            self.end_headers()

        def do_GET(self) -> None:  # noqa: N802
            if not args.no_auth and not check_auth(
                self.headers.get("Authorization"), args.user, args.password
            ):
                body = json.dumps(
                    {"error": "unauthorized", "hint": "Basic auth or Bearer token required"},
                    indent=2,
                ).encode("utf-8")
                self._send(401, body)
                return

            parsed = urlparse(self.path)
            route = parsed.path.rstrip("/") or "/"
            data = snapshot.get()
            fresh = bool(data) and time.time() <= data.get("expires_at", 0)

            if route == "/":
                self._send(200, DASHBOARD_HTML.encode("utf-8"), "text/html; charset=utf-8")
                return

            if route == "/index.json":
                self._json(200, {
                    "service": "solana-rpc-grpc-registry",
                    "endpoints": {
                        "/": "HTML dashboard",
                        "/health": "service status and scan bookkeeping",
                        "/ready": "200 when a fresh snapshot exists, else 503",
                        "/rpc": "ranked usable JSON-RPC endpoints",
                        "/grpc": "ranked Yellowstone gRPC endpoints",
                        "/all": "both lists",
                    },
                    "interval_seconds": args.interval,
                })
                return

            if route == "/health":
                self._json(200, {
                    "status": "ok",
                    "scanning": snapshot.scanning,
                    "last_error": snapshot.last_error,
                    "scanned_at": data.get("scanned_at"),
                    "age_seconds": round(time.time() - data["scanned_at"], 1) if data.get("scanned_at") else None,
                    "fresh": fresh,
                    "interval_seconds": args.interval,
                    "totals": data.get("totals", {}),
                })
                return

            if route == "/ready":
                if fresh:
                    self._json(200, {"ready": True, "scanned_at": data.get("scanned_at")})
                else:
                    self._json(503, {
                        "ready": False,
                        "reason": "no fresh snapshot yet",
                        "scanned_at": data.get("scanned_at"),
                        "scanning": snapshot.scanning,
                    })
                return

            if not data:
                self._json(503, {"error": "no scan completed yet", "scanning": snapshot.scanning})
                return

            if route == "/rpc":
                self._json(200, self._section(data, "rpc", parse_qs(parsed.query)))
                return
            if route == "/grpc":
                self._json(200, self._section(data, "grpc", parse_qs(parsed.query)))
                return
            if route == "/all":
                self._json(200, {
                    "scanned_at": data.get("scanned_at"),
                    "interval_seconds": data.get("interval_seconds"),
                    "fresh": fresh,
                    "totals": data.get("totals"),
                    "rpc": data.get("rpc", {}),
                    "grpc": data.get("grpc", {}),
                })
                return

            self._json(404, {"error": "unknown route", "path": route})

        @staticmethod
        def _section(data: dict[str, Any], key: str, query: dict[str, list[str]]) -> dict[str, Any]:
            section = dict(data.get(key) or {})
            endpoints = section.get("endpoints") or []
            try:
                limit = int((query.get("limit") or ["0"])[0])
            except ValueError:
                limit = 0
            if limit > 0:
                section = dict(section)
                section["endpoints"] = endpoints[:limit]
                section["returned"] = len(section["endpoints"])
                section["available"] = len(endpoints)
            section["scanned_at"] = data.get("scanned_at")
            section["fresh"] = time.time() <= data.get("expires_at", 0)
            return section

    return RegistryHandler


# --------------------------------------------------------------------------
# entry point
# --------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--host", default="0.0.0.0", help="bind address (default: all interfaces)")
    parser.add_argument("--port", type=int, default=8090)
    parser.add_argument("--user", default=os.environ.get("REGISTRY_USER", "admin"),
                        help="console username (env: REGISTRY_USER)")
    parser.add_argument("--password",
                        default=os.environ.get("REGISTRY_PASSWORD", DEFAULT_PASSWORD),
                        help="console password; prefer REGISTRY_PASSWORD or --password-file "
                             "so it does not show up in `ps` (env: REGISTRY_PASSWORD)")
    parser.add_argument("--password-file",
                        help="read the password from this file instead of --password")
    parser.add_argument("--no-auth", action="store_true",
                        help="disable authentication entirely (local testing only)")
    parser.add_argument("--interval", type=int, default=600,
                        help="seconds between scans (default: 600 = 10 min)")
    parser.add_argument("--cluster-rpc", default=DEFAULT_CLUSTER_RPC)
    parser.add_argument("--tool-path",
                        default=os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                             "solana-validator-rpc-health.py"),
                        help="path to the existing probe tool")
    parser.add_argument("--out-dir", default="/tmp/rpc-grpc-registry")
    parser.add_argument("--state-file", default="/tmp/rpc-grpc-registry/last-scan.json")
    parser.add_argument("--grpc-proto-dir", default=DEFAULT_PROTO_DIR)
    parser.add_argument("--grpc-proto-file", default="geyser.proto")
    parser.add_argument("--grpc-ports", default=DEFAULT_GRPC_PORTS)
    parser.add_argument("--probe-account",
                        default="So11111111111111111111111111111111111111112",
                        help="pubkey used to test getMultipleAccounts support")
    parser.add_argument("--rpc-timeout", type=float, default=3.0)
    parser.add_argument("--rpc-parallel", type=int, default=64)
    parser.add_argument("--tcp-timeout", type=float, default=0.5)
    parser.add_argument("--sweep-parallel", type=int, default=300)
    parser.add_argument("--grpc-timeout", type=float, default=8.0)
    parser.add_argument("--subscribe-timeout", type=float, default=4.0,
                        help="seconds to hold a Subscribe stream open before closing it")
    parser.add_argument("--grpc-parallel", type=int, default=16)
    parser.add_argument("--scan-timeout", type=float, default=300.0,
                        help="hard cap on one RPC scan invocation")
    parser.add_argument("--no-scan", action="store_true",
                        help="serve only the persisted snapshot; do not scan")
    parser.add_argument("--once", action="store_true",
                        help="run a single scan, print it, and exit without serving")
    parser.add_argument("--verbose", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    os.makedirs(args.out_dir, exist_ok=True)

    if args.password_file:
        try:
            with open(args.password_file, encoding="utf-8") as fh:
                args.password = fh.read().strip()
        except OSError as exc:
            print(f"[fatal] cannot read --password-file: {exc}", file=sys.stderr)
            return 2
        if not args.password:
            print("[fatal] --password-file is empty", file=sys.stderr)
            return 2
    if args.no_auth:
        print("[auth] DISABLED — do not expose this beyond localhost", file=sys.stderr)
    elif args.password_file or "REGISTRY_PASSWORD" in os.environ:
        print("[auth] enabled (password from file/env)", flush=True)
    else:
        # Falling back to the built-in password; say so without printing it.
        print(f"[auth] enabled (built-in password, user={args.user})", flush=True)

    proto_file = find_proto_file(args.grpc_proto_dir)
    if not proto_file:
        print(f"[warn] no .proto in {args.grpc_proto_dir}; gRPC scan will fail", flush=True)
        proto_file = args.grpc_proto_file
    elif proto_file != args.grpc_proto_file:
        args.grpc_proto_file = proto_file

    if not os.path.isfile(args.tool_path):
        print(f"[fatal] probe tool not found at {args.tool_path}", file=sys.stderr)
        return 2

    snapshot = Snapshot()
    restored = _restore(args.state_file)
    if restored:
        snapshot.publish(restored)
        print(f"[init] restored snapshot from {args.state_file}", flush=True)

    if args.once:
        run_scan(args, snapshot, args.grpc_proto_dir, args.grpc_proto_file)
        print(json.dumps(snapshot.get(), indent=2))
        return 0

    if not args.no_scan:
        thread = threading.Thread(
            target=scan_loop,
            args=(args, snapshot, args.grpc_proto_dir, args.grpc_proto_file),
            daemon=True,
            name="registry-scan",
        )
        thread.start()

    server = ThreadingHTTPServer((args.host, args.port), make_handler(snapshot, args))
    print(
        f"[serve] http://{args.host}:{args.port}  interval={args.interval}s "
        f"rpc_tool={args.tool_path}",
        flush=True,
    )
    try:
        server.serve_forever(poll_interval=1.0)
    except KeyboardInterrupt:
        print("\n[serve] stopped", flush=True)
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
