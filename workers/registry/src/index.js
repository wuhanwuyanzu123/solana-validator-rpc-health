/**
 * Solana RPC / gRPC registry on Cloudflare Workers.
 *
 * Model: the scanning host pushes its snapshot here; members read it here.
 * That keeps the scan box off the request path entirely — it is already busy,
 * and it must not be a dependency for every member request.
 *
 *   POST /ingest            scanner pushes a snapshot   (INGEST_TOKEN)
 *   GET  /rpc|/grpc|/all    member reads endpoints      (API key)
 *   GET  /health            scanner + snapshot status    (public, no secrets)
 *   POST /pay               redeem a USDC/SOL payment    (public)
 *   GET  /admin/keys        list keys                    (ADMIN_TOKEN)
 *   POST /admin/keys        mint a key                   (ADMIN_TOKEN)
 *   POST /admin/keys/revoke revoke a key                 (ADMIN_TOKEN)
 *   GET  /                  HTML dashboard
 */

const USDC_DECIMALS = 6;
const SOL_DECIMALS = 9;
const KEY_PREFIX = "sk_";
const SESSION_DAYS = 30;

// Durable Object RPC requires extending this base class; a plain class would
// accept the call on the stub and return a promise that never runs on the
// object itself, so writes would silently vanish.
import { DurableObject } from "cloudflare:workers";

// ---------------------------------------------------------------- utilities

const enc = new TextEncoder();

function json(data, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(data, null, 2), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store",
      ...extraHeaders,
    },
  });
}

function timingSafeEqual(a, b) {
  if (typeof a !== "string" || typeof b !== "string") return false;
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

async function sha256Hex(text) {
  const digest = await crypto.subtle.digest("SHA-256", enc.encode(text));
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function randomKey() {
  const bytes = new Uint8Array(24);
  crypto.getRandomValues(bytes);
  const body = [...bytes].map((b) => b.toString(36).padStart(2, "0")).join("");
  return KEY_PREFIX + body.slice(0, 32);
}

function bearer(req) {
  const raw = req.headers.get("authorization") || "";
  const space = raw.indexOf(" ");
  if (space < 0) return "";
  const scheme = raw.slice(0, space).toLowerCase();
  const value = raw.slice(space + 1).trim();
  return scheme === "bearer" ? value : "";
}

function nowSec() {
  return Math.floor(Date.now() / 1000);
}

// ------------------------------------------------------------------ storage

export class RegistryStore extends DurableObject {
  constructor(ctx, env) {
    super(ctx, env);
    this.sql = ctx.storage.sql;
    this.sql.exec(`
      CREATE TABLE IF NOT EXISTS snapshot (
        id INTEGER PRIMARY KEY CHECK (id = 1),
        payload TEXT NOT NULL,
        received_at INTEGER NOT NULL
      );
      CREATE TABLE IF NOT EXISTS api_keys (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        hash TEXT NOT NULL UNIQUE,
        label TEXT NOT NULL DEFAULT '',
        created_at INTEGER NOT NULL,
        expires_at INTEGER NOT NULL,
        revoked INTEGER NOT NULL DEFAULT 0,
        last_used_at INTEGER,
        uses INTEGER NOT NULL DEFAULT 0
      );
      CREATE TABLE IF NOT EXISTS payments (
        signature TEXT PRIMARY KEY,
        mint TEXT NOT NULL,
        amount TEXT NOT NULL,
        payer TEXT NOT NULL DEFAULT '',
        key_id INTEGER,
        redeemed_at INTEGER NOT NULL
      );
    `);
  }

  // -- snapshot ------------------------------------------------------------

  saveSnapshot(payload) {
    const at = nowSec();
    this.sql.exec(
      `INSERT INTO snapshot (id, payload, received_at) VALUES (1, ?, ?)
       ON CONFLICT(id) DO UPDATE SET payload = excluded.payload, received_at = excluded.received_at`,
      payload,
      at,
    );
    return at;
  }

  getSnapshot() {
    const rows = [...this.sql.exec(`SELECT payload, received_at FROM snapshot WHERE id = 1`)];
    if (!rows.length) return null;
    // Return the payload as stored. Callers parse it so a malformed row is
    // reported as corrupt data rather than throwing out of the object RPC.
    return { payload: rows[0].payload, received_at: rows[0].received_at };
  }

  // -- api keys ------------------------------------------------------------

  createKey(label, days) {
    const plaintext = randomKey();
    return sha256Hex(plaintext).then((hash) => {
      const created = nowSec();
      const expires = created + days * 86400;
      this.sql.exec(
        `INSERT INTO api_keys (hash, label, created_at, expires_at) VALUES (?, ?, ?, ?)`,
        hash,
        label || "",
        created,
        expires,
      );
      const id = [...this.sql.exec(`SELECT last_insert_rowid() AS id`)][0].id;
      return { id, key: plaintext, created_at: created, expires_at: expires, label: label || "" };
    });
  }

  async checkKey(plaintext) {
    if (!plaintext.startsWith(KEY_PREFIX)) return { ok: false, reason: "malformed" };
    const hash = await sha256Hex(plaintext);
    const rows = [
      ...this.sql.exec(
        `SELECT id, label, expires_at, revoked FROM api_keys WHERE hash = ?`,
        hash,
      ),
    ];
    if (!rows.length) return { ok: false, reason: "unknown" };
    const row = rows[0];
    if (row.revoked) return { ok: false, reason: "revoked" };
    if (row.expires_at <= nowSec()) return { ok: false, reason: "expired" };
    this.sql.exec(
      `UPDATE api_keys SET last_used_at = ?, uses = uses + 1 WHERE id = ?`,
      nowSec(),
      row.id,
    );
    return { ok: true, id: row.id, label: row.label, expires_at: row.expires_at };
  }

  listKeys() {
    return [...this.sql.exec(
      `SELECT id, label, created_at, expires_at, revoked, last_used_at, uses
       FROM api_keys ORDER BY id DESC LIMIT 200`,
    )];
  }

  revokeKey(id) {
    this.sql.exec(`UPDATE api_keys SET revoked = 1 WHERE id = ?`, id);
    return [...this.sql.exec(`SELECT id, revoked FROM api_keys WHERE id = ?`, id)][0] || null;
  }

  // -- payments ------------------------------------------------------------

  hasPayment(signature) {
    return [...this.sql.exec(`SELECT 1 FROM payments WHERE signature = ?`, signature)].length > 0;
  }

  recordPayment({ signature, mint, amount, payer, keyId }) {
    this.sql.exec(
      `INSERT INTO payments (signature, mint, amount, payer, key_id, redeemed_at)
       VALUES (?, ?, ?, ?, ?, ?)`,
      signature,
      mint,
      amount,
      payer || "",
      keyId ?? null,
      nowSec(),
    );
  }

  // -- housekeeping --------------------------------------------------------

  stats() {
    const counts = {};
    for (const [name, q] of Object.entries({
      active: `SELECT COUNT(*) AS n FROM api_keys WHERE revoked = 0 AND expires_at > ${nowSec()}`,
      revoked: `SELECT COUNT(*) AS n FROM api_keys WHERE revoked = 1`,
      expired: `SELECT COUNT(*) AS n FROM api_keys WHERE revoked = 0 AND expires_at <= ${nowSec()}`,
      payments: `SELECT COUNT(*) AS n FROM payments`,
    })) {
      counts[name] = [...this.sql.exec(q)][0].n;
    }
    return counts;
  }
}

// -------------------------------------------------------- payment verifying

/**
 * Confirm a payment landed on-chain.
 *
 * Reads the parsed transaction and compares the recipient's token balance
 * before and after, which is robust to how the transfer was constructed
 * (direct transfer, routed swap, multiple hops) in a way that scanning
 * instruction lists is not.
 */
async function verifyPayment(env, signature) {
  const price = Number(env.PRICE_USDC || "0");
  const payTo = (env.PAY_TO || "").trim();
  if (!payTo) return { ok: false, error: "收款地址未配置 (PAY_TO)" };
  if (!(price > 0)) return { ok: false, error: "价格未配置 (PRICE_USDC)" };
  if (!/^[1-9A-HJ-NP-Za-km-z]{32,90}$/.test(signature)) {
    return { ok: false, error: "签名格式不合法" };
  }

  const rpc = env.RPC_FOR_VERIFY || "https://api.mainnet-beta.solana.com";
  let tx;
  try {
    const res = await fetch(rpc, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: 1,
        method: "getTransaction",
        params: [signature, { encoding: "jsonParsed", maxSupportedTransactionVersion: 0 }],
      }),
    });
    const body = await res.json();
    tx = body.result;
    if (body.error) return { ok: false, error: `RPC: ${body.error.message || "查询失败"}` };
  } catch (err) {
    return { ok: false, error: `RPC 请求失败: ${String(err).slice(0, 80)}` };
  }

  if (!tx) return { ok: false, error: "链上找不到这笔交易，确认已确认后再试" };
  if (tx.meta && tx.meta.err) return { ok: false, error: "该交易链上执行失败" };

  const usdcMint = env.USDC_MINT || "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";
  const required = BigInt(Math.round(price * 10 ** USDC_DECIMALS));

  const balanceOf = (list, mint, owner) => {
    const hit = (list || []).find(
      (b) => b.mint === mint && b.owner === owner,
    );
    return hit ? BigInt(hit.uiTokenAmount.amount) : 0n;
  };

  const pre = balanceOf(tx.meta?.preTokenBalances, usdcMint, payTo);
  const post = balanceOf(tx.meta?.postTokenBalances, usdcMint, payTo);
  const received = post - pre;

  if (received < required) {
    const got = Number(received) / 10 ** USDC_DECIMALS;
    return {
      ok: false,
      error: `收款金额不足：收到 ${got} USDC，需要 ${price} USDC`,
      received: got,
    };
  }

  const feePayer = tx.transaction?.message?.accountKeys?.[0]?.pubkey
    || tx.transaction?.message?.accountKeys?.[0]
    || "";

  return {
    ok: true,
    signature,
    mint: usdcMint,
    amount: received.toString(),
    payer: typeof feePayer === "string" ? feePayer : "",
    slot: tx.slot,
  };
}

// ------------------------------------------------------------------ routing

async function handleIngest(req, env, store) {
  if (!env.INGEST_TOKEN) return json({ error: "INGEST_TOKEN 未配置" }, 503);
  if (!timingSafeEqual(bearer(req), env.INGEST_TOKEN)) {
    return json({ error: "unauthorized" }, 401);
  }
  let payload;
  try {
    payload = await req.text();
    JSON.parse(payload); // reject non-JSON before it reaches storage
  } catch {
    return json({ error: "body must be JSON" }, 400);
  }
  const at = await store.saveSnapshot(payload);
  return json({ ok: true, received_at: at, bytes: payload.length });
}

async function handleHealth(env, store) {
  const snap = await store.getSnapshot();
  const age = snap ? nowSec() - snap.received_at : null;
  let totals = null;
  if (snap) {
    try {
      totals = JSON.parse(snap.payload).totals || null;
    } catch { /* keep null */ }
  }
  return json({
    status: "ok",
    has_snapshot: Boolean(snap),
    snapshot_age_seconds: age,
    snapshot_received_at: snap?.received_at ?? null,
    stale: age === null ? true : age > 1800,
    totals,
    stats: await store.stats(),
  });
}

async function handlePay(req, env, store) {
  let body;
  try {
    body = await req.json();
  } catch {
    return json({ error: "body must be JSON" }, 400);
  }
  const signature = String(body.signature || "").trim();
  if (!signature) return json({ error: "缺少 signature" }, 400);

  if (await store.hasPayment(signature)) {
    return json({ error: "这笔交易已经兑换过会员了", signature }, 409);
  }

  const verdict = await verifyPayment(env, signature);
  if (!verdict.ok) return json({ error: verdict.error, ...verdict }, 400);

  const days = Number(env.GRANT_DAYS || String(SESSION_DAYS));
  const issued = await store.createKey(`paid:${signature.slice(0, 12)}`, days);
  await store.recordPayment({
    signature,
    mint: verdict.mint,
    amount: verdict.amount,
    payer: verdict.payer,
    keyId: issued.id,
  });

  return json({
    ok: true,
    api_key: issued.key,
    expires_at: issued.expires_at,
    days,
    warning: "这个 key 只显示这一次，请立即保存。",
  });
}

async function handleAdmin(req, env, store) {
  if (!env.ADMIN_TOKEN) return json({ error: "ADMIN_TOKEN 未配置" }, 503);
  if (!timingSafeEqual(bearer(req), env.ADMIN_TOKEN)) {
    return json({ error: "unauthorized" }, 401);
  }
  const url = new URL(req.url);

  if (req.method === "GET" && url.pathname === "/admin/keys") {
    return json({ keys: await store.listKeys(), stats: await store.stats() });
  }
  if (req.method === "POST" && url.pathname === "/admin/keys") {
    let body = {};
    try {
      body = await req.json();
    } catch { /* empty body is fine */ }
    const days = Number(body.days || env.GRANT_DAYS || SESSION_DAYS);
    const issued = await store.createKey(body.label || "manual", days);
    return json({ ok: true, ...issued, warning: "这个 key 只显示这一次。" });
  }
  if (req.method === "POST" && url.pathname === "/admin/keys/revoke") {
    let body = {};
    try {
      body = await req.json();
    } catch { /* fall through to the id check */ }
    const id = Number(body.id);
    if (!Number.isInteger(id)) return json({ error: "需要整数 id" }, 400);
    return json({ ok: true, key: await store.revokeKey(id) });
  }
  return json({ error: "unknown admin route" }, 404);
}

async function handleData(req, env, store, route) {
  const snap = await store.getSnapshot();
  if (!snap) {
    return json({ error: "还没有收到任何扫描数据", stale: true }, 503);
  }
  const age = nowSec() - snap.received_at;
  let data;
  try {
    data = JSON.parse(snap.payload);
  } catch {
    return json({ error: "快照损坏" }, 500);
  }

  const url = new URL(req.url);
  let limit = 0;
  try {
    limit = Math.max(0, Number(url.searchParams.get("limit") || 0));
  } catch { /* keep 0 */ }

  const meta = {
    snapshot_age_seconds: age,
    stale: age > 1800,
    served_from: "cloudflare",
  };

  const trim = (section) => {
    if (!section) return section;
    const out = { ...section };
    if (limit > 0 && Array.isArray(out.endpoints)) {
      out.available = out.endpoints.length;
      out.endpoints = out.endpoints.slice(0, limit);
      out.returned = out.endpoints.length;
    }
    return out;
  };

  if (route === "/rpc") return json({ ...meta, ...trim(data.rpc) });
  if (route === "/grpc") return json({ ...meta, ...trim(data.grpc) });
  return json({
    ...meta,
    scanned_at: data.scanned_at,
    totals: data.totals,
    rpc: trim(data.rpc),
    grpc: trim(data.grpc),
  });
}

// -------------------------------------------------------------------- entry

export default {
  async fetch(req, env) {
    const url = new URL(req.url);
    const path = url.pathname.replace(/\/+$/, "") || "/";
    const store = env.STORE.get(env.STORE.idFromName("main"));

    if (req.method === "OPTIONS") {
      return new Response(null, {
        status: 204,
        headers: {
          "access-control-allow-origin": "*",
          "access-control-allow-methods": "GET, POST, OPTIONS",
          "access-control-allow-headers": "authorization, content-type",
          "access-control-max-age": "600",
        },
      });
    }

    try {
      if (path === "/ingest" && req.method === "POST") {
        return await handleIngest(req, env, store);
      }
      if (path === "/health" && req.method === "GET") {
        return await handleHealth(env, store);
      }
      if (path === "/pay" && req.method === "POST") {
        return await handlePay(req, env, store);
      }
      if (path === "/" && req.method === "GET") {
        return new Response(DASHBOARD_HTML, {
          headers: { "content-type": "text/html; charset=utf-8", "cache-control": "no-store" },
        });
      }
      if (path.startsWith("/admin/")) {
        return await handleAdmin(req, env, store);
      }
      if (["/rpc", "/grpc", "/all"].includes(path)) {
        const presented = bearer(req);
        if (!presented) {
          return json({ error: "需要 API key", hint: "Authorization: Bearer sk_..." }, 401);
        }
        const verdict = await store.checkKey(presented);
        if (!verdict.ok) {
          return json({ error: "API key 无效", reason: verdict.reason }, 401);
        }
        return await handleData(req, env, store, path);
      }
      return json({ error: "not found", path }, 404);
    } catch (err) {
      return json({ error: "internal error", detail: String(err).slice(0, 200) }, 500);
    }
  },
};

// ---------------------------------------------------------------- dashboard

const DASHBOARD_HTML = `<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Solana RPC / gRPC Registry</title>
<style>
  :root{--bg:#0f1115;--panel:#161a21;--panel2:#1c212a;--line:#262c37;--fg:#e6e9ef;
        --dim:#8b95a7;--faint:#5d667a;--ok:#4ade80;--warn:#fbbf24;--bad:#f87171;--accent:#60a5fa}
  *{box-sizing:border-box}
  body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.5 -apple-system,
       BlinkMacSystemFont,"Segoe UI","PingFang SC","Microsoft YaHei",Roboto,sans-serif}
  .wrap{max-width:1240px;margin:0 auto;padding:28px 20px 64px}
  header{display:flex;flex-wrap:wrap;gap:16px;align-items:baseline;justify-content:space-between;margin-bottom:22px}
  h1{font-size:20px;margin:0;font-weight:650}
  h1 span{color:var(--dim);font-weight:400}
  .status{display:flex;gap:10px;align-items:center;font-size:13px;color:var(--dim)}
  .dot{width:8px;height:8px;border-radius:50%;background:var(--dim)}
  .dot.ok{background:var(--ok);box-shadow:0 0 0 3px rgba(74,222,128,.15)}
  .dot.stale{background:var(--warn);box-shadow:0 0 0 3px rgba(251,191,36,.15)}
  button{background:var(--panel2);color:var(--fg);border:1px solid var(--line);
         border-radius:6px;padding:6px 12px;font-size:13px;cursor:pointer}
  button:hover{border-color:var(--accent)}
  .cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin-bottom:24px}
  .card{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:14px 16px}
  .card .k{color:var(--dim);font-size:12px;margin-bottom:6px}
  .card .v{font-size:25px;font-weight:650;letter-spacing:-.5px}
  .card .s{color:var(--faint);font-size:11px;margin-top:4px}
  section{background:var(--panel);border:1px solid var(--line);border-radius:10px;margin-bottom:20px;overflow:hidden}
  .sec-head{display:flex;flex-wrap:wrap;gap:12px;align-items:center;justify-content:space-between;
            padding:14px 16px;border-bottom:1px solid var(--line)}
  .sec-head h2{font-size:15px;margin:0;font-weight:600}
  .sec-head .meta{color:var(--dim);font-size:12px}
  input{background:var(--panel2);border:1px solid var(--line);color:var(--fg);border-radius:6px;
        padding:6px 10px;font-size:13px}
  input:focus{outline:none;border-color:var(--accent)}
  .scroll{overflow-x:auto}
  table{width:100%;border-collapse:collapse;font-size:13px}
  th{text-align:left;color:var(--dim);font-weight:500;font-size:11px;text-transform:uppercase;
     letter-spacing:.6px;padding:10px 16px;border-bottom:1px solid var(--line);white-space:nowrap}
  td{padding:9px 16px;border-bottom:1px solid rgba(38,44,55,.55);white-space:nowrap}
  tbody tr:hover{background:rgba(96,165,250,.05)}
  tbody tr:last-child td{border-bottom:none}
  .rank{color:var(--faint);width:34px}
  .mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
  .num{text-align:right;font-variant-numeric:tabular-nums;
       font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
  .good{color:var(--ok)}.mid{color:var(--warn)}.slow{color:var(--bad)}.muted{color:var(--faint)}
  .copy{background:transparent;border:1px solid var(--line);padding:3px 8px;font-size:11px;
        border-radius:5px;color:var(--dim)}
  .copy:hover{color:var(--fg)}
  .empty{padding:26px 16px;color:var(--dim);text-align:center}
  .note{color:var(--faint);font-size:12px;margin-top:6px;padding:0 4px}
  code{background:var(--panel2);border:1px solid var(--line);padding:1px 5px;border-radius:4px;color:var(--dim);
       font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
  .gate{max-width:420px;margin:60px auto;background:var(--panel);border:1px solid var(--line);
        border-radius:12px;padding:26px 28px}
  .gate h2{margin:0 0 6px;font-size:17px}
  .gate p{margin:0 0 16px;color:var(--dim);font-size:13px}
  .gate input{width:100%;margin-bottom:10px;padding:9px 11px}
  .gate button{width:100%;background:var(--accent);border:none;color:#0b1220;font-weight:600;padding:9px}
  .err{color:var(--bad);font-size:12px;margin-top:10px;min-height:15px}
  .hide{display:none}
</style>
</head>
<body>
<div class="wrap">
  <div id="gate" class="gate">
    <h2>需要 API Key</h2>
    <p>输入你的会员 key 以查看端点列表。</p>
    <input type="password" id="key" placeholder="sk_..." autocomplete="off">
    <button id="enter">进入</button>
    <div class="err" id="err"></div>
    <p style="margin-top:18px;font-size:12px">
      还没有 key？向收款地址转入 USDC，然后到
      <code>/pay</code> 提交交易签名即可兑换。
    </p>
  </div>

  <div id="app" class="hide">
    <header>
      <h1>Solana RPC / gRPC Registry <span>· 端点可用性</span></h1>
      <div class="status">
        <span class="dot" id="dot"></span>
        <span id="age">载入中…</span>
        <button id="refresh">刷新</button>
        <button id="logout">退出</button>
      </div>
    </header>

    <div class="cards" id="cards"></div>

    <section>
      <div class="sec-head">
        <div><h2>JSON-RPC</h2><div class="meta" id="rpcMeta">—</div></div>
        <input id="rpcFilter" placeholder="过滤地址…">
      </div>
      <div class="scroll"><table>
        <thead><tr><th class="rank">#</th><th>Endpoint</th>
          <th style="text-align:right">延迟</th><th>版本</th>
          <th style="text-align:right">Slot</th><th>能力</th><th></th></tr></thead>
        <tbody id="rpcBody"><tr><td colspan="7" class="empty">载入中…</td></tr></tbody>
      </table></div>
    </section>

    <section>
      <div class="sec-head">
        <div><h2>Yellowstone gRPC</h2><div class="meta" id="grpcMeta">—</div></div>
        <input id="grpcFilter" placeholder="过滤地址…">
      </div>
      <div class="scroll"><table>
        <thead><tr><th class="rank">#</th><th>Endpoint</th>
          <th style="text-align:right">TCP</th>
          <th style="text-align:right">推送滞后</th>
          <th>版本</th>
          <th style="text-align:right">流消息</th><th></th></tr></thead>
        <tbody id="grpcBody"><tr><td colspan="7" class="empty">载入中…</td></tr></tbody>
      </table></div>
    </section>
    <div class="note">
      <b>可用判定</b>： gRPC 需 HTTP/2 前导通过 →
      <code>GetVersion</code> 返回版本 → 匿名 <code>Subscribe</code> 实际收到流数据；
      排序按<strong>推送滞后</strong>（服务端 createdAt 到本地接收的时间差）。
    </div>
  </div>
</div>

<script>
var KEY = sessionStorage.getItem('registry_key') || '';
var DATA = null;

function esc(s){return String(s==null?'':s).replace(/[&<>"]/g,function(c){
  return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c];});}
function cls(ms,a,b){return ms==null?'muted':(ms<=a?'good':(ms<=b?'mid':'slow'));}
function age(s){if(s<60)return Math.round(s)+' 秒前';if(s<3600)return Math.round(s/60)+' 分钟前';
  return (s/3600).toFixed(1)+' 小时前';}
function card(k,v,s){return '<div class="card"><div class="k">'+esc(k)+'</div><div class="v">'+esc(v)+
  '</div>'+(s?'<div class="s">'+esc(s)+'</div>':'')+'</div>';}

function load(){
  return fetch('/all',{headers:{'authorization':'Bearer '+KEY},cache:'no-store'})
    .then(function(r){
      if(r.status===401){logout();throw new Error('401');}
      if(!r.ok)throw new Error('HTTP '+r.status);
      return r.json();
    })
    .then(function(d){DATA=d;render();})
    .catch(function(e){ if(e.message!=='401')
      document.getElementById('age').textContent='加载失败: '+e.message; });
}

function render(){
  if(!DATA)return;
  var ageSec=DATA.snapshot_age_seconds, fresh=!DATA.stale;
  document.getElementById('dot').className='dot '+(fresh?'ok':'stale');
  document.getElementById('age').textContent=(fresh?'新鲜 · ':'数据过期 · ')+
    '扫描于 '+age(ageSec)+' · Cloudflare 提供';

  var t=DATA.totals||{}, r=DATA.rpc||{}, g=DATA.grpc||{};
  var rl=r.latency_ms||{}, pl=g.push_lag_ms||{};
  document.getElementById('cards').innerHTML=
    card('可用 RPC', t.rpc_usable!=null?t.rpc_usable:'—','部分可用 '+(t.rpc_partial||0))+
    card('可用 gRPC', t.grpc_usable!=null?t.grpc_usable:'—',
         'h2c 候选 '+((g.counts||{}).h2c||0))+
    card('RPC 延迟 P50', rl.p50!=null?rl.p50+'ms':'—',
         rl.min!=null?'min '+rl.min+'ms':'—')+
    card('gRPC 推送滞后 P50', pl.p50!=null?pl.p50+'ms':'—',
         pl.min!=null?'min '+pl.min+'ms':'—');

  var rc=r.counts||{}, gc=g.counts||{};
  document.getElementById('rpcMeta').textContent=
    rc.usable+' 可用 / '+rc.healthy+' 健康 / '+rc.advertised+' 广告';
  document.getElementById('grpcMeta').textContent=
    (gc.subscribe_ok||0)+' 订阅通过 / '+(gc.getversion_ok||0)+' GetVersion / '+
    (gc.cluster_ips||0)+' 节点 · '+(gc.race_slots||0)+' 条样本';

  renderRpc(r.endpoints||[]); renderGrpc(g.endpoints||[]);
}

function renderRpc(rows){
  var q=(document.getElementById('rpcFilter').value||'').toLowerCase();
  var out=rows.filter(function(e){return !q||e.endpoint.toLowerCase().indexOf(q)>=0;});
  document.getElementById('rpcBody').innerHTML = out.length ? out.map(function(e,i){
    var caps=[]; if(e.getLatestBlockhash)caps.push('blockhash');
    if(e.getMultipleAccounts)caps.push('accounts');
    return '<tr><td class="rank">'+(i+1)+'</td>'+
      '<td class="mono">'+esc(e.endpoint)+'</td>'+
      '<td class="num '+cls(e.latency_ms,50,250)+'">'+(e.latency_ms!=null?e.latency_ms+'ms':'—')+'</td>'+
      '<td>'+esc(e.version||'—')+'</td>'+
      '<td class="num muted">'+esc(e.slot||'—')+'</td>'+
      '<td class="muted">'+esc(caps.join(', ')||'—')+'</td>'+
      '<td><button class="copy" data-v="'+esc(e.endpoint)+'">复制</button></td></tr>';
  }).join('') : '<tr><td colspan="7" class="empty">没有可用的 RPC</td></tr>';
}

function renderGrpc(rows){
  var q=(document.getElementById('grpcFilter').value||'').toLowerCase();
  var out=rows.filter(function(e){return !q||e.endpoint.toLowerCase().indexOf(q)>=0;});
  document.getElementById('grpcBody').innerHTML = out.length ? out.map(function(e,i){
    return '<tr><td class="rank">'+(i+1)+'</td>'+
      '<td class="mono">'+esc(e.endpoint)+'</td>'+
      '<td class="num '+cls(e.tcp_ms,5,30)+'">'+(e.tcp_ms!=null?e.tcp_ms+'ms':'—')+'</td>'+
      '<td class="num '+cls(e.push_lag_ms,10,50)+'">'+(e.push_lag_ms!=null?e.push_lag_ms+'ms':'—')+'</td>'+
      '<td>'+esc(e.version||'—')+'</td>'+
      '<td class="num muted">'+(e.stream_messages!=null?e.stream_messages:'—')+'</td>'+
      '<td><button class="copy" data-v="'+esc(e.endpoint)+'">复制</button></td></tr>';
  }).join('') : '<tr><td colspan="7" class="empty">没有可用的 gRPC</td></tr>';
}

function enter(){
  var v=document.getElementById('key').value.trim();
  if(!v){document.getElementById('err').textContent='请输入 key';return;}
  fetch('/health',{headers:{'authorization':'Bearer '+v}})
    .then(function(r){
      if(!r.ok){document.getElementById('err').textContent='key 无效或已过期';return;}
      return fetch('/all',{headers:{'authorization':'Bearer '+v},cache:'no-store'})
        .then(function(r2){
          if(r2.status===401){document.getElementById('err').textContent='key 无效或已过期';return;}
          return r2.json().then(function(d){
            KEY=v; sessionStorage.setItem('registry_key',v);
            document.getElementById('gate').classList.add('hide');
            document.getElementById('app').classList.remove('hide');
            DATA=d; render();
          });
        });
    })
    .catch(function(){document.getElementById('err').textContent='网络错误';});
}

function logout(){
  KEY=''; sessionStorage.removeItem('registry_key');
  document.getElementById('app').classList.add('hide');
  document.getElementById('gate').classList.remove('hide');
  document.getElementById('key').value='';
}

document.getElementById('enter').addEventListener('click',enter);
document.getElementById('key').addEventListener('keydown',function(e){if(e.key==='Enter')enter();});
document.getElementById('refresh').addEventListener('click',load);
document.getElementById('logout').addEventListener('click',logout);
document.getElementById('rpcFilter').addEventListener('input',function(){if(DATA)renderRpc(DATA.rpc.endpoints||[]);});
document.getElementById('grpcFilter').addEventListener('input',function(){if(DATA)renderGrpc(DATA.grpc.endpoints||[]);});
document.addEventListener('click',function(ev){
  var b=ev.target.closest&&ev.target.closest('.copy');
  if(!b)return;
  var text=b.getAttribute('data-v');
  navigator.clipboard.writeText(text).then(function(){
    var o=b.textContent; b.textContent='已复制';
    setTimeout(function(){b.textContent=o;},1200);
  });
});

if(KEY){
  document.getElementById('gate').classList.add('hide');
  document.getElementById('app').classList.remove('hide');
  load();
}
setInterval(function(){if(KEY)load();},60000);
</script>
</body>
</html>`;
