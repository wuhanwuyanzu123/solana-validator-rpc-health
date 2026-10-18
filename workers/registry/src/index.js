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
    // Public facts the landing page and the sign-up form both need. The
    // receiving address is a published payment destination, not a secret.
    pricing: {
      price_usdc: env.PRICE_USDC || "0",
      pay_to: (env.PAY_TO || "").trim(),
      grant_days: Number(env.GRANT_DAYS || String(SESSION_DAYS)),
      usdc_mint: env.USDC_MINT || "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
      open: Boolean((env.PAY_TO || "").trim()) && Number(env.PRICE_USDC || 0) > 0,
    },
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
  body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.6 -apple-system,
       BlinkMacSystemFont,"Segoe UI","PingFang SC","Microsoft YaHei",Roboto,sans-serif;
       -webkit-font-smoothing:antialiased}
  .wrap{max-width:1180px;margin:0 auto;padding:0 20px 72px}
  a{color:var(--accent);text-decoration:none}
  code{background:var(--panel2);border:1px solid var(--line);padding:1px 6px;border-radius:4px;
       font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:.92em}
  .hide{display:none!important}

  /* ---------- shared chrome ---------- */
  nav{position:sticky;top:0;z-index:20;background:rgba(15,17,21,.88);backdrop-filter:blur(8px);
      border-bottom:1px solid var(--line);margin-bottom:0}
  .nav-in{max-width:1180px;margin:0 auto;padding:14px 20px;display:flex;gap:16px;
          align-items:center;justify-content:space-between;flex-wrap:wrap}
  .brand{font-size:15px;font-weight:650;letter-spacing:.2px;white-space:nowrap}
  .brand span{color:var(--dim);font-weight:400}
  .nav-actions{display:flex;gap:9px;align-items:center}
  button{font:inherit;background:var(--panel2);color:var(--fg);border:1px solid var(--line);
         border-radius:7px;padding:7px 15px;cursor:pointer;transition:border-color .12s,background .12s}
  button:hover{border-color:var(--accent)}
  button.primary{background:var(--accent);border-color:var(--accent);color:#0b1220;font-weight:600}
  button.primary:hover{filter:brightness(1.08)}
  button.ghost{background:transparent;color:var(--dim)}
  button.ghost:hover{color:var(--fg)}
  button.sm{padding:4px 10px;font-size:12px}

  .status{display:flex;gap:9px;align-items:center;font-size:12.5px;color:var(--dim);white-space:nowrap}
  .dot{width:8px;height:8px;border-radius:50%;background:var(--faint);flex:none}
  .dot.ok{background:var(--ok);box-shadow:0 0 0 3px rgba(74,222,128,.15)}
  .dot.stale{background:var(--warn);box-shadow:0 0 0 3px rgba(251,191,36,.15)}

  /* ---------- landing ---------- */
  .hero{padding:76px 0 54px;text-align:center}
  .hero h1{font-size:38px;line-height:1.22;margin:0 0 16px;font-weight:680;letter-spacing:-.6px}
  .hero h1 em{font-style:normal;color:var(--accent)}
  .hero p{font-size:16.5px;color:var(--dim);max-width:660px;margin:0 auto 30px;line-height:1.7}
  .cta{display:flex;gap:12px;justify-content:center;flex-wrap:wrap}
  .cta button{padding:12px 26px;font-size:15px}
  .hero-note{margin-top:16px;font-size:13px;color:var(--faint)}

  .stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:12px;margin:8px 0 56px}
  .card{background:var(--panel);border:1px solid var(--line);border-radius:11px;padding:16px 18px}
  .card .k{color:var(--dim);font-size:12.5px;margin-bottom:7px}
  .card .v{font-size:27px;font-weight:660;letter-spacing:-.6px;font-variant-numeric:tabular-nums}
  .card .s{color:var(--faint);font-size:11.5px;margin-top:5px}

  .grid3{display:grid;grid-template-columns:repeat(auto-fit,minmax(258px,1fr));gap:14px;margin-bottom:56px}
  .feat{background:var(--panel);border:1px solid var(--line);border-radius:11px;padding:20px 20px 22px}
  .feat h3{margin:0 0 8px;font-size:15.5px;font-weight:640}
  .feat p{margin:0;color:var(--dim);font-size:13.5px;line-height:1.65}
  .ico{font-size:19px;margin-bottom:11px;display:block}

  h2.sec{font-size:21px;margin:0 0 8px;font-weight:650;letter-spacing:-.2px}
  .sub{color:var(--dim);font-size:14px;margin:0 0 26px}
  .pricing{background:linear-gradient(155deg,var(--panel),#12161d);
           border:1px solid var(--line);border-radius:14px;padding:34px 30px;text-align:center;
           max-width:520px;margin:0 auto}
  .price{font-size:46px;font-weight:700;letter-spacing:-1.5px;margin:6px 0 2px}
  .price small{font-size:17px;font-weight:500;color:var(--dim);letter-spacing:0}
  .price-sub{color:var(--dim);font-size:14px;margin-bottom:22px}
  .plist{list-style:none;padding:0;margin:22px 0 0;text-align:left;max-width:340px;
         margin-left:auto;margin-right:auto;font-size:13.5px;color:var(--dim)}
  .plist li{padding:7px 0;border-bottom:1px solid var(--line);display:flex;gap:10px}
  .plist li:last-child{border-bottom:none}
  .plist .yes{color:var(--ok);flex:none}

  .flow{display:grid;grid-template-columns:repeat(auto-fit,minmax(210px,1fr));gap:14px;margin-bottom:56px}
  .step{background:var(--panel);border:1px solid var(--line);border-radius:11px;padding:18px}
  .step .n{display:inline-block;width:24px;height:24px;line-height:24px;text-align:center;
           border-radius:50%;background:var(--accent);color:#0b1220;font-size:12px;
           font-weight:700;margin-bottom:11px}
  .step h4{margin:0 0 6px;font-size:14.5px}
  .step p{margin:0;color:var(--dim);font-size:13px;line-height:1.6}

  .cbox{background:var(--panel);border:1px solid var(--line);border-radius:13px;
        max-width:470px;margin:64px auto 0;padding:30px 30px 32px}
  .cbox h2{margin:0 0 7px;font-size:19px;font-weight:650}
  .cbox p.lead{margin:0 0 20px;color:var(--dim);font-size:14px;line-height:1.65}
  .field{width:100%;background:var(--panel2);border:1px solid var(--line);color:var(--fg);
         border-radius:8px;padding:12px 13px;font:inherit;font-size:14.5px;margin-bottom:13px}
  .field::placeholder{color:var(--faint)}
  .field:focus{outline:none;border-color:var(--accent)}
  .field.mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:13.5px}
  .field.addr{word-break:break-all;font-size:13px}
  .cbox .primary{width:100%;padding:11px;font-size:15px}
  .err{color:var(--bad);font-size:13px;margin-top:12px;min-height:17px}
  .fine{font-size:12.5px;color:var(--faint);margin-top:17px;line-height:1.7}
  .fine a{cursor:pointer;text-decoration:underline;text-decoration-color:var(--faint)}
  .fine a:hover{text-decoration-color:var(--accent)}

  .payrow{background:var(--panel2);border:1px solid var(--line);border-radius:8px;
          padding:11px 13px;margin-bottom:13px}
  .payrow .lbl{font-size:11.5px;color:var(--faint);text-transform:uppercase;
               letter-spacing:.5px;margin-bottom:5px}
  .payrow .val{font-size:14.5px;font-weight:600;font-variant-numeric:tabular-nums}
  .payrow .val.addr{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;
                    font-size:12.5px;word-break:break-all;font-weight:500}
  .muted-notice{background:rgba(251,191,36,.07);border:1px solid rgba(251,191,36,.3);
                color:var(--warn);border-radius:8px;padding:11px 13px;font-size:13px;margin-bottom:14px}

  .gotkey{background:var(--panel2);border:1px solid var(--line);border-radius:9px;
          padding:15px 16px;margin-bottom:14px}
  .gotkey .lbl{font-size:11.5px;color:var(--faint);text-transform:uppercase;letter-spacing:.5px}
  .gotkey .kv{font-size:14.5px;font-weight:650;margin-top:5px;word-break:break-all;
              font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;color:var(--ok)}

  /* ---------- app ---------- */
  .app-head{display:flex;flex-wrap:wrap;gap:16px;align-items:baseline;
            justify-content:space-between;padding:34px 0 22px}
  .app-head h1{font-size:23px;margin:0;font-weight:660;letter-spacing:-.3px}
  .app-head h1 span{color:var(--dim);font-weight:400;font-size:15px}

  section{background:var(--panel);border:1px solid var(--line);border-radius:11px;
          margin-bottom:20px;overflow:hidden}
  .sec-head{display:flex;flex-wrap:wrap;gap:12px;align-items:center;justify-content:space-between;
            padding:15px 17px;border-bottom:1px solid var(--line)}
  .sec-head h2{font-size:15.5px;margin:0;font-weight:620}
  .sec-head .meta{color:var(--dim);font-size:12.5px;margin-top:3px}
  input.search{background:var(--panel2);border:1px solid var(--line);color:var(--fg);
               border-radius:7px;padding:7px 11px;font-size:13px;width:200px}
  input.search:focus{outline:none;border-color:var(--accent)}
  .scroll{overflow-x:auto}
  table{width:100%;border-collapse:collapse;font-size:13.5px}
  th{text-align:left;color:var(--dim);font-weight:500;font-size:11px;text-transform:uppercase;
     letter-spacing:.6px;padding:11px 17px;border-bottom:1px solid var(--line);white-space:nowrap}
  td{padding:10px 17px;border-bottom:1px solid rgba(38,44,55,.55);white-space:nowrap}
  tbody tr:hover{background:rgba(96,165,250,.05)}
  tbody tr:last-child td{border-bottom:none}
  .rank{color:var(--faint);width:34px}
  .mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
  .num{text-align:right;font-variant-numeric:tabular-nums;
       font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
  .good{color:var(--ok)}.mid{color:var(--warn)}.slow{color:var(--bad)}.muted{color:var(--faint)}
  .copy{background:transparent;border:1px solid var(--line);padding:4px 9px;font-size:11.5px;
        border-radius:6px;color:var(--dim)}
  .copy:hover{color:var(--fg)}
  .empty{padding:30px 17px;color:var(--dim);text-align:center}
  .note{color:var(--faint);font-size:12.5px;margin-top:7px;line-height:1.7}
  .note b{color:var(--dim);font-weight:500}

  footer{border-top:1px solid var(--line);margin-top:64px;padding-top:24px;
         color:var(--faint);font-size:12.5px;display:flex;gap:16px;
         justify-content:space-between;flex-wrap:wrap}

  @media(max-width:640px){
    .hero{padding:52px 0 40px}
    .hero h1{font-size:29px}
    .price{font-size:40px}
    .cbox{margin-top:44px;padding:24px 20px 26px}
    .nav-in{padding:12px 16px}
  }
</style>
</head>
<body>

<nav><div class="nav-in">
  <div class="brand">Solana RPC / gRPC <span>Registry</span></div>
  <div class="nav-actions">
    <div class="status"><span class="dot" id="dot"></span><span id="age">载入中…</span></div>
    <button class="ghost sm hide" id="nav-logout">退出</button>
  </div>
</div></nav>

<div class="wrap">

<!-- ============================ LANDING ============================ -->
<div id="v-landing">
  <div class="hero">
    <h1>实测可用的 Solana<br><em>RPC 与 gRPC</em> 端点</h1>
    <p>
      每 10 分钟自动扫描全网 ~3800 个验证者节点，只保留真正能用的端点：
      RPC 必须三个关键方法齐全，gRPC 必须真能推流。
      按<strong style="color:var(--fg)">推送滞后</strong>排序——不是握手延迟，是你能感觉到的数据到达速度。
    </p>
    <div class="cta">
      <button class="primary" onclick="go('register')">注册会员</button>
      <button onclick="go('login')">已有 key？登录</button>
    </div>
    <div class="hero-note">云端托管 · 无免费层 · 需 API key 访问</div>
  </div>

  <div class="stats" id="landing-stats">
    <div class="card"><div class="k">可用 JSON-RPC</div><div class="v" id="s-rpc">—</div>
      <div class="s" id="s-rpc-sub">加载中…</div></div>
    <div class="card"><div class="k">可用 Yellowstone gRPC</div><div class="v" id="s-grpc">—</div>
      <div class="s" id="s-grpc-sub">加载中…</div></div>
    <div class="card"><div class="k">数据新鲜度</div><div class="v" id="s-age">—</div>
      <div class="s">每 10 分钟刷新</div></div>
    <div class="card"><div class="k">扫描规模</div><div class="v" id="s-nodes">—</div>
      <div class="s">节点 IP</div></div>
  </div>

  <div class="grid3">
    <div class="feat"><span class="ico">📡</span><h3>推送滞后排序</h3>
      <p>同时打开所有端点的订阅流，取服务端 <code>createdAt</code> 与本地接收时间的差值中位数。
      这是真实的数据到达延迟，比 GetVersion 往返更接近你实际的使用体感。</p></div>
    <div class="feat"><span class="ico">🔍</span><h3>严苛的可用性门槛</h3>
      <p>RPC 必须 <code>getHealth</code> + <code>getLatestBlockhash</code> +
      <code>getMultipleAccounts</code> 三项全过；很多看着通的端点其实只给 <code>getSlot</code>。
      gRPC 必须 HTTP/2、返回版本、且真的能收到流数据。</p></div>
    <div class="feat"><span class="ico">🛡️</span><h3>剔除需要 token 的</h3>
      <p>需要认证的 gRPC 端点全部丢弃并只保留计数——你拿到的每一行都是能直接连的，
      不会写到一半才发现要 token。</p></div>
    <div class="feat"><span class="ico">⚡</span><h3>Cloudflare 边缘访问</h3>
      <p>扫描与服务解耦。数据由扫描机推送，你从离自己最近的 Cloudflare 节点读取，
      扫描机本身不承载任何成员请求。</p></div>
    <div class="feat"><span class="ico">📊</span><h3>内核级 RTT</h3>
      <p>连接延迟取自内核 TCP_INFO 的 <code>tcpi_rtt</code>，不受进程被调度延迟影响——
      在已经跑满的机器上，用户态计时会严重失真。</p></div>
    <div class="feat"><span class="ico">🔁</span><h3>失败自愈</h3>
      <p>扫描线程对任何异常都兜底，不会因为一次偶发超时就永久停摆。
      连续失败次数与最后成功时间直接暴露在 <code>/health</code>。</p></div>
  </div>

  <div class="flow">
    <div class="step"><span class="n">1</span><h4>选择套餐</h4>
      <p>USDC 支付，链上自动核验收款金额，无需人工确认。</p></div>
    <div class="step"><span class="n">2</span><h4>提交交易签名</h4>
      <p>把转账后的签名填进去，系统验证链上到账后立即签发 key。</p></div>
    <div class="step"><span class="n">3</span><h4>拿到 API key</h4>
      <p>网页登录直接看，或者 <code>Authorization: Bearer sk_...</code> 调接口。</p></div>
  </div>

  <div class="pricing">
    <div class="price">5 <small>USDC</small></div>
    <div class="price-sub">按 30 天 计 · 按钱包地址发放，可随续</div>
    <ul class="plist">
      <li><span class="yes">✓</span> 完整 JSON-RPC 列表 + 能力标注</li>
      <li><span class="yes">✓</span> 完整 Yellowstone gRPC 列表</li>
      <li><span class="yes">✓</span> 推送滞后 / TCP RTT 双指标排序</li>
      <li><span class="yes">✓</span> 每 10 分钟更新，边缘节点读取</li>
      <li><span class="yes">✓</span> 网页控制台 + REST API 同一 key</li>
    </ul>
    <div class="cta" style="margin-top:26px">
      <button class="primary" onclick="go('register')">立即注册</button>
    </div>
  </div>

  <footer>
    <span>数据来自公开链上观测 · 端点随时可能变化</span>
    <span>注册遇问题可直接用 <a onclick="go('login')">已有 key 登录</a></span>
  </footer>
</div>

<!-- ============================ LOGIN ============================ -->
<div id="v-login" class="hide">
  <div class="cbox">
    <h2>登录</h2>
    <p class="lead">输入你已有的 API key 查看端点列表。</p>
    <input class="field mono" type="password" id="login-key"
           placeholder="sk_..." autocomplete="current-password">
    <button class="primary" id="login-btn">进入</button>
    <div class="err" id="login-err"></div>
    <div class="fine">还没有 key？<a onclick="go('register')">去注册 →</a><br>
      <a onclick="go('landing')">← 返回首页</a></div>
  </div>
</div>

<!-- ========================== REGISTER ========================== -->
<div id="v-register" class="hide">
  <div class="cbox">
    <h2>注册会员</h2>
    <p class="lead">支付 5 USDC / 30 天，链上核验到账后立即发 key。</p>

    <div class="muted-notice hide" id="reg-closed">收款地址尚未配置，注册暂时不可用。</div>

    <div id="reg-form">
      <div class="payrow">
        <div class="lbl">收款地址 (Solana)</div>
        <div class="val addr" id="reg-addr">加载中…</div>
      </div>
      <div class="payrow">
        <div class="lbl">金额</div>
        <div class="val" id="reg-amount">5 USDC</div>
      </div>
      <div class="payrow">
        <div class="lbl">代币</div>
        <div class="val" style="font-size:13px">USDC</div>
      </div>
      <input class="field mono" id="reg-sig"
             placeholder="粘贴转账后的交易签名…" autocomplete="off">
      <button class="primary" id="reg-btn">验证到账并获取 key</button>
      <div class="err" id="reg-err"></div>
      <div class="fine">
        签名会被查询主网 <code>getTransaction</code>，比对收款地址 USDC 余额前后差额，
        同一个签名只能兑换一次。<br>
        <a onclick="go('login')">已有 key？去登录 →</a><br>
        <a onclick="go('landing')">← 返回首页</a>
      </div>
    </div>

    <div class="hide" id="reg-done">
      <div class="gotkey">
        <div class="lbl">你的 API key（只显示这一次）</div>
        <div class="kv" id="reg-key"></div>
      </div>
      <button class="primary" id="reg-use">用这个 key 进入</button>
      <div class="fine">请立即复制保存。丢失后需要重新兑换或联系管理员补发。</div>
    </div>
  </div>
</div>

<!-- ============================ APP ============================ -->
<div id="v-app" class="hide">
  <div class="app-head">
    <h1>Solana RPC / gRPC <span>· 端点可用性</span></h1>
    <div class="nav-actions">
      <button class="sm" id="app-refresh">刷新</button>
      <button class="sm ghost" id="app-back">首页</button>
    </div>
  </div>

  <div class="stats" id="app-stats">
    <div class="card"><div class="k">可用 RPC</div><div class="v" id="a-rpc">—</div>
      <div class="s" id="a-rpc-sub">—</div></div>
    <div class="card"><div class="k">可用 gRPC</div><div class="v" id="a-grpc">—</div>
      <div class="s" id="a-grpc-sub">—</div></div>
    <div class="card"><div class="k">RPC 延迟 P50</div><div class="v" id="a-rp50">—</div>
      <div class="s" id="a-rp50s">—</div></div>
    <div class="card"><div class="k">推送滞后 P50</div><div class="v" id="a-pp50">—</div>
      <div class="s" id="a-pp50s">—</div></div>
  </div>

  <section>
    <div class="sec-head">
      <div><h2>JSON-RPC</h2><div class="meta" id="rpcMeta">—</div></div>
      <input class="search" id="rpcFilter" placeholder="过滤地址…">
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
      <input class="search" id="grpcFilter" placeholder="过滤地址…">
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
    <b>RPC 可用判定</b>： <code>getHealth</code> + <code>getLatestBlockhash</code> +
    <code>getMultipleAccounts</code> 三项全过。<br>
    <b>gRPC 可用判定</b>： HTTP/2 前导通过 → <code>GetVersion</code> 返回版本 →
    匿名 <code>Subscribe</code> 实际收到流数据。需要 token 的一律剔除。<br>
    <b>排序</b>： gRPC 按推送滞后（服务端 createdAt 到本地接收的时间差），TCP 作为次级排序。
  </div>
</div>

</div>

<script>
var KEY = sessionStorage.getItem('registry_key') || '';
var DATA = null, HEAL = null;
var CURRENT = KEY ? 'app' : 'landing';

function $(id){return document.getElementById(id);}
function esc(s){return String(s==null?'':s).replace(/[&<>"]/g,function(c){
  return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c];});}
function cls(ms,a,b){return ms==null?'muted':(ms<=a?'good':(ms<=b?'mid':'slow'));}
function fmtAge(s){
  if(s==null)return '—';
  if(s<60)return Math.round(s)+' 秒前';
  if(s<3600)return Math.round(s/60)+' 分钟前';
  return (s/3600).toFixed(1)+' 小时前';
}
function cardVal(el,txt,sub){
  if(el)el.textContent=txt;
  if(sub!=null){var s=$(el.id+'-sub')||$(el.id+'s');if(s)s.textContent=sub;}
}

/* ---------------- view routing ---------------- */
function go(name){
  ['landing','login','register','app'].forEach(function(v){
    var el=$('v-'+v); if(el)el.classList.toggle('hide', v!==name);
  });
  CURRENT=name;
  var showLogout = name==='app';
  $('nav-logout').classList.toggle('hide', !showLogout);
  document.getElementById('reg-closed');
  window.scrollTo(0,0);
  if(name==='landing')loadHealth();
  if(name==='register')loadHealth();
  if(name==='login')setTimeout(function(){$('login-key').focus();},80);
  if(name==='app')load();
}

/* ---------------- public health ---------------- */
function loadHealth(){
  return fetch('/health',{cache:'no-store'}).then(function(r){return r.json();})
    .then(function(d){
      HEAL=d;
      var t=d.totals||{}, p=d.pricing||{};
      $('s-rpc').textContent = t.rpc_usable!=null?t.rpc_usable:'—';
      $('s-rpc-sub').textContent = t.rpc_usable!=null
        ? '另有 '+t.rpc_partial+' 个方法受限' : '等待首次扫描';
      $('s-grpc').textContent = t.grpc_usable!=null?t.grpc_usable:'—';
      $('s-grpc-sub').textContent = t.grpc_usable!=null
        ? '需 token 的已剔除' : '等待首次扫描';
      $('s-age').textContent = d.has_snapshot?fmtAge(d.snapshot_age_seconds):'—';
      $('s-nodes').textContent = '3800+';

      var dot=$('dot'), ageEl=$('age');
      if(!d.has_snapshot){dot.className='dot';ageEl.textContent='等待首次扫描';}
      else if(d.stale){dot.className='dot stale';ageEl.textContent='数据过期 · '+fmtAge(d.snapshot_age_seconds);}
      else {dot.className='dot ok';ageEl.textContent='新鲜 · '+fmtAge(d.snapshot_age_seconds);}

      if(p.pay_to){
        $('reg-addr').textContent=p.pay_to;
        $('reg-amount').textContent=(p.price_usdc||'5')+' USDC / '+(p.grant_days||30)+' 天';
        $('reg-closed').classList.add('hide');
        $('reg-form').classList.remove('hide');
      }else{
        $('reg-closed').classList.remove('hide');
        $('reg-form').classList.add('hide');
      }
    }).catch(function(){});
}

/* ---------------- login ---------------- */
function doLogin(){
  var v=$('login-key').value.trim();
  if(!v){$('login-err').textContent='请输入 API key';return;}
  $('login-err').textContent='';
  $('login-btn').disabled=true;
  fetch('/all',{headers:{'authorization':'Bearer '+v},cache:'no-store'})
    .then(function(r){
      $('login-btn').disabled=false;
      if(r.status===401){$('login-err').textContent='key 无效或已过期';return;}
      if(!r.ok){$('login-err').textContent='服务暂时不可用 (HTTP '+r.status+')';return;}
      return r.json().then(function(d){
        KEY=v; sessionStorage.setItem('registry_key',v);
        $('login-key').value='';
        go('app');
      });
    })
    .catch(function(e){$('login-btn').disabled=false;
      $('login-err').textContent='网络错误';});
}

/* ---------------- register ---------------- */
function doRegister(){
  var sig=$('reg-sig').value.trim();
  if(!sig){$('reg-err').textContent='请填写交易签名';return;}
  $('reg-err').textContent='';
  $('reg-btn').disabled=true;
  $('reg-btn').textContent='验证中…';
  fetch('/pay',{method:'POST',headers:{'content-type':'application/json'},
    body:JSON.stringify({signature:sig})})
    .then(function(r){return r.json().then(function(d){
      $('reg-btn').disabled=false;
      $('reg-btn').textContent='验证到账并获取 key';
      if(!r.ok){$('reg-err').textContent=d.error||('HTTP '+r.status);return;}
      $('reg-form').classList.add('hide');
      $('reg-done').classList.remove('hide');
      $('reg-key').textContent=d.api_key;
      sessionStorage.setItem('pending_key',d.api_key);
    });})
    .catch(function(){$('reg-btn').disabled=false;
      $('reg-btn').textContent='验证到账并获取 key';
      $('reg-err').textContent='网络错误';});
}

function useNewKey(){
  var v=sessionStorage.getItem('pending_key');
  if(!v)return;
  sessionStorage.removeItem('pending_key');
  KEY=v; sessionStorage.setItem('registry_key',v);
  $('reg-sig').value='';
  $('reg-done').classList.add('hide');
  $('reg-form').classList.remove('hide');
  go('app');
}

/* ---------------- app data ---------------- */
function load(){
  if(!KEY){go('login');return;}
  return fetch('/all',{headers:{'authorization':'Bearer '+KEY},cache:'no-store'})
    .then(function(r){
      if(r.status===401){sessionStorage.removeItem('registry_key');KEY='';
        go('login');return;}
      if(!r.ok)throw new Error('HTTP '+r.status);
      return r.json();
    })
    .then(function(d){DATA=d;render();})
    .catch(function(){});
}

function render(){
  if(!DATA)return;
  var ageSec=DATA.snapshot_age_seconds, fresh=!DATA.stale;
  $('dot').className='dot '+(fresh?'ok':'stale');
  $('age').textContent=(fresh?'新鲜 · ':'数据过期 · ')+fmtAge(ageSec);

  var t=DATA.totals||{}, r=DATA.rpc||{}, g=DATA.grpc||{};
  var rl=r.latency_ms||{}, pl=g.push_lag_ms||{};
  $('a-rpc').textContent=t.rpc_usable!=null?t.rpc_usable:'—';
  $('a-rpc-sub').textContent='另有 '+(t.rpc_partial||0)+' 个方法受限';
  $('a-grpc').textContent=t.grpc_usable!=null?t.grpc_usable:'—';
  $('a-grpc-sub').textContent='h2c 候选 '+((g.counts||{}).h2c||0);
  $('a-rp50').textContent=rl.p50!=null?rl.p50+'ms':'—';
  $('a-rp50s').textContent=rl.min!=null?'min '+rl.min+'ms':'—';
  $('a-pp50').textContent=pl.p50!=null?pl.p50+'ms':'—';
  $('a-pp50s').textContent=pl.min!=null?'min '+pl.min+'ms':'—';

  var rc=r.counts||{}, gc=g.counts||{};
  $('rpcMeta').textContent=
    rc.usable+' 可用 / '+rc.healthy+' 健康 / '+rc.advertised+' 广告 · '+(r.scan_seconds||0)+'s';
  $('grpcMeta').textContent=
    (gc.subscribe_ok||0)+' 订阅通过 / '+(gc.getversion_ok||0)+' GetVersion / '+
    (gc.cluster_ips||0)+' 节点 · '+(gc.race_slots||0)+' 条样本';

  renderRpc(r.endpoints||[]);
  renderGrpc(g.endpoints||[]);
}

function renderRpc(rows){
  var q=($('rpcFilter').value||'').toLowerCase();
  var out=rows.filter(function(e){return !q||e.endpoint.toLowerCase().indexOf(q)>=0;});
  $('rpcBody').innerHTML = out.length ? out.map(function(e,i){
    var caps=[]; if(e.getLatestBlockhash)caps.push('blockhash');
    if(e.getMultipleAccounts)caps.push('accounts');
    return '<tr><td class="rank">'+(i+1)+'</td>'+
      '<td class="mono">'+esc(e.endpoint)+'</td>'+
      '<td class="num '+cls(e.latency_ms,50,250)+'">'+
        (e.latency_ms!=null?e.latency_ms+'ms':'—')+'</td>'+
      '<td>'+esc(e.version||'—')+'</td>'+
      '<td class="num muted">'+esc(e.slot||'—')+'</td>'+
      '<td class="muted">'+esc(caps.join(', ')||'—')+'</td>'+
      '<td><button class="copy" data-v="'+esc(e.endpoint)+'">复制</button></td></tr>';
  }).join('') : '<tr><td colspan="7" class="empty">没有匹配的 RPC</td></tr>';
}

function renderGrpc(rows){
  var q=($('grpcFilter').value||'').toLowerCase();
  var out=rows.filter(function(e){return !q||e.endpoint.toLowerCase().indexOf(q)>=0;});
  $('grpcBody').innerHTML = out.length ? out.map(function(e,i){
    return '<tr><td class="rank">'+(i+1)+'</td>'+
      '<td class="mono">'+esc(e.endpoint)+'</td>'+
      '<td class="num '+cls(e.tcp_ms,5,30)+'">'+
        (e.tcp_ms!=null?e.tcp_ms+'ms':'—')+'</td>'+
      '<td class="num '+cls(e.push_lag_ms,10,50)+'">'+
        (e.push_lag_ms!=null?e.push_lag_ms+'ms':'—')+'</td>'+
      '<td>'+esc(e.version||'—')+'</td>'+
      '<td class="num muted">'+(e.stream_messages!=null?e.stream_messages:'—')+'</td>'+
      '<td><button class="copy" data-v="'+esc(e.endpoint)+'">复制</button></td></tr>';
  }).join('') : '<tr><td colspan="7" class="empty">没有匹配的 gRPC</td></tr>';
}

/* ---------------- wiring ---------------- */
$('login-btn').addEventListener('click',doLogin);
$('login-key').addEventListener('keydown',function(e){if(e.key==='Enter')doLogin();});
$('reg-btn').addEventListener('click',doRegister);
$('reg-use').addEventListener('click',useNewKey);
$('reg-sig').addEventListener('keydown',function(e){if(e.key==='Enter')doRegister();});
$('app-refresh').addEventListener('click',load);
$('app-back').addEventListener('click',function(){go('landing');});
$('nav-logout').addEventListener('click',function(){
  sessionStorage.removeItem('registry_key');KEY='';go('landing');});
$('rpcFilter').addEventListener('input',function(){if(DATA)renderRpc(DATA.rpc.endpoints||[]);});
$('grpcFilter').addEventListener('input',function(){if(DATA)renderGrpc(DATA.grpc.endpoints||[]);});
document.addEventListener('click',function(ev){
  var b=ev.target.closest&&ev.target.closest('.copy');
  if(!b)return;
  var text=b.getAttribute('data-v');
  if(navigator.clipboard&&navigator.clipboard.writeText){
    navigator.clipboard.writeText(text).then(function(){
      var o=b.textContent;b.textContent='已复制';
      setTimeout(function(){b.textContent=o;},1200);
    });
  }
});

if(KEY){go('app');}else{go('landing');}
setInterval(function(){if(CURRENT==='landing'||CURRENT==='register')loadHealth();
  if(CURRENT==='app')load();},60000);
</script>
</body>
</html>`;