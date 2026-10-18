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

// Workers caps PBKDF2 iterations at 100000; asking for more raises
// NotSupportedError at derive time. Stay exactly at the ceiling.
const PBKDF2_ITERATIONS = 100_000;

async function hashPassword(password, salt) {
  const material = await crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, [
    "deriveBits",
  ]);
  const bits = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      salt: enc.encode(salt),
      iterations: PBKDF2_ITERATIONS,
      hash: "SHA-256",
    },
    material,
    256,
  );
  return [...new Uint8Array(bits)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function randomSecret(bytes = 24) {
  const buf = new Uint8Array(bytes);
  crypto.getRandomValues(buf);
  return [...buf].map((b) => b.toString(36).padStart(2, "0")).join("").slice(0, bytes * 2);
}

function randomKey() {
  return KEY_PREFIX + randomSecret(24).slice(0, 32);
}

function randomSession() {
  return "sess_" + randomSecret(20).slice(0, 32);
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
      CREATE TABLE IF NOT EXISTS accounts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT NOT NULL UNIQUE,
        pw_salt TEXT NOT NULL,
        pw_hash TEXT NOT NULL,
        -- pending: signed up, no entitlement yet. active: paid and entitled.
        status TEXT NOT NULL DEFAULT 'pending',
        session_hash TEXT,
        session_expires INTEGER,
        apikey_hash TEXT,
        key_expires INTEGER,
        created_at INTEGER NOT NULL,
        paid_at INTEGER
      );
    `);
  }

  // -- accounts --------------------------------------------------------------

  /**
   * Create an account. Payment comes afterwards, so a new account is entitled
   * to nothing yet — it exists only so the holder can sign in and pay later.
   */
  async createAccount(email, password) {
    const salt = randomSecret(12);
    const pwHash = await hashPassword(password, salt);
    try {
      this.sql.exec(
        `INSERT INTO accounts (email, pw_salt, pw_hash, status, created_at)
         VALUES (?, ?, ?, 'pending', ?)`,
        email, salt, pwHash, nowSec(),
      );
    } catch (err) {
      if (/UNIQUE/i.test(String(err))) return { ok: false, error: "EMAIL_TAKEN" };
      throw err;
    }
    const id = [...this.sql.exec(`SELECT last_insert_rowid() AS id`)][0].id;
    const session = randomSession();
    this._setSession(id, session);
    return { ok: true, id, email, status: "pending", session };
  }

  async loginAccount(email, password) {
    const rows = [...this.sql.exec(
      `SELECT id, email, pw_salt, pw_hash, status FROM accounts WHERE email = ?`,
      email,
    )];
    if (!rows.length) return { ok: false, error: "BAD_CREDENTIALS" };
    const row = rows[0];
    const attempt = await hashPassword(password, row.pw_salt);
    if (!timingSafeEqual(attempt, row.pw_hash)) {
      return { ok: false, error: "BAD_CREDENTIALS" };
    }
    const session = randomSession();
    this._setSession(row.id, session);
    return { ok: true, id: row.id, email: row.email, status: row.status, session };
  }

  _setSession(id, session) {
    const at = nowSec();
    // Sessions last a day; the page re-prompts for password afterwards.
    this.sql.exec(
      `UPDATE accounts SET session_hash = ?, session_expires = ? WHERE id = ?`,
      session, at + 86400, id,
    );
    return session;
  }

  async accountBySession(token) {
    if (!token.startsWith("sess_")) return { ok: false, reason: "malformed" };
    const hash = token;
    const rows = [...this.sql.exec(
      `SELECT id, email, status, session_expires, apikey_hash, key_expires
       FROM accounts WHERE session_hash = ?`,
      hash,
    )];
    if (!rows.length) return { ok: false, reason: "unknown" };
    const row = rows[0];
    if (!row.session_expires || row.session_expires <= nowSec()) {
      return { ok: false, reason: "expired" };
    }
    return {
      ok: true,
      id: row.id,
      email: row.email,
      status: row.status,
      has_api_key: Boolean(row.apikey_hash),
      key_expires: row.key_expires,
    };
  }

  /** Entitle an account: mark it active and hand over its API key. */
  issueKeyForAccount(accountId) {
    const existing = [...this.sql.exec(
      `SELECT apikey_hash FROM accounts WHERE id = ? AND apikey_hash IS NOT NULL`,
      accountId,
    )][0];
    if (existing) return { key: null, expires: null, reused: true };

    const key = randomKey();
    const expires = nowSec() + Number(SESSION_DAYS) * 86400;
    this.sql.exec(
      `UPDATE accounts SET status = 'active', apikey_hash = ?, key_expires = ?, paid_at = ?
       WHERE id = ?`,
      key, expires, nowSec(), accountId,
    );
    return { key, expires, reused: false };
  }

  async accountByApiKey(token) {
    if (!token.startsWith(KEY_PREFIX)) return { ok: false, reason: "malformed" };
    const rows = [...this.sql.exec(
      `SELECT id, email, status, key_expires FROM accounts WHERE apikey_hash = ?`,
      token,
    )];
    if (!rows.length) return { ok: false, reason: "unknown" };
    const row = rows[0];
    if (row.status !== "active") return { ok: false, reason: "unpaid" };
    if (!row.key_expires || row.key_expires <= nowSec()) {
      return { ok: false, reason: "expired" };
    }
    return { ok: true, id: row.id, email: row.email, status: row.status };
  }

  hasPaymentForAccount(accountId) {
    return [...this.sql.exec(
      `SELECT 1 FROM payments WHERE key_id = ?`,
      accountId,
    )].length > 0;
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
  if (!payTo) return { ok: false, error: "no receiving address configured (PAY_TO)" };
  if (!(price > 0)) return { ok: false, error: "price not configured (PRICE_USDC)" };
  if (!/^[1-9A-HJ-NP-Za-km-z]{32,90}$/.test(signature)) {
    return { ok: false, error: "signature format is not valid" };
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
    if (body.error) return { ok: false, error: `RPC: ${body.error.message || "query failed"}` };
  } catch (err) {
    return { ok: false, error: `RPC request failed: ${String(err).slice(0, 80)}` };
  }

  if (!tx) return { ok: false, error: "transaction not found on chain — wait until it confirms, then retry" };
  if (tx.meta && tx.meta.err) return { ok: false, error: "that transaction failed on chain" };

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
      error: `insufficient amount received: ${got} USDC (required ${price} USDC)`,
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
  if (!env.INGEST_TOKEN) return json({ error: "INGEST_TOKEN not configured" }, 503);
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
  // Deliberately thin: this route is public, so it carries outcome counts only.
  // Scan internals live on /all, which requires an entitled session or key.
  return json({
    status: "ok",
    has_snapshot: Boolean(snap),
    snapshot_age_seconds: age,
    snapshot_received_at: snap?.received_at ?? null,
    stale: age === null ? true : age > 1800,
    totals,
    // Public facts the sign-up and payment forms both need. The receiving
    // address is a published payment destination, not a secret.
    pricing: {
      price_usdc: env.PRICE_USDC || "0",
      pay_to: (env.PAY_TO || "").trim(),
      grant_days: Number(env.GRANT_DAYS || String(SESSION_DAYS)),
      usdc_mint: env.USDC_MINT || "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
      open: Boolean((env.PAY_TO || "").trim()) && Number(env.PRICE_USDC || 0) > 0,
    },
  });
}

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;

async function handleRegister(req, store) {
  let body;
  try {
    body = await req.json();
  } catch {
    return json({ error: "JSON body required" }, 400);
  }
  const email = String(body.email || "").trim().toLowerCase();
  const password = String(body.password || "");
  if (!EMAIL_RE.test(email) || email.length > 254) {
    return json({ error: "A valid email address is required" }, 400);
  }
  if (password.length < 8) {
    return json({ error: "Password must be at least 8 characters" }, 400);
  }

  const created = await store.createAccount(email, password);
  if (!created.ok) {
    if (created.error === "EMAIL_TAKEN") {
      return json({ error: "An account with this email already exists" }, 409);
    }
    return json({ error: "could not create account" }, 500);
  }
  return json({
    ok: true,
    email: created.email,
    status: created.status,
    session: created.session,
    next: "payment", // account exists; entitlement requires paying
  });
}

async function handleLogin(req, store) {
  let body;
  try {
    body = await req.json();
  } catch {
    return json({ error: "JSON body required" }, 400);
  }
  const email = String(body.email || "").trim().toLowerCase();
  const password = String(body.password || "");
  const result = await store.loginAccount(email, password);
  if (!result.ok) {
    // One message for both unknown email and wrong password — don't confirm
    // which account exists.
    return json({ error: "Incorrect email or password" }, 401);
  }
  return json({
    ok: true,
    email: result.email,
    status: result.status,
    session: result.session,
    next: result.status === "active" ? "dashboard" : "payment",
  });
}

async function handleAccount(req, store, token) {
  const account = await store.accountBySession(token);
  if (!account.ok) return json({ error: "Sign in again", reason: account.reason }, 401);
  return json({
    ok: true,
    email: account.email,
    status: account.status,
    entitled: account.status === "active",
    has_api_key: account.has_api_key,
    key_expires: account.key_expires,
  });
}

async function handlePay(req, env, store, session) {
  let body;
  try {
    body = await req.json();
  } catch {
    return json({ error: "JSON body required" }, 400);
  }

  const account = await store.accountBySession(session || bearer(req));
  if (!account.ok) return json({ error: "Sign in first, then pay", reason: account.reason }, 401);
  if (account.status === "active") {
    return json({ error: "This account is already activated" }, 409);
  }

  const signature = String(body.signature || "").trim();
  if (!signature) return json({ error: "A transaction signature is required" }, 400);

  if (await store.hasPayment(signature)) {
    return json({ error: "This signature was already redeemed", signature }, 409);
  }

  const verdict = await verifyPayment(env, signature);
  if (!verdict.ok) return json({ error: verdict.error, ...verdict }, 400);

  const issued = await store.issueKeyForAccount(account.id);
  await store.recordPayment({
    signature,
    mint: verdict.mint,
    amount: verdict.amount,
    payer: verdict.payer,
    keyId: account.id,
  });

  const days = Number(env.GRANT_DAYS || String(SESSION_DAYS));
  return json({
    ok: true,
    status: "active",
    email: account.email,
    api_key: issued.key, // shown once, for programmatic use
    expires_at: issued.expires,
    days,
    note: "Account activated. The API key is shown only once — copy it now.",
  });
}

async function handleAdmin(req, env, store) {
  if (!env.ADMIN_TOKEN) return json({ error: "ADMIN_TOKEN not configured" }, 503);
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
    return json({ ok: true, ...issued, warning: "This key is shown only once." });
  }
  if (req.method === "POST" && url.pathname === "/admin/keys/revoke") {
    let body = {};
    try {
      body = await req.json();
    } catch { /* fall through to the id check */ }
    const id = Number(body.id);
    if (!Number.isInteger(id)) return json({ error: "an integer id is required" }, 400);
    return json({ ok: true, key: await store.revokeKey(id) });
  }
  return json({ error: "unknown admin route" }, 404);
}

async function handleData(req, env, store, route) {
  const snap = await store.getSnapshot();
  if (!snap) {
    return json({ error: "no scan data has arrived yet", stale: true }, 503);
  }
  const age = nowSec() - snap.received_at;
  let data;
  try {
    data = JSON.parse(snap.payload);
  } catch {
    return json({ error: "snapshot is corrupt" }, 500);
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
      if (path === "/" && req.method === "GET") {
        return new Response(DASHBOARD_HTML, {
          headers: { "content-type": "text/html; charset=utf-8", "cache-control": "no-store" },
        });
      }

      // Account lifecycle: sign up first, pay afterwards.
      if (path === "/register" && req.method === "POST") {
        return await handleRegister(req, store);
      }
      if (path === "/login" && req.method === "POST") {
        return await handleLogin(req, store);
      }
      if (path === "/account" && req.method === "GET") {
        return await handleAccount(req, store, bearer(req));
      }
      if (path === "/pay" && req.method === "POST") {
        return await handlePay(req, env, store, bearer(req));
      }

      if (path.startsWith("/admin/")) {
        return await handleAdmin(req, env, store);
      }

      if (["/rpc", "/grpc", "/all"].includes(path)) {
        const presented = bearer(req);
        if (!presented) {
          return json({ error: "Sign in to read endpoints", hint: "Bearer session or sk_ key" }, 401);
        }
        // Three accepted credentials: an account session (someone paying from
        // the browser), an account API key (issued on payment), or a
        // standalone admin-issued key from the api_keys table.
        const byKey = await store.accountByApiKey(presented);
        if (byKey.ok) return await handleData(req, env, store, path);

        const bySession = await store.accountBySession(presented);
        if (bySession.ok) {
          if (bySession.status !== "active") {
            return json({ error: "Payment required", reason: "unpaid" }, 402);
          }
          return await handleData(req, env, store, path);
        }

        const standalone = await store.checkKey(presented);
        if (standalone.ok) return await handleData(req, env, store, path);

        // Surface the most specific failure we have so the page can tell
        // "not paid yet" apart from "bad key".
        const reason = byKey.reason !== "unknown" ? byKey.reason : bySession.reason;
        if (reason === "unpaid") return json({ error: "Payment required", reason }, 402);
        if (reason === "expired") return json({ error: "This credential expired", reason }, 401);
        return json({ error: "Invalid or expired credential", reason }, 401);
      }
      return json({ error: "not found", path }, 404);
    } catch (err) {
      return json({ error: "internal error", detail: String(err).slice(0, 200) }, 500);
    }
  },
};

// ---------------------------------------------------------------- dashboard

const DASHBOARD_HTML = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Solana RPC / gRPC Registry</title>
<style>
  :root{--bg:#0f1115;--panel:#161a21;--panel2:#1c212a;--line:#262c37;--fg:#e6e9ef;
        --dim:#8b95a7;--faint:#5d667a;--ok:#4ade80;--warn:#fbbf24;--bad:#f87171;--accent:#60a5fa}
  *{box-sizing:border-box}
  body{margin:0;background:var(--bg);color:var(--fg);
       font:14px/1.6 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
       -webkit-font-smoothing:antialiased}
  .wrap{max-width:1180px;margin:0 auto;padding:0 20px 72px}
  a{color:var(--accent);text-decoration:none;cursor:pointer}
  a:hover{text-decoration:underline}
  code{background:var(--panel2);border:1px solid var(--line);padding:1px 6px;border-radius:4px;
       font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:.92em}
  .hide{display:none!important}

  nav{position:sticky;top:0;z-index:20;background:rgba(15,17,21,.88);backdrop-filter:blur(8px);
      border-bottom:1px solid var(--line)}
  .nav-in{max-width:1180px;margin:0 auto;padding:14px 20px;display:flex;gap:16px;
          align-items:center;justify-content:space-between;flex-wrap:wrap}
  .brand{font-size:15px;font-weight:650;letter-spacing:.2px;white-space:nowrap}
  .brand span{color:var(--dim);font-weight:400}
  .nav-actions{display:flex;gap:9px;align-items:center}
  .who{font-size:12.5px;color:var(--faint);max-width:230px;overflow:hidden;
       text-overflow:ellipsis;white-space:nowrap}
  button{font:inherit;background:var(--panel2);color:var(--fg);border:1px solid var(--line);
         border-radius:7px;padding:7px 15px;cursor:pointer;transition:border-color .12s}
  button:hover{border-color:var(--accent)}
  button.primary{background:var(--accent);border-color:var(--accent);color:#0b1220;font-weight:600}
  button.primary:hover{filter:brightness(1.08)}
  button.primary:disabled{opacity:.6;cursor:default;filter:none}
  button.ghost{background:transparent;color:var(--dim)}
  button.ghost:hover{color:var(--fg)}
  button.sm{padding:4px 10px;font-size:12px}
  button.wide{width:100%;padding:11px;font-size:15px}

  .status{display:flex;gap:9px;align-items:center;font-size:12.5px;color:var(--dim);white-space:nowrap}
  .dot{width:8px;height:8px;border-radius:50%;background:var(--faint);flex:none}
  .dot.ok{background:var(--ok);box-shadow:0 0 0 3px rgba(74,222,128,.15)}
  .dot.stale{background:var(--warn);box-shadow:0 0 0 3px rgba(251,191,36,.15)}

  /* landing */
  .hero{padding:76px 0 54px;text-align:center}
  .hero h1{font-size:40px;line-height:1.2;margin:0 0 17px;font-weight:680;letter-spacing:-.7px}
  .hero h1 em{font-style:normal;color:var(--accent)}
  .hero p{font-size:17px;color:var(--dim);max-width:640px;margin:0 auto 32px;line-height:1.72}
  .cta{display:flex;gap:12px;justify-content:center;flex-wrap:wrap}
  .cta button{padding:12px 26px;font-size:15px}
  .hero-note{margin-top:17px;font-size:13px;color:var(--faint)}

  .stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));
         gap:12px;margin:8px 0 56px}
  .card{background:var(--panel);border:1px solid var(--line);border-radius:11px;padding:16px 18px}
  .card .k{color:var(--dim);font-size:12.5px;margin-bottom:7px}
  .card .v{font-size:27px;font-weight:660;letter-spacing:-.6px;font-variant-numeric:tabular-nums}
  .card .s{color:var(--faint);font-size:11.5px;margin-top:5px}

  .grid3{display:grid;grid-template-columns:repeat(auto-fit,minmax(258px,1fr));
         gap:14px;margin-bottom:56px}
  .feat{background:var(--panel);border:1px solid var(--line);border-radius:11px;padding:20px}
  .feat h3{margin:0 0 8px;font-size:15.5px;font-weight:640}
  .feat p{margin:0;color:var(--dim);font-size:13.5px;line-height:1.65}
  .ico{font-size:19px;margin-bottom:11px;display:block}

  .flow{display:grid;grid-template-columns:repeat(auto-fit,minmax(210px,1fr));
        gap:14px;margin-bottom:56px}
  .step{background:var(--panel);border:1px solid var(--line);border-radius:11px;padding:18px}
  .step .n{display:inline-block;width:24px;height:24px;line-height:24px;text-align:center;
           border-radius:50%;background:var(--accent);color:#0b1220;font-size:12px;
           font-weight:700;margin-bottom:11px}
  .step h4{margin:0 0 6px;font-size:14.5px}
  .step p{margin:0;color:var(--dim);font-size:13px;line-height:1.6}

  .pricing{background:linear-gradient(155deg,var(--panel),#12161d);
           border:1px solid var(--line);border-radius:14px;padding:34px 30px;text-align:center;
           max-width:520px;margin:0 auto}
  .price{font-size:46px;font-weight:700;letter-spacing:-1.5px;margin:6px 0 2px}
  .price small{font-size:17px;font-weight:500;color:var(--dim);letter-spacing:0}
  .price-sub{color:var(--dim);font-size:14px;margin-bottom:22px}
  .plist{list-style:none;padding:0;margin:22px auto 0;text-align:left;max-width:340px;
         font-size:13.5px;color:var(--dim)}
  .plist li{padding:7px 0;border-bottom:1px solid var(--line);display:flex;gap:10px}
  .plist li:last-child{border-bottom:none}
  .plist .yes{color:var(--ok);flex:none}

  /* auth panels */
  .cbox{background:var(--panel);border:1px solid var(--line);border-radius:13px;
        max-width:470px;margin:64px auto 0;padding:30px}
  .cbox h2{margin:0 0 7px;font-size:19px;font-weight:650}
  .cbox p.lead{margin:0 0 20px;color:var(--dim);font-size:14px;line-height:1.65}
  .field{width:100%;background:var(--panel2);border:1px solid var(--line);color:var(--fg);
         border-radius:8px;padding:12px 13px;font:inherit;font-size:14.5px;margin-bottom:13px}
  .field::placeholder{color:var(--faint)}
  .field:focus{outline:none;border-color:var(--accent)}
  .field.mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:13.5px}
  .field.addr{word-break:break-all;font-size:12.5px}
  .err{color:var(--bad);font-size:13px;margin-top:12px;min-height:17px}
  .fine{font-size:12.5px;color:var(--faint);margin-top:17px;line-height:1.8}
  .hint{font-size:12.5px;color:var(--faint);margin:-4px 0 16px}
  .payrow{background:var(--panel2);border:1px solid var(--line);border-radius:8px;
          padding:11px 13px;margin-bottom:13px}
  .payrow .lbl{font-size:11.5px;color:var(--faint);text-transform:uppercase;
               letter-spacing:.5px;margin-bottom:5px}
  .payrow .val{font-size:14.5px;font-weight:600;font-variant-numeric:tabular-nums}
  .payrow .val.addr{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;
                    font-size:12.5px;word-break:break-all;font-weight:500}
  .notice{background:rgba(251,191,36,.07);border:1px solid rgba(251,191,36,.3);
          color:var(--warn);border-radius:8px;padding:11px 13px;font-size:13px;margin-bottom:14px}
  .notice.info{background:rgba(96,165,250,.07);border-color:rgba(96,165,250,.3);color:var(--accent)}
  .gotkey{background:var(--panel2);border:1px solid var(--line);border-radius:9px;
          padding:15px 16px;margin-bottom:14px}
  .gotkey .lbl{font-size:11.5px;color:var(--faint);text-transform:uppercase;letter-spacing:.5px}
  .gotkey .kv{font-size:14px;font-weight:650;margin-top:5px;word-break:break-all;
              font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;color:var(--ok)}

  /* app */
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
    .hero{padding:52px 0 40px}.hero h1{font-size:30px}.price{font-size:40px}
    .cbox{margin-top:44px;padding:24px 20px 26px}.nav-in{padding:12px 16px}
  }
</style>
</head>
<body>

<nav><div class="nav-in">
  <div class="brand">Solana RPC / gRPC <span>Registry</span></div>
  <div class="nav-actions">
    <div class="status"><span class="dot" id="dot"></span><span id="age">loading…</span></div>
    <span class="who hide" id="nav-who"></span>
    <button class="ghost sm hide" id="nav-logout">Sign out</button>
  </div>
</div></nav>

<div class="wrap">

<!-- ============================== LANDING ============================== -->
<div id="v-landing">
  <div class="hero">
    <h1>Ready-to-use Solana<br><em>RPC &amp; gRPC endpoints</em></h1>
    <p>
      Stop guessing which public validators will answer. Every endpoint here has
      been verified as genuinely usable and is refreshed every 10 minutes — you
      get a short list that works, not a raw directory.
    </p>
    <div class="cta">
      <button class="primary" onclick="go('register')">Create account</button>
      <button onclick="go('login')">Sign in</button>
    </div>
    <div class="hero-note">Hosted on Cloudflare · paid access · no free tier</div>
  </div>

  <div class="stats">
    <div class="card"><div class="k">Usable JSON-RPC</div><div class="v" id="s-rpc">—</div>
      <div class="s" id="s-rpc-sub">loading…</div></div>
    <div class="card"><div class="k">Usable gRPC streams</div><div class="v" id="s-grpc">—</div>
      <div class="s" id="s-grpc-sub">loading…</div></div>
    <div class="card"><div class="k">Data freshness</div><div class="v" id="s-age">—</div>
      <div class="s">updated every 10 minutes</div></div>
    <div class="card"><div class="k">Delivery</div><div class="v">Edge</div>
      <div class="s">Cloudflare network</div></div>
  </div>

  <div class="grid3">
    <div class="feat"><span class="ico">✓</span><h3>Only endpoints that work</h3>
      <p>A port being open proves nothing. Each listing is verified to answer
      correctly before it is published, so what you copy is what you get.</p></div>
    <div class="feat"><span class="ico">📊</span><h3>Ranked by real speed</h3>
      <p>Endpoints are ordered by how quickly data actually reaches you, so the
      top of the list is the fastest one to work with in practice.</p></div>
    <div class="feat"><span class="ico">🔄</span><h3>Always current</h3>
      <p>Public endpoints go up and down constantly. This one refreshes every
      10 minutes, and you can see exactly how old the data is.</p></div>
    <div class="feat"><span class="ico">⚡</span><h3>Served at the edge</h3>
      <p>Reads come straight from Cloudflare, close to you and worldwide.
      Collection runs separately, so collection load never reaches you.</p></div>
    <div class="feat"><span class="ico">🪪</span><h3>One credential, two uses</h3>
      <p>The same account opens the web console and authenticates your API
      calls. No separate key to juggle unless you want one.</p></div>
    <div class="feat"><span class="ico">🛑</span><h3>Nothing unusable gets through</h3>
      <p>Endpoints that need an access token are excluded outright rather than
      published as dead ends that fail the moment you connect.</p></div>
  </div>

  <div class="flow">
    <div class="step"><span class="n">1</span><h4>Create an account</h4>
      <p>Email and password. Nothing is charged yet — the account just gives you
      a place to sign in.</p></div>
    <div class="step"><span class="n">2</span><h4>Pay once you're in</h4>
      <p>From inside your account, send USDC and paste the transaction
      signature. Verification is automatic.</p></div>
    <div class="step"><span class="n">3</span><h4>Use it</h4>
      <p>The console unlocks immediately, and you receive an API key for
      programmatic access.</p></div>
  </div>

  <div class="pricing">
    <div class="price">5 <small>USDC</small></div>
    <div class="price-sub">per 30 days · billed on-chain</div>
    <ul class="plist">
      <li><span class="yes">✓</span> Full JSON-RPC list with capability flags</li>
      <li><span class="yes">✓</span> Full Yellowstone gRPC stream list</li>
      <li><span class="yes">✓</span> Latency ranking on every row</li>
      <li><span class="yes">✓</span> Refreshed every 10 minutes</li>
      <li><span class="yes">✓</span> Web console and REST API with one account</li>
    </ul>
    <div class="cta" style="margin-top:26px">
      <button class="primary" onclick="go('register')">Create account</button>
    </div>
  </div>

  <footer>
    <span>Endpoints change without notice — check freshness before relying on them.</span>
    <span>Already a member? <a onclick="go('login')">Sign in</a></span>
  </footer>
</div>

<!-- ============================== REGISTER ============================== -->
<div id="v-register" class="hide">
  <div class="cbox">
    <h2>Create account</h2>
    <p class="lead">Pick your credentials first. You'll pay only after you're signed in.</p>

    <input class="field" type="email" id="rg-email" placeholder="Email" autocomplete="email">
    <input class="field" type="password" id="rg-pass" placeholder="Password (8+ characters)"
           autocomplete="new-password">
    <input class="field" type="password" id="rg-pass2" placeholder="Confirm password"
           autocomplete="new-password">
    <button class="wide primary" id="rg-btn">Create account</button>
    <div class="err" id="rg-err"></div>

    <div class="fine">
      Already have one? <a onclick="go('login')">Sign in</a><br>
      <a onclick="go('landing')">← Back to overview</a>
    </div>
  </div>
</div>

<!-- ================================ LOGIN ============================== -->
<div id="v-login" class="hide">
  <div class="cbox">
    <h2>Sign in</h2>
    <p class="lead">Use the email and password for your account.</p>

    <input class="field" type="email" id="ln-email" placeholder="Email" autocomplete="email">
    <input class="field" type="password" id="ln-pass" placeholder="Password"
           autocomplete="current-password">
    <button class="wide primary" id="ln-btn">Sign in</button>
    <div class="err" id="ln-err"></div>

    <div class="fine">
      No account yet? <a onclick="go('register')">Create one</a><br>
      <a onclick="go('landing')">← Back to overview</a>
    </div>
  </div>
</div>

<!-- ================================ PAY ================================ -->
<div id="v-pay" class="hide">
  <div class="cbox">
    <h2>Activate your account</h2>
    <p class="lead">Send USDC to the address below, then paste the transaction
      signature here.</p>

    <div class="notice info" id="pay-welcome"></div>
    <div class="notice hide" id="pay-closed">
      Payments are temporarily unavailable. Your account exists — pay later.
    </div>

    <div id="pay-form">
      <div class="payrow">
        <div class="lbl">Send to (Solana)</div>
        <div class="val addr" id="pay-addr">loading…</div>
      </div>
      <div class="payrow">
        <div class="lbl">Amount</div>
        <div class="val" id="pay-amount">5 USDC / 30 days</div>
      </div>
      <div class="payrow">
        <div class="lbl">Token</div>
        <div class="val" style="font-size:13px">USDC</div>
      </div>
      <input class="field mono" id="pay-sig" placeholder="Transaction signature"
             autocomplete="off">
      <button class="wide primary" id="pay-btn">Verify and activate</button>
      <div class="err" id="pay-err"></div>
      <div class="fine">
        The signature is checked against the network: recipient balance before
        and after the transaction. One signature activates one account.<br>
        <a onclick="go('landing')">← Back to overview</a>
      </div>
    </div>

    <div class="hide" id="pay-done">
      <div class="gotkey">
        <div class="lbl">Your API key — shown once, copy it now</div>
        <div class="kv" id="pay-key"></div>
      </div>
      <button class="wide primary" id="pay-use">Open console</button>
      <div class="fine">Lost it? We can reissue from your account email.</div>
    </div>
  </div>
</div>

<!-- ================================= APP =============================== -->
<div id="v-app" class="hide">
  <div class="app-head">
    <h1>Solana RPC / gRPC <span>· usable endpoints</span></h1>
    <div class="nav-actions">
      <button class="sm" id="app-refresh">Refresh</button>
      <button class="sm ghost" id="app-back">Overview</button>
    </div>
  </div>

  <div class="stats">
    <div class="card"><div class="k">Usable RPC</div><div class="v" id="a-rpc">—</div>
      <div class="s" id="a-rpc-sub">—</div></div>
    <div class="card"><div class="k">Usable gRPC</div><div class="v" id="a-grpc">—</div>
      <div class="s" id="a-grpc-sub">—</div></div>
    <div class="card"><div class="k">RPC latency P50</div><div class="v" id="a-rp50">—</div>
      <div class="s" id="a-rp50s">—</div></div>
    <div class="card"><div class="k">Stream latency P50</div><div class="v" id="a-pp50">—</div>
      <div class="s" id="a-pp50s">—</div></div>
  </div>

  <section>
    <div class="sec-head">
      <div><h2>JSON-RPC</h2><div class="meta" id="rpcMeta">—</div></div>
      <input class="search" id="rpcFilter" placeholder="Filter endpoints…">
    </div>
    <div class="scroll"><table>
      <thead><tr><th class="rank">#</th><th>Endpoint</th>
        <th style="text-align:right">Latency</th><th>Version</th>
        <th style="text-align:right">Slot</th><th>Capabilities</th><th></th></tr></thead>
      <tbody id="rpcBody"><tr><td colspan="7" class="empty">Loading…</td></tr></tbody>
    </table></div>
  </section>

  <section>
    <div class="sec-head">
      <div><h2>Yellowstone gRPC</h2><div class="meta" id="grpcMeta">—</div></div>
      <input class="search" id="grpcFilter" placeholder="Filter endpoints…">
    </div>
    <div class="scroll"><table>
      <thead><tr><th class="rank">#</th><th>Endpoint</th>
        <th style="text-align:right">TCP</th>
        <th style="text-align:right">Stream lag</th>
        <th>Version</th>
        <th style="text-align:right">Messages</th><th></th></tr></thead>
      <tbody id="grpcBody"><tr><td colspan="7" class="empty">Loading…</td></tr></tbody>
    </table></div>
  </section>

  <div class="note">
    Every row is listed only after a successful verification. Latency is the
    time it takes for data to reach this page.
  </div>
</div>

</div>

<script>
var SESSION = sessionStorage.getItem('registry_session') || '';
var ACCOUNT = null, DATA = null;
var CURRENT = SESSION ? 'boot' : 'landing';

function $(id){return document.getElementById(id);}
function esc(s){return String(s==null?'':s).replace(/[&<>"]/g,function(c){
  return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c];});}
function cls(ms,a,b){return ms==null?'muted':(ms<=a?'good':(ms<=b?'mid':'slow'));}
function fmtAge(s){
  if(s==null)return '—';
  if(s<60)return Math.round(s)+' sec ago';
  if(s<3600)return Math.round(s/60)+' min ago';
  return (s/3600).toFixed(1)+' hr ago';
}
function err(el,msg){$(el).textContent=msg||'';}
function busy(btn,on,label){
  btn.disabled=on;
  if(on){btn.dataset.label=btn.textContent;btn.textContent=label;}
  else if(btn.dataset.label){btn.textContent=btn.dataset.label;}
}

/* ---------------- routing ---------------- */
function go(name){
  ['landing','register','login','pay','app'].forEach(function(v){
    var el=$('v-'+v); if(el)el.classList.toggle('hide', v!==name);
  });
  CURRENT=name;
  $('nav-logout').classList.toggle('hide', name==='landing'||name==='register'||name==='login');
  $('nav-who').classList.toggle('hide', !ACCOUNT);
  if(ACCOUNT) $('nav-who').textContent=ACCOUNT.email;
  window.scrollTo(0,0);
  if(name==='landing')loadHealth();
  if(name==='register')setTimeout(function(){$('rg-email').focus();},80);
  if(name==='login')setTimeout(function(){$('ln-email').focus();},80);
  if(name==='pay')loadHealth();
  if(name==='app')load();
}

/* ---------------- public health ---------------- */
function loadHealth(){
  return fetch('/health',{cache:'no-store'}).then(function(r){return r.json();})
    .then(function(d){
      var t=d.totals||{}, p=d.pricing||{};
      $('s-rpc').textContent = t.rpc_usable!=null?t.rpc_usable:'—';
      $('s-rpc-sub').textContent = t.rpc_usable!=null
        ? (t.rpc_partial||0)+' more partially capable' : 'awaiting first run';
      $('s-grpc').textContent = t.grpc_usable!=null?t.grpc_usable:'—';
      $('s-grpc-sub').textContent = t.grpc_usable!=null
        ? 'token-protected ones excluded' : 'awaiting first run';
      $('s-age').textContent = d.has_snapshot?fmtAge(d.snapshot_age_seconds):'—';

      var dot=$('dot'), ageEl=$('age');
      if(!d.has_snapshot){dot.className='dot';ageEl.textContent='awaiting first run';}
      else if(d.stale){dot.className='dot stale';ageEl.textContent='stale · '+fmtAge(d.snapshot_age_seconds);}
      else{dot.className='dot ok';ageEl.textContent='fresh · '+fmtAge(d.snapshot_age_seconds);}

      if(p.pay_to){
        $('pay-addr').textContent=p.pay_to;
        $('pay-amount').textContent=(p.price_usdc||'5')+' USDC / '+(p.grant_days||30)+' days';
        $('pay-closed').classList.add('hide');
        $('pay-form').classList.remove('hide');
      }else{
        $('pay-closed').classList.remove('hide');
        $('pay-form').classList.add('hide');
      }
    }).catch(function(){});
}

/* ---------------- register / login ---------------- */
function doRegister(){
  var email=$('rg-email').value.trim(), pw=$('rg-pass').value, pw2=$('rg-pass2').value;
  err('rg-err','');
  if(!email){err('rg-err','Enter your email');return;}
  if(pw.length<8){err('rg-err','Password must be at least 8 characters');return;}
  if(pw!==pw2){err('rg-err','Passwords do not match');return;}
  busy($('rg-btn'),true,'Creating…');
  fetch('/register',{method:'POST',headers:{'content-type':'application/json'},
    body:JSON.stringify({email:email,password:pw})})
    .then(function(r){return r.json().then(function(d){
      busy($('rg-btn'),false);
      if(!r.ok){err('rg-err',d.error||('HTTP '+r.status));return;}
      SESSION=d.session; sessionStorage.setItem('registry_session',SESSION);
      ACCOUNT={email:d.email,status:d.status};
      $('rg-pass').value=''; $('rg-pass2').value='';
      enterAfterAuth(d);
    });})
    .catch(function(){busy($('rg-btn'),false);err('rg-err','Network error');});
}

function doLogin(){
  var email=$('ln-email').value.trim(), pw=$('ln-pass').value;
  err('ln-err','');
  if(!email||!pw){err('ln-err','Enter your email and password');return;}
  busy($('ln-btn'),true,'Signing in…');
  fetch('/login',{method:'POST',headers:{'content-type':'application/json'},
    body:JSON.stringify({email:email,password:pw})})
    .then(function(r){return r.json().then(function(d){
      busy($('ln-btn'),false);
      if(!r.ok){err('ln-err',d.error||('HTTP '+r.status));return;}
      SESSION=d.session; sessionStorage.setItem('registry_session',SESSION);
      ACCOUNT={email:d.email,status:d.status};
      $('ln-pass').value='';
      enterAfterAuth(d);
    });})
    .catch(function(){busy($('ln-btn'),false);err('ln-err','Network error');});
}

function enterAfterAuth(d){
  if(d.status==='active'){go('app');return;}
  $('pay-welcome').textContent='Signed in as '+d.email+'. Account is not active yet.';
  go('pay');
}

/* ---------------- payment ---------------- */
function doPay(){
  var sig=$('pay-sig').value.trim();
  err('pay-err','');
  if(!sig){err('pay-err','Paste the transaction signature');return;}
  busy($('pay-btn'),true,'Verifying…');
  fetch('/pay',{method:'POST',headers:{'content-type':'application/json',
      'authorization':'Bearer '+SESSION},
    body:JSON.stringify({signature:sig})})
    .then(function(r){return r.json().then(function(d){
      busy($('pay-btn'),false);
      if(!r.ok){err('pay-err',d.error||('HTTP '+r.status));return;}
      ACCOUNT.status='active';
      $('pay-form').classList.add('hide');
      $('pay-done').classList.remove('hide');
      $('pay-key').textContent=d.api_key||'(issued after refresh)';
      if(d.api_key)sessionStorage.setItem('registry_apikey',d.api_key);
      $('nav-who').textContent=(ACCOUNT.email||'')+' · active';
    });})
    .catch(function(){busy($('pay-btn'),false);err('pay-err','Network error');});
}

function useSession(){go('app');}

/* ---------------- app data ---------------- */
function load(){
  if(!SESSION){go('login');return;}
  return fetch('/all',{headers:{'authorization':'Bearer '+SESSION},cache:'no-store'})
    .then(function(r){
      if(r.status===401){signOut();return;}
      if(r.status===402){
        ACCOUNT=ACCOUNT||{};
        $('pay-welcome').textContent='Signed in as '+(ACCOUNT.email||'you')+'. Account is not active yet.';
        go('pay');return;
      }
      if(!r.ok)throw new Error('HTTP '+r.status);
      return r.json();
    })
    .then(function(d){DATA=d;render();})
    .catch(function(){});
}

function render(){
  if(!DATA)return;
  var fresh=!DATA.stale;
  $('dot').className='dot '+(fresh?'ok':'stale');
  $('age').textContent=(fresh?'fresh · ':'stale · ')+fmtAge(DATA.snapshot_age_seconds);

  var t=DATA.totals||{}, r=DATA.rpc||{}, g=DATA.grpc||{};
  var rl=r.latency_ms||{}, pl=g.push_lag_ms||{};
  $('a-rpc').textContent=t.rpc_usable!=null?t.rpc_usable:'—';
  $('a-rpc-sub').textContent=(t.rpc_partial||0)+' partially capable';
  $('a-grpc').textContent=t.grpc_usable!=null?t.grpc_usable:'—';
  $('a-grpc-sub').textContent='live stream verified';
  $('a-rp50').textContent=rl.p50!=null?rl.p50+'ms':'—';
  $('a-rp50s').textContent=rl.min!=null?'min '+rl.min+'ms':'—';
  $('a-pp50').textContent=pl.p50!=null?pl.p50+'ms':'—';
  $('a-pp50s').textContent=pl.min!=null?'min '+pl.min+'ms':'—';

  var rc=r.counts||{};
  $('rpcMeta').textContent=
    rc.usable+' usable · '+(rc.advertised||0)+' monitored';
  $('grpcMeta').textContent=
    (g.counts||{}).subscribe_ok+' streams verified';

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
      '<td><button class="copy" data-v="'+esc(e.endpoint)+'">Copy</button></td></tr>';
  }).join('') : '<tr><td colspan="7" class="empty">No matching RPC endpoints</td></tr>';
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
      '<td><button class="copy" data-v="'+esc(e.endpoint)+'">Copy</button></td></tr>';
  }).join('') : '<tr><td colspan="7" class="empty">No matching gRPC endpoints</td></tr>';
}

function signOut(){
  SESSION=''; ACCOUNT=null; DATA=null;
  sessionStorage.removeItem('registry_session');
  $('ln-email').value=''; $('ln-pass').value='';
  go('landing');
}

/* ---------------- wiring ---------------- */
$('rg-btn').addEventListener('click',doRegister);
$('rg-pass2').addEventListener('keydown',function(e){if(e.key==='Enter')doRegister();});
$('ln-btn').addEventListener('click',doLogin);
$('ln-pass').addEventListener('keydown',function(e){if(e.key==='Enter')doLogin();});
$('pay-btn').addEventListener('click',doPay);
$('pay-sig').addEventListener('keydown',function(e){if(e.key==='Enter')doPay();});
$('pay-use').addEventListener('click',useSession);
$('app-refresh').addEventListener('click',load);
$('app-back').addEventListener('click',function(){go('landing');});
$('nav-logout').addEventListener('click',signOut);
$('rpcFilter').addEventListener('input',function(){if(DATA)renderRpc(DATA.rpc.endpoints||[]);});
$('grpcFilter').addEventListener('input',function(){if(DATA)renderGrpc(DATA.grpc.endpoints||[]);});
document.addEventListener('click',function(ev){
  var b=ev.target.closest&&ev.target.closest('.copy');
  if(!b)return;
  if(!navigator.clipboard)return;
  navigator.clipboard.writeText(b.getAttribute('data-v')).then(function(){
    var o=b.textContent;b.textContent='Copied';
    setTimeout(function(){b.textContent=o;},1200);
  });
});

/* boot: if a stored session still works, land straight in the console */
function boot(){
  if(!SESSION){go('landing');return;}
  fetch('/account',{headers:{'authorization':'Bearer '+SESSION},cache:'no-store'})
    .then(function(r){return r.ok?r.json():null;})
    .then(function(d){
      if(!d||!d.ok){SESSION='';sessionStorage.removeItem('registry_session');go('landing');return;}
      ACCOUNT={email:d.email,status:d.status};
      $('nav-who').classList.remove('hide');
      $('nav-who').textContent=d.email+(d.entitled?' · active':' · unpaid');
      if(d.status==='active'){go('app');}else{
        $('pay-welcome').textContent='Signed in as '+d.email+'. Account is not active yet.';
        go('pay');
      }
    })
    .catch(function(){go('landing');});
}
boot();
setInterval(function(){
  if(CURRENT==='landing')loadHealth();
  if(CURRENT==='pay')loadHealth();
  if(CURRENT==='app')load();
},60000);
</script>
</body>
</html>`;