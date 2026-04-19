// ============================================================
// NTT HUB - Combined Worker
// ============================================================

const ENCODE_KEY = "string.char"; // ← đổi key tại đây, phải khớp với Lua
const LINKVERTISE_TOKEN = "7581177bce5e0eb39a7b44cf7aa9c82128e535e9736074c5945f7255975204f0";

const MIN_FLOW_SECONDS  = 25;
const MIN_STEP2_SECONDS = 15;
const WEBHOOK_URL = "https://discord.com/api/webhooks/1492190232110698617/R99ssaRboxvn2gt4vgZcB2p3tgafRNiXdX3yUcdi6jBjQxjXUEyBwtBLX3IXL6lc-5nd";
const SESSION_TTL = 2 * 60 * 60;
const IP_WINDOW   = 24 * 60 * 60;
const IP_MAX_HWID = 20;

// ── helpers ──────────────────────────────────────────────────
const ALLOWED_ORIGINS = [
  "https://ntt-hub.xyz",
  "https://www.ntt-hub.xyz",
  "null",
];

function getCors(request) {
  const origin  = request?.headers?.get("Origin") || "";
  const allowed = ALLOWED_ORIGINS.includes(origin) ? origin : "https://ntt-hub.xyz";
  return {
    "Access-Control-Allow-Origin":  allowed,
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, User-Agent",
    "Vary": "Origin",
  };
}

function json(obj, status = 200, request = null) {
  if (status && typeof status === "object" && status.headers) {
    request = status;
    status  = 200;
  }
  return new Response(JSON.stringify(obj), {
    status,
    headers: { ...getCors(request), "Content-Type": "application/json" },
  });
}

function text(str, status = 200, request = null) {
  return new Response(str, {
    status,
    headers: { ...getCors(request), "Content-Type": "text/plain" },
  });
}

function normalizeHwid(url) {
  const raw = url.search.match(/[?&]hwid=([^&]*)/)?.[1];
  if (!raw) return null;
  try { return decodeURIComponent(raw).replace(/ /g, "+"); }
  catch { return raw.replace(/ /g, "+"); }
}

async function checkLinkvertiseHash(hash, token, userAgent) {
  const apiUrl = `https://publisher.linkvertise.com/api/v1/anti_bypassing?token=${token}&hash=${encodeURIComponent(hash)}`;
  try {
    const res  = await fetch(apiUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json", "User-Agent": userAgent || "Cloudflare-Worker" },
    });
    const data = await res.json();
    return data?.status === true;
  } catch { return false; }
}

// ── encode helpers (port từ Lua, đồng nhất với client) ───────
function simpleHash(str) {
  let hash = 0;
  for (let i = 0; i < str.length; i++) {
    hash = (hash * 131 + str.charCodeAt(i)) % 4294967296; // 2^32
  }
  return hash;
}

function toHex(str) {
  return [...str].map(c =>
    c.charCodeAt(0).toString(16).padStart(2, "0").toUpperCase()
  ).join("");
}

function encodeData(plaintext, baseKey) {
  const t = Math.floor(Date.now() / 1000);
  const rawKey    = String(baseKey) + ":" + String(t);
  const hashedKey = simpleHash(rawKey);

  const result = [];
  for (let i = 0; i < plaintext.length; i++) {
    const byte = plaintext.charCodeAt(i);
    const k    = (hashedKey + (i + 1) * 7) % 256; // Lua i bắt đầu từ 1
    let encoded = (byte ^ k);
    encoded = (encoded + k) % 256;
    result.push(String.fromCharCode(encoded));
  }

  const encodedStr  = toHex(result.join(""));
  const timeEncoded = Math.floor(simpleHash(String(t) + "salt")).toString();
  return timeEncoded + "|" + t + "|" + encodedStr;
}

// ── Discord webhook ──────────────────────────────────────────
async function sendWebhook(webhookUrl, { hwid, key, ip, hwidsToday }) {
  const embed = {
    title:  "New Key Generated",
    color:  0x44ff88,
    fields: [
      { name: "HWID",                  value: `\`${hwid}\``,   inline: false },
      { name: "Key",                   value: `\`${key}\``,    inline: false },
      { name: "IP Address",            value: `\`${ip}\``,     inline: true  },
      { name: "HWIDs Today (this IP)", value: `${hwidsToday}`, inline: true  },
    ],
    footer:    { text: "NTT HUB Key System" },
    timestamp: new Date().toISOString(),
  };
  try {
    await fetch(webhookUrl, {
      method:  "POST",
      headers: { "Content-Type": "application/json" },
      body:    JSON.stringify({ embeds: [embed] }),
    });
  } catch {}
}

// ── main handler ─────────────────────────────────────────────
export default {
  async fetch(request, env, ctx) {
    try { return await handleRequest(request, env, ctx); }
    catch (err) {
      return new Response(JSON.stringify({ status: false, error: "internal_error", message: err?.message || "unknown" }), {
        status:  500,
        headers: { ...getCors(request), "Content-Type": "application/json" },
      });
    }
  },
};

async function handleRequest(request, env, ctx) {
  const url  = new URL(request.url);
  const type = url.searchParams.get("type");
  const ua   = request.headers.get("User-Agent") || "";

  if (request.method === "OPTIONS") {
    return new Response(null, { status: 200, headers: getCors(request) });
  }

  // ══════════════════════════════════════════════════════════
  // INIT
  // ══════════════════════════════════════════════════════════
  if (type === "init") {
    let hwid, ostime;
    try {
      const body = await request.json();
      hwid   = typeof body.hwid === "string" ? body.hwid.replace(/ /g, "+") : body.hwid;
      ostime = body.ostime;
    } catch { return json({ status: false, error: "invalid_body" }, 400, request); }

    if (!hwid || !ostime) return json({ status: false, error: "missing_params" }, 400, request);

    const now    = Math.floor(Date.now() / 1000);
    const cutoff = now - SESSION_TTL;
    const ip     = request.headers.get("CF-Connecting-IP") || "unknown";

    const blRow = await env.DB.prepare("SELECT ip FROM ip_blacklist WHERE ip = ?").bind(ip).first();
    if (blRow) return json({ status: false, error: "ip_blacklisted" }, 403, request);

    let trackRow = await env.DB.prepare("SELECT hwids, first_seen FROM ip_tracking WHERE ip = ?").bind(ip).first();
    let hwids      = [];
    let first_seen = now;

    if (trackRow) {
      if (now - trackRow.first_seen > IP_WINDOW) {
        await env.DB.prepare("DELETE FROM ip_tracking WHERE ip = ?").bind(ip).run();
      } else {
        try { hwids = JSON.parse(trackRow.hwids); } catch {}
        first_seen = trackRow.first_seen;
      }
    }

    if (!hwids.includes(hwid)) hwids.push(hwid);

    if (hwids.length >= IP_MAX_HWID) {
      await env.DB.prepare(
        "INSERT INTO ip_blacklist (ip, banned_at, reason) VALUES (?, ?, ?) ON CONFLICT(ip) DO NOTHING"
      ).bind(ip, now, "exceeded_hwid_limit").run();
      return json({ status: false, error: "ip_blacklisted", reason: "exceeded_hwid_limit" }, 403, request);
    }

    await env.DB.prepare(
      `INSERT INTO ip_tracking (ip, hwids, first_seen) VALUES (?, ?, ?)
       ON CONFLICT(ip) DO UPDATE SET hwids=excluded.hwids`
    ).bind(ip, JSON.stringify(hwids), first_seen).run();

    try {
      await env.DB.prepare("DELETE FROM progress WHERE hwid != ? AND created_at < ?").bind(hwid, cutoff).run();
    } catch {}

    await env.DB.prepare(
      `INSERT INTO progress (hwid, ostime, step1, step2, created_at) VALUES (?, ?, 0, 0, ?)
       ON CONFLICT(hwid) DO UPDATE SET ostime=excluded.ostime, step1=0, step2=0, created_at=excluded.created_at`
    ).bind(hwid, ostime, now).run();

    return json({ status: true, message: "initialized" }, request);
  }

  // ══════════════════════════════════════════════════════════
  // STEP 1
  // ══════════════════════════════════════════════════════════
  if (type === "step1") {
    const hwid = normalizeHwid(url);
    if (!hwid) return json({ status: false, error: "missing_hwid" }, 400, request);

    const row = await env.DB.prepare("SELECT * FROM progress WHERE hwid = ?").bind(hwid).first();
    if (!row) return json({ status: false, error: "session_not_found" }, 404, request);

    await env.DB.prepare("UPDATE progress SET step1 = 1 WHERE hwid = ?").bind(hwid).run();
    return json({ status: true, step1: true }, request);
  }

  // ══════════════════════════════════════════════════════════
  // STEP 2
  // ══════════════════════════════════════════════════════════
  if (type === "step2") {
    const hwid = normalizeHwid(url);
    const hash = url.searchParams.get("hash");
    if (!hwid || !hash) return json({ status: false, error: "missing_params" }, 400, request);

    const row = await env.DB.prepare("SELECT * FROM progress WHERE hwid = ?").bind(hwid).first();
    if (!row) return json({ status: false, error: "session_not_found" }, 404, request);
    if (!row.step1) return json({ status: false, error: "step1_not_done" }, 403, request);

    const elapsed = Math.floor(Date.now() / 1000) - row.created_at;
    if (elapsed < MIN_STEP2_SECONDS) {
      await env.DB.prepare("DELETE FROM progress WHERE hwid = ?").bind(hwid).run();
      return json({ status: false, error: "bypass_detected" }, 403, request);
    }

    const token = env.LINKVERTISE_TOKEN || LINKVERTISE_TOKEN;
    const valid = await checkLinkvertiseHash(hash, token, ua);
    if (!valid) return json({ status: false, error: "invalid_hash" }, 403, request);

    await env.DB.prepare("UPDATE progress SET step2 = 1 WHERE hwid = ?").bind(hwid).run();
    return json({ status: true, step2: true }, request);
  }

  // ══════════════════════════════════════════════════════════
  // STEP 3
  // ══════════════════════════════════════════════════════════
  if (type === "step3") {
    const hwid = normalizeHwid(url);
    const hash = url.searchParams.get("hash");
    if (!hwid || !hash) return json({ status: false, error: "missing_params" }, 400, request);

    const row = await env.DB.prepare("SELECT * FROM progress WHERE hwid = ?").bind(hwid).first();
    if (!row) return json({ status: false, error: "session_not_found" }, 404, request);
    if (!row.step1) return json({ status: false, error: "step1_not_done" }, 403, request);
    if (!row.step2) return json({ status: false, error: "step2_not_done" }, 403, request);

    const now     = Math.floor(Date.now() / 1000);
    const elapsed = now - row.created_at;
    if (elapsed < MIN_FLOW_SECONDS) {
      await env.DB.prepare("DELETE FROM progress WHERE hwid = ?").bind(hwid).run();
      return json({ status: false, error: "bypass_detected" }, 403, request);
    }

    const token = env.LINKVERTISE_TOKEN || LINKVERTISE_TOKEN;
    const valid = await checkLinkvertiseHash(hash, token, ua);
    if (!valid) return json({ status: false, error: "invalid_hash" }, 403, request);

    if (!env.NTT_SYSTEM) return json({ status: false, error: "kv_not_bound" }, 500, request);

    const key = "KEY_" + Math.random().toString().slice(2, 12);
    try {
      await env.NTT_SYSTEM.put(`Key/${hwid}`, key, { expirationTtl: 86400, metadata: { created: now } });
    } catch (kvErr) {
      return json({ status: false, error: "kv_write_failed", message: kvErr?.message }, 500, request);
    }

    await env.DB.prepare("DELETE FROM progress WHERE hwid = ?").bind(hwid).run();

    const clientIp = request.headers.get("CF-Connecting-IP") || "unknown";
    let hwidsToday = 1;
    try {
      const tr = await env.DB.prepare("SELECT hwids FROM ip_tracking WHERE ip = ?").bind(clientIp).first();
      if (tr) hwidsToday = JSON.parse(tr.hwids).length;
    } catch {}

    ctx.waitUntil(sendWebhook(env.WEBHOOK_URL || WEBHOOK_URL, { hwid, key, ip: clientIp, hwidsToday }));
    return json({ status: true, key, expires_in: 86400 }, request);
  }

  // ══════════════════════════════════════════════════════════
  // PROGRESS
  // ══════════════════════════════════════════════════════════
  if (type === "progress") {
    const hwid = normalizeHwid(url);
    if (!hwid) return json({ status: false, error: "missing_hwid" }, 400, request);

    const row = await env.DB.prepare("SELECT * FROM progress WHERE hwid = ?").bind(hwid).first();
    if (!row) return json({ status: false, error: "not_found" }, 404, request);

    return json({ status: true, hwid: row.hwid, step1: !!row.step1, step2: !!row.step2 }, request);
  }

  // ══════════════════════════════════════════════════════════
  // DATA — Roblox check key (trả về chuỗi encoded)
  // GET /api?type=data&hwid=xxx
  // ══════════════════════════════════════════════════════════
  if (type === "data") {
    const hwid = normalizeHwid(url);
    if (!hwid) return json({ status: false, error: "missing_hwid" }, 404, request);
    if (!env.NTT_SYSTEM) return json({ status: false, error: "data_not_bound" }, 500, request);

    const result = await env.NTT_SYSTEM.getWithMetadata(`Key/${hwid}`);
    if (!result?.value) return json({ status: false, error: "key_not_found" }, 404, request);

    const key     = result.value;
    const created = result.metadata?.created;
    const now     = Math.floor(Date.now() / 1000);
    const left    = created ? Math.max(0, 86400 - (now - created)) : 0;

    const baseKey = env.ENCODE_KEY || ENCODE_KEY;
    const payload = key + "|" + left;
    const encoded = encodeData(payload, baseKey);

    return text(encoded, 200, request);
  }

  // ══════════════════════════════════════════════════════════
  // READ — Đọc key theo hwid
  // GET /api?type=read&hwid=xxx
  // ══════════════════════════════════════════════════════════
  if (type === "read") {
    const hwid = normalizeHwid(url);
    if (!hwid) return json({ status: "error", message: "Missing hwid" }, 400, request);

    const result = await env.NTT_SYSTEM.getWithMetadata(`Key/${hwid}`);
    if (!result?.value)
      return json({ status: "error", message: "Key not found or expired" }, 404, request);

    const now     = Math.floor(Date.now() / 1000);
    const created = result.metadata?.created;
    const left    = created ? Math.max(0, 86400 - (now - created)) : null;

    return json({ status: "success", hwid, key: result.value, left }, 200, request);
  }

  return json({ status: false, error: "invalid_type" }, 400, request);
}
