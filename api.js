const LINKVERTISE_TOKEN = "7581177bce5e0eb39a7b44cf7aa9c82128e535e9736074c5945f7255975204f0";
const MIN_FLOW_SECONDS  = 25;
const SYSTEM_START_LINK = "https://link-center.net/1213408/testapi";

const SESSION_TTL = 2 * 60 * 60;
const IP_WINDOW   = 24 * 60 * 60;
const IP_MAX_HWID = 20;

const ALLOWED_ORIGINS = [
  "https://ntt-hub.xyz",
  "https://www.ntt-hub.xyz",
  "https://ntt-system.pages.dev",
  "https://ntt-system.xyz",
  "https://www.ntt-system.xyz",
  "null",
];

function getCors(request) {
  const origin  = request?.headers?.get("Origin") || "";
  const allowed = (!origin || ALLOWED_ORIGINS.includes(origin)) ? (origin || "*") : "https://ntt-hub.xyz";
  return {
    "Access-Control-Allow-Origin":  allowed,
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, User-Agent, Authorization",
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
  try {
    const decoded = decodeURIComponent(raw).replace(/ /g, "+");
    return decoded.length > 50 ? null : decoded;
  } catch {
    const h = raw.replace(/ /g, "+");
    return h.length > 50 ? null : h;
  }
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

function simpleHash(str) {
  let hash = 0;
  for (let i = 0; i < str.length; i++) {
    hash = (hash * 131 + str.charCodeAt(i)) % 4294967296;
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
    const k    = (hashedKey + (i + 1) * 7) % 256;
    let encoded = (byte ^ k);
    encoded = (encoded + k) % 256;
    result.push(String.fromCharCode(encoded));
  }

  const encodedStr  = toHex(result.join(""));
  const timeEncoded = Math.floor(simpleHash(String(t) + "salt")).toString();
  return timeEncoded + "|" + t + "|" + encodedStr;
}

async function sendWebhook(webhookUrl, { hwid, key, hwidsToday }) {
  if (!webhookUrl) return;
  const embed = {
    title: "New Key Generated",
    color: 0x00ff9d,
    fields: [
      { name: "HWID",  value: `\`${hwid}\``, inline: false },
      { name: "Key",   value: `\`${key}\``,  inline: false },
      { name: "HWIDs Today (this IP)", value: `${hwidsToday}`, inline: true },
    ],
    footer: { text: "NTT System" },
    timestamp: new Date().toISOString(),
  };
  try {
    await fetch(webhookUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ embeds: [embed] }),
    });
  } catch {}
}

const JWT_SECRET = "ntt-hub-jwt-secret-change-this";
const SESSION_DURATION = 7 * 24 * 60 * 60;

async function hashPassword(password) {
  const encoder = new TextEncoder();
  const data = encoder.encode(password + "ntt-salt-key");
  const hashBuffer = await crypto.subtle.digest("SHA-256", data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, "0")).join("");
}

async function generateToken(userId, username) {
  const header  = btoa(JSON.stringify({ alg: "HS256", typ: "JWT" }));
  const payload = btoa(JSON.stringify({
    userId,
    username,
    exp: Math.floor(Date.now() / 1000) + SESSION_DURATION,
  }));
  const signature = await hashPassword(header + "." + payload + JWT_SECRET);
  return `${header}.${payload}.${signature.substring(0, 43)}`;
}

async function verifyToken(token) {
  try {
    const parts = token.split(".");
    if (parts.length !== 3) return null;
    const payload = JSON.parse(atob(parts[1]));
    if (payload.exp < Math.floor(Date.now() / 1000)) return null;
    const expectedSig = await hashPassword(parts[0] + "." + parts[1] + JWT_SECRET);
    if (!expectedSig.startsWith(parts[2])) return null;
    return payload;
  } catch {
    return null;
  }
}

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

  if (type === "init") {
    let hwid, ostime;
    try {
      const body = await request.json();
      hwid   = typeof body.hwid === "string" ? body.hwid.replace(/ /g, "+") : body.hwid;
      ostime = body.ostime;
    } catch { return json({ status: false, error: "invalid_body" }, 400, request); }

    if (!hwid || !ostime) return json({ status: false, error: "missing_params" }, 400, request);
    if (hwid.length > 50) return json({ status: false, error: "invalid_hwid" }, 400, request);

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
      `INSERT INTO progress (hwid, ostime, start, step1, step2, created_at) VALUES (?, ?, 0, 0, 0, ?)
       ON CONFLICT(hwid) DO UPDATE SET ostime=excluded.ostime, start=0, step1=0, step2=0, created_at=excluded.created_at`
    ).bind(hwid, ostime, now).run();

    return json({ status: true, message: "initialized" }, request);
  }

  if (type === "progress") {
    const hwid   = normalizeHwid(url);
    const flowId = url.searchParams.get("flow") || "default";
    if (!hwid) return json({ status: false, error: "missing_hwid" }, 400, request);

    const row = await env.DB.prepare("SELECT * FROM progress WHERE hwid = ? AND flow_id = ?").bind(hwid, flowId).first();
    if (!row) return json({ status: false, start: false, step1: false, step2: false }, 200, request);

    return json({ status: true, hwid: row.hwid, start: !!row.start, step1: !!row.step1, step2: !!row.step2 }, request);
  }

  if (type === "data") {
    const hwid = normalizeHwid(url);
    if (!hwid) return json({ status: false, error: "missing_hwid" }, 404, request);
    if (!env["ntt-system"]) return json({ status: false, error: "data_not_bound" }, 500, request);

    const result = await env["ntt-system"].getWithMetadata(`${url.searchParams.get("domain") || "default"}/${hwid}`);
    if (!result?.value) return json({ status: false, error: "key_not_found" }, 404, request);

    const key     = result.value;
    const created = result.metadata?.created;
    const now     = Math.floor(Date.now() / 1000);
    const left    = created ? Math.max(0, 86400 - (now - created)) : 0;
    const domain  = url.searchParams.get("domain") || result.metadata?.domain || "";

    let baseKey = env.ENCODE_KEY || "ntt-hub";
    if (domain) {
      const settings = await env.DB.prepare("SELECT encode_key FROM user_settings WHERE website_domain = ?")
        .bind(domain).first();
      if (settings?.encode_key) baseKey = settings.encode_key;
    }

    const payload = key + "|" + left;
    const encoded = encodeData(payload, baseKey);
    return text(encoded, 200, request);
  }

  if (type === "read") {
    const hwid = normalizeHwid(url);
    if (!hwid) return json({ status: "error", message: "Missing hwid" }, 400, request);

    const readDomain = url.searchParams.get("domain") || "";
    const kvKey = readDomain ? `${readDomain}/${hwid}` : `Key/${hwid}`;
    const result = await env["ntt-system"].getWithMetadata(kvKey);
    if (!result?.value)
      return json({ status: "error", message: "Key not found or expired" }, 404, request);

    const now     = Math.floor(Date.now() / 1000);
    const created = result.metadata?.created;
    const left    = created ? Math.max(0, 86400 - (now - created)) : null;

    return json({ status: "success", hwid, key: result.value, left }, 200, request);
  }

  if (type === "get_system_settings") {
    const s = await env.DB.prepare("SELECT * FROM system_settings WHERE id = 1").first();
    return json({ success: true, settings: s || {} }, request);
  }

  if (type === "save_system_settings") {
    let body;
    try { body = await request.json(); }
    catch { return json({ success: false, error: "Invalid JSON" }, 400, request); }

    const { start_type, start_link, start_yt_links, linkvertise_token } = body;
    const now = Math.floor(Date.now() / 1000);

    await env.DB.prepare(`
      INSERT INTO system_settings (id, start_type, start_link, start_yt_links, linkvertise_token, updated_at)
      VALUES (1, ?, ?, ?, ?, ?)
      ON CONFLICT(id) DO UPDATE SET
        start_type        = excluded.start_type,
        start_link        = excluded.start_link,
        start_yt_links    = excluded.start_yt_links,
        linkvertise_token = excluded.linkvertise_token,
        updated_at        = excluded.updated_at
    `).bind(
      start_type || "linkvertise",
      start_link || "",
      start_yt_links || "[]",
      linkvertise_token || "",
      now
    ).run();

    return json({ success: true, message: "System settings saved" }, request);
  }

  if (type === "get_start_link") {
    return json({
      success: true,
      start_link: env.SYSTEM_START_LINK || SYSTEM_START_LINK,
    }, request);
  }

  if (type === "captcha_new") {
    const hwid = url.searchParams.get("hwid");
    if (!hwid) return json({ success: false, error: "missing_hwid" }, 400, request);

    const chars  = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
    let answer   = "";
    for (let i = 0; i < 5; i++) answer += chars[Math.floor(Math.random() * chars.length)];

    const id  = crypto.randomUUID();
    const now = Math.floor(Date.now() / 1000);

    await env.DB.prepare("DELETE FROM captcha_sessions WHERE hwid = ? OR created_at < ?")
      .bind(hwid, now - 300).run();

    await env.DB.prepare(
      "INSERT INTO captcha_sessions (id, answer, hwid, used, created_at) VALUES (?, ?, ?, 0, ?)"
    ).bind(id, answer, hwid, now).run();

    const colors = ['#00ff9d','#6ee7b7','#a5f3fc','#c4b5fd','#fde68a'];
    const noises = Array.from({length: 6}, () => {
      const x1 = Math.floor(Math.random()*200), y1 = Math.floor(Math.random()*60);
      const x2 = Math.floor(Math.random()*200), y2 = Math.floor(Math.random()*60);
      const op = (0.2 + Math.random()*0.3).toFixed(2);
      return `<line x1="${x1}" y1="${y1}" x2="${x2}" y2="${y2}" stroke="rgba(255,255,255,${op})" stroke-width="1"/>`;
    }).join('');

    const letters = answer.split('').map((ch, i) => {
      const x = 20 + i * 36;
      const y = 38 + Math.floor((Math.random()-0.5)*10);
      const rot = Math.floor((Math.random()-0.5)*25);
      const size = 24 + Math.floor(Math.random()*8);
      const col = colors[i % colors.length];
      return `<text x="${x}" y="${y}" font-family="monospace" font-size="${size}" font-weight="bold" fill="${col}" transform="rotate(${rot},${x},${y})">${ch}</text>`;
    }).join('');

    const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="200" height="60"><rect width="200" height="60" fill="#0d1120"/>${noises}${letters}</svg>`;
    const b64 = btoa(svg);

    return json({ success: true, id, image: `data:image/svg+xml;base64,${b64}` }, request);
  }

  if (type === "captcha_verify") {
    let body;
    try { body = await request.json(); }
    catch { return json({ success: false, error: "Invalid JSON" }, 400, request); }

    const { id, answer, hwid } = body;
    if (!id || !answer || !hwid) return json({ success: false, error: "Missing params" }, 400, request);

    const now = Math.floor(Date.now() / 1000);
    const row = await env.DB.prepare("SELECT * FROM captcha_sessions WHERE id = ?").bind(id).first();

    if (!row) return json({ success: false, error: "Invalid captcha" }, 403, request);
    if (row.used) return json({ success: false, error: "Captcha already used" }, 403, request);
    if (row.hwid !== hwid) return json({ success: false, error: "Invalid captcha" }, 403, request);
    if (now - row.created_at > 120) {
      await env.DB.prepare("DELETE FROM captcha_sessions WHERE id = ?").bind(id).run();
      return json({ success: false, error: "Captcha expired" }, 403, request);
    }
    if (row.answer !== answer.toUpperCase().trim()) {
      await env.DB.prepare("DELETE FROM captcha_sessions WHERE id = ?").bind(id).run();
      return json({ success: false, error: "Wrong answer" }, 403, request);
    }

    const token = crypto.randomUUID();
    await env.DB.prepare("UPDATE captcha_sessions SET used = 1, id = ? WHERE id = ?")
      .bind(token, id).run();

    return json({ success: true, token }, request);
  }

  if (type === "complete_step") {
    let body;
    try { body = await request.json(); }
    catch { return json({ success: false, error: "Invalid JSON" }, 400, request); }

    const { hwid, step, hash, domain, flow_id, captcha_token } = body;
    if (!hwid || !step || !domain) return json({ success: false, error: "Missing params" }, 400, request);
    if (hwid.length > 50) return json({ success: false, error: "Invalid hwid" }, 400, request);

    const flowKey = flow_id || "default";

    if (step === "start") {
      if (!captcha_token) return json({ success: false, error: "captcha_required" }, 403, request);
      const ct = await env.DB.prepare("SELECT * FROM captcha_sessions WHERE id = ?").bind(captcha_token).first();
      if (!ct || !ct.used || ct.hwid !== hwid) return json({ success: false, error: "invalid_captcha_token" }, 403, request);
      await env.DB.prepare("DELETE FROM captcha_sessions WHERE id = ?").bind(captcha_token).run();
    }

    const userSettings = await env.DB.prepare(
      "SELECT linkvertise_token, step1_type, step2_type FROM user_settings WHERE website_domain = ?"
    ).bind(domain).first();

    if (!userSettings)
      return json({ success: false, error: "domain_not_found" }, 404, request);

    const stepType = step === 1 ? (userSettings.step1_type || "linkvertise")
                   : step === 2 ? (userSettings.step2_type || "linkvertise")
                   : (() => {
                       return "system_start";
                     })();

    let bypassSeconds = (stepType === "lootlab") ? 40 : (stepType === "workink") ? 30 : 10;

    if (step === "start") {
      const sys = await env.DB.prepare("SELECT * FROM system_settings WHERE id = 1").first();
      const sysType = sys?.start_type || "linkvertise";
      bypassSeconds = (sysType === "lootlab") ? 40 : (sysType === "workink") ? 30 : 10;
      if (sysType === "linkvertise" && sys?.linkvertise_token?.trim()) {
        if (!hash || hash.length < 10) return json({ success: false, error: "missing_hash" }, 403, request);
        const valid = await checkLinkvertiseHash(hash, sys.linkvertise_token, ua);
        if (!valid) return json({ success: false, error: "invalid_hash" }, 403, request);
      }
    } else if (stepType === "linkvertise" && userSettings.linkvertise_token?.trim()) {
      if (!hash || hash.length < 10) return json({ success: false, error: "missing_hash" }, 403, request);
      const valid = await checkLinkvertiseHash(hash, userSettings.linkvertise_token, ua);
      if (!valid) return json({ success: false, error: "invalid_hash" }, 403, request);
    }

    const now = Math.floor(Date.now() / 1000);

    let progress = await env.DB.prepare("SELECT * FROM progress WHERE hwid = ? AND flow_id = ?").bind(hwid, flowKey).first();

    if (!progress) {
      await env.DB.prepare(
        "INSERT INTO progress (hwid, ostime, start, step1, step2, created_at, flow_id) VALUES (?, ?, 0, 0, 0, ?, ?)"
      ).bind(hwid, now, now, flowKey).run();
      progress = { created_at: now, start: 0, step1: 0, step2: 0 };
    }

    if (step !== "start" && progress.start) {
      const elapsed = now - progress.created_at;
      if (elapsed < bypassSeconds) {
        await env.DB.prepare("DELETE FROM progress WHERE hwid = ? AND flow_id = ?").bind(hwid, flowKey).run();
        return json({ success: false, error: "bypass_detected", message: "Too fast, please try again" }, 403, request);
      }
    }

    if (step === "start") {
      await env.DB.prepare("UPDATE progress SET start = 1, created_at = ? WHERE hwid = ? AND flow_id = ?").bind(now, hwid, flowKey).run();
    } else if (step === 1) {
      await env.DB.prepare("UPDATE progress SET start = 1, step1 = 1 WHERE hwid = ? AND flow_id = ?").bind(hwid, flowKey).run();
    } else if (step === 2) {
      await env.DB.prepare("UPDATE progress SET step2 = 1 WHERE hwid = ? AND flow_id = ?").bind(hwid, flowKey).run();
    }

    return json({ success: true, message: `Step ${step} completed` }, request);
  }

  if (type === "create_key") {
    let body;
    try { body = await request.json(); }
    catch { return json({ success: false, error: "Invalid JSON" }, 400, request); }

    const { hwid, domain, key_prefix, flow_id } = body;
    if (!hwid || !domain || !key_prefix)
      return json({ success: false, error: "Missing params" }, 400, request);
    if (hwid.length > 50) return json({ success: false, error: "Invalid hwid" }, 400, request);

    const flowKey = flow_id || "default";
    const progress = await env.DB.prepare("SELECT * FROM progress WHERE hwid = ? AND flow_id = ?").bind(hwid, flowKey).first();
    const settings = await env.DB.prepare("SELECT * FROM user_settings WHERE website_domain = ?")
      .bind(domain).first();

    if (!settings)
      return json({ success: false, error: "Settings not found" }, 404, request);

    if (!progress)
      return json({ success: false, error: "No progress found. Please complete the steps." }, 403, request);

    const now = Math.floor(Date.now() / 1000);
    const step1Type = settings.step1_type || "linkvertise";
    const bypassSeconds = (step1Type === "lootlab") ? 40 : (step1Type === "workink") ? 30 : 10;
    if (progress.start && (now - progress.created_at) < bypassSeconds) {
      await env.DB.prepare("DELETE FROM progress WHERE hwid = ?").bind(hwid).run();
      return json({ success: false, error: "bypass_detected", message: "Too fast, please try again" }, 403, request);
    }

    if (!progress.step1)
      return json({ success: false, error: "Step 1 not completed" }, 403, request);

    if (settings.ad_steps === 2 && !progress.step2)
      return json({ success: false, error: "Step 2 not completed" }, 403, request);

    const keyId = Math.random().toString().slice(2, 9);
    const key   = `${key_prefix.toUpperCase()}_${keyId}`;

    if (!env["ntt-system"])
      return json({ success: false, error: "KV not bound" }, 500, request);

    await env["ntt-system"].put(`${domain}/${hwid}`, key, {
      expirationTtl: 86400,
      metadata: { created: now, domain },
    });

    await env.DB.prepare(
      "UPDATE user_settings SET total_keys = total_keys + 1 WHERE website_domain = ?"
    ).bind(domain).run();

    await env.DB.prepare("DELETE FROM progress WHERE hwid = ? AND flow_id = ?").bind(hwid, flowKey).run();

    const updatedSettings = await env.DB.prepare(
      "SELECT total_keys, discord_webhook FROM user_settings WHERE website_domain = ?"
    ).bind(domain).first();

    let hwidsToday = 1;
    try {
      const tr = await env.DB.prepare("SELECT hwids FROM ip_tracking WHERE ip = ?")
        .bind(request.headers.get("CF-Connecting-IP") || "unknown").first();
      if (tr) hwidsToday = JSON.parse(tr.hwids).length;
    } catch {}

    if (updatedSettings?.discord_webhook) {
      ctx.waitUntil(sendWebhook(updatedSettings.discord_webhook, { hwid, key, hwidsToday }));
    }

    return json({
      success: true,
      key,
      expires_in: 86400,
      total_keys: updatedSettings?.total_keys || 1,
    }, request);
  }

  if (type === "register") {
    let body;
    try { body = await request.json(); }
    catch { return json({ success: false, error: "Invalid JSON" }, 400, request); }

    const { username, email, password } = body;
    if (!username || !email || !password)
      return json({ success: false, error: "All fields required" }, 400, request);

    if (!/^[a-zA-Z0-9_ ]+$/.test(username))
      return json({ success: false, error: "Username can only contain letters, numbers, spaces, and underscores" }, 400, request);

    if (username.length < 3 || username.length > 15)
      return json({ success: false, error: "Username must be 3-15 chars" }, 400, request);
    if (password.length < 6 || password.length > 20)
      return json({ success: false, error: "Password must be 6-20 chars" }, 400, request);

    const existing = await env.DB.prepare("SELECT id FROM users WHERE username = ? OR email = ?")
      .bind(username, email).first();
    if (existing)
      return json({ success: false, error: "Username or email exists" }, 409, request);

    const hashedPassword = await hashPassword(password);
    const now = Math.floor(Date.now() / 1000);

    const result = await env.DB.prepare(
      "INSERT INTO users (username, email, password, created_at) VALUES (?, ?, ?, ?) RETURNING id"
    ).bind(username, email, hashedPassword, now).first();

    const defaultDomain = username.toLowerCase().replace(/\s+/g, '-').replace(/[^a-z0-9\-]/g, '').slice(0, 15);
    await env.DB.prepare(`
      INSERT INTO user_settings (user_id, website_domain, key_domain, encode_key, linkvertise_token, discord_webhook, ad_steps, step1_link, step2_link, created_at, updated_at)
      VALUES (?, ?, 'KEY', 'ntt-hub', '', '', 1, '', '', ?, ?)
      ON CONFLICT(user_id) DO NOTHING
    `).bind(result.id, defaultDomain, now, now).run();

    const token = await generateToken(result.id, username);

    return json({
      success: true,
      message: "Account created",
      user: { id: result.id, username, email },
      token,
    }, 201, request);
  }

  if (type === "login") {
    let body;
    try { body = await request.json(); }
    catch { return json({ success: false, error: "Invalid JSON" }, 400, request); }

    const { username, password } = body;
    if (!username || !password)
      return json({ success: false, error: "Username and password required" }, 400, request);

    const user = await env.DB.prepare("SELECT * FROM users WHERE username = ? OR email = ?")
      .bind(username, username).first();
    if (!user)
      return json({ success: false, error: "Invalid credentials" }, 401, request);

    const hashedInput = await hashPassword(password);
    if (hashedInput !== user.password)
      return json({ success: false, error: "Invalid credentials" }, 401, request);

    const token = await generateToken(user.id, user.username);

    return json({
      success: true,
      message: "Login successful",
      user: { id: user.id, username: user.username, email: user.email },
      token,
    }, request);
  }

  if (type === "verify") {
    const authHeader = request.headers.get("Authorization");
    if (!authHeader || !authHeader.startsWith("Bearer "))
      return json({ success: false, error: "No token" }, 401, request);

    const token = authHeader.substring(7);
    const payload = await verifyToken(token);
    if (!payload)
      return json({ success: false, error: "Invalid token" }, 401, request);

    const user = await env.DB.prepare(
      "SELECT id, username, email, created_at FROM users WHERE id = ?"
    ).bind(payload.userId).first();

    if (!user)
      return json({ success: false, error: "User not found" }, 404, request);

    return json({
      success: true,
      user: { id: user.id, username: user.username, email: user.email, created_at: user.created_at },
    }, request);
  }

  if (type === "save_settings") {
    let body;
    try { body = await request.json(); }
    catch { return json({ success: false, error: "Invalid JSON" }, 400, request); }

    const {
      user_id, website_domain, key_domain, encode_key,
      linkvertise_token, discord_webhook, ad_steps,
      step1_link, step2_link, step1_type, step2_type,
      step1_yt_links, step2_yt_links,
    } = body;

    if (!user_id || !website_domain)
      return json({ success: false, error: "Missing required fields" }, 400, request);

    const finalDomain = website_domain
      .trim().toLowerCase()
      .replace(/\s+/g, "-")
      .replace(/[^a-z0-9\-]/g, "")
      .slice(0, 15);

    if (!finalDomain)
      return json({ success: false, error: "Invalid website domain" }, 400, request);

    const finalKeyDomain = (key_domain || "KEY").toUpperCase();
    if (finalKeyDomain.length > 10)
      return json({ success: false, error: "Key domain max 10 chars" }, 400, request);

    const now            = Math.floor(Date.now() / 1000);
    const finalEncodeKey = encode_key || "ntt-hub";
    if (finalEncodeKey.length > 20)
      return json({ success: false, error: "Encode key max 20 chars" }, 400, request);

    const domainTaken = await env.DB.prepare(
      "SELECT user_id FROM user_settings WHERE website_domain = ? AND user_id != ?"
    ).bind(finalDomain, user_id).first();
    if (domainTaken)
      return json({ success: false, error: "Domain already taken by another user" }, 409, request);

    const existing = await env.DB.prepare("SELECT * FROM user_settings WHERE user_id = ?")
      .bind(user_id).first();

    const finalToken     = linkvertise_token !== undefined ? linkvertise_token : (existing?.linkvertise_token || "");
    const finalWebhook   = discord_webhook   !== undefined ? discord_webhook   : (existing?.discord_webhook   || "");
    const finalSteps     = ad_steps          !== undefined ? ad_steps          : (existing?.ad_steps          || 1);
    const finalStep1     = step1_link        !== undefined ? step1_link        : (existing?.step1_link        || "");
    const finalStep2     = step2_link        !== undefined ? step2_link        : (existing?.step2_link        || "");
    const finalStep1Type  = step1_type       !== undefined ? step1_type       : (existing?.step1_type       || "linkvertise");
    const finalStep2Type  = step2_type       !== undefined ? step2_type       : (existing?.step2_type       || "linkvertise");
    const finalStep1Yt    = step1_yt_links   !== undefined ? step1_yt_links   : (existing?.step1_yt_links   || "[]");
    const finalStep2Yt    = step2_yt_links   !== undefined ? step2_yt_links   : (existing?.step2_yt_links   || "[]");

    await env.DB.prepare(`
      INSERT INTO user_settings
        (user_id, website_domain, key_domain, encode_key, linkvertise_token, discord_webhook, ad_steps, step1_link, step2_link, step1_type, step2_type, step1_yt_links, step2_yt_links, created_at, updated_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT(user_id) DO UPDATE SET
        website_domain    = excluded.website_domain,
        key_domain        = excluded.key_domain,
        encode_key        = excluded.encode_key,
        linkvertise_token = excluded.linkvertise_token,
        discord_webhook   = excluded.discord_webhook,
        ad_steps          = excluded.ad_steps,
        step1_link        = excluded.step1_link,
        step2_link        = excluded.step2_link,
        step1_type        = excluded.step1_type,
        step2_type        = excluded.step2_type,
        step1_yt_links    = excluded.step1_yt_links,
        step2_yt_links    = excluded.step2_yt_links,
        updated_at        = excluded.updated_at
    `).bind(
      user_id, finalDomain, finalKeyDomain, finalEncodeKey,
      finalToken, finalWebhook, finalSteps,
      finalStep1, finalStep2, finalStep1Type, finalStep2Type,
      finalStep1Yt, finalStep2Yt, now, now,
    ).run();

    return json({ success: true, message: "Settings saved", website_domain: finalDomain }, request);
  }

  if (type === "get_settings") {
    const userId = url.searchParams.get("user_id");
    if (!userId) return json({ success: false, error: "Missing user_id" }, 400, request);

    const settings = await env.DB.prepare("SELECT * FROM user_settings WHERE user_id = ?")
      .bind(userId).first();

    if (!settings)
      return json({ success: false, error: "Settings not found" }, 404, request);

    return json({ success: true, settings }, request);
  }

  if (type === "get_flows") {
    const userId = url.searchParams.get("user_id");
    if (!userId) return json({ success: false, error: "Missing user_id" }, 400, request);
    const flows = await env.DB.prepare("SELECT * FROM user_flows WHERE user_id = ? ORDER BY flow_id ASC").bind(userId).all();
    return json({ success: true, flows: flows.results || [] }, request);
  }

  if (type === "save_flow") {
    let body;
    try { body = await request.json(); }
    catch { return json({ success: false, error: "Invalid JSON" }, 400, request); }

    const { user_id, flow_id, name, ad_steps, step1_type, step1_link, step1_yt_links, step2_type, step2_link, step2_yt_links } = body;
    if (!user_id || !flow_id) return json({ success: false, error: "Missing params" }, 400, request);

    const now = Math.floor(Date.now() / 1000);
    await env.DB.prepare(`
      INSERT INTO user_flows (user_id, flow_id, name, ad_steps, step1_type, step1_link, step1_yt_links, step2_type, step2_link, step2_yt_links, created_at, updated_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT(user_id, flow_id) DO UPDATE SET
        name           = excluded.name,
        ad_steps       = excluded.ad_steps,
        step1_type     = excluded.step1_type,
        step1_link     = excluded.step1_link,
        step1_yt_links = excluded.step1_yt_links,
        step2_type     = excluded.step2_type,
        step2_link     = excluded.step2_link,
        step2_yt_links = excluded.step2_yt_links,
        updated_at     = excluded.updated_at
    `).bind(
      user_id, flow_id, name || `Flow ${flow_id}`, ad_steps || 1,
      step1_type || "linkvertise", step1_link || "", step1_yt_links || "[]",
      step2_type || "linkvertise", step2_link || "", step2_yt_links || "[]",
      now, now
    ).run();

    return json({ success: true, message: "Flow saved" }, request);
  }

  if (type === "delete_flow") {
    let body;
    try { body = await request.json(); }
    catch { return json({ success: false, error: "Invalid JSON" }, 400, request); }

    const { user_id, flow_id } = body;
    if (!user_id || !flow_id) return json({ success: false, error: "Missing params" }, 400, request);

    await env.DB.prepare("DELETE FROM user_flows WHERE user_id = ? AND flow_id = ?").bind(user_id, flow_id).run();
    return json({ success: true, message: "Flow deleted" }, request);
  }

  if (type === "get_settings_by_domain") {
    const domain  = url.searchParams.get("domain");
    const flowId  = url.searchParams.get("flow");
    if (!domain) return json({ success: false, error: "Missing domain" }, 400, request);

    const settings = await env.DB.prepare("SELECT * FROM user_settings WHERE website_domain = ?")
      .bind(domain).first();

    if (!settings)
      return json({ success: false, error: "Settings not found" }, 404, request);

    const sys = await env.DB.prepare("SELECT * FROM system_settings WHERE id = 1").first();

    let flowSettings = {};
    if (flowId) {
      const flow = await env.DB.prepare("SELECT * FROM user_flows WHERE user_id = ? AND flow_id = ?")
        .bind(settings.user_id, flowId).first();
      if (flow) {
        flowSettings = {
          ad_steps:       flow.ad_steps,
          step1_type:     flow.step1_type,
          step1_link:     flow.step1_link,
          step1_yt_links: flow.step1_yt_links,
          step2_type:     flow.step2_type,
          step2_link:     flow.step2_link,
          step2_yt_links: flow.step2_yt_links,
        };
      }
    }

    return json({
      success: true,
      settings: {
        ...settings,
        ...flowSettings,
        start_link:     sys?.start_link     || env.SYSTEM_START_LINK || SYSTEM_START_LINK,
        start_type:     sys?.start_type     || "linkvertise",
        start_yt_links: sys?.start_yt_links || "[]",
      },
    }, request);
  }

  if (type === "change_username") {
    let body;
    try { body = await request.json(); }
    catch { return json({ success: false, error: "Invalid JSON" }, 400, request); }

    const { user_id, new_username, password } = body;
    if (!user_id || !new_username || !password)
      return json({ success: false, error: "Missing parameters" }, 400, request);

    if (!/^[a-zA-Z0-9_ ]+$/.test(new_username))
      return json({ success: false, error: "Username can only contain letters, numbers, spaces, and underscores" }, 400, request);

    if (new_username.length < 3 || new_username.length > 15)
      return json({ success: false, error: "Username must be 3-15 chars" }, 400, request);

    const userCheck = await env.DB.prepare("SELECT password FROM users WHERE id = ?")
      .bind(user_id).first();
    if (!userCheck) return json({ success: false, error: "User not found" }, 404, request);

    const hashedInput = await hashPassword(password);
    if (hashedInput !== userCheck.password)
      return json({ success: false, error: "Incorrect password" }, 401, request);

    const existing = await env.DB.prepare("SELECT id FROM users WHERE username = ? AND id != ?")
      .bind(new_username, user_id).first();
    if (existing)
      return json({ success: false, error: "Username already taken" }, 409, request);

    await env.DB.prepare("UPDATE users SET username = ? WHERE id = ?")
      .bind(new_username, user_id).run();

    return json({ success: true, message: "Username updated" }, request);
  }

  if (type === "change_password") {
    let body;
    try { body = await request.json(); }
    catch { return json({ success: false, error: "Invalid JSON" }, 400, request); }

    const { user_id, current_password, new_password } = body;
    if (!user_id || !current_password || !new_password)
      return json({ success: false, error: "Missing parameters" }, 400, request);

    if (new_password.length < 6 || new_password.length > 20)
      return json({ success: false, error: "Password must be 6-20 chars" }, 400, request);

    const user = await env.DB.prepare("SELECT password FROM users WHERE id = ?")
      .bind(user_id).first();
    if (!user)
      return json({ success: false, error: "User not found" }, 404, request);

    const hashedCurrent = await hashPassword(current_password);
    if (hashedCurrent !== user.password)
      return json({ success: false, error: "Current password is incorrect" }, 401, request);

    const hashedNew = await hashPassword(new_password);
    await env.DB.prepare("UPDATE users SET password = ? WHERE id = ?")
      .bind(hashedNew, user_id).run();

    return json({ success: true, message: "Password updated" }, request);
  }

  if (type === "get_system_total") {
    try {
      const result = await env.DB.prepare("SELECT SUM(total_keys) as total FROM user_settings").first();
      return json({ success: true, total: result?.total || 0 }, request);
    } catch {
      return json({ success: true, total: 0 }, request);
    }
  }

  if (type === "get_stats") {
    try {
      const keysRow  = await env.DB.prepare("SELECT SUM(total_keys) as total FROM user_settings").first();
      const usersRow = await env.DB.prepare("SELECT COUNT(*) as total FROM users").first();
      return json({
        success:     true,
        total_keys:  keysRow?.total  || 0,
        total_users: usersRow?.total || 0,
      }, request);
    } catch {
      return json({ success: true, total_keys: 0, total_users: 0 }, request);
    }
  }

  return json({ status: false, error: "invalid_type" }, 400, request);
}
