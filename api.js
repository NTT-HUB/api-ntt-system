// ============================================================
// NTT HUB - Authentication System
// ============================================================

const ALLOWED_ORIGINS = [
  "https://ntt-hub.xyz",
  "https://www.ntt-hub.xyz",
  "http://localhost:3000",
  "null",
];

const JWT_SECRET = "your-super-secret-jwt-key-change-this"; // Change this!
const SESSION_TTL = 7 * 24 * 60 * 60; // 7 days

// ── Helpers ──────────────────────────────────────────────────
function getCors(request) {
  const origin = request?.headers?.get("Origin") || "";
  const allowed = ALLOWED_ORIGINS.includes(origin) ? origin : "https://ntt-hub.xyz";
  return {
    "Access-Control-Allow-Origin": allowed,
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
    "Access-Control-Allow-Credentials": "true",
    "Vary": "Origin",
  };
}

function json(obj, status = 200, request = null) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { ...getCors(request), "Content-Type": "application/json" },
  });
}

// Simple hash function (use bcrypt in production!)
async function hashPassword(password) {
  const encoder = new TextEncoder();
  const data = encoder.encode(password + "salt-key"); // Add salt
  const hashBuffer = await crypto.subtle.digest("SHA-256", data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, "0")).join("");
}

// Generate JWT token
async function generateToken(userId, username) {
  const header = btoa(JSON.stringify({ alg: "HS256", typ: "JWT" }));
  const payload = btoa(JSON.stringify({
    userId,
    username,
    exp: Math.floor(Date.now() / 1000) + SESSION_TTL,
  }));
  const signature = await hashPassword(header + "." + payload + JWT_SECRET);
  return `${header}.${payload}.${signature.substring(0, 43)}`;
}

// Verify JWT token
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

// ── Main Handler ─────────────────────────────────────────────
export default {
  async fetch(request, env, ctx) {
    try {
      return await handleRequest(request, env, ctx);
    } catch (err) {
      return json({ success: false, error: err.message }, 500, request);
    }
  },
};

async function handleRequest(request, env, ctx) {
  const url = new URL(request.url);
  const path = url.pathname;

  if (request.method === "OPTIONS") {
    return new Response(null, { status: 200, headers: getCors(request) });
  }

  // ══════════════════════════════════════════════════════════
  // REGISTER
  // ══════════════════════════════════════════════════════════
  if (path === "/auth/register" && request.method === "POST") {
    let body;
    try {
      body = await request.json();
    } catch {
      return json({ success: false, error: "Invalid JSON" }, 400, request);
    }

    const { username, email, password } = body;

    // Validation
    if (!username || !email || !password) {
      return json({ success: false, error: "All fields are required" }, 400, request);
    }

    if (username.length < 3) {
      return json({ success: false, error: "Username must be at least 3 characters" }, 400, request);
    }

    if (password.length < 6) {
      return json({ success: false, error: "Password must be at least 6 characters" }, 400, request);
    }

    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return json({ success: false, error: "Invalid email format" }, 400, request);
    }

    // Check if user exists
    const existingUser = await env.DB.prepare(
      "SELECT id FROM users WHERE username = ? OR email = ?"
    ).bind(username, email).first();

    if (existingUser) {
      return json({ success: false, error: "Username or email already exists" }, 409, request);
    }

    // Hash password
    const hashedPassword = await hashPassword(password);
    const now = Math.floor(Date.now() / 1000);

    // Create user
    const result = await env.DB.prepare(
      `INSERT INTO users (username, email, password, created_at) 
       VALUES (?, ?, ?, ?) RETURNING id`
    ).bind(username, email, hashedPassword, now).first();

    const token = await generateToken(result.id, username);

    return json({
      success: true,
      message: "Account created successfully",
      user: { id: result.id, username, email },
      token,
    }, 201, request);
  }

  // ══════════════════════════════════════════════════════════
  // LOGIN
  // ══════════════════════════════════════════════════════════
  if (path === "/auth/login" && request.method === "POST") {
    let body;
    try {
      body = await request.json();
    } catch {
      return json({ success: false, error: "Invalid JSON" }, 400, request);
    }

    const { username, password } = body;

    if (!username || !password) {
      return json({ success: false, error: "Username and password are required" }, 400, request);
    }

    // Find user
    const user = await env.DB.prepare(
      "SELECT * FROM users WHERE username = ? OR email = ?"
    ).bind(username, username).first();

    if (!user) {
      return json({ success: false, error: "Invalid credentials" }, 401, request);
    }

    // Verify password
    const hashedInput = await hashPassword(password);
    if (hashedInput !== user.password) {
      return json({ success: false, error: "Invalid credentials" }, 401, request);
    }

    // Generate token
    const token = await generateToken(user.id, user.username);

    return json({
      success: true,
      message: "Login successful",
      user: {
        id: user.id,
        username: user.username,
        email: user.email,
      },
      token,
    }, request);
  }

  // ══════════════════════════════════════════════════════════
  // VERIFY TOKEN (Check if logged in)
  // ══════════════════════════════════════════════════════════
  if (path === "/auth/verify" && request.method === "GET") {
    const authHeader = request.headers.get("Authorization");
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return json({ success: false, error: "No token provided" }, 401, request);
    }

    const token = authHeader.substring(7);
    const payload = await verifyToken(token);

    if (!payload) {
      return json({ success: false, error: "Invalid or expired token" }, 401, request);
    }

    // Get user info
    const user = await env.DB.prepare(
      "SELECT id, username, email, created_at FROM users WHERE id = ?"
    ).bind(payload.userId).first();

    if (!user) {
      return json({ success: false, error: "User not found" }, 404, request);
    }

    return json({
      success: true,
      user: {
        id: user.id,
        username: user.username,
        email: user.email,
        created_at: user.created_at,
      },
    }, request);
  }

  // ══════════════════════════════════════════════════════════
  // LOGOUT (client-side only, just invalidate token)
  // ══════════════════════════════════════════════════════════
  if (path === "/auth/logout" && request.method === "POST") {
    return json({
      success: true,
      message: "Logged out successfully",
    }, request);
  }

  return json({ success: false, error: "Not found" }, 404, request);
}
