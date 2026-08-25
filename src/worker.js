/**
 * Cloudflare Worker — auth backend for the login page.
 * Endpoints:
 *   POST /api/signup   { email, password }  -> creates a new account
 *   POST /api/login     { email, password }  -> verifies credentials
 *   GET  /api/me                             -> checks the session cookie
 *   POST /api/logout                         -> clears the session cookie
 *
 * Storage: Cloudflare D1 (binding name: DB). See schema.sql.
 * Sessions: a random token stored in D1 and set as an HttpOnly cookie.
 */

const SESSION_COOKIE = "session";
const SESSION_TTL_SECONDS = 60 * 60 * 24 * 7; // 7 days

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    // CORS for local dev / calling the API from a different origin than the Worker.
    if (request.method === "OPTIONS") {
      return withCors(new Response(null, { status: 204 }));
    }

    try {
      if (url.pathname === "/api/signup" && request.method === "POST") {
        return withCors(await handleSignup(request, env));
      }
      if (url.pathname === "/api/login" && request.method === "POST") {
        return withCors(await handleLogin(request, env));
      }
      if (url.pathname === "/api/me" && request.method === "GET") {
        return withCors(await handleMe(request, env));
      }
      if (url.pathname === "/api/logout" && request.method === "POST") {
        return withCors(handleLogout());
      }
    } catch (err) {
      return withCors(json({ error: "Something went wrong." }, 500));
    }

    if (!url.pathname.startsWith("/api/")) {
      return env.ASSETS.fetch(request);
    }

    return withCors(json({ error: "Not found." }, 404));
  },
};

async function handleSignup(request, env) {
  const { email, password, turnstileToken } = await safeJson(request);
  const cleanEmail = normalizeEmail(email);

  const captchaOk = await verifyTurnstile(turnstileToken, env, request);
  if (!captchaOk) return json({ error: "Verification failed. Please try again." }, 400);

  const validationError = validate(cleanEmail, password);
  if (validationError) return json({ error: validationError }, 400);

  const existing = await env.DB.prepare("SELECT id FROM users WHERE email = ?")
    .bind(cleanEmail)
    .first();
  if (existing) {
    return json({ error: "An account with that email already exists." }, 409);
  }

  const { hash, salt } = await hashPassword(password);
  const result = await env.DB.prepare(
    "INSERT INTO users (email, password_hash, password_salt, created_at) VALUES (?, ?, ?, ?)"
  )
    .bind(cleanEmail, hash, salt, Date.now())
    .run();

  const userId = result.meta.last_row_id;
  const token = await createSession(env, userId);

  return json({ ok: true, email: cleanEmail }, 201, sessionCookieHeader(token));
}

async function handleLogin(request, env) {
  const { email, password, turnstileToken } = await safeJson(request);
  const cleanEmail = normalizeEmail(email);

  const captchaOk = await verifyTurnstile(turnstileToken, env, request);
  if (!captchaOk) return json({ error: "Verification failed. Please try again." }, 400);

  const user = await env.DB.prepare(
    "SELECT id, password_hash, password_salt FROM users WHERE email = ?"
  )
    .bind(cleanEmail)
    .first();

  // Same generic error whether the email is unknown or the password is wrong,
  // so we don't reveal which accounts exist.
  const genericError = () => json({ error: "Incorrect email or password." }, 401);

  if (!user) return genericError();

  const computed = await hashPassword(password, user.password_salt);
  if (computed.hash !== user.password_hash) return genericError();

  const token = await createSession(env, user.id);
  return json({ ok: true, email: cleanEmail }, 200, sessionCookieHeader(token));
}

async function handleMe(request, env) {
  const token = getCookie(request, SESSION_COOKIE);
  if (!token) return json({ authenticated: false }, 200);

  const session = await env.DB.prepare(
    "SELECT users.email as email, sessions.expires_at as expires_at FROM sessions JOIN users ON users.id = sessions.user_id WHERE sessions.token = ?"
  )
    .bind(token)
    .first();

  if (!session || session.expires_at < Date.now()) {
    return json({ authenticated: false }, 200);
  }

  return json({ authenticated: true, email: session.email }, 200);
}

function handleLogout() {
  return json({ ok: true }, 200, [
    `${SESSION_COOKIE}=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0`,
  ]);
}

// ---------- helpers ----------

async function verifyTurnstile(token, env, request) {
  if (!token) return false;
  const formData = new FormData();
  formData.append("secret", env.TURNSTILE_SECRET_KEY);
  formData.append("response", token);
  const ip = request.headers.get("CF-Connecting-IP");
  if (ip) formData.append("remoteip", ip);

  const res = await fetch("https://challenges.cloudflare.com/turnstile/v0/siteverify", {
    method: "POST",
    body: formData,
  });
  const data = await res.json();
  return data.success === true;
}

async function createSession(env, userId) {
  const token = crypto.randomUUID() + crypto.randomUUID();
  const expiresAt = Date.now() + SESSION_TTL_SECONDS * 1000;
  await env.DB.prepare(
    "INSERT INTO sessions (token, user_id, expires_at) VALUES (?, ?, ?)"
  )
    .bind(token, userId, expiresAt)
    .run();
  return token;
}

function sessionCookieHeader(token) {
  return [
    `${SESSION_COOKIE}=${token}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=${SESSION_TTL_SECONDS}`,
  ];
}

function getCookie(request, name) {
  const header = request.headers.get("Cookie") || "";
  const match = header.match(new RegExp(`(?:^|;\\s*)${name}=([^;]+)`));
  return match ? match[1] : null;
}

function normalizeEmail(email) {
  return (email || "").trim().toLowerCase();
}

function validate(email, password) {
  const emailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailPattern.test(email)) return "Enter a valid email address.";
  if (!password || password.length < 8) {
    return "Password must be at least 8 characters.";
  }
  return null;
}

async function hashPassword(password, existingSaltHex) {
  const saltBytes = existingSaltHex
    ? hexToBytes(existingSaltHex)
    : crypto.getRandomValues(new Uint8Array(16));
  const saltHex = existingSaltHex || bytesToHex(saltBytes);

  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    { name: "PBKDF2" },
    false,
    ["deriveBits"]
  );

  const derived = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt: saltBytes, iterations: 100000, hash: "SHA-256" },
    keyMaterial,
    256
  );

  return { hash: bytesToHex(new Uint8Array(derived)), salt: saltHex };
}

function bytesToHex(bytes) {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

function hexToBytes(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
  }
  return bytes;
}

async function safeJson(request) {
  try {
    return await request.json();
  } catch {
    return {};
  }
}

function json(data, status = 200, extraHeaders = []) {
  const headers = new Headers({ "Content-Type": "application/json" });
  for (const h of extraHeaders) headers.append("Set-Cookie", h);
  return new Response(JSON.stringify(data), { status, headers });
}

function withCors(response) {
  const headers = new Headers(response.headers);
  headers.set("Access-Control-Allow-Origin", "*");
  headers.set("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  headers.set("Access-Control-Allow-Headers", "Content-Type");
  headers.set("Access-Control-Allow-Credentials", "true");
  return new Response(response.body, { status: response.status, headers });
}
