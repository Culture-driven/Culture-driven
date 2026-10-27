
const COOKIE_NAME = "__Host-culture_admin";
const SESSION_SECONDS = 8 * 60 * 60;

function json(data, status = 200, headers = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store",
      "X-Content-Type-Options": "nosniff",
      ...headers,
    },
  });
}

function bytesToHex(bytes) {
  return [...new Uint8Array(bytes)]
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

async function sha256(value) {
  return crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(value)
  );
}

async function sameSecret(a, b) {
  const x = new Uint8Array(await sha256(a));
  const y = new Uint8Array(await sha256(b));
  let diff = 0;
  for (let i = 0; i < x.length; i++) diff |= x[i] ^ y[i];
  return diff === 0;
}

async function sign(value, secret) {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const signature = await crypto.subtle.sign(
    "HMAC",
    key,
    new TextEncoder().encode(value)
  );
  return bytesToHex(signature);
}

async function validSession(request, secret) {
  const cookie = request.headers.get("Cookie") || "";
  const match = cookie.match(
    /(?:^|;\s*)__Host-culture_admin=([0-9]+\.[a-f0-9]+)(?:;|$)/
  );
  if (!match) return false;

  const [expiryText, suppliedSignature] = match[1].split(".");
  const expiry = Number(expiryText);
  if (!Number.isSafeInteger(expiry) || expiry <= Date.now()) return false;

  const expected = await sign(expiryText, secret);
  return sameSecret(suppliedSignature, expected);
}

function cookieHeader(value, maxAge) {
  return `${COOKIE_NAME}=${value}; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=${maxAge}`;
}

export async function onRequest({ request, env }) {
  if (!env.ADMIN_PASSWORD || !env.SESSION_SECRET) {
    return json({ error: "Admin security is not configured." }, 503);
  }

  if (request.method === "GET") {
    const authenticated = await validSession(request, env.SESSION_SECRET);
    return json({ authenticated });
  }

  if (request.method !== "POST") {
    return json({ error: "Method not allowed." }, 405, {
      Allow: "GET, POST",
    });
  }

  const contentType = request.headers.get("Content-Type") || "";
  if (!contentType.toLowerCase().includes("application/json")) {
    return json({ error: "Send JSON data." }, 415);
  }

  let body;
  try {
    body = await request.json();
  } catch {
    return json({ error: "Invalid request." }, 400);
  }

  if (body?.action === "logout") {
    return json(
      { success: true },
      200,
      { "Set-Cookie": cookieHeader("", 0) }
    );
  }

  if (body?.action !== "login" || typeof body.password !== "string") {
    return json({ error: "Invalid request." }, 400);
  }

  if (body.password.length > 1024) {
    return json({ error: "Invalid password." }, 401);
  }

  const matches = await sameSecret(body.password, env.ADMIN_PASSWORD);
  if (!matches) {
    return json({ error: "Incorrect password." }, 401);
  }

  const expiry = String(Date.now() + SESSION_SECONDS * 1000);
  const signature = await sign(expiry, env.SESSION_SECRET);

  return json(
    { success: true, expiresIn: SESSION_SECONDS },
    200,
    {
      "Set-Cookie": cookieHeader(
        `${expiry}.${signature}`,
        SESSION_SECONDS
      ),
    }
  );
}
