function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store",
      "X-Content-Type-Options": "nosniff"
    }
  });
}

async function signCloudinaryParams(params, secret) {
  const text = Object.keys(params)
    .filter((key) => key !== "file" && key !== "api_key" && key !== "resource_type")
    .sort()
    .map((key) => `${key}=${params[key]}`)
    .join("&");

  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-1" },
    false,
    ["sign"]
  );

  const signature = await crypto.subtle.sign(
    "HMAC",
    key,
    new TextEncoder().encode(text)
  );

  return [...new Uint8Array(signature)]
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

async function isAdmin(request, secret) {
  if (!secret) return false;

  const cookie = request.headers.get("Cookie") || "";
  const match = cookie.match(
    /(?:^|;\s*)__Host-culture_admin=([0-9]+\.[a-f0-9]+)(?:;|$)/
  );

  if (!match) return false;

  const [expiryText, suppliedSignature] = match[1].split(".");
  const expiry = Number(expiryText);

  if (!Number.isSafeInteger(expiry) || expiry <= Date.now()) {
    return false;
  }

  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );

  const result = await crypto.subtle.sign(
    "HMAC",
    key,
    new TextEncoder().encode(expiryText)
  );

  const expected = [...new Uint8Array(result)]
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");

  if (expected.length !== suppliedSignature.length) return false;

  let difference = 0;
  for (let i = 0; i < expected.length; i++) {
    difference |= expected.charCodeAt(i) ^ suppliedSignature.charCodeAt(i);
  }

  return difference === 0;
}

export async function onRequest({ request, env }) {
  if (request.method !== "POST") {
    return json({ error: "Method not allowed." }, 405);
  }

  if (!(await isAdmin(request, env.SESSION_SECRET))) {
    return json({ error: "Please sign in as administrator." }, 401);
  }

  if (
    !env.CLOUDINARY_CLOUD_NAME ||
    !env.CLOUDINARY_API_KEY ||
    !env.CLOUDINARY_API_SECRET
  ) {
    return json({ error: "Cloudinary settings are missing." }, 503);
  }

  const timestamp = Math.floor(Date.now() / 1000);
  const params = {
    folder: "culture-driven",
    timestamp
  };

  try {
    const signature = await signCloudinaryParams(
      params,
      env.CLOUDINARY_API_SECRET
    );

    return json({
      cloudName: env.CLOUDINARY_CLOUD_NAME,
      apiKey: env.CLOUDINARY_API_KEY,
      timestamp,
      folder: params.folder,
      signature
    });
  } catch {
    return json({ error: "Could not prepare photo upload." }, 500);
  }
}