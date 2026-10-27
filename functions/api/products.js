
const COOKIE_NAME = "__Host-culture_admin";

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

  return [...new Uint8Array(signature)]
    .map(b => b.toString(16).padStart(2, "0"))
    .join("");
}

async function isAdmin(request, env) {
  if (!env.SESSION_SECRET) return false;

  const cookie = request.headers.get("Cookie") || "";
  const escapedName = COOKIE_NAME.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const match = cookie.match(
    new RegExp("(?:^|;\\s*)" + escapedName + "=([0-9]+\\.[a-f0-9]+)(?:;|$)")
  );

  if (!match) return false;

  const [expiryText, suppliedSignature] = match[1].split(".");
  const expiry = Number(expiryText);

  if (!Number.isSafeInteger(expiry) || expiry <= Date.now()) {
    return false;
  }

  const expected = await sign(expiryText, env.SESSION_SECRET);

  if (expected.length !== suppliedSignature.length) return false;

  let difference = 0;
  for (let i = 0; i < expected.length; i++) {
    difference |= expected.charCodeAt(i) ^ suppliedSignature.charCodeAt(i);
  }

  return difference === 0;
}

function parseArray(value) {
  if (Array.isArray(value)) return value;

  if (typeof value === "string") {
    try {
      const parsed = JSON.parse(value);
      return Array.isArray(parsed) ? parsed : [];
    } catch {
      return [];
    }
  }

  return [];
}

function formatProduct(row) {
  return {
    ...row,
    photos: parseArray(row.photos),
    options: parseArray(row.options)
  };
}

function validProduct(body, needsId = false) {
  const name = String(body.name || "").trim();
  const price = Number(body.price);
  const discount = body.discount_price == null ||
    body.discount_price === ""
    ? null
    : Number(body.discount_price);

  if (
    (needsId && (!Number.isSafeInteger(Number(body.id)) || Number(body.id) <= 0)) ||
    !name ||
    name.length > 200 ||
    !Number.isFinite(price) ||
    price <= 0
  ) {
    return { error: "Enter a valid product name and price." };
  }

  if (
    discount !== null &&
    (!Number.isFinite(discount) || discount <= 0 || discount >= price)
  ) {
    return { error: "Discount price must be lower than the original price." };
  }

  return {
    name,
    description: String(body.description || "").slice(0, 5000),
    price,
    discount,
    photos: parseArray(body.photos),
    options: parseArray(body.options),
    id: Number(body.id)
  };
}

export async function onRequestGet({ env }) {
  try {
    const result = await env.CULTURE_DB.prepare(
      `SELECT id, name, description, price,
       discount_price, photos, options, created_at
       FROM products ORDER BY id DESC`
    ).all();

    return json({
      products: (result.results || []).map(formatProduct)
    });
  } catch {
    return json({ error: "Could not load products. Check the database setup." }, 500);
  }
}

export async function onRequestPost({ request, env }) {
  if (!(await isAdmin(request, env))) {
    return json({ error: "Administrator sign-in required." }, 401);
  }

  try {
    const body = await request.json();
    const product = validProduct(body);

    if (product.error) return json({ error: product.error }, 400);

    const result = await env.CULTURE_DB.prepare(
      `INSERT INTO products
       (name, description, price, discount_price, photos, options)
       VALUES (?, ?, ?, ?, ?, ?)`
    ).bind(
      product.name,
      product.description,
      product.price,
      product.discount,
      JSON.stringify(product.photos),
      JSON.stringify(product.options)
    ).run();

    return json({
      success: true,
      id: result.meta?.last_row_id
    }, 201);
  } catch {
    return json({ error: "Could not save product." }, 500);
  }
}

export async function onRequestPut({ request, env }) {
  if (!(await isAdmin(request, env))) {
    return json({ error: "Administrator sign-in required." }, 401);
  }

  try {
    const body = await request.json();
    const product = validProduct(body, true);

    if (product.error) return json({ error: product.error }, 400);

    const result = await env.CULTURE_DB.prepare(
      `UPDATE products SET name=?, description=?, price=?,
       discount_price=?, photos=?, options=? WHERE id=?`
    ).bind(
      product.name,
      product.description,
      product.price,
      product.discount,
      JSON.stringify(product.photos),
      JSON.stringify(product.options),
      product.id
    ).run();

    return json({
      success: true,
      changes: result.meta?.changes || 0
    });
  } catch {
    return json({ error: "Could not update product." }, 500);
  }
}

export async function onRequestDelete({ request, env }) {
  if (!(await isAdmin(request, env))) {
    return json({ error: "Administrator sign-in required." }, 401);
  }

  try {
    const body = await request.json();
    const id = Number(body.id);

    if (!Number.isSafeInteger(id) || id <= 0) {
      return json({ error: "A valid product ID is required." }, 400);
    }

    const result = await env.CULTURE_DB.prepare(
      "DELETE FROM products WHERE id = ?"
    ).bind(id).run();

    return json({
      success: true,
      changes: result.meta?.changes || 0
    });
  } catch {
    return json({ error: "Could not delete product." }, 500);
  }
}
