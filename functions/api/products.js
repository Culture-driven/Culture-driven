
function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store"
    }
  });
}

function isAdmin(request) {
  const cookie = request.headers.get("Cookie") || "";
  return cookie.split(";").some(part =>
    part.trim() === "admin_session=authenticated"
  );
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

export async function onRequestGet({ env }) {
  try {
    const result = await env.CULTURE_DB
      .prepare(
        `SELECT id, name, description, price,
         discount_price, photos, options, created_at
         FROM products ORDER BY id DESC`
      )
      .all();

    return json({ products: (result.results || []).map(formatProduct) });
  } catch (error) {
    return json({ error: "Could not load products. Check the database setup." }, 500);
  }
}

export async function onRequestPost({ request, env }) {
  if (!isAdmin(request)) {
    return json({ error: "Please sign in as administrator." }, 401);
  }

  try {
    const body = await request.json();
    const name = String(body.name || "").trim();
    const description = String(body.description || "");
    const price = Number(body.price);
    const discount = body.discount_price == null ||
      body.discount_price === ""
      ? null : Number(body.discount_price);
    const photos = parseArray(body.photos);
    const options = parseArray(body.options);

    if (!name || !Number.isFinite(price) || price <= 0) {
      return json({ error: "Enter a product name and valid price." }, 400);
    }

    if (discount !== null &&
        (!Number.isFinite(discount) || discount <= 0 || discount >= price)) {
      return json({ error: "Discount price must be lower than the original price." }, 400);
    }

    const result = await env.CULTURE_DB.prepare(
      `INSERT INTO products
       (name, description, price, discount_price, photos, options)
       VALUES (?, ?, ?, ?, ?, ?)`
    ).bind(
      name, description, price, discount,
      JSON.stringify(photos), JSON.stringify(options)
    ).run();

    return json({ success: true, id: result.meta?.last_row_id });
  } catch (error) {
    return json({ error: "Could not save product. Check the submitted details." }, 500);
  }
}

export async function onRequestPut({ request, env }) {
  if (!isAdmin(request)) {
    return json({ error: "Please sign in as administrator." }, 401);
  }

  try {
    const body = await request.json();
    const id = Number(body.id);
    const name = String(body.name || "").trim();
    const description = String(body.description || "");
    const price = Number(body.price);
    const discount = body.discount_price == null ||
      body.discount_price === ""
      ? null : Number(body.discount_price);
    const photos = parseArray(body.photos);
    const options = parseArray(body.options);

    if (!Number.isInteger(id) || id <= 0 || !name ||
        !Number.isFinite(price) || price <= 0) {
      return json({ error: "Enter a valid product ID, name and price." }, 400);
    }

    if (discount !== null &&
        (!Number.isFinite(discount) || discount <= 0 || discount >= price)) {
      return json({ error: "Discount price must be lower than the original price." }, 400);
    }

    const result = await env.CULTURE_DB.prepare(
      `UPDATE products SET name=?, description=?, price=?,
       discount_price=?, photos=?, options=? WHERE id=?`
    ).bind(
      name, description, price, discount,
      JSON.stringify(photos), JSON.stringify(options), id
    ).run();

    return json({ success: true, changes: result.meta?.changes || 0 });
  } catch (error) {
    return json({ error: "Could not update product." }, 500);
  }
}

export async function onRequestDelete({ request, env }) {
  if (!isAdmin(request)) {
    return json({ error: "Please sign in as administrator." }, 401);
  }

  try {
    const body = await request.json();
    const id = Number(body.id);

    if (!Number.isInteger(id) || id <= 0) {
      return json({ error: "A valid product ID is required." }, 400);
    }

    const result = await env.CULTURE_DB.prepare(
      "DELETE FROM products WHERE id = ?"
    ).bind(id).run();

    return json({ success: true, changes: result.meta?.changes || 0 });
  } catch (error) {
    return json({ error: "Could not delete product." }, 500);
  }
}
