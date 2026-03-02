// /api/login
// Password dicek DI SINI di server — tidak pernah dikirim ke browser

async function hmacSign(data, secret) {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey(
    "raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", key, enc.encode(data));
  return btoa(String.fromCharCode(...new Uint8Array(sig)));
}

export default async (req) => {
  const cors = { "Access-Control-Allow-Origin": "*", "Content-Type": "application/json" };

  if (req.method === "OPTIONS") return new Response("", { status: 204, headers: cors });
  if (req.method !== "POST") return new Response("Method Not Allowed", { status: 405 });

  try {
    const { password } = await req.json();

    const APP_PASSWORD = process.env.APP_PASSWORD;
    const APP_SECRET   = process.env.APP_SECRET || "change_this_secret_immediately";

    if (!APP_PASSWORD) {
      return new Response(JSON.stringify({ ok: false, error: "APP_PASSWORD belum diisi di Netlify env vars" }), { status: 500, headers: cors });
    }

    if (password !== APP_PASSWORD) {
      return new Response(JSON.stringify({ ok: false, error: "Password salah" }), { status: 401, headers: cors });
    }

    // Buat session token pakai HMAC — valid 24 jam
    const payload = `${crypto.randomUUID()}:${Date.now()}`;
    const signature = await hmacSign(payload, APP_SECRET);
    const token = btoa(`${payload}:${signature}`);

    return new Response(JSON.stringify({ ok: true, token }), { status: 200, headers: cors });
  } catch (e) {
    return new Response(JSON.stringify({ ok: false, error: "Request tidak valid" }), { status: 400, headers: cors });
  }
};

export const config = { path: "/api/login" };
