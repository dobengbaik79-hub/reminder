// /api/send-telegram
// Bot Token, Chat ID, Thread ID — semua ada di ENV, tidak pernah keluar ke browser

async function hmacSign(data, secret) {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey(
    "raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", key, enc.encode(data));
  return btoa(String.fromCharCode(...new Uint8Array(sig)));
}

async function verifyToken(token) {
  if (!token) return false;
  try {
    const decoded   = atob(token);
    const lastColon = decoded.lastIndexOf(":");
    const payload   = decoded.slice(0, lastColon);
    const signature = decoded.slice(lastColon + 1);
    const timestamp = parseInt(payload.split(":")[1]);
    if (Date.now() - timestamp > 24 * 60 * 60 * 1000) return false;
    const secret   = process.env.APP_SECRET || "change_this_secret_immediately";
    const expected = await hmacSign(payload, secret);
    return signature === expected;
  } catch { return false; }
}

export default async (req) => {
  const cors = { "Access-Control-Allow-Origin": "*", "Content-Type": "application/json" };

  if (req.method === "OPTIONS") return new Response("", { status: 204, headers: cors });
  if (req.method !== "POST")    return new Response("Method Not Allowed", { status: 405 });

  // Verifikasi session token — hanya user yang sudah login yang bisa kirim
  const authHeader = req.headers.get("Authorization") || "";
  const sessionToken = authHeader.replace("Bearer ", "").trim();
  if (!await verifyToken(sessionToken)) {
    return new Response(JSON.stringify({ ok: false, error: "Unauthorized" }), { status: 401, headers: cors });
  }

  // Ambil semua credential dari ENV — tidak pernah ada di browser
  const BOT_TOKEN = process.env.TG_BOT_TOKEN;
  const CHAT_ID   = process.env.TG_CHAT_ID;
  const THREAD_ID = process.env.TG_THREAD_ID; // opsional

  if (!BOT_TOKEN || !CHAT_ID) {
    return new Response(JSON.stringify({ ok: false, error: "TG_BOT_TOKEN atau TG_CHAT_ID belum diisi di Netlify env vars" }), { status: 500, headers: cors });
  }

  try {
    const { message } = await req.json();
    if (!message) return new Response(JSON.stringify({ ok: false, error: "Pesan kosong" }), { status: 400, headers: cors });

    const body = { chat_id: CHAT_ID, text: message, parse_mode: "Markdown" };
    if (THREAD_ID) body.message_thread_id = parseInt(THREAD_ID);

    const r = await fetch(`https://api.telegram.org/bot${BOT_TOKEN}/sendMessage`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body)
    });
    const result = await r.json();

    if (result.ok) {
      return new Response(JSON.stringify({ ok: true }), { status: 200, headers: cors });
    } else {
      return new Response(JSON.stringify({ ok: false, error: result.description }), { status: 400, headers: cors });
    }
  } catch (e) {
    return new Response(JSON.stringify({ ok: false, error: "Gagal mengirim ke Telegram" }), { status: 500, headers: cors });
  }
};

export const config = { path: "/api/send-telegram" };
