// /api/verify
// Verifikasi session token — cek signature dan expired

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
    const decoded = atob(token);
    const lastColon = decoded.lastIndexOf(":");
    const payload   = decoded.slice(0, lastColon);
    const signature = decoded.slice(lastColon + 1);

    // Cek expired (24 jam)
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
  if (req.method !== "POST") return new Response("Method Not Allowed", { status: 405 });

  try {
    const { token } = await req.json();
    const ok = await verifyToken(token);
    return new Response(JSON.stringify({ ok }), { status: 200, headers: cors });
  } catch {
    return new Response(JSON.stringify({ ok: false }), { status: 400, headers: cors });
  }
};

export const config = { path: "/api/verify" };
