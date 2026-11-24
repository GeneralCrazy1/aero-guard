// Aero Guard – Freischalt-Server (Cloudflare Worker + KV)
//
// App:
//   POST /activate  {"key":"AG-XXXX-XXXX-XXXX","device":"<id>"}  -> Key einlösen (bindet ihn an dieses Handy)
//   POST /check     {"key":"...","device":"..."}                  -> gilt der Key noch?
// Admin (Passwort = Secret ADMIN_SECRET):
//   GET  /admin                     -> Webseite zum Erzeugen und Ansehen der Keys
//   POST /admin/create {"days":30,"count":5,"note":"Max"}
//   GET  /admin/list
//   POST /admin/revoke {"key":"..."}
//
// Gespeichert wird je Key (KV-Schlüssel "key:AG-..."):
//   {days, note, created, device, activatedAt, expiresAt, revoked}

const ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
const DURATIONS = [7, 30, 90, 180, 365];
const DAY = 86400000;

function json(obj, status = 200) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { "content-type": "application/json; charset=utf-8", "access-control-allow-origin": "*" },
  });
}

function normalize(input) {
  const raw = String(input || "").toUpperCase().replace(/[^A-Z0-9]/g, "").replace(/^AG/, "");
  if (raw.length !== 12 || [...raw].some((c) => !ALPHABET.includes(c))) return null;
  return "AG-" + raw.match(/.{4}/g).join("-");
}

function newKey() {
  const bytes = new Uint8Array(12);
  crypto.getRandomValues(bytes);
  const raw = [...bytes].map((b) => ALPHABET[b % ALPHABET.length]).join("");
  return "AG-" + raw.match(/.{4}/g).join("-");
}

async function sha(text) {
  const d = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
  return [...new Uint8Array(d)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

async function isAdmin(req, env) {
  if (!env.ADMIN_SECRET) return false;
  const h = req.headers.get("authorization") || "";
  const given = h.startsWith("Bearer ") ? h.slice(7) : "";
  // Vergleich über Hashes (gleich lange Zeichenketten)
  return (await sha(given)) === (await sha(env.ADMIN_SECRET));
}

// Einfache Bremse gegen Durchprobieren: max. 20 Versuche pro 10 Minuten je IP.
async function rateLimited(env, req) {
  const ip = req.headers.get("cf-connecting-ip") || "unknown";
  const k = "rate:" + ip;
  const n = parseInt((await env.KEYS.get(k)) || "0", 10);
  if (n >= 20) return true;
  await env.KEYS.put(k, String(n + 1), { expirationTtl: 600 });
  return false;
}

async function activate(req, env, checkOnly) {
  let body;
  try { body = await req.json(); } catch { return json({ ok: false, error: "format" }, 400); }
  const key = normalize(body.key);
  const device = String(body.device || "").slice(0, 100);
  if (!key || !device) return json({ ok: false, error: "format" }, 400);
  if (!checkOnly && (await rateLimited(env, req))) return json({ ok: false, error: "rate" }, 429);

  const raw = await env.KEYS.get("key:" + key);
  if (!raw) return json({ ok: false, error: "unknown" }, 404);
  const rec = JSON.parse(raw);
  if (rec.revoked) return json({ ok: false, error: "revoked" }, 403);

  const now = Date.now();
  if (rec.device && rec.device !== device) return json({ ok: false, error: "used" }, 403);
  if (!rec.device) {
    if (checkOnly) return json({ ok: false, error: "unknown" }, 404);
    // Erstes Einlösen: an dieses Handy binden, Laufzeit startet jetzt.
    rec.device = device;
    rec.activatedAt = now;
    rec.expiresAt = now + rec.days * DAY;
    await env.KEYS.put("key:" + key, JSON.stringify(rec));
  }
  if (now >= rec.expiresAt) return json({ ok: false, error: "expired", expiresAt: rec.expiresAt }, 403);
  return json({ ok: true, expiresAt: rec.expiresAt, days: rec.days });
}

async function adminCreate(req, env) {
  const body = await req.json().catch(() => ({}));
  const days = parseInt(body.days, 10);
  const count = Math.min(Math.max(parseInt(body.count || "1", 10), 1), 100);
  if (!DURATIONS.includes(days)) return json({ ok: false, error: "days", allowed: DURATIONS }, 400);
  const keys = [];
  for (let i = 0; i < count; i++) {
    let key;
    do { key = newKey(); } while (await env.KEYS.get("key:" + key));
    const rec = { days, note: String(body.note || "").slice(0, 100), created: Date.now(), device: null, activatedAt: null, expiresAt: null, revoked: false };
    await env.KEYS.put("key:" + key, JSON.stringify(rec));
    keys.push(key);
  }
  return json({ ok: true, days, keys });
}

async function adminList(env) {
  const out = [];
  let cursor;
  do {
    const page = await env.KEYS.list({ prefix: "key:", cursor });
    for (const k of page.keys) {
      const rec = JSON.parse((await env.KEYS.get(k.name)) || "{}");
      out.push({ key: k.name.slice(4), ...rec, device: rec.device ? rec.device.slice(0, 6) + "…" : null });
    }
    cursor = page.list_complete ? null : page.cursor;
  } while (cursor);
  out.sort((a, b) => (b.created || 0) - (a.created || 0));
  return json({ ok: true, keys: out });
}

async function adminRevoke(req, env) {
  const body = await req.json().catch(() => ({}));
  const key = normalize(body.key);
  const raw = key && (await env.KEYS.get("key:" + key));
  if (!raw) return json({ ok: false, error: "unknown" }, 404);
  const rec = JSON.parse(raw);
  rec.revoked = true;
  await env.KEYS.put("key:" + key, JSON.stringify(rec));
  return json({ ok: true });
}

const ADMIN_PAGE = `<!doctype html><html lang="de"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>Aero Guard Keys</title>
<style>body{font-family:system-ui,sans-serif;background:#041026;color:#e6f2ec;max-width:760px;margin:auto;padding:16px}
input,select,button{font-size:16px;padding:8px;margin:4px 0;border-radius:8px;border:1px solid #3a6;background:#0b1f35;color:#e6f2ec}
button{background:#3c6;color:#000;font-weight:bold;cursor:pointer}table{width:100%;border-collapse:collapse;font-size:13px}
td,th{border-bottom:1px solid #234;padding:4px;text-align:left}#out{white-space:pre;background:#0b1f35;padding:10px;border-radius:8px;font-family:monospace}</style></head>
<body><h2>Aero Guard – Freischalt-Keys</h2>
<p>Admin-Passwort (dein ADMIN_SECRET):<br><input id="pw" type="password" style="width:100%"></p>
<h3>Neue Keys erzeugen</h3>
<p>Laufzeit: <select id="days"><option value="7">7 Tage</option><option value="30">30 Tage</option><option value="90">90 Tage</option><option value="180">180 Tage</option><option value="365">1 Jahr</option></select>
Anzahl: <input id="count" type="number" value="1" min="1" max="100" style="width:70px">
Notiz: <input id="note" placeholder="z. B. Name"></p>
<button onclick="create()">Keys erzeugen</button>
<div id="out">Hier erscheinen die neuen Keys. Jeder Key gilt nur auf einem Handy. Die Laufzeit startet beim Einlösen.</div>
<h3>Alle Keys</h3><button onclick="list()">Liste laden</button>
<table id="list"></table>
<script>
const pw=()=>document.getElementById('pw').value;
async function api(path,body){const r=await fetch(path,{method:body?'POST':'GET',headers:{'authorization':'Bearer '+pw(),'content-type':'application/json'},body:body?JSON.stringify(body):undefined});return r.json();}
async function create(){const r=await api('/admin/create',{days:+days.value,count:+count.value,note:note.value});
out.textContent=r.ok?('Neue Keys ('+(r.days==365?'1 Jahr':r.days+' Tage')+'):\\n'+r.keys.join('\\n')):'Fehler: '+(r.error||'Passwort falsch?');}
const d=t=>t?new Date(t).toLocaleString('de-DE'):'–';
async function list(){const r=await api('/admin/list');if(!r.ok){out.textContent='Fehler: Passwort falsch?';return;}
document.getElementById('list').innerHTML='<tr><th>Key</th><th>Laufzeit</th><th>Notiz</th><th>Eingelöst</th><th>Läuft ab</th><th></th></tr>'+
r.keys.map(k=>'<tr><td>'+k.key+'</td><td>'+(k.days==365?'1 Jahr':k.days+' T')+'</td><td>'+(k.note||'')+'</td><td>'+(k.device?d(k.activatedAt):'frei')+'</td><td>'+(k.revoked?'GESPERRT':d(k.expiresAt))+'</td><td>'+(k.revoked?'':'<button onclick="revoke(\\''+k.key+'\\')">Sperren</button>')+'</td></tr>').join('');}
async function revoke(k){if(!confirm('Key '+k+' sperren?'))return;await api('/admin/revoke',{key:k});list();}
</script></body></html>`;

export default {
  async fetch(req, env) {
    const url = new URL(req.url);
    if (req.method === "OPTIONS") return new Response(null, { headers: { "access-control-allow-origin": "*", "access-control-allow-headers": "authorization, content-type" } });
    if (!env.KEYS) return json({ ok: false, error: "server", message: "KV-Speicher KEYS fehlt (siehe Anleitung)." }, 500);
    try {
      if (url.pathname === "/activate" && req.method === "POST") return await activate(req, env, false);
      if (url.pathname === "/check" && req.method === "POST") return await activate(req, env, true);
      if (url.pathname === "/admin") return new Response(ADMIN_PAGE, { headers: { "content-type": "text/html; charset=utf-8" } });
      if (url.pathname.startsWith("/admin/")) {
        if (!env.ADMIN_SECRET) return json({ ok: false, error: "secret", message: "ADMIN_SECRET ist nicht gesetzt." }, 500);
        if (!(await isAdmin(req, env))) return json({ ok: false, error: "auth" }, 401);
        if (url.pathname === "/admin/create" && req.method === "POST") return await adminCreate(req, env);
        if (url.pathname === "/admin/list") return await adminList(env);
        if (url.pathname === "/admin/revoke" && req.method === "POST") return await adminRevoke(req, env);
      }
      if (url.pathname === "/") return json({ ok: true, service: "Aero Guard Keys" });
      return json({ ok: false, error: "not_found" }, 404);
    } catch (e) {
      return json({ ok: false, error: "server", message: String(e) }, 500);
    }
  },
};
