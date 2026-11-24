// Aero Guard – Freischalt-Server (Cloudflare Worker + KV)
//
// App:
//   POST /activate  {"key":"AG-XXXX-XXXX-XXXX","device":"<id>"}  -> Key einlösen (bindet ihn an dieses Handy)
//   POST /check     {"key":"...","device":"..."}                  -> gilt der Key noch?
// Admin (Passwort = Secret ADMIN_SECRET), Webseite unter /admin:
//   POST /admin/create  {"seconds":2592000,"count":5,"note":"Max"}   (Laufzeit frei wählbar, mind. 5 Sekunden)
//   GET  /admin/list     POST /admin/revoke | unrevoke | delete | reset | extend
//
// Gespeichert wird je Key (KV-Schlüssel "key:AG-..."):
//   {seconds, note, name, created, device, activatedAt, expiresAt, revoked,
//    model, version, lastSeen, stats:{opens, starts, warnings}}
// Die App meldet beim Prüfen nur: Handy-Modell, App-Version und drei Zähler (App geöffnet, Radar gestartet, Warnungen). Keine Standorte.

const ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
const MIN_SECONDS = 5;
const MAX_SECONDS = 3650 * 86400;

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
  return (await sha(given)) === (await sha(env.ADMIN_SECRET));
}

// Bremse gegen Durchprobieren: max. 20 Versuche pro 10 Minuten je IP.
async function rateLimited(env, req) {
  const ip = req.headers.get("cf-connecting-ip") || "unknown";
  const k = "rate:" + ip;
  const n = parseInt((await env.KEYS.get(k)) || "0", 10);
  if (n >= 20) return true;
  await put(env, k, String(n + 1), { expirationTtl: 600 });
  return false;
}

// Alte Keys (nur "days") weiter verstehen.
function secondsOf(rec) {
  return rec.seconds != null ? rec.seconds : (rec.days || 0) * 86400;
}

function nameOf(rec) { return rec.name != null ? rec.name : (rec.note || ""); }

// Meldungen der App (Modell, Version, Zähler) übernehmen. Gibt true zurück, wenn sich etwas geändert hat.
function telemetry(rec, body, now, ip) {
  let changed = false;
  const model = String(body.model || "").slice(0, 60);
  const version = String(body.version || "").slice(0, 20);
  if (model && model !== rec.model) { rec.model = model; changed = true; }
  if (version && version !== rec.version) { rec.version = version; changed = true; }
  if (body.stats && typeof body.stats === "object") {
    const st = rec.stats || { opens: 0, starts: 0, warnings: 0 };
    for (const k of ["opens", "starts", "warnings"]) {
      const v = Math.max(0, Math.min(1e9, Math.round(Number(body.stats[k]) || 0)));
      if (v !== st[k]) { st[k] = v; changed = true; }
    }
    rec.stats = st;
  }
  // "zuletzt gesehen" höchstens alle 10 Minuten schreiben (spart KV-Schreibvorgänge im kostenlosen Tarif).
  if (!rec.lastSeen || now - rec.lastSeen > 10 * 60000) { rec.lastSeen = now; if (ip) rec.ip = ip; changed = true; }
  return changed;
}

// ---- Schreib-Zähler (Cloudflare nennt den Verbrauch nicht per Abfrage, deshalb zählt der Server seine eigenen Schreibvorgänge) ----
// Der Wert ist eine Untergrenze: Er wird nur alle 5 Schreibvorgänge gespeichert, und Löschungen/Zugriffe anderer Dienste fehlen.
const W = { day: "", n: 0, flushed: 0 };
const WRITE_LIMIT = 1000;
function today() { return new Date().toISOString().slice(0, 10); }
async function wload(env) {
  const d = today();
  if (W.day === d) return;
  W.day = d;
  const s = JSON.parse((await env.KEYS.get("stats:w:" + d)) || "{}");
  W.n = s.n || 0; W.flushed = W.n;
}
async function put(env, k, v, opts) {
  await wload(env);
  await env.KEYS.put(k, v, opts);
  W.n++;
  if (W.n - W.flushed >= 5) {
    W.n++; W.flushed = W.n;
    await env.KEYS.put("stats:w:" + W.day, JSON.stringify({ n: W.n }), { expirationTtl: 172800 });
  }
}

// ---- Nutzer (User-ID), Sperren, Meldungen, Support ----
function ipOf(req) { return req.headers.get("cf-connecting-ip") || ""; }
async function getBlocks(env) { return JSON.parse((await env.KEYS.get("blocks")) || "null") || { devices: {}, ips: {} }; }
function blockHit(b, device, ip) { return (device && b.devices[device]) || (ip && b.ips[ip]) || null; }
function blockedJson(h) { return json({ ok: false, error: "blocked", message: h.reason || "Gesperrt" }, 403); }
function newUid() {
  const bytes = new Uint8Array(4);
  crypto.getRandomValues(bytes);
  return "U-" + [...bytes].map((b) => ALPHABET[b % ALPHABET.length]).join("");
}
async function userByUid(env, uid) { return uid ? JSON.parse((await env.KEYS.get("user:" + uid)) || "null") : null; }
async function userByDevice(env, device) {
  const uid = await env.KEYS.get("dev:" + (await sha("dev:" + device)).slice(0, 16));
  return userByUid(env, uid);
}
async function createUser(env, device) {
  const old = await userByDevice(env, device);
  if (old) return old;
  let uid;
  do { uid = newUid(); } while (await env.KEYS.get("user:" + uid));
  const u = { uid, device, name: "", admin: false, quota: {}, created: Date.now() };
  await put(env, "user:" + uid, JSON.stringify(u));
  await put(env, "dev:" + (await sha("dev:" + device)).slice(0, 16), uid);
  return u;
}
const UN = { last: 0 };
// "Nicht autorisierter Zugriff": ein Eintrag je Gerät, höchstens alle 6 Stunden geschrieben und mit Schutz fürs Tageslimit.
async function logUnauth(env, device, ip, why, body) {
  const now = Date.now();
  if (now - UN.last < 15000) return;
  await wload(env);
  if (W.n > 700) return;
  const id = device || (ip ? "ip:" + ip : "");
  if (!id) return;
  const st = JSON.parse((await env.KEYS.get("unauth")) || "{}");
  const e = st[id];
  if (e && now - e.t < 6 * 3600000 && e.why === why) return;
  UN.last = now;
  st[id] = { t: now, first: e ? e.first : now, n: (e ? e.n : 0) + 1, why, model: String((body && body.model) || "").slice(0, 60), ip, dev: device || "", version: String((body && body.version) || "").slice(0, 20) };
  const ids = Object.keys(st).sort((a, b) => st[b].t - st[a].t);
  ids.slice(100).forEach((x) => delete st[x]);
  await put(env, "unauth", JSON.stringify(st));
}

async function activate(req, env, checkOnly) {
  let body;
  try { body = await req.json(); } catch { return json({ ok: false, error: "format" }, 400); }
  const key = normalize(body.key);
  const device = String(body.device || "").slice(0, 100);
  const ip = ipOf(req);
  const hit = blockHit(await getBlocks(env), device, ip);
  if (hit) { await logUnauth(env, device, ip, "Gesperrtes Gerät/IP versucht Zugriff", body); return blockedJson(hit); }
  if (!key || !device) { await logUnauth(env, device, ip, "Key mit falschem Format", body); return json({ ok: false, error: "format" }, 400); }
  if (!checkOnly && (await rateLimited(env, req))) return json({ ok: false, error: "rate" }, 429);

  const raw = await env.KEYS.get("key:" + key);
  if (!raw) { await logUnauth(env, device, ip, "Unbekannter Key", body); return json({ ok: false, error: "unknown" }, 404); }
  const rec = JSON.parse(raw);
  if (rec.revoked) return json({ ok: false, error: "revoked", message: rec.revokeReason || "" }, 403);

  const now = Date.now();
  if (rec.device && rec.device !== device) { await logUnauth(env, device, ip, "Key ist schon auf einem anderen Handy", body); return json({ ok: false, error: "used" }, 403); }
  let dirty = false;
  if (!rec.device) {
    if (checkOnly) return json({ ok: false, error: "unknown" }, 404);
    // Erstes Einlösen: an dieses Handy binden, Laufzeit startet jetzt.
    rec.device = device;
    rec.activatedAt = now;
    rec.expiresAt = now + secondsOf(rec) * 1000;
    rec.uid = (await createUser(env, device)).uid;
    telemetry(rec, body, now, ip);
    await put(env, "key:" + key, JSON.stringify(rec));
  }
  const seconds = secondsOf(rec);
  if (now >= rec.expiresAt) return json({ ok: false, error: "expired", expiresAt: rec.expiresAt }, 403);
  if (!rec.uid) { rec.uid = (await createUser(env, device)).uid; dirty = true; } // Handy aus der Zeit vor den User-IDs
  if (telemetry(rec, body, now, ip) || dirty) await put(env, "key:" + key, JSON.stringify(rec));
  const user = await userByUid(env, rec.uid);
  return json({ ok: true, expiresAt: rec.expiresAt, seconds, days: Math.round(seconds / 86400), name: nameOf(rec) || (user && user.name) || "", uid: rec.uid, admin: !!(user && user.admin) });
}

async function adminCreate(req, env) {
  const body = await req.json().catch(() => ({}));
  let seconds = Math.round(Number(body.seconds != null ? body.seconds : (body.days || 0) * 86400));
  const count = Math.min(Math.max(parseInt(body.count || "1", 10), 1), 100);
  if (!Number.isFinite(seconds) || seconds < MIN_SECONDS || seconds > MAX_SECONDS) {
    return json({ ok: false, error: "seconds", message: "Laufzeit muss zwischen 5 Sekunden und 10 Jahren liegen." }, 400);
  }
  const keys = [];
  for (let i = 0; i < count; i++) {
    let key;
    do { key = newKey(); } while (await env.KEYS.get("key:" + key));
    const rec = { seconds, note: "", name: String(body.note || body.name || "").slice(0, 100), created: Date.now(), device: null, activatedAt: null, expiresAt: null, revoked: false, issuedBy: "main" };
    await put(env, "key:" + key, JSON.stringify(rec));
    keys.push(key);
  }
  return json({ ok: true, seconds, keys });
}

async function adminList(env) {
  const out = [], users = [];
  let cursor;
  do {
    const page = await env.KEYS.list({ prefix: "key:", cursor });
    for (const k of page.keys) {
      const rec = JSON.parse((await env.KEYS.get(k.name)) || "{}");
      out.push({ key: k.name.slice(4), ...rec, name: nameOf(rec), seconds: secondsOf(rec), device: rec.device ? rec.device.slice(0, 6) + "…" : null, ip: undefined, hasIp: !!rec.ip });
    }
    cursor = page.list_complete ? null : page.cursor;
  } while (cursor);
  cursor = undefined;
  do {
    const page = await env.KEYS.list({ prefix: "user:", cursor });
    for (const k of page.keys) { const u = JSON.parse((await env.KEYS.get(k.name)) || "null"); if (u) users.push({ ...u, device: undefined }); }
    cursor = page.list_complete ? null : page.cursor;
  } while (cursor);
  out.sort((a, b) => (b.created || 0) - (a.created || 0));
  await wload(env);
  const stored = JSON.parse((await env.KEYS.get("stats:w:" + W.day)) || "{}");
  const unauth = JSON.parse((await env.KEYS.get("unauth")) || "{}");
  const support = JSON.parse((await env.KEYS.get("support")) || "{}").msgs || [];
  const blocks = await getBlocks(env);
  const now = Date.now();
  return json({
    ok: true, now, keys: out, users,
    writes: { n: Math.max(W.n, stored.n || 0), limit: WRITE_LIMIT, day: W.day },
    unauth24: Object.values(unauth).filter((e) => now - e.t < 86400000).length,
    supportOpen: support.filter((m) => !m.done).length,
    blocked: { devices: Object.keys(blocks.devices).length, ips: Object.keys(blocks.ips).length },
  });
}

async function adminAction(req, env, action) {
  const body = await req.json().catch(() => ({}));
  const key = normalize(body.key);
  const raw = key && (await env.KEYS.get("key:" + key));
  if (!raw) return json({ ok: false, error: "unknown" }, 404);
  const rec = JSON.parse(raw);
  if (action === "delete") { await env.KEYS.delete("key:" + key); return json({ ok: true }); }
  if (action === "rename") {
    rec.name = String(body.name || "").slice(0, 100);
    const u = await userByUid(env, rec.uid);
    if (u) { u.name = rec.name; await put(env, "user:" + u.uid, JSON.stringify(u)); }
  }
  if (action === "revoke") {
    rec.revoked = true;
    rec.revokeReason = String(body.reason || "").slice(0, 300);
    if ((body.blockDevice && rec.device) || (body.blockIp && rec.ip)) {
      const b = await getBlocks(env);
      const entry = { reason: rec.revokeReason, at: Date.now(), key };
      if (body.blockDevice && rec.device) b.devices[rec.device] = entry;
      if (body.blockIp && rec.ip) b.ips[rec.ip] = entry;
      await put(env, "blocks", JSON.stringify(b));
    }
  }
  if (action === "unrevoke") {
    rec.revoked = false; rec.revokeReason = "";
    const b = await getBlocks(env);
    let ch = false;
    if (rec.device && b.devices[rec.device]) { delete b.devices[rec.device]; ch = true; }
    for (const ip of Object.keys(b.ips)) if (b.ips[ip].key === key) { delete b.ips[ip]; ch = true; }
    if (ch) await put(env, "blocks", JSON.stringify(b));
  }
  if (action === "reset") { rec.device = null; rec.activatedAt = null; rec.expiresAt = null; } // frei für ein anderes Handy, Laufzeit startet neu
  if (action === "extend") {
    const add = Math.round(Number(body.seconds));
    if (!Number.isFinite(add) || add < 1) return json({ ok: false, error: "seconds" }, 400);
    if (rec.expiresAt) rec.expiresAt = Math.max(rec.expiresAt, Date.now()) + add * 1000;
    else rec.seconds = secondsOf(rec) + add;
  }
  await put(env, "key:" + key, JSON.stringify(rec));
  return json({ ok: true });
}

// Admin: Nutzer bearbeiten (Name, Admin-Rolle, Kontingente je Laufzeit).
async function adminUser(req, env) {
  const body = await req.json().catch(() => ({}));
  const u = await userByUid(env, String(body.uid || "").toUpperCase());
  if (!u) return json({ ok: false, error: "unknown" }, 404);
  if (body.name != null) u.name = String(body.name).slice(0, 100);
  if (body.admin != null) {
    u.admin = body.admin === true;
    if (u.admin && !Object.keys(u.quota || {}).length) u.quota = { "604800": { limit: 10, used: 0, reason: false }, "1209600": { limit: 3, used: 0, reason: true } };
  }
  if (body.quota && typeof body.quota === "object") {
    const q = {};
    for (const k of Object.keys(body.quota).slice(0, 20)) {
      const secs = Math.round(Number(k));
      const v = body.quota[k] || {};
      if (!Number.isFinite(secs) || secs < MIN_SECONDS || secs > MAX_SECONDS) continue;
      q[String(secs)] = { limit: Math.max(0, Math.min(10000, Math.round(Number(v.limit) || 0))), used: Math.max(0, Math.round(Number(v.used) || 0)), reason: v.reason === true };
    }
    u.quota = q;
  }
  await put(env, "user:" + u.uid, JSON.stringify(u));
  // Name auch an den Keys dieses Nutzers nachziehen (Anzeige in der Liste)
  if (body.name != null) {
    let cursor;
    do {
      const page = await env.KEYS.list({ prefix: "key:", cursor });
      for (const k of page.keys) {
        const rec = JSON.parse((await env.KEYS.get(k.name)) || "{}");
        if (rec.uid === u.uid && rec.name !== u.name) { rec.name = u.name; await put(env, k.name, JSON.stringify(rec)); }
      }
      cursor = page.list_complete ? null : page.cursor;
    } while (cursor);
  }
  return json({ ok: true });
}

// Admin: Sperrlisten, Meldungen, Support
async function adminBlocks(req, env, action) {
  if (action === "blocks") {
    const b = await getBlocks(env);
    const mask = (s) => s.length > 8 ? s.slice(0, 6) + "…" : s;
    return json({ ok: true, devices: Object.keys(b.devices).map((d) => ({ id: mask(d), full: d, ...b.devices[d] })), ips: Object.keys(b.ips).map((i) => ({ id: i, ...b.ips[i] })) });
  }
  const body = await req.json().catch(() => ({}));
  const b = await getBlocks(env);
  const type = body.type === "ip" ? "ip" : "device";
  let value = String(body.value || "").slice(0, 100);
  if (action === "block") {
    const un = JSON.parse((await env.KEYS.get("unauth")) || "{}");
    if (un[value]) value = type === "ip" ? un[value].ip : un[value].dev; // aus der Meldungsliste
    if (!value) return json({ ok: false, error: "value" }, 400);
    (type === "ip" ? b.ips : b.devices)[value] = { reason: String(body.reason || "").slice(0, 300), at: Date.now() };
  } else if (action === "unblock") {
    const m = type === "ip" ? b.ips : b.devices;
    const hit = Object.keys(m).find((k) => k === value);
    if (hit) delete m[hit];
  }
  await put(env, "blocks", JSON.stringify(b));
  return json({ ok: true });
}

async function adminUnauth(req, env, action) {
  if (action === "unauth") {
    const st = JSON.parse((await env.KEYS.get("unauth")) || "{}");
    const list = Object.keys(st).map((id) => ({ id, ...st[id], dev: undefined, device: st[id].dev ? st[id].dev.slice(0, 6) + "…" : "" })).sort((a, b) => b.t - a.t);
    return json({ ok: true, list });
  }
  await put(env, "unauth", "{}");
  return json({ ok: true });
}

async function adminSupport(req, env, action) {
  const st = JSON.parse((await env.KEYS.get("support")) || "{}");
  const msgs = st.msgs || [];
  if (action === "support") return json({ ok: true, msgs: msgs.map((m) => ({ ...m, device: undefined })).sort((a, b) => b.t - a.t) });
  const body = await req.json().catch(() => ({}));
  const m = msgs.find((x) => x.id === body.id);
  if (!m) return json({ ok: false, error: "unknown" }, 404);
  if (action === "support-reply") { m.reply = String(body.reply || "").slice(0, 500); m.repliedAt = Date.now(); m.done = true; }
  if (action === "support-done") m.done = body.done !== false;
  if (action === "support-delete") msgs.splice(msgs.indexOf(m), 1);
  await put(env, "support", JSON.stringify({ msgs }));
  return json({ ok: true });
}

// App: Nachricht an den Support (auch ohne gültigen Key). Gibt die eigenen Nachrichten samt Antworten zurück.
async function support(req, env) {
  let body;
  try { body = await req.json(); } catch { return json({ ok: false, error: "format" }, 400); }
  const device = String(body.device || "").slice(0, 100);
  if (device.length < 6) return json({ ok: false, error: "format" }, 400);
  const text = String(body.text || "").trim().slice(0, 500);
  const st = JSON.parse((await env.KEYS.get("support")) || "{}");
  const msgs = st.msgs || [];
  const now = Date.now();
  if (text) {
    if (text.length < 3) return json({ ok: false, error: "short" }, 400);
    if (msgs.filter((m) => m.device === device && now - m.t < 86400000).length >= 5) return json({ ok: false, error: "rate" }, 429);
    const user = await userByDevice(env, device);
    const key = normalize(body.key);
    const rec = key ? JSON.parse((await env.KEYS.get("key:" + key)) || "null") : null;
    msgs.push({ id: Math.random().toString(36).slice(2, 10), t: now, device, uid: user ? user.uid : (rec && rec.uid) || "", name: (user && user.name) || (rec && nameOf(rec)) || "", model: String(body.model || "").slice(0, 60), key: rec ? key : "", text, reply: "", done: false });
    msgs.splice(0, Math.max(0, msgs.length - 200));
    await put(env, "support", JSON.stringify({ msgs }));
  }
  return json({ ok: true, messages: msgs.filter((m) => m.device === device).slice(-10).map((m) => ({ t: m.t, text: m.text, reply: m.reply, done: m.done })) });
}

// App-Admin (z. B. Partnerin): Kontingent sehen, Keys holen, eigene Keys mit Restlaufzeit sehen.
async function sub(req, env) {
  let body;
  try { body = await req.json(); } catch { return json({ ok: false, error: "format" }, 400); }
  const key = normalize(body.key);
  const device = String(body.device || "").slice(0, 100);
  if (!key || !device) return json({ ok: false, error: "format" }, 400);
  const hit = blockHit(await getBlocks(env), device, ipOf(req));
  if (hit) return blockedJson(hit);
  const rec = JSON.parse((await env.KEYS.get("key:" + key)) || "null");
  const now = Date.now();
  if (!rec || rec.revoked || rec.device !== device || now >= rec.expiresAt) return json({ ok: false, error: "auth" }, 403);
  const user = await userByUid(env, rec.uid);
  if (!user || !user.admin || user.device !== device) return json({ ok: false, error: "auth" }, 403);

  if (body.action === "issue") {
    const secs = Math.round(Number(body.seconds));
    const q = (user.quota || {})[String(secs)];
    if (!q) return json({ ok: false, error: "quota" }, 400);
    if (q.used >= q.limit) return json({ ok: false, error: "empty" }, 400);
    const reason = String(body.reason || "").trim().slice(0, 200);
    if (q.reason && reason.length < 5) return json({ ok: false, error: "reason" }, 400);
    let nk;
    do { nk = newKey(); } while (await env.KEYS.get("key:" + nk));
    const nrec = { seconds: secs, note: "", name: String(body.name || "").slice(0, 100), created: now, device: null, activatedAt: null, expiresAt: null, revoked: false, issuedBy: user.uid, issueReason: reason };
    q.used++;
    await put(env, "key:" + nk, JSON.stringify(nrec));
    await put(env, "user:" + user.uid, JSON.stringify(user));
    return json({ ok: true, key: nk, seconds: secs });
  }

  const quota = Object.keys(user.quota || {}).map(Number).sort((a, b) => a - b).map((s) => {
    const q = user.quota[String(s)];
    return { seconds: s, left: Math.max(0, q.limit - q.used), limit: q.limit, reason: !!q.reason };
  });
  const keys = [];
  let cursor;
  do {
    const page = await env.KEYS.list({ prefix: "key:", cursor });
    for (const k of page.keys) {
      const r = JSON.parse((await env.KEYS.get(k.name)) || "{}");
      if (r.issuedBy !== user.uid) continue;
      const state = r.revoked ? "revoked" : !r.device ? "free" : now >= r.expiresAt ? "expired" : "active";
      const holder = r.uid ? await userByUid(env, r.uid) : null;
      keys.push({ key: k.name.slice(4), seconds: secondsOf(r), state, expiresAt: r.expiresAt || null, remaining: state === "active" ? Math.round((r.expiresAt - now) / 1000) : 0, name: nameOf(r), holderUid: r.uid || "", holderName: (holder && holder.name) || "", created: r.created || 0 });
    }
    cursor = page.list_complete ? null : page.cursor;
  } while (cursor);
  keys.sort((a, b) => b.created - a.created);
  return json({ ok: true, uid: user.uid, quota, keys });
}

// ---- Gemeinsamer Stand der Tester: Flugplätze + Hörweiten ----
//   POST /share {key, device, events:[{icao,hex,kind:"L"|"T",t,label}], answers:[{key,slant,factor,loud,base}], reset?}
//   -> {ok, parked:{ICAO:[{hex,since,label}]}, ranges:{TYP:km}}
// Alles liegt in EINEM KV-Eintrag "af:state". Es wird nur geschrieben, wenn sich etwas ändert
// (doppelte Meldungen desselben Ereignisses von mehreren Handys ändern nichts). Standorte werden nie gespeichert.
const AF_KEEP_MS = 30 * 86400 * 1000;
function learnRange(base, slant, factor, loud) {
  const needed = slant / Math.max(factor, 0.1);
  let next = base;
  if (loud) { const t = needed * 1.15; if (base < t) next = base + 0.6 * (t - base); }
  else { const t = needed * 0.85; if (base > t) next = base - 0.6 * (base - t); }
  return Math.min(30, Math.max(1.5, next));
}
async function share(req, env) {
  let body;
  try { body = await req.json(); } catch { return json({ ok: false, error: "format" }, 400); }
  const key = normalize(body.key);
  const device = String(body.device || "").slice(0, 100);
  if (!key || !device) return json({ ok: false, error: "format" }, 400);
  const hit = blockHit(await getBlocks(env), device, ipOf(req));
  if (hit) return blockedJson(hit);
  const rec = JSON.parse((await env.KEYS.get("key:" + key)) || "null");
  const now = Date.now();
  if (!rec || rec.revoked || !rec.device || rec.device !== device || now >= rec.expiresAt) return json({ ok: false, error: "auth" }, 403);

  const st = JSON.parse((await env.KEYS.get("af:state")) || "{}");
  const parked = st.parked || {};
  const ranges = st.ranges || {};
  let changed = false;
  if (body.reset === true) { for (const k of Object.keys(parked)) delete parked[k]; changed = true; }

  const events = Array.isArray(body.events) ? body.events.slice(0, 40) : [];
  for (const ev of events) {
    const icao = String((ev && ev.icao) || "").toUpperCase();
    const hex = String((ev && ev.hex) || "").toLowerCase();
    if (!/^[A-Z0-9]{3,5}$/.test(icao) || !/^[0-9a-f]{6}$/.test(hex)) continue;
    let t = Number(ev.t);
    if (!isFinite(t) || t > now + 600000 || t < now - 6 * 3600000) t = now;
    const here = parked[icao] && parked[icao][hex];
    if (ev.kind === "L") {
      if (here) continue;
      let newer = false;
      for (const f of Object.keys(parked)) if (parked[f][hex] && parked[f][hex].s > t) newer = true;
      if (newer) continue;
      for (const f of Object.keys(parked)) if (parked[f][hex]) delete parked[f][hex];
      (parked[icao] = parked[icao] || {})[hex] = { s: t, l: String(ev.label || "").slice(0, 60) };
      changed = true;
    } else if (ev.kind === "T") {
      if (here && here.s <= t) { delete parked[icao][hex]; changed = true; }
    }
  }

  const answers = Array.isArray(body.answers) ? body.answers.slice(0, 20) : [];
  for (const a of answers) {
    const k = String((a && a.key) || "").toUpperCase().slice(0, 30);
    const slant = Number(a.slant), factor = Number(a.factor), base = Number(a.base);
    if (!/^[A-Z0-9_]{2,30}$/.test(k) || !isFinite(slant) || !isFinite(factor) || slant <= 0) continue;
    const cur = ranges[k] != null ? ranges[k] : (isFinite(base) ? Math.min(30, Math.max(1.5, base)) : 8);
    const next = Math.round(learnRange(cur, slant, factor, a.loud === true) * 100) / 100;
    if (ranges[k] == null || next !== ranges[k]) { ranges[k] = next; changed = true; }
  }

  for (const f of Object.keys(parked)) {
    for (const h of Object.keys(parked[f])) if (now - parked[f][h].s > AF_KEEP_MS) { delete parked[f][h]; changed = true; }
    if (!Object.keys(parked[f]).length) delete parked[f];
  }
  if (changed) await put(env, "af:state", JSON.stringify({ parked, ranges }));

  const out = {};
  for (const f of Object.keys(parked)) out[f] = Object.keys(parked[f]).map((h) => ({ hex: h, since: parked[f][h].s, label: parked[f][h].l }));
  return json({ ok: true, now, parked: out, ranges });
}

// Neuinstallation: Hat dieses Handy (Geräte-Kennung) schon einen gültigen Key, gibt der Server ihn zurück.
// Gesperrte oder abgelaufene Keys werden nicht zurückgegeben. Es wird nichts geschrieben.
async function restore(req, env) {
  let body;
  try { body = await req.json(); } catch { return json({ ok: false, error: "format" }, 400); }
  const device = String(body.device || "").slice(0, 100);
  if (device.length < 6) return json({ ok: false, error: "format" }, 400);
  const ip = ipOf(req);
  const hit = blockHit(await getBlocks(env), device, ip);
  if (hit) { await logUnauth(env, device, ip, "Gesperrtes Gerät/IP versucht Zugriff", body); return blockedJson(hit); }
  const now = Date.now();
  let best = null, cursor, revokedReason = null;
  do {
    const page = await env.KEYS.list({ prefix: "key:", cursor });
    for (const k of page.keys) {
      const rec = JSON.parse((await env.KEYS.get(k.name)) || "{}");
      if (rec.device === device && rec.revoked && revokedReason == null) revokedReason = rec.revokeReason || "";
      if (rec.device === device && !rec.revoked && rec.expiresAt > now && (!best || rec.expiresAt > best.rec.expiresAt)) best = { key: k.name.slice(4), rec };
    }
    cursor = page.list_complete ? null : page.cursor;
  } while (cursor);
  if (!best) {
    await logUnauth(env, device, ip, revokedReason != null ? "Gesperrter Key, App neu installiert" : "App ohne Key geöffnet", body);
    return json({ ok: false, error: revokedReason != null ? "revoked" : "none", message: revokedReason || "" });
  }
  return json({ ok: true, key: best.key, expiresAt: best.rec.expiresAt, name: nameOf(best.rec) });
}
const ADMIN_PAGE = `<!doctype html><html lang="de"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>Aero Guard Admin</title>
<style>
*{box-sizing:border-box}
body{margin:0;font-family:system-ui,Segoe UI,sans-serif;background:#07101c;color:#e6f2ec;display:flex;min-height:100vh}
#side{width:220px;background:#0a1828;border-right:1px solid #16304a;padding:16px 10px;display:flex;flex-direction:column;gap:4px;position:sticky;top:0;height:100vh}
#side h1{font-size:17px;margin:0 8px 14px;color:#4cd98a}
#side a{display:block;padding:10px 12px;border-radius:8px;color:#b9cfc4;cursor:pointer;text-decoration:none;font-size:15px}
#side a:hover{background:#10263c}#side a.on{background:#17402f;color:#fff;font-weight:600}
#side .sp{flex:1}
#main{flex:1;padding:22px;max-width:1100px}
h2{margin:0 0 14px}
.card{background:#0c1d2f;border:1px solid #16304a;border-radius:12px;padding:16px;margin-bottom:16px}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:12px;margin-bottom:16px}
.stat{background:#0c1d2f;border:1px solid #16304a;border-radius:12px;padding:14px}.stat b{display:block;font-size:28px;color:#4cd98a}.stat span{font-size:13px;color:#8aa59a}
label{display:block;font-size:13px;color:#8aa59a;margin:10px 0 4px}
input,select,button,textarea{font:inherit;padding:9px 11px;border-radius:8px;border:1px solid #2a5a45;background:#081624;color:#e6f2ec}
button{background:#3cc47a;color:#04130b;font-weight:700;cursor:pointer;border:0}button.sec{background:#16304a;color:#e6f2ec}button.red{background:#c0392b;color:#fff}
button:hover{filter:brightness(1.1)}
.row{display:flex;gap:10px;flex-wrap:wrap;align-items:flex-end}
.presets button{margin:0 6px 6px 0;font-size:13px;padding:6px 10px}
table{width:100%;border-collapse:collapse;font-size:13.5px}th,td{padding:8px 6px;border-bottom:1px solid #16304a;text-align:left;vertical-align:middle}th{color:#8aa59a;font-weight:600}
tr:hover td{background:#0e2339}
.tag{padding:2px 8px;border-radius:10px;font-size:12px;font-weight:700}.free{background:#1d3b66}.active{background:#17603f}.expired{background:#6b5a14}.revoked{background:#7a2a22}
.mono{font-family:ui-monospace,Consolas,monospace}
#out{white-space:pre-wrap;background:#081624;border:1px dashed #2a5a45;border-radius:8px;padding:12px;margin-top:12px;min-height:50px}
#login{position:fixed;inset:0;background:#07101c;display:flex;align-items:center;justify-content:center;z-index:9}
#login .card{width:340px}
.hide{display:none!important}
.small{font-size:12.5px;color:#8aa59a}
details.grp{border:1px solid #16304a;border-radius:10px;margin:10px 0;background:#0a1a2b}
details.grp summary{cursor:pointer;padding:12px 14px;font-size:15px;list-style:none;display:flex;gap:12px;align-items:center;flex-wrap:wrap}
details.grp summary::-webkit-details-marker{display:none}
details.grp summary::before{content:"▸";color:#4cd98a;display:inline-block;width:14px}
details.grp[open] summary::before{content:"▾"}
details.grp .cnt{background:#17402f;border-radius:10px;padding:2px 10px;font-size:13px;font-weight:700}
details.grp table{margin:0 0 6px}
.acts button{padding:4px 8px;font-size:12px;margin:1px}
@media(max-width:720px){body{flex-direction:column}#side{width:100%;height:auto;flex-direction:row;flex-wrap:wrap;position:static}#side h1{width:100%}#side .sp{display:none}}
#modal{display:none;position:fixed;inset:0;background:rgba(0,0,0,.55);z-index:99;align-items:center;justify-content:center}#modal.on{display:flex}#modal .box{background:#1c2430;color:#fff;border-radius:10px;padding:20px;max-width:440px;width:90%}#modal h3{margin:0 0 8px}#modal p{margin:0 0 12px;line-height:1.4}#modal input{width:100%;box-sizing:border-box;margin-bottom:12px}#mX label{display:flex;gap:8px;align-items:center;margin:4px 0 10px;color:#e6f2ec;font-size:14px}#mX input{width:auto;margin:0}#modal .row{display:flex;gap:8px;justify-content:flex-end}
</style></head><body>
<div id="modal"><div class="box"><h3 id="mT"></h3><p id="mM"></p><input id="mI"><div id="mX"></div><div class="row"><button class="sec" id="mC">Abbrechen</button><button id="mO">OK</button></div></div></div>
<div id="login"><div class="card"><h2>Aero Guard Admin</h2><label>Admin-Passwort</label>
<input id="pw" type="password" style="width:100%" autofocus><p><button id="loginBtn" style="width:100%">Anmelden</button></p><div id="loginMsg" class="small"></div></div></div>

<nav id="side"><h1>✈ Aero Guard</h1>
<a data-p="home" class="on">📊 Dashboard</a>
<a data-p="create">➕ Key erzeugen</a>
<a data-p="devices">📱 Geräte</a>
<a data-p="users">👥 Nutzer &amp; Admins</a>
<a data-p="support">💬 Support <span id="supBadge"></span></a>
<a data-p="unauth">🚨 Meldungen <span id="unBadge"></span></a>
<a data-p="blocks">⛔ Sperren</a>
<a data-p="keys">🔑 Alle Keys</a>
<a data-p="help">ℹ️ Hilfe</a>
<div class="sp"></div><a id="logout">⎋ Abmelden</a></nav>

<div id="main">
<section id="p-home"><h2>Dashboard</h2><div class="stats" id="stats"></div>
<div class="card"><b>Schreibvorgänge heute (Cloudflare-KV, Gratis-Tarif: 1.000 pro Tag)</b><div id="wbar" style="background:#081624;border-radius:8px;height:18px;margin:10px 0;overflow:hidden"><div id="wfill" style="height:100%;background:#3cc47a;width:0"></div></div><div id="wtext" class="small"></div></div>
<div class="card"><b>Zuletzt eingelöst</b><table id="recent"></table></div></section>

<section id="p-create" class="hide"><h2>Key erzeugen</h2><div class="card">
<label>Laufzeit ab dem Einlösen auf dem Handy</label>
<div class="presets" id="presets"></div>
<div class="row"><div><label>Zahl</label><input id="dur" type="number" min="1" value="30" style="width:110px"></div>
<div><label>Einheit</label><select id="unit"><option value="1">Sekunden</option><option value="60">Minuten</option><option value="3600">Stunden</option><option value="86400" selected>Tage</option></select></div>
<div><label>Anzahl Keys</label><input id="count" type="number" min="1" max="100" value="1" style="width:90px"></div>
<div style="flex:1;min-width:160px"><label>Name (z. B. wer bekommt den Key)</label><input id="note" style="width:100%"></div></div>
<p><button id="createBtn">Keys erzeugen</button> <span class="small" id="durText"></span></p>
<div id="out">Hier erscheinen die neuen Keys.</div>
<p><button class="sec" id="copyBtn">Alle kopieren</button></p></div>
<p class="small">Tipp zum Testen: 30 Sekunden einstellen. Nach dem Einlösen läuft die Zeit auf dem Handy ab und die App sperrt sich.</p></section>

<section id="p-devices" class="hide"><h2>Geräte</h2><div class="card">
<p class="small">Jedes Handy, das einen Key eingelöst hat. Die App meldet beim Prüfen Handy-Modell, App-Version und drei Zähler (App geöffnet, Radar gestartet, Warnungen), nie den Standort. „Zuletzt online“ ist auf ca. 10 Minuten genau.</p>
<div class="row"><div><label>Suche (User-ID, Name, Handy, Key)</label><input id="dq" placeholder="z. B. U-7K3F oder Anna" style="width:260px"></div></div>
<div style="overflow:auto;margin-top:10px"><table id="devs"></table></div></div></section>

<section id="p-keys" class="hide"><h2>Alle Keys</h2><div class="card">
<div class="row"><div><label>Suche</label><input id="q" placeholder="Key oder Name"></div>
<div><label>Status</label><select id="flt"><option value="">alle</option><option value="free">frei</option><option value="active">aktiv</option><option value="expired">abgelaufen</option><option value="revoked">gesperrt</option></select></div>
<div><button class="sec" id="reload">↻ Neu laden</button> <button class="sec" id="expandAll">Alle auf</button> <button class="sec" id="collapseAll">Alle zu</button></div></div>
<div style="overflow:auto;margin-top:10px"><div id="keys"></div></div></div></section>

<section id="p-users" class="hide"><h2>Nutzer &amp; Admins</h2><div class="card">
<p class="small">Jedes Handy bekommt beim Freischalten eine User-ID (z. B. U-7K3F, steht in der App unter Einstellungen). Hier kannst du nach ID oder Namen suchen, Namen vergeben und festlegen, wer Admin ist. Ein Admin bekommt in der App ein Werkzeug, um Keys aus seinem Kontingent auszugeben.</p>
<div class="row"><div><label>Suche (ID, Name, Handy, Key)</label><input id="uq" placeholder="z. B. U-7K3F oder Anna" style="width:260px"></div></div>
<div style="overflow:auto;margin-top:10px"><table id="users"></table></div></div>
<div class="card hide" id="quotaCard"><b id="quotaTitle"></b>
<p class="small">Pro Laufzeit: Kontingent (wie viele Keys der Admin insgesamt ausgeben darf) und ob er einen Grund angeben muss. Ohne Haken zieht er frei, solange das Kontingent reicht. „Schon ausgegeben“ kannst du zurücksetzen.</p>
<table id="quotaTbl"></table>
<p class="row"><button class="sec" id="qAdd">+ Laufzeit hinzufügen</button><button id="qSave">Speichern</button></p></div></section>

<section id="p-support" class="hide"><h2>Support</h2><div class="card"><p class="small">Nachrichten aus der App („Support kontaktieren“). Deine Antwort sieht die Person in der App.</p>
<div style="overflow:auto"><table id="supTbl"></table></div></div></section>

<section id="p-unauth" class="hide"><h2>Meldungen: nicht autorisierter Zugriff</h2><div class="card">
<p class="small">Versuche ohne gültigen Key: App ohne Key geöffnet, unbekannter oder fremder Key, gesperrtes Gerät. Ein Eintrag je Gerät, höchstens alle 6 Stunden aktualisiert. Die Karte ohne Key ist erlaubt und erscheint hier nicht als Angriff, nur als „App ohne Key geöffnet“.</p>
<p><button class="red" data-n="unauthClear">Liste leeren</button></p>
<div style="overflow:auto"><table id="unTbl"></table></div></div></section>

<section id="p-blocks" class="hide"><h2>Sperren</h2><div class="card">
<p class="small">Gesperrte Geräte-Kennungen und IP-Adressen. Eine MAC-Adresse kann Android-Apps nicht auslesen, die Geräte-Kennung ist das Beste, was es gibt. Die IP wechselt im Mobilfunk oft und trifft bei Router-Sperren auch andere im selben WLAN. Sperre sie nur zusätzlich.</p>
<div style="overflow:auto"><table id="blTbl"></table></div>
<div class="row" style="margin-top:12px"><div><label>IP-Adresse manuell sperren</label><input id="blIp" placeholder="z. B. 203.0.113.5"></div><div><label>Grund</label><input id="blWhy" placeholder="wird dem Handy angezeigt" style="width:260px"></div><button data-n="blockIp">IP sperren</button></div></div></section>

<section id="p-help" class="hide"><h2>Hilfe</h2><div class="card">
<p><b>Frei</b> = noch nicht eingelöst. Die Laufzeit startet erst beim Einlösen.</p>
<p><b>Aktiv</b> = auf einem Handy eingelöst und noch gültig.</p>
<p><b>Handy lösen</b> = der Key wird wieder frei und kann auf einem anderen Handy neu eingelöst werden (Laufzeit startet neu).</p>
<p><b>Verlängern</b> = hängt Zeit an. Bei freien Keys wird die Laufzeit länger.</p>
<p><b>Lizenz entziehen / Sperren</b> = die App prüft jede Stunde und beim Öffnen. Danach sperrt sie sich und das Radar stoppt. Ohne Internet läuft sie bis zum normalen Ablauf weiter.</p>
<p><b>Name ändern</b> = hilft, die Tester auseinanderzuhalten.</p>
<p><b>Zähler</b> = wie oft die App geöffnet, das Radar gestartet und gewarnt wurde. Der Stand kommt beim nächsten Prüfen der App an.</p>
</div></section>
</div>
<script>
var PW = sessionStorage.getItem("agpw") || "", DATA = [], NOW = Date.now();
function $(i){return document.getElementById(i);}
function api(path, body){return fetch(path,{method:body?"POST":"GET",headers:{authorization:"Bearer "+PW,"content-type":"application/json"},body:body?JSON.stringify(body):undefined}).then(function(r){return r.json();});}
function fmtDur(s){ if(s<60) return s+" Sek."; if(s<3600) return Math.round(s/60*10)/10+" Min."; if(s<86400) return Math.round(s/3600*10)/10+" Std."; if(s==31536000||s==365*86400) return "1 Jahr"; return Math.round(s/86400*10)/10+" Tage"; }
function fmtDate(t){ return t? new Date(t).toLocaleString("de-DE"):"–"; }
function status(k){ if(k.revoked) return "revoked"; if(!k.device) return "free"; if(NOW>=k.expiresAt) return "expired"; return "active"; }
var NAMES={free:"frei",active:"aktiv",expired:"abgelaufen",revoked:"gesperrt"};
function remaining(k){ var s=status(k); if(s!="active") return ""; var d=Math.max(0,(k.expiresAt-NOW)/1000); return " (noch "+fmtDur(Math.round(d))+")"; }
function esc(t){ return String(t==null?"":t).replace(/[&<>"]/g,function(c){return {"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c];}); }

function show(p){
  ["home","create","devices","users","support","unauth","blocks","keys","help"].forEach(function(x){ $("p-"+x).classList.toggle("hide",x!=p); });
  document.querySelectorAll("#side a[data-p]").forEach(function(a){ a.classList.toggle("on",a.getAttribute("data-p")==p); });
  if(p=="home"||p=="keys"||p=="devices"||p=="users") load();
  if(p=="support") loadSupport(); if(p=="unauth") loadUnauth(); if(p=="blocks") loadBlocks();
}
document.querySelectorAll("#side a[data-p]").forEach(function(a){ a.onclick=function(){ show(a.getAttribute("data-p")); }; });

function login(){
  PW=$("pw").value||PW;
  api("/admin/list").then(function(r){
    if(!r.ok){ $("loginMsg").textContent="Passwort falsch."; return; }
    sessionStorage.setItem("agpw",PW); $("login").classList.add("hide"); apply(r);
  }).catch(function(){ $("loginMsg").textContent="Keine Verbindung."; });
}
$("loginBtn").onclick=login; $("pw").onkeydown=function(e){ if(e.key=="Enter") login(); };
$("logout").onclick=function(){ sessionStorage.removeItem("agpw"); location.reload(); };
if(PW) login();

function load(){ return api("/admin/list").then(function(r){ if(r.ok) apply(r); else location.reload(); }); }
var USERS=[], EX={};
function apply(r){ DATA=r.keys; NOW=r.now; USERS=r.users||[]; EX=r; renderHome(); renderKeys(); renderDevs(); renderUsers();
  $("supBadge").textContent=r.supportOpen?"("+r.supportOpen+")":""; $("unBadge").textContent=r.unauth24?"("+r.unauth24+")":""; }
function userOf(uid){ return USERS.filter(function(u){return u.uid==uid;})[0]; }

function renderHome(){
  var c={free:0,active:0,expired:0,revoked:0}; DATA.forEach(function(k){ c[status(k)]++; });
  var online=DATA.filter(function(k){return k.lastSeen&&NOW-k.lastSeen<2*3600*1000;}).length, adm=USERS.filter(function(u){return u.admin;}).length, wr=EX.writes||{n:0,limit:1000}, bl=EX.blocked||{devices:0,ips:0};
  $("stats").innerHTML=[["Keys gesamt",DATA.length],["Frei",c.free],["Aktiv",c.active],["Abgelaufen",c.expired],["Gesperrt",c.revoked],["Nutzer",USERS.length],["Admins",adm],["Online (2 Std.)",online],["Meldungen 24 Std.",EX.unauth24||0],["Support offen",EX.supportOpen||0],["Gesperrte Geräte/IPs",bl.devices+bl.ips],["Schreibvorgänge heute",wr.n+" / "+wr.limit]]
    .map(function(x){ return '<div class="stat"><b>'+x[1]+'</b><span>'+x[0]+'</span></div>'; }).join("");
  var pct=Math.min(100,Math.round(wr.n/wr.limit*100)); $("wfill").style.width=pct+"%"; $("wfill").style.background=pct>80?"#c0392b":pct>50?"#d4a017":"#3cc47a";
  $("wtext").innerHTML="Verbraucht (gezählt vom Server): <b>"+wr.n+"</b> von "+wr.limit+" · noch frei: <b>"+Math.max(0,wr.limit-wr.n)+"</b> (Tag "+esc(wr.day||"")+", UTC, Zähler setzt sich um 01:00/02:00 Uhr deutscher Zeit zurück).<br>Hinweis: Cloudflare bietet keine Abfrage für den Verbrauch. Der Server zählt seine eigenen Schreibvorgänge mit und speichert den Stand alle 5 Schreibvorgänge. Der Wert ist eine Untergrenze. Der genaue Stand steht im Cloudflare-Dashboard unter Storage &amp; Databases → KV → Metrics.";
  var rec=DATA.filter(function(k){return k.activatedAt;}).sort(function(a,b){return b.activatedAt-a.activatedAt;}).slice(0,8);
  $("recent").innerHTML="<tr><th>Name</th><th>Key</th><th>Eingelöst</th><th>Status</th></tr>"+(rec.length?rec.map(function(k){
    return "<tr><td>"+esc(k.name)+"</td><td class=mono>"+k.key+"</td><td>"+fmtDate(k.activatedAt)+"</td><td><span class='tag "+status(k)+"'>"+NAMES[status(k)]+"</span>"+remaining(k)+"</td></tr>"; }).join(""):"<tr><td colspan=4 class=small>Noch nichts eingelöst.</td></tr>");
}

var OPEN={};
function renderKeys(){
  var q=($("q").value||"").toUpperCase(), f=$("flt").value, filtering=!!(q||f);
  var list=DATA.filter(function(k){ return (!f||status(k)==f)&&(!q||k.key.indexOf(q)>=0||(k.name||"").toUpperCase().indexOf(q)>=0); });
  var groups={}; list.forEach(function(k){ (groups[k.seconds]=groups[k.seconds]||[]).push(k); });
  var secs=Object.keys(groups).map(Number).sort(function(a,b){return b-a;});
  if(!secs.length){ $("keys").innerHTML="<p class=small>Keine Keys.</p>"; return; }
  $("keys").innerHTML=secs.map(function(sec){
    var g=groups[sec], c={free:0,active:0,expired:0,revoked:0}; g.forEach(function(k){ c[status(k)]++; });
    var parts=[]; ["active","free","expired","revoked"].forEach(function(x){ if(c[x]) parts.push(c[x]+" "+NAMES[x]); });
    var open=filtering||OPEN[sec];
    var rows=g.map(function(k){ var s=status(k);
      return "<tr><td class=mono>"+k.key+"</td><td>"+esc(k.name)+(k.issuedBy&&k.issuedBy!="main"?"<div class=small>von "+esc(k.issuedBy)+(k.issueReason?" · Grund: "+esc(k.issueReason):"")+"</div>":"")+(k.revoked&&k.revokeReason?"<div class=small>Sperrgrund: "+esc(k.revokeReason)+"</div>":"")+"</td><td class=mono>"+(k.device||"–")+(k.uid?"<div class=small>"+esc(k.uid)+"</div>":"")+"</td><td>"+fmtDate(k.activatedAt)+"</td><td>"+fmtDate(k.expiresAt)+"</td>"+
      "<td><span class='tag "+s+"'>"+NAMES[s]+"</span>"+remaining(k)+"</td><td class=acts>"+
      "<button class=sec data-a=copy data-k="+k.key+">Kopieren</button>"+
      (s!="free"&&!k.revoked?"<button class=sec data-a=extend data-k="+k.key+">Verlängern</button>":"")+
      (k.device?"<button class=sec data-a=reset data-k="+k.key+">Handy lösen</button>":"")+
      (k.revoked?"<button class=sec data-a=unrevoke data-k="+k.key+">Entsperren</button>":"<button class=sec data-a=revoke data-k="+k.key+">Sperren</button>")+
      "<button class=red data-a=delete data-k="+k.key+">Löschen</button></td></tr>"; }).join("");
    return "<details class=grp data-s='"+sec+"'"+(open?" open":"")+"><summary><b>"+fmtDur(sec)+"</b> <span class=cnt>"+g.length+(g.length==1?" Key":" Keys")+"</span> <span class=small>"+parts.join(" · ")+"</span></summary>"+
      "<div style='overflow:auto'><table><tr><th>Key</th><th>Name</th><th>Handy</th><th>Eingelöst</th><th>Läuft ab</th><th>Status</th><th></th></tr>"+rows+"</table></div></details>";
  }).join("");
}
$("keys").addEventListener("toggle",function(e){ var d=e.target; if(d&&d.classList&&d.classList.contains("grp")) OPEN[d.getAttribute("data-s")]=d.open; },true);
$("expandAll").onclick=function(){ document.querySelectorAll("#keys details").forEach(function(d){ d.open=true; }); };
$("collapseAll").onclick=function(){ document.querySelectorAll("#keys details").forEach(function(d){ d.open=false; }); };
function ago(t){ if(!t) return "–"; var m=Math.round((NOW-t)/60000); if(m<2) return "gerade eben"; if(m<60) return "vor "+m+" Min."; if(m<1440) return "vor "+Math.round(m/60)+" Std."; return "vor "+Math.round(m/1440)+" Tagen"; }
function renderDevs(){
  var dq=($("dq").value||"").toUpperCase();
  var list=DATA.filter(function(k){return k.device;}).filter(function(k){ return !dq||(k.uid||"").indexOf(dq)>=0||(k.name||"").toUpperCase().indexOf(dq)>=0||(k.model||"").toUpperCase().indexOf(dq)>=0||k.key.indexOf(dq)>=0; }).sort(function(a,b){return (b.lastSeen||0)-(a.lastSeen||0);});
  $("devs").innerHTML="<tr><th>Name / ID</th><th>Handy</th><th>Key</th><th>Lizenz</th><th>Zuletzt online</th><th>App geöffnet</th><th>Radar gestartet</th><th>Warnungen</th><th></th></tr>"+
  (list.length?list.map(function(k){ var s=status(k), st=k.stats||{opens:0,starts:0,warnings:0}, on=k.lastSeen&&(NOW-k.lastSeen)<2*3600*1000;
    return "<tr><td><b>"+(esc(k.name)||"<i class=small>ohne Namen</i>")+"</b><div class='small mono'>"+esc(k.uid||"keine ID")+(k.issuedBy&&k.issuedBy!="main"?" · von "+esc(k.issuedBy):"")+"</div></td><td>"+esc(k.model||"?")+"<div class=small>App "+esc(k.version||"?")+"</div></td><td class=mono>"+k.key+"</td>"+
    "<td><span class='tag "+s+"'>"+NAMES[s]+"</span><div class=small>"+(s=="active"?"noch "+fmtDur(Math.round((k.expiresAt-NOW)/1000))+" · bis "+fmtDate(k.expiresAt):(s=="expired"?"seit "+fmtDate(k.expiresAt):""))+"</div></td>"+
    "<td>"+(on?"🟢 ":"⚪ ")+ago(k.lastSeen)+"</td><td>"+st.opens+"</td><td>"+st.starts+"</td><td>"+st.warnings+"</td><td class=acts>"+
    "<button class=sec data-a=rename data-k="+k.key+">Name ändern</button>"+
    (s!="expired"&&!k.revoked?"<button class=sec data-a=extend data-k="+k.key+">Verlängern</button>":"")+
    (k.revoked?"<button data-a=unrevoke data-k="+k.key+">Lizenz wieder erlauben</button>":"<button class=red data-a=revoke data-k="+k.key+">Lizenz entziehen</button>")+
    "<button class=sec data-a=reset data-k="+k.key+">Handy lösen</button></td></tr>"; }).join(""):"<tr><td colspan=9 class=small>Noch kein Handy freigeschaltet.</td></tr>");
}
$("devs").onclick=function(e){ $("keys").onclick(e); };
$("dq").oninput=renderDevs; $("uq").oninput=renderUsers; $("q").oninput=renderKeys; $("flt").onchange=renderKeys; $("reload").onclick=load;
function dlg(title,msg,defVal,withInput,noCancel,extra){ return new Promise(function(res){
  $("mX").innerHTML=extra||"";
  $("mT").textContent=title; $("mM").textContent=msg; var i=$("mI"); i.style.display=withInput?"block":"none"; i.value=defVal||"";
  $("mC").style.display=noCancel?"none":"inline-block"; $("modal").className="on"; if(withInput){ i.focus(); i.select(); } else $("mO").focus();
  function done(v){ $("modal").className=""; $("mO").onclick=$("mC").onclick=i.onkeydown=null; res(v); }
  $("mO").onclick=function(){ done(withInput?i.value:true); }; $("mC").onclick=function(){ done(withInput?null:false); };
  i.onkeydown=function(ev){ if(ev.key=="Enter") $("mO").onclick(); if(ev.key=="Escape") $("mC").onclick(); };
}); }
$("keys").onclick=function(e){
  var b=e.target.closest("button"); if(!b) return; var a=b.getAttribute("data-a"), k=b.getAttribute("data-k");
  if(a=="copy"){ try{ navigator.clipboard.writeText(k); }catch(x){} b.textContent="✓"; return; }
  var body={key:k}, ask=Promise.resolve(true);
  if(a=="rename"){ var cur=(DATA.filter(function(x){return x.key==k;})[0]||{}).name||"";
    ask=dlg("Name ändern","Name für dieses Gerät:",cur,true).then(function(v){ if(v===null) return false; body.name=v; return true; }); }
  else if(a=="delete") ask=dlg("Löschen","Key "+k+" endgültig löschen?");
  else if(a=="revoke") ask=dlg("Lizenz entziehen","Grund (wird dem Nutzer in der App angezeigt):","",true,false,
    "<label><input type=checkbox id=cbDev checked> Geräte-Kennung sperren (kommt auch mit neuem Key nicht mehr rein)</label><label><input type=checkbox id=cbIp> Zusätzlich IP-Adresse sperren</label>").then(function(v){ if(v===null) return false; body.reason=v; body.blockDevice=$("cbDev").checked; body.blockIp=$("cbIp").checked; return true; });
  else if(a=="unrevoke") ask=Promise.resolve(true);
  else if(a=="reset") ask=dlg("Handy lösen","Key "+k+" vom Handy lösen? Die Laufzeit startet beim nächsten Einlösen neu.");
  else if(a=="extend") ask=dlg("Verlängern","Wie viele Tage verlängern? (Kommazahl erlaubt, z. B. 0.5 = 12 Std.)","30",true).then(function(v){ if(!v) return false; var n=parseFloat(v.replace(",",".")); if(!(n>0)) return false; body.seconds=Math.round(n*86400); return true; });
  ask.then(function(ok){ if(!ok) return; return api("/admin/"+a,body).then(function(r){ if(!r.ok) return dlg("Fehler",String(r.error||"?"),"",false,true); }).then(load); });
};

function fmtRest(s){ return s>0?fmtDur(s):"–"; }
function secLabel(s){ return fmtDur(+s); }
function renderUsers(){
  var q=($("uq").value||"").toUpperCase();
  var list=USERS.filter(function(u){ var ks=DATA.filter(function(k){return k.uid==u.uid;}); return !q||u.uid.indexOf(q)>=0||(u.name||"").toUpperCase().indexOf(q)>=0||ks.some(function(k){return k.key.indexOf(q)>=0||(k.model||"").toUpperCase().indexOf(q)>=0;}); })
    .sort(function(a,b){return (b.admin?1:0)-(a.admin?1:0)||(b.created||0)-(a.created||0);});
  $("users").innerHTML="<tr><th>ID</th><th>Name</th><th>Handy</th><th>Rolle</th><th>Kontingent (übrig / gesamt)</th><th></th></tr>"+(list.length?list.map(function(u){
    var ks=DATA.filter(function(k){return k.uid==u.uid;}), m=ks[0]&&ks[0].model||"?";
    var q2=Object.keys(u.quota||{}).sort(function(a,b){return a-b;}).map(function(s){ var x=u.quota[s]; return secLabel(s)+": "+Math.max(0,x.limit-x.used)+"/"+x.limit+(x.reason?" 📝":""); }).join("<br>");
    return "<tr><td class=mono>"+u.uid+"</td><td><b>"+(esc(u.name)||"<i class=small>ohne Namen</i>")+"</b></td><td>"+esc(m)+"</td><td>"+(u.admin?"<span class='tag active'>Admin</span>":"Nutzer")+"</td><td class=small>"+(u.admin?q2:"–")+"</td><td class=acts>"+
    "<button class=sec data-n=uName data-u="+u.uid+">Name</button>"+
    "<button class=sec data-n=uAdmin data-u="+u.uid+">"+(u.admin?"Admin entziehen":"Zum Admin machen")+"</button>"+
    (u.admin?"<button class=sec data-n=uQuota data-u="+u.uid+">Kontingent</button>":"")+"</td></tr>"; }).join(""):"<tr><td colspan=6 class=small>Keine Nutzer.</td></tr>");
}
var QU=null;
function openQuota(uid){ var u=userOf(uid); QU={uid:uid,rows:Object.keys(u.quota||{}).map(function(s){ var x=u.quota[s]; return {days:s/86400,limit:x.limit,used:x.used,reason:!!x.reason}; })}; drawQuota(); }
function drawQuota(){
  var u=userOf(QU.uid); $("quotaCard").classList.remove("hide"); $("quotaTitle").textContent="Kontingent von "+(u.name||u.uid)+" ("+u.uid+")";
  $("quotaTbl").innerHTML="<tr><th>Laufzeit (Tage)</th><th>Kontingent</th><th>Schon ausgegeben</th><th>Grund nötig</th><th></th></tr>"+QU.rows.map(function(r,i){
    return "<tr><td><input data-q=days data-i="+i+" value='"+r.days+"' style='width:90px'></td><td><input data-q=limit data-i="+i+" value='"+r.limit+"' style='width:80px'></td><td><input data-q=used data-i="+i+" value='"+r.used+"' style='width:80px'></td><td><input type=checkbox data-q=reason data-i="+i+(r.reason?" checked":"")+"></td><td><button class=red data-n=qDel data-i="+i+">×</button></td></tr>"; }).join("");
}
function readQuota(){ document.querySelectorAll("#quotaTbl [data-q]").forEach(function(el){ var r=QU.rows[+el.getAttribute("data-i")], f=el.getAttribute("data-q");
  if(f=="reason") r.reason=el.checked; else r[f]=parseFloat(String(el.value).replace(",","."))||0; }); }
$("qAdd").onclick=function(){ readQuota(); QU.rows.push({days:30,limit:1,used:0,reason:true}); drawQuota(); };
$("qSave").onclick=function(){ readQuota(); var q={}; QU.rows.forEach(function(r){ if(r.days>0) q[Math.round(r.days*86400)]={limit:r.limit,used:r.used,reason:r.reason}; });
  api("/admin/user",{uid:QU.uid,quota:q}).then(function(r){ return dlg(r.ok?"Gespeichert":"Fehler",r.ok?"Das Kontingent gilt sofort. Die App holt es beim nächsten Öffnen des Admin-Werkzeugs.":String(r.error),"",false,true); }).then(load); };

function loadSupport(){ api("/admin/support").then(function(r){ if(!r.ok) return;
  $("supTbl").innerHTML="<tr><th>Von</th><th>Nachricht</th><th>Antwort</th><th></th></tr>"+(r.msgs.length?r.msgs.map(function(m){
    return "<tr><td><b>"+(esc(m.name)||"?")+"</b><div class='small mono'>"+esc(m.uid||"")+" · "+esc(m.model||"")+"</div><div class=small>"+fmtDate(m.t)+"</div></td><td style='max-width:340px'>"+esc(m.text)+"</td><td style='max-width:280px'>"+(m.reply?esc(m.reply):"<i class=small>noch keine</i>")+"</td><td class=acts>"+
    "<button data-n=sReply data-id="+m.id+">Antworten</button><button class=sec data-n=sDone data-id="+m.id+" data-d="+(m.done?0:1)+">"+(m.done?"Wieder öffnen":"Erledigt")+"</button><button class=red data-n=sDel data-id="+m.id+">Löschen</button></td></tr>"; }).join(""):"<tr><td colspan=4 class=small>Keine Nachrichten.</td></tr>"); }); }
function loadUnauth(){ api("/admin/unauth").then(function(r){ if(!r.ok) return;
  $("unTbl").innerHTML="<tr><th>Gerät</th><th>Was</th><th>Wann</th><th>Anzahl</th><th></th></tr>"+(r.list.length?r.list.map(function(e){
    return "<tr><td><div class=mono>"+esc(e.device||e.id)+"</div><div class=small>"+esc(e.model||"")+" "+esc(e.version||"")+(e.ip?" · IP "+esc(e.ip):"")+"</div></td><td>"+esc(e.why)+"</td><td>"+fmtDate(e.t)+"<div class=small>erstmals "+fmtDate(e.first)+"</div></td><td>"+e.n+"</td><td class=acts>"+
    (e.device?"<button class=red data-n=unBlock data-t=device data-id='"+esc(e.id)+"'>Gerät sperren</button>":"")+(e.ip?"<button class=red data-n=unBlock data-t=ip data-id='"+esc(e.id)+"'>IP sperren</button>":"")+"</td></tr>"; }).join(""):"<tr><td colspan=5 class=small>Keine Meldungen.</td></tr>"); }); }
function loadBlocks(){ api("/admin/blocks").then(function(r){ if(!r.ok) return;
  var rows=r.devices.map(function(d){ return {t:"device",id:d.full,label:"Gerät "+d.id,why:d.reason,at:d.at}; }).concat(r.ips.map(function(d){ return {t:"ip",id:d.id,label:"IP "+d.id,why:d.reason,at:d.at}; }));
  $("blTbl").innerHTML="<tr><th>Gesperrt</th><th>Grund</th><th>Seit</th><th></th></tr>"+(rows.length?rows.map(function(x){
    return "<tr><td class=mono>"+esc(x.label)+"</td><td>"+esc(x.why)+"</td><td>"+fmtDate(x.at)+"</td><td><button class=sec data-n=unblock data-t="+x.t+" data-id='"+esc(x.id)+"'>Entsperren</button></td></tr>"; }).join(""):"<tr><td colspan=4 class=small>Nichts gesperrt.</td></tr>"); }); }
$("main").addEventListener("click",function(e){
  var b=e.target.closest("button[data-n]"); if(!b) return; var n=b.getAttribute("data-n"), u=b.getAttribute("data-u"), id=b.getAttribute("data-id");
  function fin(r){ if(r&&!r.ok) return dlg("Fehler",String(r.error||"?"),"",false,true); }
  if(n=="uName"){ dlg("Name","Name für "+u+":",(userOf(u)||{}).name||"",true).then(function(v){ if(v===null) return; return api("/admin/user",{uid:u,name:v}).then(fin).then(load); }); }
  else if(n=="uAdmin"){ var me=userOf(u); dlg(me.admin?"Admin entziehen":"Zum Admin machen",(me.admin?"Admin-Rolle von ":"")+(me.name||u)+(me.admin?" entziehen?":" zum Admin machen? Die App zeigt dann das Admin-Werkzeug (nach dem nächsten Öffnen). Ein Standard-Kontingent wird angelegt, das du danach ändern kannst.")).then(function(ok){ if(!ok) return; return api("/admin/user",{uid:u,admin:!me.admin}).then(fin).then(load).then(function(){ if(!me.admin) openQuota(u); }); }); }
  else if(n=="uQuota"){ openQuota(u); }
  else if(n=="qDel"){ readQuota(); QU.rows.splice(+b.getAttribute("data-i"),1); drawQuota(); }
  else if(n=="sReply"){ dlg("Antworten","Antwort an den Nutzer (er sieht sie in der App):","",true).then(function(v){ if(!v) return; return api("/admin/support-reply",{id:id,reply:v}).then(fin).then(loadSupport).then(load); }); }
  else if(n=="sDone"){ api("/admin/support-done",{id:id,done:b.getAttribute("data-d")=="1"}).then(loadSupport).then(load); }
  else if(n=="sDel"){ dlg("Löschen","Nachricht löschen?").then(function(ok){ if(ok) return api("/admin/support-delete",{id:id}).then(loadSupport).then(load); }); }
  else if(n=="unauthClear"){ dlg("Liste leeren","Alle Meldungen löschen?").then(function(ok){ if(ok) return api("/admin/unauth-clear",{}).then(loadUnauth).then(load); }); }
  else if(n=="unBlock"){ var t=b.getAttribute("data-t"); dlg("Sperren","Grund (wird dem Handy angezeigt):","",true).then(function(v){ if(v===null) return; return api("/admin/block",{type:t,value:id,reason:v}).then(fin).then(loadUnauth); }); }
  else if(n=="unblock"){ api("/admin/unblock",{type:b.getAttribute("data-t"),value:id}).then(loadBlocks).then(load); }
  else if(n=="blockIp"){ var ip=($("blIp").value||"").trim(); if(!ip) return; api("/admin/block",{type:"ip",value:ip,reason:$("blWhy").value||""}).then(fin).then(function(){ $("blIp").value=""; loadBlocks(); }); }
});

var PRESETS=[["30 Sek.",30],["1 Min.",60],["5 Min.",300],["1 Std.",3600],["1 Tag",86400],["7 Tage",604800],["30 Tage",2592000],["90 Tage",7776000],["180 Tage",15552000],["1 Jahr",31536000]];
$("presets").innerHTML=PRESETS.map(function(p){ return '<button class="sec" data-s="'+p[1]+'">'+p[0]+'</button>'; }).join("");
$("presets").onclick=function(e){ var b=e.target.closest("button"); if(!b) return; var s=+b.getAttribute("data-s");
  var u=s%86400==0?86400:s%3600==0?3600:s%60==0?60:1; $("unit").value=u; $("dur").value=s/u; durText(); };
function seconds(){ return Math.round(parseFloat(($("dur").value||"0").replace(",","."))*(+$("unit").value)); }
function durText(){ var s=seconds(); $("durText").textContent=s>0?"= "+fmtDur(s)+" ab dem Einlösen":""; }
$("dur").oninput=durText; $("unit").onchange=durText; durText();
$("createBtn").onclick=function(){
  api("/admin/create",{seconds:seconds(),count:+$("count").value,note:$("note").value}).then(function(r){
    $("out").textContent=r.ok?("Neue Keys ("+fmtDur(r.seconds)+"):\\n"+r.keys.join("\\n")):"Fehler: "+(r.message||r.error); load(); });
};
$("copyBtn").onclick=function(){ var t=$("out").textContent.split("\\n").filter(function(l){return l.indexOf("AG-")==0;}).join("\\n"); if(t) navigator.clipboard.writeText(t); };
</script></body></html>
`;

export default {
  async fetch(req, env) {
    const url = new URL(req.url);
    if (req.method === "OPTIONS") return new Response(null, { headers: { "access-control-allow-origin": "*", "access-control-allow-headers": "authorization, content-type" } });
    if (!env.KEYS) return json({ ok: false, error: "server", message: "KV-Speicher KEYS fehlt (siehe Anleitung)." }, 500);
    try {
      if (url.pathname === "/activate" && req.method === "POST") return await activate(req, env, false);
      if (url.pathname === "/share" && req.method === "POST") return await share(req, env);
      if (url.pathname === "/support" && req.method === "POST") return await support(req, env);
      if (url.pathname === "/sub" && req.method === "POST") return await sub(req, env);
      if (url.pathname === "/restore" && req.method === "POST") return await restore(req, env);
      if (url.pathname === "/check" && req.method === "POST") return await activate(req, env, true);
      if (url.pathname === "/admin" || url.pathname === "/admin/") return new Response(ADMIN_PAGE, { headers: { "content-type": "text/html; charset=utf-8", "cache-control": "no-store" } });
      if (url.pathname.startsWith("/admin/")) {
        if (!env.ADMIN_SECRET) return json({ ok: false, error: "secret", message: "ADMIN_SECRET ist nicht gesetzt." }, 500);
        if (!(await isAdmin(req, env))) return json({ ok: false, error: "auth" }, 401);
        const action = url.pathname.slice(7);
        if (action === "create" && req.method === "POST") return await adminCreate(req, env);
        if (action === "list") return await adminList(env);
        if (["revoke", "unrevoke", "delete", "reset", "extend", "rename"].includes(action) && req.method === "POST") return await adminAction(req, env, action);
        if (action === "user" && req.method === "POST") return await adminUser(req, env);
        if (["blocks", "block", "unblock"].includes(action)) return await adminBlocks(req, env, action);
        if (["unauth", "unauth-clear"].includes(action)) return await adminUnauth(req, env, action);
        if (["support", "support-reply", "support-done", "support-delete"].includes(action)) return await adminSupport(req, env, action);
      }
      if (url.pathname === "/") return json({ ok: true, service: "Aero Guard Keys" });
      return json({ ok: false, error: "not_found" }, 404);
    } catch (e) {
      return json({ ok: false, error: "server", message: String(e) }, 500);
    }
  },
};
