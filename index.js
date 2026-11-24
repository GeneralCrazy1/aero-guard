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
  await env.KEYS.put(k, String(n + 1), { expirationTtl: 600 });
  return false;
}

// Alte Keys (nur "days") weiter verstehen.
function secondsOf(rec) {
  return rec.seconds != null ? rec.seconds : (rec.days || 0) * 86400;
}

function nameOf(rec) { return rec.name != null ? rec.name : (rec.note || ""); }

// Meldungen der App (Modell, Version, Zähler) übernehmen. Gibt true zurück, wenn sich etwas geändert hat.
function telemetry(rec, body, now) {
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
  if (!rec.lastSeen || now - rec.lastSeen > 10 * 60000) { rec.lastSeen = now; changed = true; }
  return changed;
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
    rec.expiresAt = now + secondsOf(rec) * 1000;
    telemetry(rec, body, now);
    await env.KEYS.put("key:" + key, JSON.stringify(rec));
  }
  const seconds = secondsOf(rec);
  if (now >= rec.expiresAt) return json({ ok: false, error: "expired", expiresAt: rec.expiresAt }, 403);
  if (telemetry(rec, body, now)) await env.KEYS.put("key:" + key, JSON.stringify(rec));
  return json({ ok: true, expiresAt: rec.expiresAt, seconds, days: Math.round(seconds / 86400), name: nameOf(rec) });
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
    const rec = { seconds, note: "", name: String(body.note || body.name || "").slice(0, 100), created: Date.now(), device: null, activatedAt: null, expiresAt: null, revoked: false };
    await env.KEYS.put("key:" + key, JSON.stringify(rec));
    keys.push(key);
  }
  return json({ ok: true, seconds, keys });
}

async function adminList(env) {
  const out = [];
  let cursor;
  do {
    const page = await env.KEYS.list({ prefix: "key:", cursor });
    for (const k of page.keys) {
      const rec = JSON.parse((await env.KEYS.get(k.name)) || "{}");
      out.push({ key: k.name.slice(4), ...rec, name: nameOf(rec), seconds: secondsOf(rec), device: rec.device ? rec.device.slice(0, 6) + "…" : null });
    }
    cursor = page.list_complete ? null : page.cursor;
  } while (cursor);
  out.sort((a, b) => (b.created || 0) - (a.created || 0));
  return json({ ok: true, now: Date.now(), keys: out });
}

async function adminAction(req, env, action) {
  const body = await req.json().catch(() => ({}));
  const key = normalize(body.key);
  const raw = key && (await env.KEYS.get("key:" + key));
  if (!raw) return json({ ok: false, error: "unknown" }, 404);
  const rec = JSON.parse(raw);
  if (action === "delete") { await env.KEYS.delete("key:" + key); return json({ ok: true }); }
  if (action === "rename") rec.name = String(body.name || "").slice(0, 100);
  if (action === "revoke") rec.revoked = true;
  if (action === "unrevoke") rec.revoked = false;
  if (action === "reset") { rec.device = null; rec.activatedAt = null; rec.expiresAt = null; } // frei für ein anderes Handy, Laufzeit startet neu
  if (action === "extend") {
    const add = Math.round(Number(body.seconds));
    if (!Number.isFinite(add) || add < 1) return json({ ok: false, error: "seconds" }, 400);
    if (rec.expiresAt) rec.expiresAt = Math.max(rec.expiresAt, Date.now()) + add * 1000;
    else rec.seconds = secondsOf(rec) + add;
  }
  await env.KEYS.put("key:" + key, JSON.stringify(rec));
  return json({ ok: true });
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
  if (changed) await env.KEYS.put("af:state", JSON.stringify({ parked, ranges }));

  const out = {};
  for (const f of Object.keys(parked)) out[f] = Object.keys(parked[f]).map((h) => ({ hex: h, since: parked[f][h].s, label: parked[f][h].l }));
  return json({ ok: true, now, parked: out, ranges });
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
#modal{display:none;position:fixed;inset:0;background:rgba(0,0,0,.55);z-index:99;align-items:center;justify-content:center}#modal.on{display:flex}#modal .box{background:#1c2430;color:#fff;border-radius:10px;padding:20px;max-width:440px;width:90%}#modal h3{margin:0 0 8px}#modal p{margin:0 0 12px;line-height:1.4}#modal input{width:100%;box-sizing:border-box;margin-bottom:12px}#modal .row{display:flex;gap:8px;justify-content:flex-end}
</style></head><body>
<div id="modal"><div class="box"><h3 id="mT"></h3><p id="mM"></p><input id="mI"><div class="row"><button class="sec" id="mC">Abbrechen</button><button id="mO">OK</button></div></div></div>
<div id="login"><div class="card"><h2>Aero Guard Admin</h2><label>Admin-Passwort</label>
<input id="pw" type="password" style="width:100%" autofocus><p><button id="loginBtn" style="width:100%">Anmelden</button></p><div id="loginMsg" class="small"></div></div></div>

<nav id="side"><h1>✈ Aero Guard</h1>
<a data-p="home" class="on">📊 Übersicht</a>
<a data-p="create">➕ Key erzeugen</a>
<a data-p="devices">📱 Geräte</a>
<a data-p="keys">🔑 Alle Keys</a>
<a data-p="help">ℹ️ Hilfe</a>
<div class="sp"></div><a id="logout">⎋ Abmelden</a></nav>

<div id="main">
<section id="p-home"><h2>Übersicht</h2><div class="stats" id="stats"></div>
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
<div style="overflow:auto"><table id="devs"></table></div></div></section>

<section id="p-keys" class="hide"><h2>Alle Keys</h2><div class="card">
<div class="row"><div><label>Suche</label><input id="q" placeholder="Key oder Name"></div>
<div><label>Status</label><select id="flt"><option value="">alle</option><option value="free">frei</option><option value="active">aktiv</option><option value="expired">abgelaufen</option><option value="revoked">gesperrt</option></select></div>
<div><button class="sec" id="reload">↻ Neu laden</button> <button class="sec" id="expandAll">Alle auf</button> <button class="sec" id="collapseAll">Alle zu</button></div></div>
<div style="overflow:auto;margin-top:10px"><div id="keys"></div></div></div></section>

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
  ["home","create","devices","keys","help"].forEach(function(x){ $("p-"+x).classList.toggle("hide",x!=p); });
  document.querySelectorAll("#side a[data-p]").forEach(function(a){ a.classList.toggle("on",a.getAttribute("data-p")==p); });
  if(p=="home"||p=="keys"||p=="devices") load();
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

function load(){ api("/admin/list").then(function(r){ if(r.ok) apply(r); else location.reload(); }); }
function apply(r){ DATA=r.keys; NOW=r.now; renderHome(); renderKeys(); renderDevs(); }

function renderHome(){
  var c={free:0,active:0,expired:0,revoked:0}; DATA.forEach(function(k){ c[status(k)]++; });
  $("stats").innerHTML=[["Keys gesamt",DATA.length],["Frei",c.free],["Aktiv",c.active],["Abgelaufen",c.expired],["Gesperrt",c.revoked]]
    .map(function(x){ return '<div class="stat"><b>'+x[1]+'</b><span>'+x[0]+'</span></div>'; }).join("");
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
      return "<tr><td class=mono>"+k.key+"</td><td>"+esc(k.name)+"</td><td class=mono>"+(k.device||"–")+"</td><td>"+fmtDate(k.activatedAt)+"</td><td>"+fmtDate(k.expiresAt)+"</td>"+
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
  var list=DATA.filter(function(k){return k.device;}).sort(function(a,b){return (b.lastSeen||0)-(a.lastSeen||0);});
  $("devs").innerHTML="<tr><th>Name</th><th>Handy</th><th>Key</th><th>Lizenz</th><th>Zuletzt online</th><th>App geöffnet</th><th>Radar gestartet</th><th>Warnungen</th><th></th></tr>"+
  (list.length?list.map(function(k){ var s=status(k), st=k.stats||{opens:0,starts:0,warnings:0}, on=k.lastSeen&&(NOW-k.lastSeen)<2*3600*1000;
    return "<tr><td><b>"+(esc(k.name)||"<i class=small>ohne Namen</i>")+"</b></td><td>"+esc(k.model||"?")+"<div class=small>App "+esc(k.version||"?")+"</div></td><td class=mono>"+k.key+"</td>"+
    "<td><span class='tag "+s+"'>"+NAMES[s]+"</span><div class=small>"+(s=="active"?"noch "+fmtDur(Math.round((k.expiresAt-NOW)/1000))+" · bis "+fmtDate(k.expiresAt):(s=="expired"?"seit "+fmtDate(k.expiresAt):""))+"</div></td>"+
    "<td>"+(on?"🟢 ":"⚪ ")+ago(k.lastSeen)+"</td><td>"+st.opens+"</td><td>"+st.starts+"</td><td>"+st.warnings+"</td><td class=acts>"+
    "<button class=sec data-a=rename data-k="+k.key+">Name ändern</button>"+
    (s!="expired"&&!k.revoked?"<button class=sec data-a=extend data-k="+k.key+">Verlängern</button>":"")+
    (k.revoked?"<button data-a=unrevoke data-k="+k.key+">Lizenz wieder erlauben</button>":"<button class=red data-a=revoke data-k="+k.key+">Lizenz entziehen</button>")+
    "<button class=sec data-a=reset data-k="+k.key+">Handy lösen</button></td></tr>"; }).join(""):"<tr><td colspan=9 class=small>Noch kein Handy freigeschaltet.</td></tr>");
}
$("devs").onclick=function(e){ $("keys").onclick(e); };
$("q").oninput=renderKeys; $("flt").onchange=renderKeys; $("reload").onclick=load;
function dlg(title,msg,defVal,withInput,noCancel){ return new Promise(function(res){
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
  else if(a=="revoke") ask=dlg("Lizenz entziehen","Lizenz von Key "+k+" entziehen? Die App sperrt sich, sobald das Handy Internet hat (spätestens nach rund einer Stunde).");
  else if(a=="reset") ask=dlg("Handy lösen","Key "+k+" vom Handy lösen? Die Laufzeit startet beim nächsten Einlösen neu.");
  else if(a=="extend") ask=dlg("Verlängern","Wie viele Tage verlängern? (Kommazahl erlaubt, z. B. 0.5 = 12 Std.)","30",true).then(function(v){ if(!v) return false; var n=parseFloat(v.replace(",",".")); if(!(n>0)) return false; body.seconds=Math.round(n*86400); return true; });
  ask.then(function(ok){ if(!ok) return; return api("/admin/"+a,body).then(function(r){ if(!r.ok) return dlg("Fehler",String(r.error||"?"),"",false,true); }).then(load); });
};

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
      if (url.pathname === "/check" && req.method === "POST") return await activate(req, env, true);
      if (url.pathname === "/admin" || url.pathname === "/admin/") return new Response(ADMIN_PAGE, { headers: { "content-type": "text/html; charset=utf-8", "cache-control": "no-store" } });
      if (url.pathname.startsWith("/admin/")) {
        if (!env.ADMIN_SECRET) return json({ ok: false, error: "secret", message: "ADMIN_SECRET ist nicht gesetzt." }, 500);
        if (!(await isAdmin(req, env))) return json({ ok: false, error: "auth" }, 401);
        const action = url.pathname.slice(7);
        if (action === "create" && req.method === "POST") return await adminCreate(req, env);
        if (action === "list") return await adminList(env);
        if (["revoke", "unrevoke", "delete", "reset", "extend", "rename"].includes(action) && req.method === "POST") return await adminAction(req, env, action);
      }
      if (url.pathname === "/") return json({ ok: true, service: "Aero Guard Keys" });
      return json({ ok: false, error: "not_found" }, 404);
    } catch (e) {
      return json({ ok: false, error: "server", message: String(e) }, 500);
    }
  },
};
