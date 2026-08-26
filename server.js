"use strict";

const http = require("http");
const { Readable } = require("stream");
const crypto = require("crypto");

const PORT = Number(process.env.PORT || 10000);
const UPSTREAM_BASE = String(process.env.UPSTREAM_BASE || "").replace(/\/+$/g, "");
const TOKEN_SECRET = String(process.env.TOKEN_SECRET || "");
const ALLOWED_ORIGIN = String(process.env.ALLOWED_ORIGIN || "*");

function corsHeaders(extra = {}) {
  return {
    "Access-Control-Allow-Origin": ALLOWED_ORIGIN,
    "Access-Control-Allow-Headers": "Content-Type, Authorization, Range",
    "Access-Control-Allow-Methods": "GET,POST,OPTIONS",
    "Access-Control-Expose-Headers":
      "Content-Length, Content-Range, Accept-Ranges, Content-Type, X-Pixel-Stream-Mode, X-Pixel-Upstream-Status",
    ...extra
  };
}

function sendJson(res, data, status = 200, headers = {}) {
  const body = Buffer.from(JSON.stringify(data));
  res.writeHead(status, corsHeaders({
    "Content-Type": "application/json; charset=utf-8",
    "Content-Length": body.length,
    ...headers
  }));
  res.end(body);
}

function sendText(res, text, status = 200, headers = {}) {
  const body = Buffer.from(String(text));
  res.writeHead(status, corsHeaders({
    "Content-Type": "text/plain; charset=utf-8",
    "Content-Length": body.length,
    ...headers
  }));
  res.end(body);
}

function requireConfig() {
  if (!/^https?:\/\//i.test(UPSTREAM_BASE)) throw new Error("UPSTREAM_BASE no configurado");
  if (TOKEN_SECRET.length < 32) throw new Error("TOKEN_SECRET debe tener al menos 32 caracteres");
}

function b64url(buf) {
  return Buffer.from(buf).toString("base64")
    .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}
function fromB64url(s) {
  let x = String(s || "").replace(/-/g, "+").replace(/_/g, "/");
  while (x.length % 4) x += "=";
  return Buffer.from(x, "base64");
}
function keyBytes() {
  return crypto.createHash("sha256").update(TOKEN_SECRET).digest();
}
function seal(obj) {
  requireConfig();
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", keyBytes(), iv);
  const plain = Buffer.from(JSON.stringify(obj), "utf8");
  const ct = Buffer.concat([cipher.update(plain), cipher.final()]);
  const tag = cipher.getAuthTag();
  return b64url(Buffer.concat([iv, ct, tag]));
}
function unseal(token) {
  requireConfig();
  const all = fromB64url(token);
  if (all.length < 12 + 16 + 1) throw new Error("Sesión inválida");
  const iv = all.subarray(0, 12);
  const tag = all.subarray(all.length - 16);
  const ct = all.subarray(12, all.length - 16);
  const decipher = crypto.createDecipheriv("aes-256-gcm", keyBytes(), iv);
  decipher.setAuthTag(tag);
  const plain = Buffer.concat([decipher.update(ct), decipher.final()]);
  const obj = JSON.parse(plain.toString("utf8"));
  if (!obj.exp || Date.now() > obj.exp) throw new Error("Sesión vencida");
  return obj;
}

async function readJsonBody(req) {
  const chunks = [];
  let total = 0;
  for await (const chunk of req) {
    total += chunk.length;
    if (total > 1024 * 1024) throw new Error("Solicitud demasiado grande");
    chunks.push(chunk);
  }
  if (!chunks.length) return {};
  try {
    return JSON.parse(Buffer.concat(chunks).toString("utf8"));
  } catch {
    return {};
  }
}

function playerUrl(user, pass, action, extra = {}) {
  const u = new URL(UPSTREAM_BASE + "/player_api.php");
  u.searchParams.set("username", user);
  u.searchParams.set("password", pass);
  if (action) u.searchParams.set("action", action);
  for (const [k, v] of Object.entries(extra)) {
    if (v !== undefined && v !== null && v !== "") u.searchParams.set(k, String(v));
  }
  return u.toString();
}

async function fetchJson(url) {
  const r = await fetch(url, {
    redirect: "follow",
    headers: {
      "Accept": "application/json,text/plain,*/*",
      "User-Agent": "Mozilla/5.0"
    }
  });
  const text = await r.text();
  let data;
  try { data = JSON.parse(text); }
  catch { throw new Error(`Respuesta inválida del servidor IPTV (${r.status})`); }
  if (!r.ok) throw new Error(`Servidor IPTV respondió ${r.status}`);
  return data;
}

function sanitizeUser(data, user) {
  const ui = data?.user_info || {};
  return {
    username: user,
    auth: Number(ui.auth || 0),
    status: ui.status || "",
    exp_date: ui.exp_date || "",
    max_connections: ui.max_connections || "",
    active_cons: ui.active_cons || "",
    created_at: ui.created_at || "",
    allowed_output_formats: Array.isArray(ui.allowed_output_formats) ? ui.allowed_output_formats : []
  };
}

function authTokenFromReq(req, url) {
  const auth = String(req.headers.authorization || "");
  if (auth.startsWith("Bearer ")) return auth.slice(7);
  return url.searchParams.get("token") || "";
}
function sessionFromReq(req, url) {
  return unseal(authTokenFromReq(req, url));
}

function allowedAction(action) {
  return new Set([
    "get_live_categories", "get_live_streams",
    "get_vod_categories", "get_vod_streams",
    "get_series_categories", "get_series",
    "get_vod_info", "get_series_info", "get_short_epg"
  ]).has(action);
}

function safeExt(v, fallback = "mp4") {
  const x = String(v || fallback).replace(/[^a-zA-Z0-9]/g, "").toLowerCase();
  return x || fallback;
}

function streamCandidates(session, kind, id, ext, mode) {
  const u = encodeURIComponent(session.u);
  const p = encodeURIComponent(session.p);
  const sid = encodeURIComponent(id);

  if (kind === "live") {
    if (mode === "hls") {
      return [
        `${UPSTREAM_BASE}/live/${u}/${p}/${sid}.m3u8`,
        `${UPSTREAM_BASE}/${u}/${p}/${sid}.m3u8`
      ];
    }
    return [
      `${UPSTREAM_BASE}/live/${u}/${p}/${sid}.ts`,
      `${UPSTREAM_BASE}/${u}/${p}/${sid}.ts`,
      `${UPSTREAM_BASE}/${u}/${p}/${sid}`
    ];
  }

  return [`${UPSTREAM_BASE}/${kind}/${u}/${p}/${sid}.${safeExt(ext, "mp4")}`];
}

function looksLikeManifest(ct, url) {
  const x = String(ct || "").toLowerCase();
  return x.includes("mpegurl") || x.includes("m3u8") || /\.m3u8(?:$|\?)/i.test(url);
}

function upstreamHeaders(req, options = {}) {
  const h = new Headers();
  h.set("Accept", req.headers.accept || "*/*");
  h.set("User-Agent", options.userAgent || "VLC/3.0.21 LibVLC/3.0.21");
  const range = req.headers.range;
  if (range && options.allowRange !== false) h.set("Range", range);
  return h;
}

async function proxyFetch(target, req, options = {}) {
  return fetch(target, {
    method: "GET",
    headers: upstreamHeaders(req, options),
    redirect: "follow"
  });
}

function copyUpstreamHeaders(r, extra = {}) {
  const h = corsHeaders();
  for (const k of [
    "content-type", "content-length", "content-range",
    "accept-ranges", "cache-control", "etag",
    "last-modified", "content-disposition"
  ]) {
    const v = r.headers.get(k);
    if (v) h[k] = v;
  }
  return { ...h, ...extra };
}

function pipeWebBody(r, res, extraHeaders = {}) {
  res.writeHead(r.status, copyUpstreamHeaders(r, extraHeaders));
  if (!r.body) return res.end();
  Readable.fromWeb(r.body).pipe(res);
}

function proxyToken(targetUrl, session) {
  return seal({
    url: targetUrl,
    u: session.u,
    p: session.p,
    exp: Date.now() + 2 * 60 * 60 * 1000
  });
}

function publicBase(req) {
  const proto = String(req.headers["x-forwarded-proto"] || "https").split(",")[0].trim();
  const host = req.headers.host;
  return `${proto}://${host}`;
}

function rewriteManifest(text, manifestUrl, req, session) {
  const base = publicBase(req);
  const out = [];

  for (let line of String(text || "").split(/\r?\n/)) {
    if (line.startsWith("#")) {
      const matches = [...line.matchAll(/URI="([^"]+)"/g)];
      for (const m of matches) {
        const original = m[1];
        const abs = new URL(original, manifestUrl).toString();
        const proxied = `${base}/segment?s=${encodeURIComponent(proxyToken(abs, session))}`;
        line = line.replace(`URI="${original}"`, `URI="${proxied}"`);
      }
      out.push(line);
      continue;
    }

    if (!line.trim()) {
      out.push(line);
      continue;
    }

    const abs = new URL(line.trim(), manifestUrl).toString();
    out.push(`${base}/segment?s=${encodeURIComponent(proxyToken(abs, session))}`);
  }
  return out.join("\n");
}

function isPrivateHost(host) {
  const h = String(host || "").toLowerCase();
  if (!h || h === "localhost" || h.endsWith(".local")) return true;
  if (/^(127\.|10\.|0\.|169\.254\.)/.test(h)) return true;
  const m172 = h.match(/^172\.(\d+)\./);
  if (m172 && Number(m172[1]) >= 16 && Number(m172[1]) <= 31) return true;
  if (/^192\.168\./.test(h)) return true;
  if (h === "::1") return true;
  return false;
}

async function handleLogin(req, res) {
  const { username, password } = await readJsonBody(req);
  if (!username || !password) return sendJson(res, { error: "Escribe usuario y contraseña" }, 400);

  const data = await fetchJson(playerUrl(username, password));
  const ui = data?.user_info;
  if (!ui || Number(ui.auth) !== 1) return sendJson(res, { error: "Usuario o contraseña incorrectos" }, 401);
  if (ui.status && String(ui.status).toLowerCase() !== "active") {
    return sendJson(res, { error: `Cuenta ${ui.status}` }, 403);
  }

  const exp = Date.now() + 8 * 60 * 60 * 1000;
  const token = seal({ u: username, p: password, exp });
  return sendJson(res, {
    token,
    user: sanitizeUser(data, username),
    session_expires: exp
  });
}

async function handleData(req, res, url) {
  const s = sessionFromReq(req, url);
  const body = await readJsonBody(req);
  const action = String(body.action || "");

  if (!allowedAction(action)) return sendJson(res, { error: "Acción no permitida" }, 400);

  const extra = {};
  if (action === "get_vod_info") extra.vod_id = body.vod_id;
  if (action === "get_series_info") extra.series_id = body.series_id;
  if (action === "get_short_epg") {
    extra.stream_id = body.stream_id;
    extra.limit = body.limit || 5;
  }

  const data = await fetchJson(playerUrl(s.u, s.p, action, extra));
  return sendJson(res, data);
}

async function handleStream(req, res, url, kind, id) {
  const s = sessionFromReq(req, url);
  let ext = url.searchParams.get("ext") || "mp4";
  let mode = url.searchParams.get("mode") || "";
  if (kind === "live") mode = mode === "ts" ? "ts" : "hls";

  const candidates = streamCandidates(s, kind, id, ext, mode);
  let lastStatus = 502;

  for (let i = 0; i < candidates.length; i++) {
    const target = candidates[i];
    let r;
    try {
      r = await proxyFetch(target, req);
    } catch {
      continue;
    }

    lastStatus = r.status || lastStatus;

    if (!r.ok) {
      try { await r.body?.cancel(); } catch {}
      if ([401, 403, 429].includes(r.status)) {
        return sendText(res, `No se pudo abrir el stream (${r.status})`, r.status, {
          "X-Pixel-Stream-Mode": kind === "live" ? mode : safeExt(ext),
          "X-Pixel-Upstream-Status": String(r.status)
        });
      }
      if (![404, 405].includes(r.status) || i === candidates.length - 1) {
        return sendText(res, `No se pudo abrir el stream (${r.status})`, r.status, {
          "X-Pixel-Stream-Mode": kind === "live" ? mode : safeExt(ext),
          "X-Pixel-Upstream-Status": String(r.status)
        });
      }
      continue;
    }

    const finalUrl = r.url || target;
    const ct = r.headers.get("content-type") || "";

    if (looksLikeManifest(ct, finalUrl)) {
      const manifest = await r.text();
      if (!manifest.trim().startsWith("#EXTM3U")) {
        return sendText(res, "El proveedor no devolvió una lista HLS válida", 415);
      }
      const rewritten = rewriteManifest(manifest, finalUrl, req, s);
      return sendText(res, rewritten, 200, {
        "Content-Type": "application/vnd.apple.mpegurl; charset=utf-8",
        "Cache-Control": "no-store",
        "X-Pixel-Stream-Mode": "hls"
      });
    }

    return pipeWebBody(r, res, {
      "X-Pixel-Stream-Mode": kind === "live" ? "ts" : safeExt(ext),
      ...(kind === "live" && !ct ? { "Content-Type": "video/mp2t" } : {})
    });
  }

  return sendText(res, `No se pudo abrir el stream (${lastStatus})`, lastStatus, {
    "X-Pixel-Stream-Mode": kind === "live" ? mode : safeExt(ext)
  });
}

async function handleSegment(req, res, url) {
  const payload = unseal(url.searchParams.get("s") || "");
  const target = new URL(payload.url);

  if (!/^https?:$/.test(target.protocol)) return sendText(res, "Origen no permitido", 403);

  const r = await proxyFetch(target.toString(), req);
  if (!r.ok) return sendText(res, `Segmento no disponible (${r.status})`, r.status);

  const finalUrl = r.url || target.toString();
  const ct = r.headers.get("content-type") || "";

  if (looksLikeManifest(ct, finalUrl)) {
    const manifest = await r.text();
    if (manifest.trim().startsWith("#EXTM3U")) {
      const rewritten = rewriteManifest(manifest, finalUrl, req, payload);
      return sendText(res, rewritten, 200, {
        "Content-Type": "application/vnd.apple.mpegurl; charset=utf-8",
        "Cache-Control": "no-store"
      });
    }
  }

  return pipeWebBody(r, res);
}

async function handleImage(req, res, url) {
  sessionFromReq(req, url);

  const encoded = url.searchParams.get("u") || "";
  let raw = "";
  try {
    let x = encoded.replace(/-/g, "+").replace(/_/g, "/");
    while (x.length % 4) x += "=";
    raw = Buffer.from(x, "base64").toString("utf8");
  } catch {}

  if (!raw) return sendText(res, "Imagen inválida", 400);

  let target;
  try { target = new URL(raw); }
  catch { return sendText(res, "Imagen inválida", 400); }

  if (!/^https?:$/.test(target.protocol) || isPrivateHost(target.hostname)) {
    return sendText(res, "Origen de imagen no permitido", 403);
  }

  const r = await fetch(target.toString(), {
    redirect: "follow",
    headers: { "User-Agent": "Mozilla/5.0" }
  });

  if (!r.ok) return sendText(res, "Imagen no disponible", r.status);

  return pipeWebBody(r, res, { "Cache-Control": "public, max-age=86400" });
}

async function route(req, res) {
  if (req.method === "OPTIONS") {
    res.writeHead(204, corsHeaders());
    return res.end();
  }

  try {
    const url = new URL(req.url, `http://${req.headers.host || "localhost"}`);
    const path = url.pathname;

    if (path === "/health" && req.method === "GET") {
      return sendJson(res, {
        ok: true,
        service: "Pixel IPTV Render Proxy",
        version: "V001",
        upstreamConfigured: /^https?:\/\//i.test(UPSTREAM_BASE)
      });
    }

    requireConfig();

    if (path === "/api/login" && req.method === "POST") return await handleLogin(req, res);
    if (path === "/api/data" && req.method === "POST") return await handleData(req, res, url);
    if (path === "/image" && req.method === "GET") return await handleImage(req, res, url);
    if (path === "/segment" && req.method === "GET") return await handleSegment(req, res, url);

    const m = path.match(/^\/stream\/(live|movie|series)\/([^/]+)$/);
    if (m && req.method === "GET") {
      return await handleStream(req, res, url, m[1], decodeURIComponent(m[2]));
    }

    return sendJson(res, { error: "Ruta no encontrada" }, 404);
  } catch (e) {
    console.error(e);
    return sendJson(res, { error: e?.message || "Error interno" }, 500);
  }
}

const server = http.createServer((req, res) => {
  route(req, res).catch(err => {
    console.error(err);
    if (!res.headersSent) sendJson(res, { error: "Error interno" }, 500);
    else res.destroy();
  });
});

server.keepAliveTimeout = 70_000;
server.headersTimeout = 75_000;

server.listen(PORT, "0.0.0.0", () => {
  console.log(`Pixel IPTV Render Proxy V001 escuchando en 0.0.0.0:${PORT}`);
});
