"use strict";

const http = require("http");
const { Readable } = require("stream");
const crypto = require("crypto");
const dns = require("dns").promises;
const net = require("net");

const PORT = Number(process.env.PORT || 10000);
const UPSTREAM_BASE = String(process.env.UPSTREAM_BASE || "").replace(/\/+$/g, "");
const UPSTREAM_HOST = (() => { try { return new URL(UPSTREAM_BASE).hostname.toLowerCase(); } catch { return ""; } })();
const TOKEN_SECRET = String(process.env.TOKEN_SECRET || "");
const ALLOWED_ORIGIN = String(process.env.ALLOWED_ORIGIN || "https://iptv.pixelservicecr.com").replace(/\/+$/g, "");
const PLAYER_REFERER = String(process.env.PLAYER_REFERER || "https://nubweb.nubservices.com/");
const PLAYER_ORIGIN = String(process.env.PLAYER_ORIGIN || "https://nubweb.nubservices.com");
const SESSION_MS = 8 * 60 * 60 * 1000;
const STREAM_TICKET_MS = 10 * 60 * 1000;
const UPSTREAM_JSON_TIMEOUT_MS = 15_000;
const UPSTREAM_STREAM_TIMEOUT_MS = 18_000;
const IMAGE_TIMEOUT_MS = 12_000;
const MAX_JSON_BODY = 256 * 1024;

const loginBuckets = new Map();
const liveGroupCache = new Map();
const liveCatalogCache = new Map();
const LIVE_GROUP_CACHE_MS = 10 * 60 * 1000;
const LIVE_GROUP_TIMEOUT_MS = 25_000;
const LIVE_CATALOG_CACHE_MS = 10 * 60 * 1000;
const LIVE_CATALOG_TIMEOUT_MS = 45_000;

class HttpError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

function corsHeaders(extra = {}) {
  const h = {
    "Access-Control-Allow-Origin": ALLOWED_ORIGIN,
    "Access-Control-Allow-Headers": "Content-Type, Authorization, Range",
    "Access-Control-Allow-Methods": "GET,POST,OPTIONS",
    "Access-Control-Expose-Headers": [
      "Content-Length", "Content-Range", "Accept-Ranges", "Content-Type",
      "X-Pixel-Stream-Mode", "X-Pixel-Upstream-Status", "X-Pixel-Header-Profile",
      "X-Pixel-Attempts"
    ].join(", "),
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "X-Permitted-Cross-Domain-Policies": "none",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=(), usb=()",
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    ...extra
  };
  if (ALLOWED_ORIGIN !== "*") h.Vary = "Origin";
  return h;
}

function sendJson(res, data, status = 200, headers = {}) {
  if (res.destroyed || res.writableEnded) return;
  const body = Buffer.from(JSON.stringify(data));
  res.writeHead(status, corsHeaders({
    "Content-Type": "application/json; charset=utf-8",
    "Content-Length": body.length,
    "Cache-Control": "no-store",
    ...headers
  }));
  res.end(body);
}

function sendText(res, text, status = 200, headers = {}) {
  if (res.destroyed || res.writableEnded) return;
  const body = Buffer.from(String(text));
  res.writeHead(status, corsHeaders({
    "Content-Type": "text/plain; charset=utf-8",
    "Content-Length": body.length,
    ...headers
  }));
  res.end(body);
}

function requireConfig() {
  if (!/^https?:\/\//i.test(UPSTREAM_BASE)) throw new HttpError(503, "UPSTREAM_BASE no configurado");
  if (TOKEN_SECRET.length < 32) throw new HttpError(503, "TOKEN_SECRET debe tener al menos 32 caracteres");
  if (!/^https:\/\//i.test(ALLOWED_ORIGIN) || ALLOWED_ORIGIN === "*") throw new HttpError(503, "ALLOWED_ORIGIN debe ser el dominio HTTPS exacto de Pixel IPTV");
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
function unseal(token, expectedScope = "") {
  requireConfig();
  try {
    const all = fromB64url(token);
    if (all.length < 29) throw new Error("token corto");
    const iv = all.subarray(0, 12);
    const tag = all.subarray(all.length - 16);
    const ct = all.subarray(12, all.length - 16);
    const decipher = crypto.createDecipheriv("aes-256-gcm", keyBytes(), iv);
    decipher.setAuthTag(tag);
    const plain = Buffer.concat([decipher.update(ct), decipher.final()]);
    const obj = JSON.parse(plain.toString("utf8"));
    if (!obj.exp || Date.now() > Number(obj.exp)) throw new HttpError(401, "Sesión vencida");
    if (expectedScope && obj.scope !== expectedScope) throw new HttpError(403, "Token no válido para esta acción");
    return obj;
  } catch (e) {
    if (e instanceof HttpError) throw e;
    throw new HttpError(401, "Sesión inválida");
  }
}

async function readJsonBody(req) {
  const chunks = [];
  let total = 0;
  for await (const chunk of req) {
    total += chunk.length;
    if (total > MAX_JSON_BODY) throw new HttpError(413, "Solicitud demasiado grande");
    chunks.push(chunk);
  }
  if (!chunks.length) return {};
  try {
    const parsed = JSON.parse(Buffer.concat(chunks).toString("utf8"));
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) throw new Error("objeto requerido");
    return parsed;
  } catch {
    throw new HttpError(400, "JSON inválido");
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

async function fetchWithTimeout(url, options = {}, timeoutMs = 15_000) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(new Error("timeout")), timeoutMs);
  if (typeof timer.unref === "function") timer.unref();
  try {
    return await fetch(url, { ...options, signal: controller.signal });
  } catch (e) {
    if (controller.signal.aborted) throw new HttpError(504, "El servidor IPTV tardó demasiado en responder");
    throw new HttpError(502, "No se pudo conectar con el servidor IPTV");
  } finally {
    clearTimeout(timer);
  }
}

async function fetchJson(url) {
  const r = await fetchWithTimeout(url, {
    redirect: "follow",
    headers: {
      "Accept": "application/json,text/plain,*/*",
      "User-Agent": "Mozilla/5.0"
    }
  }, UPSTREAM_JSON_TIMEOUT_MS);
  const text = await r.text();
  let data;
  try { data = JSON.parse(text); }
  catch { throw new HttpError(502, `Respuesta inválida del servidor IPTV (${r.status})`); }
  if (!r.ok) throw new HttpError(r.status >= 400 && r.status < 600 ? r.status : 502, `Servidor IPTV respondió ${r.status}`);
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
  return unseal(authTokenFromReq(req, url), "session");
}


function playlistUrl(user, pass) {
  const u = new URL(UPSTREAM_BASE + "/get.php");
  u.searchParams.set("username", user);
  u.searchParams.set("password", pass);
  u.searchParams.set("type", "m3u_plus");
  u.searchParams.set("output", "ts");
  return u.toString();
}

function liveGroupCacheKey(user, pass) {
  return crypto.createHash("sha256").update(`${user}\n${pass}`).digest("hex");
}

function cleanM3uAttr(value) {
  return String(value || "")
    .replace(/[\u0000-\u001F\u007F]/g, " ")
    .replace(/\s+/g, " ")
    .trim()
    .slice(0, 180);
}

function streamIdFromPlaylistUrl(rawUrl) {
  try {
    const u = new URL(String(rawUrl || "").trim());
    const parts = u.pathname.split("/").filter(Boolean);
    if (!parts.length) return "";
    let last = decodeURIComponent(parts[parts.length - 1] || "");
    last = last.replace(/\.(?:ts|m3u8|mp4|mkv|avi|mov|mpegts|m2ts)$/i, "");
    return /^[A-Za-z0-9._-]{1,128}$/.test(last) ? last : "";
  } catch {
    return "";
  }
}

function parseLiveGroupsM3u(text) {
  const lines = String(text || "").split(/\r?\n/);
  const entries = [];
  const categories = [];
  const seenCategories = new Set();
  let pendingGroup = "";

  for (const rawLine of lines) {
    const line = String(rawLine || "").trim();
    if (!line) continue;

    if (line.startsWith("#EXTINF")) {
      const m = line.match(/group-title\s*=\s*"([^"]*)"/i) || line.match(/group-title\s*=\s*'([^']*)'/i);
      pendingGroup = cleanM3uAttr(m ? m[1] : "");
      continue;
    }

    if (line.startsWith("#")) continue;
    if (!pendingGroup) continue;

    const streamId = streamIdFromPlaylistUrl(line);
    if (streamId) {
      entries.push([streamId, pendingGroup]);
      const key = pendingGroup.toLocaleLowerCase("es");
      if (!seenCategories.has(key)) {
        seenCategories.add(key);
        categories.push(pendingGroup);
      }
    }
    pendingGroup = "";
  }

  return { categories, entries };
}

async function fetchLiveGroups(user, pass) {
  const key = liveGroupCacheKey(user, pass);
  const cached = liveGroupCache.get(key);
  if (cached && Date.now() - cached.at < LIVE_GROUP_CACHE_MS) return cached.data;

  const r = await fetchWithTimeout(playlistUrl(user, pass), {
    redirect: "follow",
    headers: {
      "Accept": "audio/x-mpegurl,application/x-mpegURL,text/plain,*/*",
      "User-Agent": "Mozilla/5.0"
    }
  }, LIVE_GROUP_TIMEOUT_MS);

  const text = await r.text();
  if (!r.ok) throw new HttpError(r.status >= 400 && r.status < 600 ? r.status : 502, `Lista M3U respondió ${r.status}`);
  if (!/^\s*#EXTM3U/i.test(text)) throw new HttpError(502, "El servidor IPTV no devolvió una lista M3U válida");

  const data = parseLiveGroupsM3u(text);
  liveGroupCache.set(key, { at: Date.now(), data });
  if (liveGroupCache.size > 100) {
    const oldest = [...liveGroupCache.entries()].sort((a,b) => a[1].at - b[1].at).slice(0, liveGroupCache.size - 100);
    for (const [k] of oldest) liveGroupCache.delete(k);
  }
  return data;
}


function extinfDisplayName(line) {
  let quoted = false;
  let quote = "";
  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (ch === `"` || ch === `'`) {
      if (!quoted) { quoted = true; quote = ch; }
      else if (quote === ch) { quoted = false; quote = ""; }
      continue;
    }
    if (ch === "," && !quoted) return cleanM3uAttr(line.slice(i + 1));
  }
  return "";
}

function extinfAttrs(line) {
  const out = {};
  const re = /([A-Za-z0-9_-]+)\s*=\s*(?:"([^"]*)"|'([^']*)')/g;
  let m;
  while ((m = re.exec(String(line || "")))) {
    out[String(m[1] || "").toLowerCase()] = cleanM3uAttr(m[2] ?? m[3] ?? "");
  }
  return out;
}

function playlistEntryKind(rawUrl) {
  try {
    const u = new URL(String(rawUrl || "").trim());
    const path = u.pathname.toLowerCase();
    if (/(^|\/)movie(\/|$)/.test(path)) return "movie";
    if (/(^|\/)series(\/|$)/.test(path)) return "series";
    if (/(^|\/)live(\/|$)/.test(path)) return "live";
    if (/\.(?:ts|m3u8|mpegts|m2ts)$/i.test(path)) return "live";
    return "unknown";
  } catch {
    return "unknown";
  }
}

function parseLiveCatalogM3u(text) {
  const lines = String(text || "").split(/\r?\n/);
  const entries = [];
  let pending = null;

  for (const rawLine of lines) {
    const line = String(rawLine || "").trim();
    if (!line) continue;

    if (line.startsWith("#EXTINF")) {
      const attrs = extinfAttrs(line);
      pending = {
        group: cleanM3uAttr(attrs["group-title"] || ""),
        name: cleanM3uAttr(extinfDisplayName(line) || attrs["tvg-name"] || ""),
        logo: String(attrs["tvg-logo"] || "").trim().slice(0, 4096),
        epg_channel_id: cleanM3uAttr(attrs["tvg-id"] || "")
      };
      continue;
    }

    if (line.startsWith("#")) continue;
    if (!pending) continue;

    const streamId = streamIdFromPlaylistUrl(line);
    if (streamId) {
      entries.push({
        stream_id: streamId,
        name: pending.name,
        stream_icon: pending.logo,
        epg_channel_id: pending.epg_channel_id,
        group_title: pending.group,
        playlist_kind: playlistEntryKind(line)
      });
    }
    pending = null;
  }
  return entries;
}

function categoryKey(value) {
  return cleanM3uAttr(value).normalize("NFD").replace(/[\u0300-\u036f]/g, "").toLowerCase();
}

function m3uCategoryId(label) {
  const key = categoryKey(label);
  if (!key) return "";
  return "m3u-" + crypto.createHash("sha1").update(key).digest("hex").slice(0, 12);
}

async function fetchLiveCatalog(user, pass) {
  const key = liveGroupCacheKey(user, pass);
  const cached = liveCatalogCache.get(key);
  if (cached && Date.now() - cached.at < LIVE_CATALOG_CACHE_MS) return cached.data;

  const playlistPromise = (async () => {
    const r = await fetchWithTimeout(playlistUrl(user, pass), {
      redirect: "follow",
      headers: {
        "Accept": "audio/x-mpegurl,application/x-mpegURL,text/plain,*/*",
        "User-Agent": "Mozilla/5.0",
        "Referer": PLAYER_REFERER,
        "Origin": PLAYER_ORIGIN
      }
    }, LIVE_CATALOG_TIMEOUT_MS);
    const text = await r.text();
    if (!r.ok) throw new HttpError(r.status >= 400 && r.status < 600 ? r.status : 502, `Lista M3U respondió ${r.status}`);
    if (!/^\s*#EXTM3U/i.test(text)) throw new HttpError(502, "El servidor IPTV no devolvió una lista M3U válida");
    return text;
  })();

  const streamsPromise = fetchJson(playerUrl(user, pass, "get_live_streams")).catch(() => []);
  const catsPromise = fetchJson(playerUrl(user, pass, "get_live_categories")).catch(() => []);

  let playlistText = "";
  let playlistError = null;
  try { playlistText = await playlistPromise; }
  catch (e) { playlistError = e; }

  const [officialStreamsRaw, officialCatsRaw] = await Promise.all([streamsPromise, catsPromise]);
  const officialStreams = Array.isArray(officialStreamsRaw) ? officialStreamsRaw : [];
  const officialCats = Array.isArray(officialCatsRaw) ? officialCatsRaw : [];

  if (!playlistText && !officialStreams.length) {
    throw playlistError || new HttpError(502, "No se pudo cargar el catálogo de TV en vivo");
  }

  const officialById = new Map();
  for (const item of officialStreams) {
    const id = String(item?.stream_id ?? "").trim();
    if (id) officialById.set(id, item);
  }

  // V015: la categoría oficial de Xtream y el group-title del M3U son
  // membresías COMPLEMENTARIAS. V014 reemplazaba la oficial por la del M3U
  // cuando el canal existía en ambas fuentes, lo que reducía el catálogo a
  // los pocos grupos M3U visibles (p.ej. ~28) aunque Xtream tuviera muchos más.
  const categories = [];
  const categoryByKey = new Map();
  const officialCanonicalByRawId = new Map();

  const ensureCategory = (rawLabel, preferredId = "") => {
    const label = cleanM3uAttr(rawLabel);
    if (!label) return "";
    const keyName = categoryKey(label);
    if (!keyName) return "";
    if (categoryByKey.has(keyName)) return categoryByKey.get(keyName).category_id;

    const preferred = String(preferredId || "").trim();
    const id = preferred || m3uCategoryId(label);
    if (!id) return "";

    const category = { category_id: id, category_name: label };
    categoryByKey.set(keyName, category);
    categories.push(category);
    return id;
  };

  // Registrar primero TODAS las categorías oficiales y conservar su orden/ID.
  for (const c of officialCats) {
    const rawId = String(c?.category_id ?? c?.id ?? "").trim();
    const label = cleanM3uAttr(c?.category_name ?? c?.name ?? "");
    if (!label) continue;
    const canonicalId = ensureCategory(label, rawId);
    if (rawId && canonicalId) officialCanonicalByRawId.set(rawId, canonicalId);
  }

  const officialCategoryForStream = official => {
    const rawId = String(official?.category_id ?? "").trim();
    if (!rawId) return "";
    if (officialCanonicalByRawId.has(rawId)) return officialCanonicalByRawId.get(rawId);

    // Algunos paneles devuelven category_id en streams pero omiten esa entrada
    // en get_live_categories. No la perdemos: usamos el nombre si viene incluido.
    const label = cleanM3uAttr(official?.category_name || official?.category || `Categoría ${rawId}`);
    const canonicalId = ensureCategory(label, rawId);
    if (canonicalId) officialCanonicalByRawId.set(rawId, canonicalId);
    return canonicalId;
  };

  const channels = new Map();
  const addChannel = (base, categoryIds = []) => {
    const id = String(base?.stream_id ?? "").trim();
    if (!id) return;

    let item = channels.get(id);
    if (!item) {
      item = {
        stream_id: id,
        name: cleanM3uAttr(base?.name || "") || `Canal ${id}`,
        stream_icon: String(base?.stream_icon || "").trim().slice(0, 4096),
        epg_channel_id: cleanM3uAttr(base?.epg_channel_id || ""),
        category_id: "",
        category_ids: [],
        group_title: cleanM3uAttr(base?.group_title || "")
      };
      channels.set(id, item);
    } else {
      if (!item.stream_icon && base?.stream_icon) item.stream_icon = String(base.stream_icon).trim().slice(0, 4096);
      if (!item.epg_channel_id && base?.epg_channel_id) item.epg_channel_id = cleanM3uAttr(base.epg_channel_id);
      if ((!item.name || /^Canal \d+$/i.test(item.name)) && base?.name) item.name = cleanM3uAttr(base.name);
      if (!item.group_title && base?.group_title) item.group_title = cleanM3uAttr(base.group_title);
    }

    for (const rawCid of Array.isArray(categoryIds) ? categoryIds : [categoryIds]) {
      const cid = String(rawCid || "").trim();
      if (cid && !item.category_ids.includes(cid)) item.category_ids.push(cid);
    }
    if (!item.category_id && item.category_ids.length) item.category_id = item.category_ids[0];
  };

  let parsedEntries = [];
  if (playlistText) {
    parsedEntries = parseLiveCatalogM3u(playlistText);

    for (const entry of parsedEntries) {
      const id = String(entry.stream_id || "");
      const official = officialById.get(id);
      const keep =
        entry.playlist_kind === "live" ||
        (entry.playlist_kind === "unknown" && !!official);
      if (!keep) continue;

      const memberships = [];
      const officialCid = official ? officialCategoryForStream(official) : "";
      if (officialCid) memberships.push(officialCid);

      const m3uLabel = cleanM3uAttr(entry.group_title || "");
      const m3uCid = m3uLabel ? ensureCategory(m3uLabel) : "";
      if (m3uCid && !memberships.includes(m3uCid)) memberships.push(m3uCid);

      if (!memberships.length) {
        memberships.push(ensureCategory("Sin categoría"));
      }

      addChannel({
        stream_id: id,
        name: entry.name || official?.name || "",
        stream_icon: entry.stream_icon || official?.stream_icon || "",
        epg_channel_id: entry.epg_channel_id || official?.epg_channel_id || "",
        group_title: m3uLabel || cleanM3uAttr(official?.category_name || "")
      }, memberships);
    }
  }

  // Completar desde Xtream y, MUY IMPORTANTE, añadir SIEMPRE la membresía
  // oficial incluso si el canal ya había aparecido en el M3U.
  for (const official of officialStreams) {
    const id = String(official?.stream_id ?? "").trim();
    if (!id) continue;

    let officialCid = officialCategoryForStream(official);
    if (!officialCid) officialCid = ensureCategory("Sin categoría");

    addChannel({
      stream_id: id,
      name: official?.name || "",
      stream_icon: official?.stream_icon || "",
      epg_channel_id: official?.epg_channel_id || "",
      group_title: cleanM3uAttr(official?.category_name || "")
    }, [officialCid]);
  }

  const streams = [...channels.values()];
  const used = new Set(streams.flatMap(x => x.category_ids || []).filter(Boolean));
  const visibleCategories = categories.filter(c => used.has(c.category_id));

  const m3uCategoryKeys = new Set(
    parsedEntries
      .filter(e => e.playlist_kind === "live" || (e.playlist_kind === "unknown" && officialById.has(String(e.stream_id))))
      .map(e => categoryKey(e.group_title))
      .filter(Boolean)
  );

  const data = {
    source: playlistText ? "xtream+m3u-union" : "xtream-fallback",
    categories: visibleCategories,
    streams,
    counts: {
      categories: visibleCategories.length,
      streams: streams.length,
      playlist_entries: parsedEntries.length,
      xtream_streams: officialStreams.length,
      xtream_categories: officialCats.length,
      m3u_categories: m3uCategoryKeys.size,
      categorized_streams: streams.filter(x => Array.isArray(x.category_ids) && x.category_ids.length).length,
      multi_category_streams: streams.filter(x => Array.isArray(x.category_ids) && x.category_ids.length > 1).length
    }
  };

  liveCatalogCache.set(key, { at: Date.now(), data });
  if (liveCatalogCache.size > 100) {
    const oldest = [...liveCatalogCache.entries()].sort((a,b) => a[1].at - b[1].at).slice(0, liveCatalogCache.size - 100);
    for (const [k] of oldest) liveCatalogCache.delete(k);
  }

  return data;
}

function allowedAction(action) {
  return new Set([
    "get_live_categories", "get_live_streams", "get_live_groups", "get_live_catalog",
    "get_vod_categories", "get_vod_streams",
    "get_series_categories", "get_series",
    "get_vod_info", "get_series_info", "get_short_epg"
  ]).has(action);
}

function safeExt(v, fallback = "mp4") {
  const x = String(v || fallback).replace(/[^a-zA-Z0-9]/g, "").toLowerCase();
  return x || fallback;
}

function mediaTypeForExt(ext) {
  const x = safeExt(ext, "mp4");
  if (x === "mp4" || x === "m4v") return "video/mp4";
  if (x === "webm") return "video/webm";
  if (x === "m3u8") return "application/vnd.apple.mpegurl";
  if (["ts","mpegts","m2ts"].includes(x)) return "video/mp2t";
  if (x === "mov") return "video/quicktime";
  return "application/octet-stream";
}
function usableMediaContentType(ct) {
  const x = String(ct || "").toLowerCase().split(";")[0].trim();
  return x && !["application/octet-stream","binary/octet-stream","application/download"].includes(x);
}
function safeId(v) {
  const x = String(v ?? "").trim();
  if (!x || x.length > 128 || !/^[A-Za-z0-9._-]+$/.test(x)) throw new HttpError(400, "ID de contenido inválido");
  return x;
}
function safeKind(v) {
  const x = String(v || "");
  if (!["live", "movie", "series"].includes(x)) throw new HttpError(400, "Tipo de contenido inválido");
  return x;
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

  const prefix = `${UPSTREAM_BASE}/${kind}/${u}/${p}/${sid}`;
  if (mode === "hls") {
    return [
      `${prefix}.m3u8`,
      `${UPSTREAM_BASE}/${u}/${p}/${sid}.m3u8`
    ];
  }
  if (mode === "ts") {
    return [
      `${prefix}.ts`,
      `${UPSTREAM_BASE}/${u}/${p}/${sid}.ts`
    ];
  }
  if (mode === "mp4") {
    return [`${prefix}.mp4`];
  }

  const original = safeExt(ext, "mp4");
  const out = [`${prefix}.${original}`];
  if (original !== "mp4") out.push(`${prefix}.mp4`);
  return out;
}

function looksLikeManifest(ct, url) {
  const x = String(ct || "").toLowerCase();
  return x.includes("mpegurl") || x.includes("m3u8") || /\.m3u8(?:$|\?)/i.test(url);
}
function looksLikeHtml(ct) {
  const x = String(ct || "").toLowerCase();
  return x.includes("text/html") || x.includes("application/xhtml");
}

function streamHeaderProfiles() {
  return [
    { id: "vlc", ua: "VLC/3.0.21 LibVLC/3.0.21" },
    { id: "exo", ua: "ExoPlayerLib/2.19.1 (Linux;Android 13) ExoPlayer" },
    {
      id: "browser",
      ua: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36",
      referer: PLAYER_REFERER, origin: PLAYER_ORIGIN
    },
    {
      id: "androidtv",
      ua: "Mozilla/5.0 (Linux; Android 12; Android TV) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
      referer: PLAYER_REFERER, origin: PLAYER_ORIGIN
    }
  ];
}
function profileById(id) {
  return streamHeaderProfiles().find(x => x.id === id) || streamHeaderProfiles()[0];
}
function upstreamHeaders(req, options = {}) {
  const h = new Headers();
  const profile = options.profile || profileById(options.profileId);
  h.set("Accept", req.headers.accept || "*/*");
  h.set("User-Agent", options.userAgent || profile.ua || "VLC/3.0.21 LibVLC/3.0.21");
  if (profile.referer) h.set("Referer", profile.referer);
  if (profile.origin) h.set("Origin", profile.origin);
  h.set("Accept-Language", "es-419,es;q=0.9,en;q=0.7");
  const range = req.headers.range;
  if (range && options.allowRange !== false) h.set("Range", range);
  return h;
}
async function assertStreamUrl(raw) {
  let u;
  try { u = new URL(raw); } catch { throw new HttpError(400, "URL de stream inválida"); }
  if (!/^https?:$/.test(u.protocol)) throw new HttpError(403, "Origen de stream no permitido");
  if (UPSTREAM_HOST && u.hostname.toLowerCase() === UPSTREAM_HOST) return u;
  return assertPublicUrl(u.toString());
}

async function proxyFetch(target, req, options = {}) {
  let current = await assertStreamUrl(target);
  for (let i = 0; i < 6; i++) {
    const r = await fetchWithTimeout(current.toString(), {
      method: "GET",
      headers: upstreamHeaders(req, options),
      redirect: "manual"
    }, options.timeoutMs || UPSTREAM_STREAM_TIMEOUT_MS);
    if ([301,302,303,307,308].includes(r.status)) {
      const loc = r.headers.get("location");
      try { await r.body?.cancel(); } catch {}
      if (!loc) throw new HttpError(502, "Redirección de stream inválida");
      current = await assertStreamUrl(new URL(loc, current).toString());
      continue;
    }
    return r;
  }
  throw new HttpError(508, "Demasiadas redirecciones de stream");
}
async function tryTargetProfiles(target, req, preferredProfileId = "") {
  const all = streamHeaderProfiles();
  const first = preferredProfileId ? profileById(preferredProfileId) : null;
  const profiles = first ? [first, ...all.filter(x => x.id !== first.id)] : all;
  const attempts = [];
  let lastResponse = null;

  for (const profile of profiles) {
    let r;
    try {
      r = await proxyFetch(target, req, { profile });
    } catch (e) {
      attempts.push({ profile: profile.id, status: Number(e?.status || 0), error: e?.message || "fetch" });
      continue;
    }
    attempts.push({ profile: profile.id, status: r.status || 0 });
    if (r.ok) return { response: r, profile, attempts };
    lastResponse = r;
    try { await r.body?.cancel(); } catch {}
    if (![401,403,404,405,429,500,502,503,504].includes(r.status)) break;
  }
  return { response: lastResponse && !lastResponse.bodyUsed ? lastResponse : null, profile: null, attempts };
}

function copyUpstreamHeaders(r, extra = {}) {
  const h = corsHeaders();
  for (const k of [
    "content-type", "content-length", "content-range", "accept-ranges",
    "cache-control", "etag", "last-modified", "content-disposition"
  ]) {
    const v = r.headers.get(k);
    if (v) h[k] = v;
  }
  return { ...h, ...extra };
}
function pipeWebBody(r, res, extraHeaders = {}) {
  if (res.destroyed || res.writableEnded) return;
  res.writeHead(r.status, copyUpstreamHeaders(r, extraHeaders));
  if (!r.body) return res.end();

  const body = Readable.fromWeb(r.body);
  let finished = false;

  const close = () => {
    if (finished) return;
    finished = true;
    try { if (!body.destroyed) body.destroy(); } catch {}
  };

  reqCloseGuard(res, close);
  body.once("end", () => { finished = true; });
  body.once("close", () => { finished = true; });
  body.on("error", err => {
    finished = true;
    if (err?.name !== "AbortError" && err?.code !== "ERR_STREAM_PREMATURE_CLOSE") {
      console.warn("Stream upstream cerrado:", err?.message || err);
    }
    if (!res.destroyed) res.destroy();
  });
  res.on("error", close);
  body.pipe(res);
}
function reqCloseGuard(res, fn) {
  let done = false;
  const once = () => { if (done) return; done = true; fn(); };
  res.once("close", once);
  res.once("finish", () => { done = true; });
}

function proxyToken(targetUrl, session, profileId = "") {
  return seal({
    scope: "segment", url: targetUrl, u: session.u, p: session.p, profileId,
    exp: Math.min(Number(session.sessionExp || session.exp || 0) || (Date.now() + SESSION_MS), Date.now() + SESSION_MS)
  });
}
function publicBase(req) {
  const proto = String(req.headers["x-forwarded-proto"] || "https").split(",")[0].trim();
  const host = req.headers.host;
  return `${proto}://${host}`;
}
function rewriteManifest(text, manifestUrl, req, session, profileId = "") {
  const raw = String(text || "");
  if (!raw.trim().startsWith("#EXTM3U")) throw new HttpError(415, "Manifest HLS inválido");
  if (raw.length > 5 * 1024 * 1024) throw new HttpError(413, "Manifest HLS demasiado grande");
  const base = publicBase(req);
  const out = [];
  for (let line of raw.split(/\r?\n/)) {
    if (line.startsWith("#")) {
      const matches = [...line.matchAll(/URI="([^"]+)"/g)];
      for (const m of matches) {
        const original = m[1];
        let abs;
        try { abs = new URL(original, manifestUrl).toString(); } catch { continue; }
        const proxied = `${base}/segment?s=${encodeURIComponent(proxyToken(abs, session, profileId))}`;
        line = line.replace(`URI="${original}"`, `URI="${proxied}"`);
      }
      out.push(line);
      continue;
    }
    if (!line.trim()) { out.push(line); continue; }
    let abs;
    try { abs = new URL(line.trim(), manifestUrl).toString(); }
    catch { throw new HttpError(415, "URI inválida en manifest HLS"); }
    out.push(`${base}/segment?s=${encodeURIComponent(proxyToken(abs, session, profileId))}`);
  }
  return out.join("\n");
}

function isPrivateIp(ip) {
  const fam = net.isIP(ip);
  if (fam === 4) {
    const p = ip.split(".").map(Number);
    if (p[0] === 10 || p[0] === 127 || p[0] === 0) return true;
    if (p[0] === 169 && p[1] === 254) return true;
    if (p[0] === 192 && p[1] === 168) return true;
    if (p[0] === 172 && p[1] >= 16 && p[1] <= 31) return true;
    return false;
  }
  if (fam === 6) {
    const x = ip.toLowerCase();
    return x === "::1" || x === "::" || x.startsWith("fc") || x.startsWith("fd") || x.startsWith("fe8") || x.startsWith("fe9") || x.startsWith("fea") || x.startsWith("feb");
  }
  return true;
}
const publicHostCache = new Map();

async function assertPublicUrl(raw) {
  let u;
  try { u = new URL(raw); } catch { throw new HttpError(400, "URL inválida"); }
  if (!/^https?:$/.test(u.protocol)) throw new HttpError(403, "Origen no permitido");
  const host = u.hostname.toLowerCase();
  if (!host || host === "localhost" || host.endsWith(".local")) throw new HttpError(403, "Origen no permitido");
  if (net.isIP(host)) {
    if (isPrivateIp(host)) throw new HttpError(403, "Origen no permitido");
    return u;
  }
  const cached = publicHostCache.get(host);
  if (cached && cached > Date.now()) return u;
  let records;
  try { records = await dns.lookup(host, { all: true, verbatim: true }); }
  catch { throw new HttpError(502, "No se pudo resolver el origen de imagen"); }
  if (!records.length || records.some(r => isPrivateIp(r.address))) throw new HttpError(403, "Origen no permitido");
  publicHostCache.set(host, Date.now() + 10 * 60 * 1000);
  if (publicHostCache.size > 2000) {
    const now = Date.now();
    for (const [k,exp] of publicHostCache) if (exp <= now) publicHostCache.delete(k);
  }
  return u;
}

function clientIp(req) {
  return String(req.headers["x-forwarded-for"] || req.socket.remoteAddress || "unknown").split(",")[0].trim();
}
function checkLoginRateLimit(req) {
  const key = clientIp(req);
  const now = Date.now();
  const win = 10 * 60 * 1000;
  const item = loginBuckets.get(key) || { start: now, count: 0 };
  if (now - item.start > win) { item.start = now; item.count = 0; }
  item.count++;
  loginBuckets.set(key, item);
  if (item.count > 12) throw new HttpError(429, "Demasiados intentos de acceso. Intenta de nuevo en unos minutos.");
  if (loginBuckets.size > 5000) {
    for (const [k, v] of loginBuckets) if (now - v.start > win) loginBuckets.delete(k);
  }
}

async function handleLogin(req, res) {
  checkLoginRateLimit(req);
  const { username, password } = await readJsonBody(req);
  const user = String(username || "").trim();
  const pass = String(password || "");
  if (!user || !pass) return sendJson(res, { error: "Escribe usuario y contraseña" }, 400);
  if (user.length > 128 || pass.length > 256) return sendJson(res, { error: "Credenciales inválidas" }, 400);

  let data;
  try { data = await fetchJson(playerUrl(user, pass)); }
  catch (e) {
    if ([401,403].includes(Number(e?.status))) return sendJson(res, { error: "Usuario o contraseña incorrectos" }, 401);
    throw e;
  }
  const ui = data?.user_info;
  if (!ui || Number(ui.auth) !== 1) return sendJson(res, { error: "Usuario o contraseña incorrectos" }, 401);
  if (ui.status && String(ui.status).toLowerCase() !== "active") return sendJson(res, { error: `Cuenta ${ui.status}` }, 403);

  const exp = Date.now() + SESSION_MS;
  const token = seal({ scope: "session", u: user, p: pass, exp });
  const imageToken = seal({ scope: "image", exp });
  return sendJson(res, { token, image_token: imageToken, user: sanitizeUser(data, user), session_expires: exp });
}

async function handleData(req, res, url) {
  const s = sessionFromReq(req, url);
  const body = await readJsonBody(req);
  const action = String(body.action || "");
  if (!allowedAction(action)) return sendJson(res, { error: "Acción no permitida" }, 400);
  if (action === "get_live_groups") {
    const data = await fetchLiveGroups(s.u, s.p);
    return sendJson(res, data);
  }
  if (action === "get_live_catalog") {
    const data = await fetchLiveCatalog(s.u, s.p);
    return sendJson(res, data);
  }

  const extra = {};
  if (action === "get_vod_info") extra.vod_id = safeId(body.vod_id);
  if (action === "get_series_info") extra.series_id = safeId(body.series_id);
  if (action === "get_short_epg") {
    extra.stream_id = safeId(body.stream_id);
    extra.limit = Math.max(1, Math.min(20, Number(body.limit || 5)));
  }
  const data = await fetchJson(playerUrl(s.u, s.p, action, extra));
  return sendJson(res, data);
}

async function handleImageToken(req, res, url) {
  const s = sessionFromReq(req, url);
  const exp = Math.min(Number(s.exp || 0), Date.now() + SESSION_MS);
  return sendJson(res, { image_token: seal({ scope: "image", exp }), expires: exp });
}

async function handleTicket(req, res, url) {
  const s = sessionFromReq(req, url);
  const body = await readJsonBody(req);
  const kind = safeKind(body.kind);
  const id = safeId(body.id);
  const ext = safeExt(body.ext || "mp4");
  const requestedMode = String(body.mode || "").toLowerCase();
  const mode = kind === "live"
    ? (requestedMode === "ts" ? "ts" : "hls")
    : (["hls","ts","mp4"].includes(requestedMode) ? requestedMode : "direct");
  const exp = Math.min(Number(s.exp || 0), Date.now() + STREAM_TICKET_MS);
  const ticket = seal({ scope: "stream", u: s.u, p: s.p, kind, id, ext, mode, sessionExp: s.exp, exp });
  return sendJson(res, { ticket, expires: exp });
}

function streamSessionFromUrl(url, kind, id) {
  const ticket = url.searchParams.get("ticket") || "";
  if (ticket) {
    const s = unseal(ticket, "stream");
    if (s.kind !== kind || String(s.id) !== String(id)) throw new HttpError(403, "Ticket no corresponde a este contenido");
    return s;
  }
  // Compatibilidad temporal con V022 durante el despliegue escalonado.
  const token = url.searchParams.get("token") || "";
  if (token) return unseal(token, "session");
  throw new HttpError(401, "Falta autorización de reproducción");
}

async function handleStream(req, res, url, kind, id) {
  kind = safeKind(kind); id = safeId(id);
  const s = streamSessionFromUrl(url, kind, id);
  let ext = safeExt(url.searchParams.get("ext") || s.ext || "mp4");
  let mode = String(url.searchParams.get("mode") || s.mode || "").toLowerCase();
  if (kind === "live") mode = mode === "ts" ? "ts" : "hls";
  else mode = ["hls","ts","mp4"].includes(mode) ? mode : "direct";

  const candidates = streamCandidates(s, kind, id, ext, mode);
  const allAttempts = [];
  let lastStatus = 502;

  for (const target of candidates) {
    const tried = await tryTargetProfiles(target, req);
    allAttempts.push(...tried.attempts.map(a => ({ ...a, target })));
    if (!tried.response || !tried.response.ok) {
      const statuses = tried.attempts.map(a => a.status).filter(Boolean);
      if (statuses.length) lastStatus = statuses[statuses.length - 1];
      continue;
    }
    const r = tried.response;
    const profile = tried.profile;
    const finalUrl = r.url || target;
    const ct = r.headers.get("content-type") || "";

    if (looksLikeManifest(ct, finalUrl)) {
      const manifest = await r.text();
      const rewritten = rewriteManifest(manifest, finalUrl, req, s, profile?.id || "");
      return sendText(res, rewritten, 200, {
        "Content-Type": "application/vnd.apple.mpegurl; charset=utf-8",
        "Cache-Control": "no-store",
        "X-Pixel-Stream-Mode": "hls",
        "X-Pixel-Header-Profile": profile?.id || "",
        "X-Pixel-Attempts": String(allAttempts.length)
      });
    }

    // Si pedimos HLS para compatibilidad y el proveedor devolvió un archivo
    // normal, no se lo entregamos a hls.js como si fuera un manifest.
    if (kind !== "live" && mode === "hls") {
      lastStatus = 415;
      try { await r.body?.cancel(); } catch {}
      continue;
    }

    if (looksLikeHtml(ct)) {
      lastStatus = 415;
      try { await r.body?.cancel(); } catch {}
      continue;
    }

    const fallbackType = kind === "live"
      ? "video/mp2t"
      : mode === "ts"
        ? "video/mp2t"
        : mediaTypeForExt(mode === "mp4" ? "mp4" : ext);

    return pipeWebBody(r, res, {
      "Content-Type": usableMediaContentType(ct) ? ct : fallbackType,
      "Content-Disposition": "inline",
      "X-Pixel-Stream-Mode": kind === "live" ? "ts" : mode,
      "X-Pixel-Header-Profile": profile?.id || "",
      "X-Pixel-Attempts": String(allAttempts.length)
    });
  }

  const seen = allAttempts.map(a => `${a.profile}:${a.status || "ERR"}`).join(",");
  return sendText(res, `No se pudo abrir el stream (${lastStatus})`, lastStatus || 502, {
    "X-Pixel-Stream-Mode": kind === "live" ? mode : safeExt(ext),
    "X-Pixel-Upstream-Status": String(lastStatus || 502),
    "X-Pixel-Attempts": String(allAttempts.length),
    "X-Pixel-Attempt-Summary": seen.slice(0, 500)
  });
}

async function handleSegment(req, res, url) {
  const payload = unseal(url.searchParams.get("s") || "", "segment");
  let target;
  try { target = new URL(payload.url); } catch { throw new HttpError(400, "Segmento inválido"); }
  if (!/^https?:$/.test(target.protocol)) throw new HttpError(403, "Origen no permitido");

  const tried = await tryTargetProfiles(target.toString(), req, payload.profileId || "");
  const r = tried.response;
  if (!r || !r.ok) {
    const statuses = tried.attempts.map(a => a.status).filter(Boolean);
    const status = statuses.length ? statuses[statuses.length - 1] : 502;
    return sendText(res, `Segmento no disponible (${status})`, status, { "X-Pixel-Attempts": String(tried.attempts.length) });
  }
  const finalUrl = r.url || target.toString();
  const ct = r.headers.get("content-type") || "";
  const profileId = tried.profile?.id || payload.profileId || "";
  if (looksLikeManifest(ct, finalUrl)) {
    const rewritten = rewriteManifest(await r.text(), finalUrl, req, payload, profileId);
    return sendText(res, rewritten, 200, {
      "Content-Type": "application/vnd.apple.mpegurl; charset=utf-8",
      "Cache-Control": "no-store",
      "X-Pixel-Header-Profile": profileId
    });
  }
  if (looksLikeHtml(ct)) throw new HttpError(415, "El servidor devolvió HTML en lugar de video");
  return pipeWebBody(r, res, { "X-Pixel-Header-Profile": profileId });
}

async function fetchPublicImage(raw) {
  let current = await assertPublicUrl(raw);
  for (let i = 0; i < 5; i++) {
    const r = await fetchWithTimeout(current.toString(), {
      redirect: "manual",
      headers: { "User-Agent": "Mozilla/5.0", "Accept": "image/avif,image/webp,image/apng,image/svg+xml,image/*,*/*;q=0.8" }
    }, IMAGE_TIMEOUT_MS);
    if ([301,302,303,307,308].includes(r.status)) {
      const loc = r.headers.get("location");
      try { await r.body?.cancel(); } catch {}
      if (!loc) throw new HttpError(502, "Redirección de imagen inválida");
      current = await assertPublicUrl(new URL(loc, current).toString());
      continue;
    }
    return r;
  }
  throw new HttpError(508, "Demasiadas redirecciones de imagen");
}

async function handleImage(req, res, url) {
  const token = url.searchParams.get("it") || url.searchParams.get("token") || "";
  // V023 usa un token de imagen separado; V022 sigue funcionando durante transición.
  try { unseal(token, "image"); }
  catch (e) {
    try { unseal(token, "session"); }
    catch { throw e; }
  }

  const encoded = url.searchParams.get("u") || "";
  let raw = "";
  try { raw = fromB64url(encoded).toString("utf8"); } catch {}
  if (!raw || raw.length > 4096) throw new HttpError(400, "Imagen inválida");

  const r = await fetchPublicImage(raw);
  if (!r.ok) return sendText(res, "Imagen no disponible", r.status >= 400 && r.status < 600 ? r.status : 502);
  const ct = String(r.headers.get("content-type") || "").toLowerCase();
  if (ct && !ct.startsWith("image/")) {
    try { await r.body?.cancel(); } catch {}
    throw new HttpError(415, "El origen no devolvió una imagen");
  }
  return pipeWebBody(r, res, { "Cache-Control": "public, max-age=86400, immutable" });
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
        version: "V015",
        upstreamConfigured: /^https?:\/\//i.test(UPSTREAM_BASE),
        alternateHeaderProfiles: true,
        alternateStreamPaths: true,
        scopedStreamTickets: true,
        scopedImageTokens: true,
        upstreamTimeouts: true,
        vodCompatibilityFallbacks: true,
        normalizedMediaTypes: true,
        safeStreamShutdown: true,
        playerRefererConfigured: !!PLAYER_REFERER,
        m3uLiveGroups: true,
        m3uAuthoritativeLiveCatalog: false,
        unionXtreamAndM3uCategories: true,
        preservesOfficialCategoryMembership: true,
        liveCatalogEndpoint: "get_live_catalog",
        playerCodeUnchangedFromV005: true
      });
    }

    requireConfig();
    if (path === "/api/login" && req.method === "POST") return await handleLogin(req, res);
    if (path === "/api/data" && req.method === "POST") return await handleData(req, res, url);
    if (path === "/api/image-token" && req.method === "POST") return await handleImageToken(req, res, url);
    if (path === "/api/ticket" && req.method === "POST") return await handleTicket(req, res, url);
    if (path === "/image" && req.method === "GET") return await handleImage(req, res, url);
    if (path === "/segment" && req.method === "GET") return await handleSegment(req, res, url);

    const m = path.match(/^\/stream\/(live|movie|series)\/([^/]+)$/);
    if (m && req.method === "GET") return await handleStream(req, res, url, m[1], decodeURIComponent(m[2]));
    return sendJson(res, { error: "Ruta no encontrada" }, 404);
  } catch (e) {
    const status = Number(e?.status || 500);
    if (status >= 500) console.error(e);
    return sendJson(res, { error: e?.message || "Error interno" }, status >= 400 && status < 600 ? status : 500);
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
server.requestTimeout = 30_000;
server.maxRequestsPerSocket = 1000;
server.on("clientError", (err, socket) => {
  if (socket.writable) socket.end("HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n");
});

function shutdown(signal) {
  console.log(`Pixel IPTV Render Proxy V013 cerrando por ${signal}`);
  server.close(() => process.exit(0));
  setTimeout(() => {
    try { server.closeIdleConnections?.(); } catch {}
    try { server.closeAllConnections?.(); } catch {}
    process.exit(0);
  }, 8_000).unref();
}
process.once("SIGTERM", () => shutdown("SIGTERM"));
process.once("SIGINT", () => shutdown("SIGINT"));

server.listen(PORT, "0.0.0.0", () => {
  console.log(`Pixel IPTV Render Proxy V013 escuchando en 0.0.0.0:${PORT}`);
});
