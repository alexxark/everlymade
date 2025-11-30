// api/thankyouclaim.js — CommonJS (Vercel /api/*)
// Household-wide monthly lock + IP-first reuse + 48h validity, no remint in same month.
// Supports Upstash Redis REST or Vercel KV REST. GraphQL discount creation with collision retry.
// Active-IP reuse is handled FIRST; reuse works across devices via exact-IP key, legacy IP+UA key,
// and (optionally) "household" network prefix keys (/24 for IPv4, /64 for IPv6). When a reuse match
// is found, we mirror the record to all keys for the remaining TTL so subsequent devices align.
//
// --- Required ENVs ---
// KV (choose one pair):
//   UPSTASH_REDIS_REST_URL, UPSTASH_REDIS_REST_TOKEN
//   or KV_REST_API_URL, KV_REST_API_TOKEN
// Shopify:
//   SHOPIFY_SHOP, SHOPIFY_ADMIN_TOKEN
//   SHOPIFY_API_VERSION (optional; default '2025-07')
//
// --- Optional behavior ENVs (defaults chosen to match your requirements) ---
// IP_HASH_SALT                 (default 'change-me-long-random-salt')
// TY_PERCENT                   (default 20)
// TY_COOLDOWN_HOURS            (default 0)         // keep at 0 per your ask
// PERIOD_MONTHS                (default 1)         // monthly limit
// REQUIRE_SIGNED_IN            (default false)     // unused by default
// STRICT_ONCE                  (default false)     // off per your ask
// EVER_TTL_DAYS                (default 0)         // off per your ask
// REQUIRE_REAL_IP_FOR_GUEST    (default false)     // can set true if you want to force sign-in behind proxy
// HASH_IP_WITH_UA              (default false)     // only affects visitor hash; not active-IP reuse
// VISITOR_KEY_MODE             (default "cookie+ip")
// ACTIVE_IP_SCOPE              (default "household") // "exact" | "household"

const crypto = require('crypto');

// ----- Shopify -----
const SHOPIFY_SHOP        = process.env.SHOPIFY_SHOP;
const SHOPIFY_ADMIN_TOKEN = process.env.SHOPIFY_ADMIN_TOKEN;
const API_VERSION         = process.env.SHOPIFY_API_VERSION || '2025-07';

// Scope discount to this collection only: “Discount Eligible”
// Admin URL: https://admin.shopify.com/store/charmsforchange/collections/497414078761
// GID form:
const DISCOUNT_COLLECTION_ID = 'gid://shopify/Collection/497414078761';

// ----- KV / Redis (Upstash or Vercel) -----
const KV_URL   = process.env.KV_REST_API_URL || process.env.UPSTASH_REDIS_REST_URL;
const KV_TOKEN = process.env.KV_REST_API_TOKEN || process.env.UPSTASH_REDIS_REST_TOKEN;

function kvStyle(url) {
  const u = (url || '').toLowerCase();
  if (u.includes('vercel-storage.com') || u.includes('kv.vercel-storage.com')) return 'vercel';
  if (u.includes('.upstash.io')) return 'upstash';
  return 'vercel';
}
const KV_STYLE = kvStyle(KV_URL);

// ----- Behavior flags -----
const IP_HASH_SALT      = process.env.IP_HASH_SALT || 'change-me-long-random-salt';
const TY_PERCENT        = parseFloat(process.env.TY_PERCENT || '20') || 20;
const TY_COOLDOWN_HOURS = parseFloat(process.env.TY_COOLDOWN_HOURS || '0') || 0;

const PERIOD_MONTHS     = Math.max(1, parseInt(process.env.PERIOD_MONTHS || '1', 10));
const REQUIRE_SIGNED_IN = String(process.env.REQUIRE_SIGNED_IN || 'false').toLowerCase() === 'true';

const STRICT_ONCE   = String(process.env.STRICT_ONCE || 'false').toLowerCase() === 'true';
const EVER_TTL_DAYS = parseFloat(process.env.EVER_TTL_DAYS || '0') || 0;

const REQUIRE_REAL_IP_FOR_GUEST = String(process.env.REQUIRE_REAL_IP_FOR_GUEST || 'false').toLowerCase() === 'true';
const HASH_IP_WITH_UA           = String(process.env.HASH_IP_WITH_UA || 'false').toLowerCase() === 'true';
const VISITOR_KEY_MODE          = String(process.env.VISITOR_KEY_MODE || 'cookie+ip').toLowerCase();
const ACTIVE_IP_SCOPE           = String(process.env.ACTIVE_IP_SCOPE || 'household').toLowerCase(); // 'exact' | 'household'

// ----- Env guard -----
function assertEnvOrThrow() {
  const missing = [];
  if (!SHOPIFY_SHOP) missing.push('SHOPIFY_SHOP');
  if (!SHOPIFY_ADMIN_TOKEN) missing.push('SHOPIFY_ADMIN_TOKEN');
  if (!KV_URL) missing.push('KV_REST_API_URL or UPSTASH_REDIS_REST_URL');
  if (!KV_TOKEN) missing.push('KV_REST_API_TOKEN or UPSTASH_REDIS_REST_TOKEN');
  if (!process.env.IP_HASH_SALT || process.env.IP_HASH_SALT === 'change-me-long-random-salt') {
    missing.push('IP_HASH_SALT (must be a strong secret)');
  }
  if (missing.length) throw new Error(`Missing ENV: ${missing.join(', ')}`);
}

// ----- KV helpers (with style fallbacks for 400s) -----
async function kvGet(key) {
  if (!KV_URL || !KV_TOKEN || !key) return null;
  const r = await fetch(`${KV_URL}/get/${encodeURIComponent(key)}`, {
    headers: { Authorization: `Bearer ${KV_TOKEN}` },
    cache: 'no-store',
  });
  if (!r.ok) throw new Error(`KV GET failed: ${r.status}`);
  const data = await r.json().catch(() => null);
  try { return data?.result ? JSON.parse(data.result) : null; } catch { return data?.result ?? null; }
}

async function kvSetEx(key, value, ttlSeconds) {
  const ttl = encodeURIComponent(ttlSeconds);
  const payload = encodeURIComponent(JSON.stringify(value));
  const primary = KV_STYLE === 'upstash'
    ? `${KV_URL}/set/${encodeURIComponent(key)}/${payload}?EX=${ttl}`
    : `${KV_URL}/set/${encodeURIComponent(key)}/${payload}?ex=${ttl}`;
  const fallback = KV_STYLE === 'upstash'
    ? `${KV_URL}/set/${encodeURIComponent(key)}/${payload}?ex=${ttl}`
    : `${KV_URL}/set/${encodeURIComponent(key)}/${payload}?EX=${ttl}`;

  let r = await fetch(primary, { method: 'POST', headers: { Authorization: `Bearer ${KV_TOKEN}` }});
  if (r.status === 400) r = await fetch(fallback, { method: 'POST', headers: { Authorization: `Bearer ${KV_TOKEN}` }});
  if (!r.ok) throw new Error(`KV SET EX failed: ${r.status}`);
  const data = await r.json().catch(() => ({}));
  if (data?.error) throw new Error(`KV error: ${data.error}`);
  return true;
}

async function kvSetNxEx(key, value, ttlSeconds) {
  if (!KV_URL || !KV_TOKEN) throw new Error('KV not configured');
  const ttl = encodeURIComponent(ttlSeconds);
  const base = `${KV_URL}/set/${encodeURIComponent(key)}/${encodeURIComponent(JSON.stringify(value))}`;

  const candidates = [];
  if (KV_STYLE === 'upstash') {
    candidates.push(`${base}?EX=${ttl}&NX=true`);
    candidates.push(`${base}?EX=${ttl}&NX=1`);
    candidates.push(`${base}?EX=${ttl}&NX`);
    candidates.push(`${base}?ex=${ttl}&nx=true`);
  } else {
    candidates.push(`${base}?ex=${ttl}&nx=true`);
    candidates.push(`${base}?EX=${ttl}&NX=true`);
    candidates.push(`${base}?EX=${ttl}&NX=1`);
    candidates.push(`${base}?EX=${ttl}&NX`);
  }

  let lastResp = null;
  for (const url of candidates) {
    const r = await fetch(url, { method: 'POST', headers: { Authorization: `Bearer ${KV_TOKEN}` } });
    lastResp = r;
    if (r.status === 400) continue;
    if (!r.ok) throw new Error(`KV SET NX EX failed: ${r.status}`);
    const data = await r.json().catch(() => null);
    return data?.result === 'OK';
  }

  throw new Error(`KV SET NX EX failed: ${lastResp ? lastResp.status : 'unknown'}`);
}

async function kvDel(key) {
  const r = await fetch(`${KV_URL}/del/${encodeURIComponent(key)}`, {
    method: 'POST', headers: { Authorization: `Bearer ${KV_TOKEN}` }
  });
  if (!r.ok) throw new Error(`KV DEL failed: ${r.status}`);
  return true;
}

async function kvSet(key, value) {
  const r = await fetch(`${KV_URL}/set/${encodeURIComponent(key)}/${encodeURIComponent(JSON.stringify(value))}`, {
    method: 'POST', headers: { Authorization: `Bearer ${KV_TOKEN}` }
  });
  if (!r.ok) throw new Error(`KV SET failed: ${r.status}`);
  const data = await r.json().catch(() => ({}));
  if (data?.error) throw new Error(`KV error: ${data.error}`);
  return true;
}

async function kvSetExDays(key, value, days) {
  if (days <= 0) return kvSet(key, value);
  const ttlSeconds = Math.max(1, Math.floor(days * 86400));
  return kvSetEx(key, value, ttlSeconds);
}

// ----- Utils -----
function genCode(prefix = 'TY') {
  const pool = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'; // no 0/O/1/I
  let four = '';
  for (let i = 0; i < 4; i++) four += pool[Math.floor(Math.random() * pool.length)];
  return `${prefix}-${four}`;
}
function isPrivateIp(ip) {
  // IPv6 ULA is fc00::/7 => fc00::/8 and fd00::/8
  return /^10\.|^192\.168\.|^172\.(1[6-9]|2\d|3[0-1])\.|^127\.|^::1$|^f[cd]00:|^fe80:/i.test(ip);
}
function normalizeIp(ip) {
  return String(ip || '').replace(/^::ffff:/, '');
}
function hmacHash(input, salt = IP_HASH_SALT) {
  return crypto.createHmac('sha256', salt).update(String(input)).digest('hex');
}
function parseCookies(req) {
  const h = req.headers.cookie || '';
  return h.split(';').reduce((acc, part) => {
    const [k, ...rest] = part.split('=');
    if (!k || rest.length === 0) return acc;
    acc[k.trim()] = decodeURIComponent(rest.join('=').trim());
    return acc;
  }, {});
}
function appendHeader(res, name, value) {
  const prev = res.getHeader(name);
  if (!prev) return res.setHeader(name, value);
  if (Array.isArray(prev)) return res.setHeader(name, prev.concat(value));
  return res.setHeader(name, [prev, value]);
}
function setCookie(res, name, value, { maxAgeSec, path='/', httpOnly=true, sameSite='Lax', secure=true } = {}) {
  const parts = [`${name}=${encodeURIComponent(value)}`, `Path=${path}`, `SameSite=${sameSite}`];
  if (httpOnly) parts.push('HttpOnly');
  if (secure) parts.push('Secure');
  if (Number.isFinite(maxAgeSec)) parts.push(`Max-Age=${Math.max(0, Math.floor(maxAgeSec))}`);
  appendHeader(res, 'Set-Cookie', parts.join('; '));
}
function addMonths(date, n) {
  const d = new Date(date);
  const m = d.getMonth();
  d.setMonth(m + n);
  if (d.getMonth() !== ((m + n) % 12 + 12) % 12) d.setDate(0);
  return d;
}
function getPeriodStart(nowMs) { const d = new Date(nowMs); d.setUTCDate(1); d.setUTCHours(0,0,0,0); return d; }
function getPeriodEnd(nowMs, months) { return addMonths(getPeriodStart(nowMs), months); }
function secondsUntil(fromMs, toDate) { return Math.max(1, Math.ceil((toDate.getTime() - fromMs)/1000)); }

// ----- Active-IP household helpers -----
function ipV4Prefix(ip) {
  const m = String(ip || '').match(/^(\d+)\.(\d+)\.(\d+)\.\d+$/);
  return m ? `${m[1]}.${m[2]}.${m[3]}.0/24` : null;
}
function ipV6Prefix(ip) {
  const parts = String(ip || '').split(':');
  if (parts.length < 4) return null;
  return `${parts.slice(0,4).join(':')}::/64`;
}
function buildActiveIpHashes(ip, ua) {
  const cleanIp = normalizeIp(ip);
  const hashes = new Set();

  // exact IP (current canonical)
  hashes.add(hmacHash(cleanIp));
  // legacy exact (IP+UA) — earlier deployments may have stored like this
  if (ua) hashes.add(hmacHash(`${cleanIp}|${ua}`));

  // optional household scope
  if (ACTIVE_IP_SCOPE === 'household') {
    const v4p = ipV4Prefix(cleanIp);
    const v6p = cleanIp.includes(':') ? ipV6Prefix(cleanIp) : null;
    if (v4p) hashes.add(hmacHash(`net:${v4p}`));
    if (v6p) hashes.add(hmacHash(`net:${v6p}`));
  }
  return Array.from(hashes);
}
function getHouseholdAnchor(ip) {
  const clean = normalizeIp(ip);
  const v4 = ipV4Prefix(clean);
  if (v4) return `net:${v4}`;
  if (clean.includes(':')) {
    const v6 = ipV6Prefix(clean);
    if (v6) return `net:${v6}`;
  }
  return `ip:${clean}`; // fallback exact IP
}

// Collect all public IPs we can see across headers (may include both v4 and v6)
function collectClientIps(req) {
  const out = new Set();
  const add = (ip) => {
    ip = normalizeIp(ip);
    if (!ip) return;
    if (/^[0-9a-fA-F:.]+$/.test(ip) && !isPrivateIp(ip)) out.add(ip);
  };
  const hdrs = [
    req.headers['cf-connecting-ip'],
    req.headers['true-client-ip'],
    req.headers['x-vercel-forwarded-for'],
    req.headers['x-forwarded-for'],
  ].filter(Boolean);
  for (const h of hdrs) {
    String(h).split(',').map(s => s.trim()).filter(Boolean).forEach(add);
  }
  if (req.headers['x-real-ip']) add(req.headers['x-real-ip']);
  if (req?.socket?.remoteAddress) add(req.socket.remoteAddress);
  return Array.from(out);
}

// Derive anchors (/24, /64, and exact fallback) from a list of IPs
function anchorsFromIps(ips) {
  const set = new Set();
  for (const ip of ips) {
    const v4p = ipV4Prefix(ip);
    const v6p = ip.includes(':') ? ipV6Prefix(ip) : null;
    if (v4p) set.add(`net:${v4p}`);
    if (v6p) set.add(`net:${v6p}`);
    set.add(`ip:${normalizeIp(ip)}`); // exact fallback
  }
  return Array.from(set);
}

// ----- Visitor identity -----
function getOrCreateVisitorId(req, res) {
  const cookies = parseCookies(req);
  let vid = cookies['ty_vid'];
  if (!vid || !/^[a-z0-9-]{12,}$/.test(vid)) {
    vid = `${Date.now().toString(36)}-${Math.random().toString(36).slice(2,10)}`;
    setCookie(res, 'ty_vid', vid, { maxAgeSec: 365*24*3600, httpOnly: true, sameSite: 'Lax', secure: true });
  }
  return vid;
}
function makeVisitorHash({ mode, vid, hasRealIp, ip, ua }) {
  if (mode === 'cookie') return hmacHash(`vid:${vid}`);
  if (mode === 'ip') {
    const ipBase = hasRealIp ? (HASH_IP_WITH_UA ? `${ip}|${ua}` : ip) : 'noip';
    return hmacHash(`ip:${ipBase}`);
  }
  const ipPart = hasRealIp ? (HASH_IP_WITH_UA ? `${ip}|${ua}` : ip) : 'noip';
  return hmacHash(`vid:${vid}|ip:${ipPart}`);
}

// ----- Shopify GraphQL -----
async function shopifyGraphQL(query, variables) {
  const r = await fetch(`https://${SHOPIFY_SHOP}/admin/api/${API_VERSION}/graphql.json`, {
    method: 'POST',
    headers: { 'X-Shopify-Access-Token': SHOPIFY_ADMIN_TOKEN, 'Content-Type': 'application/json' },
    body: JSON.stringify({ query, variables })
  });
  const data = await r.json().catch(() => ({}));
  return { ok: r.ok, data, status: r.status };
}

// NOTE: this now creates an “Amount off products” discount scoped to the
// “Discount Eligible” collection (DISCOUNT_COLLECTION_ID), 20% off.
async function createDiscountBasic({ code, startsAt, endsAt, percent }) {
  const mutation = `
    mutation discountCodeBasicCreate($basicCodeDiscount: DiscountCodeBasicInput!) {
      discountCodeBasicCreate(basicCodeDiscount: $basicCodeDiscount) {
        codeDiscountNode { id }
        userErrors { field message }
      }
    }`;

  const variables = {
    basicCodeDiscount: {
      title: code,
      startsAt,
      endsAt,
      customerSelection: { all: true },
      async function createDiscountBasic({ code, startsAt, endsAt, percent }) {
  const mutation = `
    mutation discountCodeBasicCreate($basicCodeDiscount: DiscountCodeBasicInput!) {
      discountCodeBasicCreate(basicCodeDiscount: $basicCodeDiscount) {
        codeDiscountNode { id }
        userErrors { field message }
      }
    }`;

  const variables = {
    basicCodeDiscount: {
      title: code,
      startsAt,
      endsAt,
      customerSelection: { all: true },
      customerGets: {
        value: {
          // 20% off products in the collection
          percentage: Math.min(1, Math.max(0, percent / 100)),
        },
        items: {
          collections: {
            // ✅ correct field name
            collectionIds: [DISCOUNT_COLLECTION_ID],
          },
        },
      },
      combinesWith: {
        orderDiscounts: false,
        productDiscounts: true,
        shippingDiscounts: true,
      },
      usageLimit: 1,
      appliesOncePerCustomer: true,
      code,
    },
  };

  const { ok, data, status } = await shopifyGraphQL(mutation, variables);
  if (!ok) throw new Error(`Shopify HTTP ${status}`);
  if (data?.errors?.length) throw new Error(`GraphQL: ${JSON.stringify(data.errors)}`);
  const errs = data?.data?.discountCodeBasicCreate?.userErrors;
  if (errs?.length) {
    const exists = errs.find(e =>
      String(e.message || '').toLowerCase().includes('already exists')
    );
    if (exists) throw new Error('Code collision');
    throw new Error(`Shopify validation: ${JSON.stringify(errs)}`);
  }
  const node = data?.data?.discountCodeBasicCreate?.codeDiscountNode;
  if (!node) throw new Error('No codeDiscountNode returned');
  return node.id;
}
      combinesWith: { orderDiscounts: false, productDiscounts: true, shippingDiscounts: true },
      usageLimit: 1,
      appliesOncePerCustomer: true,
      code
    }
  };

  const { ok, data, status } = await shopifyGraphQL(mutation, variables);
  if (!ok) throw new Error(`Shopify HTTP ${status}`);
  if (data?.errors?.length) throw new Error(`GraphQL: ${JSON.stringify(data.errors)}`);
  const errs = data?.data?.discountCodeBasicCreate?.userErrors;
  if (errs?.length) {
    const exists = errs.find(e => String(e.message || '').toLowerCase().includes('already exists'));
    if (exists) throw new Error('Code collision');
    throw new Error(`Shopify validation: ${JSON.stringify(errs)}`);
  }
  const node = data?.data?.discountCodeBasicCreate?.codeDiscountNode;
  if (!node) throw new Error('No codeDiscountNode returned');
  return node.id;
}

async function deleteDiscountByNodeId(nodeId) {
  const mutation = `
    mutation discountCodeDelete($id: ID!) {
      discountCodeDelete(id: $id) {
        deletedCodeDiscountId
        userErrors { field message }
      }
    }`;
  const { ok, data, status } = await shopifyGraphQL(mutation, { id: nodeId });
  if (!ok) throw new Error(`Shopify HTTP ${status}`);
  const errs = data?.data?.discountCodeDelete?.userErrors;
  if (errs?.length) throw new Error(`Delete validation: ${JSON.stringify(errs)}`);
  return true;
}

// ----- Debug helpers -----
function setDebugHeaders(res, obj = {}) {
  for (const [k, v] of Object.entries(obj)) if (v != null)
    res.setHeader(`X-TY-${k}`, typeof v === 'string' ? v : JSON.stringify(v));
  res.setHeader('Access-Control-Expose-Headers',
    [
      'X-TY-ipKind','X-TY-ipHash','X-TY-ipHashes','X-TY-visitorHash','X-TY-visitorMode',
      'X-TY-householdKey','X-TY-householdKeys','X-TY-activeIpKey','X-TY-activeIpKeys',
      'X-TY-reason','X-TY-kvStyle','X-TY-scope','X-TY-apiVersion','X-TY-shop'
    ].join(', ')
  );
}
function getDebugFlag(req, body) {
  try {
    const url = req.url ? new URL(req.url, 'http://localhost') : null;
    const q = url ? url.searchParams.get('debug') : null;
    const inQuery = q === '1' || q === 'true';
    const inBody  = body && (body.debug === 1 || body.debug === true || body.debug === '1' || body.debug === 'true');
    return Boolean(inQuery || inBody);
  } catch { return false; }
}

// ----- Handler -----
module.exports = async (req, res) => {
  // CORS
  if (req.method === 'OPTIONS') {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
    return res.status(204).end();
  }
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  // Env guard
  try { assertEnvOrThrow(); }
  catch (e) {
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('Access-Control-Allow-Origin', '*');
    setDebugHeaders(res, { reason: 'server_misconfig', error: String(e?.message || e), apiVersion: API_VERSION, shop: SHOPIFY_SHOP, kvStyle: KV_STYLE, scope: ACTIVE_IP_SCOPE });
    return res.status(500).json({ error: 'server_misconfig', message: String(e?.message || e) });
  }

  try {
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('Access-Control-Allow-Origin', '*');

    const body = typeof req.body === 'string' ? JSON.parse(req.body || '{}') : (req.body || {});
    const DEBUG = getDebugFlag(req, body);

    const clientExpiresAtIso = body?.expiresAt;
    const customerIdRaw      = body?.customerId || null;       // optional
    const customerEmailRaw   = body?.customerEmail || null;     // optional

    if (REQUIRE_SIGNED_IN && !customerIdRaw && !customerEmailRaw) {
      setDebugHeaders(res, { reason: 'signin_required', apiVersion: API_VERSION, shop: SHOPIFY_SHOP });
      return res.status(401).json({ error: 'signin_required', reason: 'signin_required' });
    }

    let customerKeyHash = null;
    if (customerIdRaw) customerKeyHash = hmacHash(`id:${String(customerIdRaw).trim()}`);
    else if (customerEmailRaw) customerKeyHash = hmacHash(`email:${String(customerEmailRaw).trim().toLowerCase()}`);

    const now = Date.now();
    const startsAt = new Date(now);
    const serverDefaultEnd = new Date(now + 48 * 3600 * 1000);

    let chosenEndsAt = serverDefaultEnd;
    if (clientExpiresAtIso) {
      const clientEndMs = Date.parse(clientExpiresAtIso);
      if (!Number.isNaN(clientEndMs) && clientEndMs > now && clientEndMs < serverDefaultEnd.getTime()) {
        chosenEndsAt = new Date(clientEndMs);
      }
    }

    // Identity
    const ipInfo    = getClientIpDetailed(req);
    const hasRealIp = ipInfo.kind !== 'pseudo';
    const uaForHash = (req.headers['user-agent'] || '').toString().slice(0, 200);

    // Build active-IP hashes: exact, legacy IP+UA, and optional household (/24 or /64)
    const activeIpHashes = hasRealIp ? buildActiveIpHashes(ipInfo.ip, uaForHash) : [];
    const activeIpKeys   = activeIpHashes.map(h => `ty:ip:${h}`);

    // Monthly windows (YYYYMM label)
    const periodStart = getPeriodStart(now);
    const periodEndsAt = getPeriodEnd(now, PERIOD_MONTHS);
    const ttlSecPeriod = secondsUntil(now, periodEndsAt);
    const cy = periodStart.getUTCFullYear();
    const cm = String(periodStart.getUTCMonth() + 1).padStart(2, '0');
    const periodLabel = `${cy}${cm}`;

    // Household keys: multi-anchor if we have real public IPs; else visitor key
    let houseKeys = [];
    if (hasRealIp) {
      const allIps = collectClientIps(req);
      const anchors = allIps.length ? anchorsFromIps(allIps) : [ getHouseholdAnchor(ipInfo.ip) ];
      houseKeys = anchors.map(a => `ty:month:${PERIOD_MONTHS}m:${periodLabel}:house:${hmacHash(a)}`);
    } else {
      const vid = getOrCreateVisitorId(req, res);
      const visitorHash = makeVisitorHash({ mode: VISITOR_KEY_MODE, vid, hasRealIp, ip: ipInfo.ip, ua: uaForHash });
      houseKeys = [`ty:month:${PERIOD_MONTHS}m:${periodLabel}:visitor:${visitorHash}`];
    }

    // Ever keys (STRICT_ONCE disabled by default)
    const kvKeyEverIp      = hasRealIp ? `ty:ip:ever:${hmacHash(normalizeIp(ipInfo.ip))}` : null;
    const kvKeyCustEver    = customerKeyHash ? `ty:cust:ever:${customerKeyHash}` : null;

    setDebugHeaders(res, {
      ipKind: ipInfo.kind,
      ipHash: activeIpHashes[0],
      ipHashes: activeIpHashes,
      visitorHash: null, // not used for monthly when IP is real
      visitorMode: VISITOR_KEY_MODE,
      householdKey: houseKeys[0],
      householdKeys: houseKeys,
      activeIpKey: activeIpKeys[0],
      activeIpKeys,
      kvStyle: KV_STYLE,
      scope: ACTIVE_IP_SCOPE,
      apiVersion: API_VERSION,
      shop: SHOPIFY_SHOP
    });

    if (!hasRealIp && !customerKeyHash && REQUIRE_REAL_IP_FOR_GUEST) {
      setDebugHeaders(res, { reason: 'no-real-ip-and-guest' });
      return res.status(401).json({ error: 'signin_required', reason: 'no-real-ip-and-guest' });
    }

    // -------- DEBUG (no writes) --------
    if (DEBUG) {
      let existingAct = null, activeHitKey = null;
      for (const k of activeIpKeys) { existingAct = await kvGet(k).catch(()=>null); if (existingAct) { activeHitKey = k; break; } }
      const existingHouses = await Promise.all(houseKeys.map(hk => kvGet(hk).catch(()=>null)));
      const existingEverI = kvKeyEverIp ? await kvGet(kvKeyEverIp).catch(()=>null) : null;
      const existingEverC = kvKeyCustEver ? await kvGet(kvKeyCustEver).catch(()=>null) : null;

      setDebugHeaders(res, { debug: '1', activeHitKey });
      return res.status(200).json({
        ok: true, debug: true,
        keys: { householdKeys: houseKeys, activeIpKeys, kvKeyEverIp, kvKeyCustEver },
        existing: { household: existingHouses, activeIp: existingAct, everIp: existingEverI, everCustomer: existingEverC },
        note: 'No writes performed in debug mode.'
      });
    }
    // no writes happen above this line

    // -------- Active IP reuse (FIRST) --------
    if (hasRealIp && activeIpKeys.length) {
      try {
        for (const k of activeIpKeys) {
          const existing = await kvGet(k);
          if (!existing) continue;
          const existingEnd = Date.parse(existing.endsAt);
          if (existingEnd > now) {
            // Mirror to all active keys INCLUDING net anchors inferred from all visible IPs
            try {
              const allIps  = collectClientIps(req);
              const anchors = anchorsFromIps(allIps);
              const netKeys = anchors.map(a => `ty:ip:${hmacHash(a)}`);
              const allActiveKeys = Array.from(new Set([...activeIpKeys, ...netKeys]));
              const ttlLeft = Math.max(1, Math.ceil((existingEnd - now) / 1000));
              await Promise.all(allActiveKeys.map(mk => kvSetEx(mk, existing, ttlLeft).catch(()=>{})));
            } catch {}
            return res.status(200).json({
              ok: true, reused: true, reason: 'active-ip-reuse',
              code: existing.code, startsAt: existing.startsAt, endsAt: existing.endsAt,
              nodeId: existing.nodeId || null, ipKind: ipInfo.kind, activeKey: k
            });
          }
          if (TY_COOLDOWN_HOURS > 0) {
            const cooldownUntil = existingEnd + TY_COOLDOWN_HOURS * 3600 * 1000;
            if (cooldownUntil > now) {
              return res.status(429).json({
                error: 'rate_limited', reason: 'cooldown-active',
                message: 'Already claimed from your network. Try again later.',
                code: existing.code, endsAt: existing.endsAt,
                cooldownUntil: new Date(cooldownUntil).toISOString(),
                ipKind: ipInfo.kind, activeKey: k
              });
            }
          }
        }
      } catch (e) {
        setDebugHeaders(res, { ipReuseReadError: String(e?.message || e) });
      }
    }

    // -------- STRICT once (optional; OFF by default) --------
    if (STRICT_ONCE) {
      const cookies = parseCookies(req);
      const browserClaimed = cookies['ty_claimed'] === '1';
      if (browserClaimed) return res.status(429).json({ error: 'already_claimed', reason: 'browser-cookie' });
      if (hasRealIp && kvKeyEverIp) {
        const everIp = await kvGet(kvKeyEverIp);
        if (everIp) return res.status(429).json({ error: 'already_claimed', reason: 'ip-ever-lock' });
      }
      if (customerKeyHash && kvKeyCustEver) {
        const everCust = await kvGet(kvKeyCustEver);
        if (everCust) return res.status(429).json({ error: 'already_claimed_customer', reason: 'customer-ever-lock' });
      }
    }

    // -------- MONTHLY RESERVATION (HOUSEHOLD-WIDE, multi-anchor) --------
    const reservePayload = { code: null, marker: 'house-reserve', firstClaimAt: new Date(now).toISOString(), periodEndsAt: periodEndsAt.toISOString(), nodeId: null };

    // reserve on ALL anchors; rollback if any conflict
    const reserved = [];
    for (const hk of houseKeys) {
      try {
        const ok = await kvSetNxEx(hk, reservePayload, ttlSecPeriod);
        reserved.push([hk, ok]);
      } catch (kvErr) {
        // kv outage—rollback any prior reservations
        await Promise.all(reserved.filter(([,ok]) => ok).map(([k]) => kvDel(k).catch(()=>{})));
        setDebugHeaders(res, { reason: 'kv-failure', kvError: String(kvErr?.message || kvErr), kvStyle: KV_STYLE });
        return res.status(500).json({ error: 'kv_unavailable', message: String(kvErr?.message || kvErr) });
      }
    }
    const allOk = reserved.every(([,ok]) => ok);
    if (!allOk) {
      // someone in this household already claimed via another family/prefix
      await Promise.all(reserved.filter(([,ok]) => ok).map(([k]) => kvDel(k).catch(()=>{})));
      // try to fetch an existing record (from the conflicting key if possible)
      const conflictKey = (reserved.find(([,ok]) => !ok) || [houseKeys[0]])[0];
      const existing = await kvGet(conflictKey).catch(()=>null);
      return res.status(429).json({
        error: 'already_claimed_monthly',
        reason: 'monthly-lock-household',
        periodEndsAt: periodEndsAt.toISOString(),
        code: existing?.code || undefined,
        reused: true
      });
    }

    // -------- Mint code via Shopify (48h) --------
    let code = null, nodeId = null;
    try {
      for (let attempt = 1; attempt <= 5; attempt++) {
        const tryCode = genCode('TY');
        try {
          const id = await createDiscountBasic({
            code: tryCode,
            startsAt: startsAt.toISOString(),
            endsAt:   chosenEndsAt.toISOString(),
            percent:  TY_PERCENT
          });
          code = tryCode; nodeId = id; break;
        } catch (err) {
          if (String(err?.message || '').includes('Code collision')) continue;
          throw err;
        }
      }
      if (!code) throw new Error('Failed to create discount code');
    } catch (err) {
      // rollback reservations on failure
      await Promise.all(houseKeys.map(hk => kvDel(hk).catch(()=>{})));
      return res.status(502).json({ error: 'Failed to create discount code', message: String(err?.message || err) });
    }

    // Persist monthly (household) with TTL to end-of-period
    const monthlyRecord = { code, nodeId, firstClaimAt: new Date(now).toISOString(), periodEndsAt: periodEndsAt.toISOString() };
    await Promise.all(houseKeys.map(hk => kvSetEx(hk, monthlyRecord, ttlSecPeriod)));

    // Race defense (extremely rare): if any key got a different code, revoke the fresh mint
    const checkHouses = await Promise.all(houseKeys.map(hk => kvGet(hk).catch(()=>null)));
    const mismatch = checkHouses.find(r => r && r.code && r.code !== code);
    if (mismatch) {
      try { await deleteDiscountByNodeId(nodeId); } catch {}
      return res.status(429).json({
        error: 'already_claimed_monthly',
        reason: 'monthly-lock-race',
        periodEndsAt: periodEndsAt.toISOString(),
        code: mismatch.code, revokedNewMint: true, reused: true, ipKind: ipInfo.kind
      });
    }

    // Active IP lock through expiry (+ cooldown if any) — write to all active keys (exact, legacy, + net anchors)
    if (hasRealIp) {
      const allIps  = collectClientIps(req);
      const anchors = anchorsFromIps(allIps);
      const netActiveKeys = anchors.map(a => `ty:ip:${hmacHash(a)}`);
      const allActiveKeys = Array.from(new Set([...(activeIpKeys || []), ...netActiveKeys]));

      const ttlSecActive =
        Math.max(1, Math.ceil((chosenEndsAt.getTime() - now) / 1000)) +
        Math.max(0, Math.floor(TY_COOLDOWN_HOURS * 3600));
      const payload = { code, startsAt: startsAt.toISOString(), endsAt: chosenEndsAt.toISOString(), nodeId };

      await Promise.all(allActiveKeys.map(k =>
        kvSetEx(k, payload, ttlSecActive).catch(e => setDebugHeaders(res, { ipWriteWarn: String(e?.message || e), ipKey: k }))
      ));
    }

    // Optional "once ever"
    if (STRICT_ONCE && hasRealIp && kvKeyEverIp) {
      await kvSetExDays(kvKeyEverIp, { code, firstClaimAt: startsAt.toISOString(), endsAt: chosenEndsAt.toISOString(), nodeId }, EVER_TTL_DAYS);
      if (customerKeyHash && kvKeyCustEver) {
        await kvSetExDays(kvKeyCustEver, { code, firstClaimAt: startsAt.toISOString(), endsAt: chosenEndsAt.toISOString(), nodeId }, EVER_TTL_DAYS);
      }
    }

    // Soft browser cookie (purely UX)
    const cookieMaxAge = Math.max(1, Math.ceil((chosenEndsAt.getTime() - now) / 1000));
    setCookie(res, 'ty_claimed', '1', { maxAgeSec: cookieMaxAge });

    setDebugHeaders(res, { reason: 'minted', code, nodeId, endsAt: chosenEndsAt.toISOString(), ipKind: ipInfo.kind, apiVersion: API_VERSION, kvStyle: KV_STYLE, scope: ACTIVE_IP_SCOPE, shop: SHOPIFY_SHOP });

    return res.status(200).json({
      ok: true, reason: 'minted',
      code, startsAt: startsAt.toISOString(), endsAt: chosenEndsAt.toISOString(),
      nodeId,
      householdLimitedByMonths: PERIOD_MONTHS,
      ipKind: ipInfo.kind
    });

  } catch (e) {
    console.error('Unhandled error creating discount', e);
    setDebugHeaders(res, { reason: 'server-error', error: String(e?.message || e), apiVersion: API_VERSION, scope: ACTIVE_IP_SCOPE, shop: SHOPIFY_SHOP });
    return res.status(500).json({ error: 'Unhandled error', message: e?.message || String(e) });
  }
};

// Helper to find client IP info
function getClientIpDetailed(req) {
  const pick = v => (typeof v === 'string' && v.trim()) ? v.trim() : '';
  const cf  = pick(req.headers['cf-connecting-ip']);        if (cf)  return { ip: cf.replace(/^::ffff:/,''), kind: 'cf'  };
  const tci = pick(req.headers['true-client-ip']);          if (tci) return { ip: tci.replace(/^::ffff:/,''), kind: 'tci' };
  const vff = pick(req.headers['x-vercel-forwarded-for']);  if (vff) return { ip: vff.split(',')[0].trim().replace(/^::ffff:/, ''), kind: 'vff' };
  const xff = pick(req.headers['x-forwarded-for']);
  if (xff) {
    const parts = xff.split(',')
      .map(s => s.trim())
      .filter(Boolean)
      .map(s => s.replace(/^::ffff:/, ''))
      .filter(s => /^[0-9a-fA-F:.]+$/.test(s)); // keep only IP-ish strings
    for (const ip of parts) { if (!isPrivateIp(ip)) return { ip, kind: 'xff' }; }
    if (parts.length) return { ip: parts[0], kind: 'xff' };
  }
  const xr = pick(req.headers['x-real-ip']);                if (xr)  return { ip: xr.replace(/^::ffff:/, ''), kind: 'xr' };
  const sock = pick(req.socket?.remoteAddress);             if (sock) return { ip: sock.replace(/^::ffff:/, ''), kind: 'sock' };
  return { ip: 'pseudo', kind: 'pseudo' };
}
