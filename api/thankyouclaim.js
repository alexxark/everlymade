// api/thankyouclaim.js — CommonJS serverless function (Vercel /api/*)
// - One active code per IP (plus your existing localStorage guard)
// - Upstash Redis via REST (no extra npm deps)
// api/thankyouclaim.js — CommonJS (Vercel /api/*)
// - One active code per IP (Upstash Redis lock)
// - Honors a *client-provided* earlier expiresAt (grabs old timer)
// - Codes shaped like TY-####

const crypto = require('crypto');

const SHOPIFY_SHOP         = process.env.SHOPIFY_SHOP;               // e.g. charmsforchange.myshopify.com
const SHOPIFY_ADMIN_TOKEN  = process.env.SHOPIFY_ADMIN_TOKEN;        // shpat_...
const API_VERSION          = '2025-07';
const SHOPIFY_SHOP        = process.env.SHOPIFY_SHOP;               // e.g. charmsforchange.myshopify.com
const SHOPIFY_ADMIN_TOKEN = process.env.SHOPIFY_ADMIN_TOKEN;        // shpat_...
const API_VERSION         = '2025-07';

// Upstash Redis (REST)
// Upstash Redis REST
const UPSTASH_URL   = process.env.UPSTASH_REDIS_REST_URL;
const UPSTASH_TOKEN = process.env.UPSTASH_REDIS_REST_TOKEN;

// Env options
const IP_HASH_SALT       = process.env.IP_HASH_SALT || 'change-me-long-random-salt';
const TY_PERCENT         = parseFloat(process.env.TY_PERCENT || '20') || 20;  // e.g. "20"
const TY_COOLDOWN_HOURS  = parseFloat(process.env.TY_COOLDOWN_HOURS || '0') || 0; // hours after expiry
const IP_HASH_SALT      = process.env.IP_HASH_SALT || 'change-me-long-random-salt';
const TY_PERCENT        = parseFloat(process.env.TY_PERCENT || '20') || 20; // percentage number, e.g. 20
const TY_COOLDOWN_HOURS = parseFloat(process.env.TY_COOLDOWN_HOURS || '0') || 0; // hours after expiry

// ---- Upstash helpers (REST) ----
// ---- Redis helpers ----
async function kvGet(key) {
if (!UPSTASH_URL || !UPSTASH_TOKEN) return null;
const r = await fetch(`${UPSTASH_URL}/get/${encodeURIComponent(key)}`, {
@@ -31,18 +31,24 @@ async function kvGet(key) {

async function kvSetEx(key, value, ttlSeconds) {
if (!UPSTASH_URL || !UPSTASH_TOKEN) return false;
  // Upstash expects the value in the path and TTL via ?EX=
  const url = `${UPSTASH_URL}/set/${encodeURIComponent(key)}/${encodeURIComponent(JSON.stringify(value))}?EX=${encodeURIComponent(ttlSeconds)}`;
  const url = `${UPSTASH_URL}/set/${encodeURIComponent(key)}/${encodeURIComponent(
    JSON.stringify(value)
  )}?EX=${encodeURIComponent(ttlSeconds)}`;
const r = await fetch(url, {
method: 'POST',
headers: { Authorization: `Bearer ${UPSTASH_TOKEN}` },
});
return r.ok;
}

// ---- Utility helpers ----
// ---- Utils ----

// Make TY-#### (4 base36 uppercase)
function genCode(prefix = 'TY') {
  const slug = Math.random().toString(36).slice(2, 10).toUpperCase(); // 8 chars → very low collision
  let slug = Math.random().toString(36).slice(2, 6).toUpperCase();
  // ensure exactly 4 chars (fallback)
  while (slug.length < 4) slug += '0';
  slug = slug.slice(0, 4);
return `${prefix}-${slug}`;
}

@@ -69,38 +75,48 @@ module.exports = async (req, res) => {
try {
res.setHeader('Access-Control-Allow-Origin', '*');

    // Parse body + compute the desired expiry window
    // Parse request
const body = typeof req.body === 'string' ? JSON.parse(req.body || '{}') : (req.body || {});
    const { expiresAt } = body;
    const clientExpiresAtIso = body?.expiresAt; // from your front-end timer/localStorage

    const now = Date.now();
    const startsAt = new Date(now);

    // Default server window = 48h from now
    const serverDefaultEnd = new Date(now + 48 * 60 * 60 * 1000);

    const startsAt = new Date();
    const endsAt   = expiresAt ? new Date(expiresAt) : new Date(startsAt.getTime() + 48 * 60 * 60 * 1000);
    const nowMs    = Date.now();
    // If client sent a valid *earlier* expiry, honor it (grab old timer)
    let chosenEndsAt = serverDefaultEnd;
    if (clientExpiresAtIso) {
      const clientEndMs = Date.parse(clientExpiresAtIso);
      if (!Number.isNaN(clientEndMs) && clientEndMs > now && clientEndMs < serverDefaultEnd.getTime()) {
        chosenEndsAt = new Date(clientEndMs);
      }
    }

    // ---- IP lock: check for existing active code for this IP ----
    const ip     = getClientIp(req);
    // ---- IP lock ----
    const ip = getClientIp(req);
const ipHash = hashIp(ip);
    const kvKey  = `ty:ip:${ipHash}`;
    const kvKey = `ty:ip:${ipHash}`;

const existing = await kvGet(kvKey);

if (existing) {
const existingEnd = Date.parse(existing.endsAt);
      if (existingEnd > nowMs) {
        // Still active → return the same code (no new Shopify mutation)
      if (existingEnd > now) {
        // still active: return same code and the original endsAt (keeps timer consistent)
return res.status(200).json({
ok: true,
code:     existing.code,
startsAt: existing.startsAt,
endsAt:   existing.endsAt,
nodeId:   existing.nodeId || null,
          reused:   true
          reused:   true,
});
}
// Optional cooldown after expiry
if (TY_COOLDOWN_HOURS > 0) {
const cooldownUntil = existingEnd + TY_COOLDOWN_HOURS * 3600 * 1000;
        if (cooldownUntil > nowMs) {
        if (cooldownUntil > now) {
return res.status(429).json({
error: 'rate_limited',
message: 'This offer was already claimed from your network. Try again later.',
@@ -112,8 +128,7 @@ module.exports = async (req, res) => {
}
}

    // ---- Create a Shopify discount (new code) ----
    // Retry a few times in the unlikely event of a collision or transient error
    // ---- Create Shopify discount (new code) ----
let lastErr = null;
let code = null;
let nodeId = null;
@@ -132,14 +147,14 @@ module.exports = async (req, res) => {

const variables = {
basicCodeDiscount: {
          title: tryCode, // admin title = code (no "Thank you" prefix)
          title: tryCode,                                 // Title == code (clean)
startsAt: startsAt.toISOString(),
          endsAt:   endsAt.toISOString(),
          endsAt:   chosenEndsAt.toISOString(),

customerSelection: { all: true },

customerGets: {
            value: { percentage: Math.min(1, Math.max(0, TY_PERCENT / 100)) }, // decimal 0–1
            value: { percentage: Math.min(1, Math.max(0, TY_PERCENT / 100)) },
items: { all: true }
},

@@ -167,34 +182,19 @@ module.exports = async (req, res) => {

const data = await r.json().catch(() => ({}));

      if (!r.ok) {
        lastErr = new Error(`Shopify HTTP ${r.status}`);
        continue;
      }

      if (data?.errors?.length) {
        lastErr = new Error(`GraphQL: ${JSON.stringify(data.errors)}`);
        continue;
      }
      if (!r.ok) { lastErr = new Error(`Shopify HTTP ${r.status}`); continue; }
      if (data?.errors?.length) { lastErr = new Error(`GraphQL: ${JSON.stringify(data.errors)}`); continue; }

const errs = data?.data?.discountCodeBasicCreate?.userErrors;
if (errs?.length) {
        // If code already exists, retry; otherwise bail with validation error
const existsErr = errs.find(e => String(e.message || '').toLowerCase().includes('already exists'));
        if (existsErr) {
          lastErr = new Error('Code collision, retrying…');
          continue;
        }
        if (existsErr) { lastErr = new Error('Code collision, retrying…'); continue; }
return res.status(400).json({ error: 'Shopify validation error', userErrors: errs });
}

const node = data?.data?.discountCodeBasicCreate?.codeDiscountNode;
      if (!node) {
        lastErr = new Error('No codeDiscountNode returned');
        continue;
      }
      if (!node) { lastErr = new Error('No codeDiscountNode returned'); continue; }

      // Success
code   = tryCode;
nodeId = node.id;
break;
@@ -205,23 +205,23 @@ module.exports = async (req, res) => {
return res.status(502).json({ error: 'Failed to create discount code' });
}

    // Save to Redis (TTL = time until expiry + optional cooldown)
    // Save IP lock: TTL = time until chosenEndsAt + optional cooldown
const ttlSec =
      Math.max(1, Math.ceil((Date.parse(endsAt) - nowMs) / 1000)) +
      Math.max(1, Math.ceil((chosenEndsAt.getTime() - now) / 1000)) +
Math.max(0, Math.floor(TY_COOLDOWN_HOURS * 3600));

await kvSetEx(kvKey, {
code,
startsAt: startsAt.toISOString(),
      endsAt:   endsAt.toISOString(),
      endsAt:   chosenEndsAt.toISOString(),
nodeId
}, ttlSec);

return res.status(200).json({
ok: true,
code,
startsAt: startsAt.toISOString(),
      endsAt:   endsAt.toISOString(),
      endsAt:   chosenEndsAt.toISOString(),
nodeId
});
} catch (e) {
