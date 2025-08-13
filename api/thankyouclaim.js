// api/thankyouclaim.js — CommonJS (Vercel /api/*)
// - One active code per IP (Upstash Redis lock)
// - Honors a *client-provided* earlier expiresAt (grabs old timer)
// - Codes shaped like TY-####

const crypto = require('crypto');

const SHOPIFY_SHOP        = process.env.SHOPIFY_SHOP;               // e.g. charmsforchange.myshopify.com
const SHOPIFY_ADMIN_TOKEN = process.env.SHOPIFY_ADMIN_TOKEN;        // shpat_...
const API_VERSION         = '2025-07';

// Upstash Redis REST
const UPSTASH_URL   = process.env.UPSTASH_REDIS_REST_URL;
const UPSTASH_TOKEN = process.env.UPSTASH_REDIS_REST_TOKEN;

const IP_HASH_SALT      = process.env.IP_HASH_SALT || 'change-me-long-random-salt';
const TY_PERCENT        = parseFloat(process.env.TY_PERCENT || '20') || 20; // percentage number, e.g. 20
const TY_COOLDOWN_HOURS = parseFloat(process.env.TY_COOLDOWN_HOURS || '0') || 0; // hours after expiry

// ---- Redis helpers ----
async function kvGet(key) {
  if (!UPSTASH_URL || !UPSTASH_TOKEN) return null;
  const r = await fetch(`${UPSTASH_URL}/get/${encodeURIComponent(key)}`, {
    headers: { Authorization: `Bearer ${UPSTASH_TOKEN}` },
    cache: 'no-store',
  });
  if (!r.ok) return null;
  const data = await r.json().catch(() => null);
  return data?.result ? JSON.parse(data.result) : null;
}

async function kvSetEx(key, value, ttlSeconds) {
  if (!UPSTASH_URL || !UPSTASH_TOKEN) return false;
  const url = `${UPSTASH_URL}/set/${encodeURIComponent(key)}/${encodeURIComponent(
    JSON.stringify(value)
  )}?EX=${encodeURIComponent(ttlSeconds)}`;
  const r = await fetch(url, {
    method: 'POST',
    headers: { Authorization: `Bearer ${UPSTASH_TOKEN}` },
  });
  return r.ok;
}

// ---- Utils ----

// Make TY-#### (4 base36 uppercase)
function genCode(prefix = 'TY') {
  let slug = Math.random().toString(36).slice(2, 6).toUpperCase();
  // ensure exactly 4 chars (fallback)
  while (slug.length < 4) slug += '0';
  slug = slug.slice(0, 4);
  return `${prefix}-${slug}`;
}

function getClientIp(req) {
  const xf = req.headers['x-forwarded-for'];
  if (typeof xf === 'string' && xf.length) return xf.split(',')[0].trim();
  return req.headers['x-real-ip'] || req.socket?.remoteAddress || '0.0.0.0';
}

function hashIp(ip) {
  return crypto.createHmac('sha256', IP_HASH_SALT).update(ip).digest('hex');
}

module.exports = async (req, res) => {
  // CORS preflight
  if (req.method === 'OPTIONS') {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
    return res.status(204).end();
  }
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  try {
    res.setHeader('Access-Control-Allow-Origin', '*');

    // Parse request
    const body = typeof req.body === 'string' ? JSON.parse(req.body || '{}') : (req.body || {});
    const clientExpiresAtIso = body?.expiresAt; // from your front-end timer/localStorage

    const now = Date.now();
    const startsAt = new Date(now);

    // Default server window = 48h from now
    const serverDefaultEnd = new Date(now + 48 * 60 * 60 * 1000);

    // If client sent a valid *earlier* expiry, honor it (grab old timer)
    let chosenEndsAt = serverDefaultEnd;
    if (clientExpiresAtIso) {
      const clientEndMs = Date.parse(clientExpiresAtIso);
      if (!Number.isNaN(clientEndMs) && clientEndMs > now && clientEndMs < serverDefaultEnd.getTime()) {
        chosenEndsAt = new Date(clientEndMs);
      }
    }

    // ---- IP lock ----
    const ip = getClientIp(req);
    const ipHash = hashIp(ip);
    const kvKey = `ty:ip:${ipHash}`;

    const existing = await kvGet(kvKey);
    if (existing) {
      const existingEnd = Date.parse(existing.endsAt);
      if (existingEnd > now) {
        // still active: return same code and the original endsAt (keeps timer consistent)
        return res.status(200).json({
          ok: true,
          code:     existing.code,
          startsAt: existing.startsAt,
          endsAt:   existing.endsAt,
          nodeId:   existing.nodeId || null,
          reused:   true,
        });
      }
      // Optional cooldown after expiry
      if (TY_COOLDOWN_HOURS > 0) {
        const cooldownUntil = existingEnd + TY_COOLDOWN_HOURS * 3600 * 1000;
        if (cooldownUntil > now) {
          return res.status(429).json({
            error: 'rate_limited',
            message: 'This offer was already claimed from your network. Try again later.',
            code: existing.code,
            endsAt: existing.endsAt,
            cooldownUntil: new Date(cooldownUntil).toISOString(),
          });
        }
      }
    }

    // ---- Create Shopify discount (new code) ----
    let lastErr = null;
    let code = null;
    let nodeId = null;

    for (let attempt = 1; attempt <= 5; attempt++) {
      const tryCode = genCode('TY');

      const mutation = `
        mutation discountCodeBasicCreate($basicCodeDiscount: DiscountCodeBasicInput!) {
          discountCodeBasicCreate(basicCodeDiscount: $basicCodeDiscount) {
            codeDiscountNode { id }
            userErrors { field message }
          }
        }
      `;

      const variables = {
        basicCodeDiscount: {
          title: tryCode,                                 // Title == code (clean)
          startsAt: startsAt.toISOString(),
          endsAt:   chosenEndsAt.toISOString(),

          customerSelection: { all: true },

          customerGets: {
            value: { percentage: Math.min(1, Math.max(0, TY_PERCENT / 100)) },
            items: { all: true }
          },

          combinesWith: {
            orderDiscounts: false,
            productDiscounts: true,
            shippingDiscounts: true
          },

          usageLimit: 1,
          appliesOncePerCustomer: true,

          code: tryCode
        }
      };

      const r = await fetch(`https://${SHOPIFY_SHOP}/admin/api/${API_VERSION}/graphql.json`, {
        method: 'POST',
        headers: {
          'X-Shopify-Access-Token': SHOPIFY_ADMIN_TOKEN,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ query: mutation, variables })
      });

      const data = await r.json().catch(() => ({}));

      if (!r.ok) { lastErr = new Error(`Shopify HTTP ${r.status}`); continue; }
      if (data?.errors?.length) { lastErr = new Error(`GraphQL: ${JSON.stringify(data.errors)}`); continue; }

      const errs = data?.data?.discountCodeBasicCreate?.userErrors;
      if (errs?.length) {
        const existsErr = errs.find(e => String(e.message || '').toLowerCase().includes('already exists'));
        if (existsErr) { lastErr = new Error('Code collision, retrying…'); continue; }
        return res.status(400).json({ error: 'Shopify validation error', userErrors: errs });
      }

      const node = data?.data?.discountCodeBasicCreate?.codeDiscountNode;
      if (!node) { lastErr = new Error('No codeDiscountNode returned'); continue; }

      code   = tryCode;
      nodeId = node.id;
      break;
    }

    if (!code) {
      console.error('Failed to create code', lastErr);
      return res.status(502).json({ error: 'Failed to create discount code' });
    }

    // Save IP lock: TTL = time until chosenEndsAt + optional cooldown
    const ttlSec =
      Math.max(1, Math.ceil((chosenEndsAt.getTime() - now) / 1000)) +
      Math.max(0, Math.floor(TY_COOLDOWN_HOURS * 3600));

    await kvSetEx(kvKey, {
      code,
      startsAt: startsAt.toISOString(),
      endsAt:   chosenEndsAt.toISOString(),
      nodeId
    }, ttlSec);

    return res.status(200).json({
      ok: true,
      code,
      startsAt: startsAt.toISOString(),
      endsAt:   chosenEndsAt.toISOString(),
      nodeId
    });
  } catch (e) {
    console.error('Unhandled error creating discount', e);
    return res.status(500).json({ error: 'Unhandled error', message: e?.message || String(e) });
  }
};
