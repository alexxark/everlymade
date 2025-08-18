// api/thankyouclaim.js — CommonJS (Vercel /api/*)
// Layers of protection:
// 1) Browser cookie lock (same browser)
// 2) IP active lock + optional cooldown (same network)
// 3) Per-customer monthly limit (if signed-in)
// 4) Per-guest monthly limit (if NOT signed-in) — NEW
// 5) Optional "ever" strict-once across IP/browser/customer
//
// ENV VARS to set (most you already have):
//   SHOPIFY_SHOP, SHOPIFY_ADMIN_TOKEN
//   UPSTASH_REDIS_REST_URL, UPSTASH_REDIS_REST_TOKEN
//   IP_HASH_SALT (long random string)
//   TY_PERCENT (default 20), TY_COOLDOWN_HOURS (default 0)
//   PERIOD_MONTHS (default 1)                  // once-per-month window
//   REQUIRE_SIGNED_IN=true|false (default false)
//   STRICT_ONCE=true|false (default false)     // hard "once ever"
//   EVER_TTL_DAYS=0                            // 0=persist ever lock; or N days

const crypto = require('crypto');

const SHOPIFY_SHOP        = process.env.SHOPIFY_SHOP;
const SHOPIFY_ADMIN_TOKEN = process.env.SHOPIFY_ADMIN_TOKEN;
const API_VERSION         = '2025-07';

// Upstash Redis REST
const UPSTASH_URL   = process.env.UPSTASH_REDIS_REST_URL;
const UPSTASH_TOKEN = process.env.UPSTASH_REDIS_REST_TOKEN;

const IP_HASH_SALT      = process.env.IP_HASH_SALT || 'change-me-long-random-salt';
const TY_PERCENT        = parseFloat(process.env.TY_PERCENT || '20') || 20;
const TY_COOLDOWN_HOURS = parseFloat(process.env.TY_COOLDOWN_HOURS || '0') || 0;

const PERIOD_MONTHS     = Math.max(1, parseInt(process.env.PERIOD_MONTHS || '1', 10));
const REQUIRE_SIGNED_IN = String(process.env.REQUIRE_SIGNED_IN || 'false').toLowerCase() === 'true';

const STRICT_ONCE   = String(process.env.STRICT_ONCE || 'false').toLowerCase() === 'true';
const EVER_TTL_DAYS = parseFloat(process.env.EVER_TTL_DAYS || '0') || 0; // 0 => persist (no TTL)

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

async function kvSet(key, value) {
  if (!UPSTASH_URL || !UPSTASH_TOKEN) return false;
  const url = `${UPSTASH_URL}/set/${encodeURIComponent(key)}/${encodeURIComponent(JSON.stringify(value))}`;
  const r = await fetch(url, { method: 'POST', headers: { Authorization: `Bearer ${UPSTASH_TOKEN}` }});
  return r.ok;
}

async function kvSetExDays(key, value, days) {
  if (days <= 0) return kvSet(key, value); // persist (no TTL)
  const ttlSeconds = Math.floor(days * 86400);
  return kvSetEx(key, value, ttlSeconds);
}

// ---- Utils ----
function genCode(prefix = 'TY') {
  let slug = Math.random().toString(36).slice(2, 6).toUpperCase();
  while (slug.length < 4) slug += '0';
  slug = slug.slice(0, 4);
  return `${prefix}-${slug}`;
}

function getClientIp(req) {
  const xf = req.headers['x-forwarded-for'];
  if (typeof xf === 'string' && xf.length) return xf.split(',')[0].trim();
  return req.headers['x-real-ip'] || req.socket?.remoteAddress || '0.0.0.0';
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

// period helpers: month windows (calendar months)
function addMonths(date, n) {
  const d = new Date(date);
  const month = d.getMonth();
  d.setMonth(month + n);
  if (d.getMonth() !== ((month + n) % 12 + 12) % 12) d.setDate(0); // clamp overflow
  return d;
}
function getPeriodStart(now) {
  const start = new Date(now);
  start.setUTCDate(1); start.setUTCHours(0,0,0,0);
  return start;
}
function getPeriodEnd(now, months) {
  return addMonths(getPeriodStart(now), months); // exclusive bound
}
function secondsUntil(dateFromMs, dateTo) {
  const ms = Math.max(0, dateTo.getTime() - dateFromMs);
  return Math.ceil(ms / 1000);
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
    const clientExpiresAtIso = body?.expiresAt; // from front-end timer/localStorage
    const customerIdRaw      = body?.customerId || null;     // Shopify numeric ID or GID
    const customerEmailRaw   = body?.customerEmail || null;  // fallback if no ID

    const cookies = parseCookies(req);
    const browserClaimed = cookies['ty_claimed'] === '1';

    // Optional: require login
    if (REQUIRE_SIGNED_IN && !customerIdRaw && !customerEmailRaw) {
      return res.status(401).json({
        error: 'signin_required',
        message: 'Please sign in to claim this offer.'
      });
    }

    // Normalize / hash customer identity for privacy in Redis
    let customerKeyHash = null;
    if (customerIdRaw) customerKeyHash = hmacHash(`id:${String(customerIdRaw).trim()}`);
    else if (customerEmailRaw) customerKeyHash = hmacHash(`email:${String(customerEmailRaw).trim().toLowerCase()}`);

    const now = Date.now();
    const startsAt = new Date(now);

    // Default server window = 48h from now
    const serverDefaultEnd = new Date(now + 48 * 60 * 60 * 1000);

    // Honor earlier client expiry (grab old timer)
    let chosenEndsAt = serverDefaultEnd;
    if (clientExpiresAtIso) {
      const clientEndMs = Date.parse(clientExpiresAtIso);
      if (!Number.isNaN(clientEndMs) && clientEndMs > now && clientEndMs < serverDefaultEnd.getTime()) {
        chosenEndsAt = new Date(clientEndMs);
      }
    }

    // ---- Keys ----
    const ip = getClientIp(req);
    const ipHash = hmacHash(ip);

    // Period window (same for all, used for per-customer and per-guest limits)
    const periodStart = getPeriodStart(now);
    const periodEndsAt = getPeriodEnd(now, PERIOD_MONTHS);
    const cy = periodStart.getUTCFullYear();
    const cm = String(periodStart.getUTCMonth() + 1).padStart(2, '0'); // current period label
    const periodLabel = `${cy}${cm}`;

    const kvKeyActiveIp   = `ty:ip:${ipHash}`;                          // active IP window (48h)
    const kvKeyEverIp     = `ty:ip:ever:${ipHash}`;                     // optional strict-ever IP
    const kvKeyCustPeriod = customerKeyHash ? `ty:cust:period:${PERIOD_MONTHS}m:${periodLabel}:${customerKeyHash}` : null;
    const kvKeyCustEver   = customerKeyHash ? `ty:cust:ever:${customerKeyHash}` : null;

    // NEW: guest monthly key (only when NOT signed-in)
    const isGuest = !customerKeyHash;
    const kvKeyGuestPeriod = isGuest ? `ty:guest:period:${PERIOD_MONTHS}m:${periodLabel}:${ipHash}` : null;

    // ---- STRICT once guards ----
    if (STRICT_ONCE) {
      if (browserClaimed) {
        return res.status(429).json({
          error: 'already_claimed',
          message: 'This offer was already claimed from this browser.'
        });
      }
      const everIp = await kvGet(kvKeyEverIp);
      if (everIp) {
        return res.status(429).json({
          error: 'already_claimed',
          message: 'This offer was already claimed from your network.'
        });
      }
      if (customerKeyHash) {
        const everCust = await kvGet(kvKeyCustEver);
        if (everCust) {
          return res.status(429).json({
            error: 'already_claimed_customer',
            message: 'This offer was already claimed on this customer account.'
          });
        }
      }
    }

    // ---- Monthly checks (run BEFORE active-window reuse) ----
    // Signed-in customers: per-customer period limit
    if (customerKeyHash && kvKeyCustPeriod) {
      const custPeriod = await kvGet(kvKeyCustPeriod);
      if (custPeriod) {
        return res.status(429).json({
          error: 'already_claimed_monthly',
          message: 'You have already claimed this offer for the current period.',
          periodEndsAt: periodEndsAt.toISOString(),
          code: custPeriod.code || undefined,
          reused: true
        });
      }
    }
    // Guests: per-IP period limit (NEW)
    if (isGuest && kvKeyGuestPeriod) {
      const guestPeriod = await kvGet(kvKeyGuestPeriod);
      if (guestPeriod) {
        return res.status(429).json({
          error: 'already_claimed_monthly',
          message: 'You have already claimed this offer for the current period.',
          periodEndsAt: periodEndsAt.toISOString(),
          code: guestPeriod.code || undefined,
          reused: true
        });
      }
    }

    // ---- Active IP lock (reuse if still active; cooldown if set) ----
    const existing = await kvGet(kvKeyActiveIp);
    if (existing) {
      const existingEnd = Date.parse(existing.endsAt);
      if (existingEnd > now) {
        // still active: return same code and endsAt
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
          title: tryCode,
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

    // ---- Save locks + set cookie ----

    // Active IP lock TTL = time until chosenEndsAt + optional cooldown
    const ttlSecActive =
      Math.max(1, Math.ceil((chosenEndsAt.getTime() - now) / 1000)) +
      Math.max(0, Math.floor(TY_COOLDOWN_HOURS * 3600));

    await kvSetEx(kvKeyActiveIp, {
      code,
      startsAt: startsAt.toISOString(),
      endsAt:   chosenEndsAt.toISOString(),
      nodeId
    }, ttlSecActive);

    // Ever-claimed locks (if STRICT_ONCE)
    if (STRICT_ONCE) {
      await kvSetExDays(kvKeyEverIp, {
        code, firstClaimAt: startsAt.toISOString(), endsAt: chosenEndsAt.toISOString(), nodeId
      }, EVER_TTL_DAYS);
      if (customerKeyHash) {
        await kvSetExDays(kvKeyCustEver, {
          code, firstClaimAt: startsAt.toISOString(), endsAt: chosenEndsAt.toISOString(), nodeId
        }, EVER_TTL_DAYS);
      }
    }

    // Per-customer monthly lock (if signed-in)
    if (customerKeyHash && kvKeyCustPeriod) {
      const ttlSecPeriod = secondsUntil(now, periodEndsAt);
      await kvSetEx(kvKeyCustPeriod, {
        code,
        customerKeyHash,
        periodEndsAt: periodEndsAt.toISOString(),
        firstClaimAt: startsAt.toISOString(),
        nodeId
      }, Math.max(1, ttlSecPeriod));
    }

    // Per-guest monthly lock (NEW)
    if (isGuest && kvKeyGuestPeriod) {
      const ttlSecPeriod = secondsUntil(now, periodEndsAt);
      await kvSetEx(kvKeyGuestPeriod, {
        code,
        ipHash,
        periodEndsAt: periodEndsAt.toISOString(),
        firstClaimAt: startsAt.toISOString(),
        nodeId
      }, Math.max(1, ttlSecPeriod));
    }

    // Browser cookie: block same browser from minting again (matches active IP window; strict -> long)
    const cookieMaxAge = STRICT_ONCE ? 10 * 365 * 24 * 3600 : ttlSecActive;
    setCookie(res, 'ty_claimed', '1', { maxAgeSec: cookieMaxAge });

    // Success
    return res.status(200).json({
      ok: true,
      code,
      startsAt: startsAt.toISOString(),
      endsAt:   chosenEndsAt.toISOString(),
      nodeId,
      customerLimitedByMonths: customerKeyHash ? PERIOD_MONTHS : undefined,
      guestLimitedByMonths: isGuest ? PERIOD_MONTHS : undefined
    });
  } catch (e) {
    console.error('Unhandled error creating discount', e);
    return res.status(500).json({ error: 'Unhandled error', message: e?.message || String(e) });
  }
};
