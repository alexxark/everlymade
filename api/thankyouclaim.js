// api/thankyouclaim.js — CommonJS (Vercel /api/*)
// Protections:
// 1) Browser cookie lock (same browser)
// 2) IP active lock + optional cooldown (same network)
// 3) Per-customer monthly limit (signed-in) — ATOMIC (NX)
// 4) Per-guest monthly limit (not signed-in) — ATOMIC (NX)
// 5) Signed-in mint mirrors a guest/IP monthly key (blocks browser-swap)
// 6) Optional "ever" strict-once across IP/browser/customer
// 7) Cross-check + rollback: if a conflicting monthly record is found AFTER mint,
//    delete the new Shopify discount and return 429 already_claimed_monthly with
//    { revokedNewMint: true } so the front-end hides/cancels it.
//
// ENV VARS:
//   SHOPIFY_SHOP, SHOPIFY_ADMIN_TOKEN
//   UPSTASH_REDIS_REST_URL, UPSTASH_REDIS_REST_TOKEN
//   IP_HASH_SALT
//   TY_PERCENT (default 20), TY_COOLDOWN_HOURS (default 0)
//   PERIOD_MONTHS (default 1)  // calendar months
//   REQUIRE_SIGNED_IN (default false)
//   STRICT_ONCE (default false), EVER_TTL_DAYS (default 0)

const crypto = require('crypto');

const SHOPIFY_SHOP        = process.env.SHOPIFY_SHOP;
const SHOPIFY_ADMIN_TOKEN = process.env.SHOPIFY_ADMIN_TOKEN;
const API_VERSION         = '2025-07';

const UPSTASH_URL   = process.env.UPSTASH_REDIS_REST_URL;
const UPSTASH_TOKEN = process.env.UPSTASH_REDIS_REST_TOKEN;

const IP_HASH_SALT      = process.env.IP_HASH_SALT || 'change-me-long-random-salt';
const TY_PERCENT        = parseFloat(process.env.TY_PERCENT || '20') || 20;
const TY_COOLDOWN_HOURS = parseFloat(process.env.TY_COOLDOWN_HOURS || '0') || 0;

const PERIOD_MONTHS     = Math.max(1, parseInt(process.env.PERIOD_MONTHS || '1', 10));
const REQUIRE_SIGNED_IN = String(process.env.REQUIRE_SIGNED_IN || 'false').toLowerCase() === 'true';

const STRICT_ONCE   = String(process.env.STRICT_ONCE || 'false').toLowerCase() === 'true';
const EVER_TTL_DAYS = parseFloat(process.env.EVER_TTL_DAYS || '0') || 0;

// ---------- Upstash helpers ----------
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

// SET with EX seconds
async function kvSetEx(key, value, ttlSeconds) {
  if (!UPSTASH_URL || !UPSTASH_TOKEN) return false;
  const url = `${UPSTASH_URL}/set/${encodeURIComponent(key)}/${encodeURIComponent(JSON.stringify(value))}?EX=${encodeURIComponent(ttlSeconds)}`;
  const r = await fetch(url, { method: 'POST', headers: { Authorization: `Bearer ${UPSTASH_TOKEN}` }});
  return r.ok;
}

// SET with NX + EX (atomic reservation). true if new reservation, false if exists.
async function kvSetNxEx(key, value, ttlSeconds) {
  if (!UPSTASH_URL || !UPSTASH_TOKEN) return false;
  const url = `${UPSTASH_URL}/set/${encodeURIComponent(key)}/${encodeURIComponent(JSON.stringify(value))}?EX=${encodeURIComponent(ttlSeconds)}&NX=1`;
  const r = await fetch(url, { method: 'POST', headers: { Authorization: `Bearer ${UPSTASH_TOKEN}` }});
  if (!r.ok) return false;
  const data = await r.json().catch(() => null);
  return data?.result === 'OK';
}

async function kvDel(key) {
  if (!UPSTASH_URL || !UPSTASH_TOKEN) return false;
  const url = `${UPSTASH_URL}/del/${encodeURIComponent(key)}`;
  const r = await fetch(url, { method: 'POST', headers: { Authorization: `Bearer ${UPSTASH_TOKEN}` }});
  return r.ok;
}

async function kvSet(key, value) {
  if (!UPSTASH_URL || !UPSTASH_TOKEN) return false;
  const url = `${UPSTASH_URL}/set/${encodeURIComponent(key)}/${encodeURIComponent(JSON.stringify(value))}`;
  const r = await fetch(url, { method: 'POST', headers: { Authorization: `Bearer ${UPSTASH_TOKEN}` }});
  return r.ok;
}

async function kvSetExDays(key, value, days) {
  if (days <= 0) return kvSet(key, value); // persist
  const ttlSeconds = Math.floor(days * 86400);
  return kvSetEx(key, value, ttlSeconds);
}

// ---------- Utils ----------
function genCode(prefix = 'TY') {
  let slug = Math.random().toString(36).slice(2, 6).toUpperCase();
  while (slug.length < 4) slug += '0';
  slug = slug.slice(0, 4);
  return `${prefix}-${slug}`;
}

function isPrivateIp(ip) {
  return /^10\.|^192\.168\.|^172\.(1[6-9]|2\d|3[0-1])\.|^127\.|^::1$|^fc00:|^fe80:/.test(ip);
}

// UPDATED: more robust client IP resolver with safe fallback
function getClientIp(req) {
  const pick = val => (typeof val === 'string' && val.trim()) ? val.trim() : '';

  // Prefer well-known proxy/CDN headers
  const cf = pick(req.headers['cf-connecting-ip']);
  if (cf) return cf;

  const tci = pick(req.headers['true-client-ip']);
  if (tci) return tci;

  const vff = pick(req.headers['x-vercel-forwarded-for']);
  if (vff) {
    const ip = vff.split(',')[0].trim().replace(/^::ffff:/, '');
    if (ip) return ip;
  }

  const xff = pick(req.headers['x-forwarded-for']);
  if (xff) {
    const parts = xff.split(',').map(s => s.trim()).filter(Boolean).map(s => s.replace(/^::ffff:/, ''));
    for (const ip of parts) {
      if (!isPrivateIp(ip)) return ip;
    }
    if (parts.length) return parts[0];
  }

  const xr = pick(req.headers['x-real-ip']);
  if (xr) return xr.replace(/^::ffff:/, '');

  const sock = pick(req.socket?.remoteAddress);
  if (sock) return sock.replace(/^::ffff:/, '');

  // LAST RESORT: synthesize a pseudo-identifier so one user doesn't lock everyone.
  const ua = pick(req.headers['user-agent']);
  const al = pick(req.headers['accept-language']);
  const pseudo = crypto.createHash('sha1').update(ua + '|' + al).digest('hex').slice(0, 8);
  return `0.0.0.${parseInt(pseudo.slice(0, 2), 16)}`; // pseudo, but not universal
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

// Month windows (calendar)
function addMonths(date, n) {
  const d = new Date(date);
  const m = d.getMonth();
  d.setMonth(m + n);
  if (d.getMonth() !== ((m + n) % 12 + 12) % 12) d.setDate(0);
  return d;
}
function getPeriodStart(now) {
  const start = new Date(now);
  start.setUTCDate(1); start.setUTCHours(0,0,0,0);
  return start;
}
function getPeriodEnd(now, months) {
  return addMonths(getPeriodStart(now), months); // exclusive
}
function secondsUntil(fromMs, dateTo) {
  const ms = Math.max(0, dateTo.getTime() - fromMs);
  return Math.ceil(ms / 1000);
}

// ---------- Shopify helpers ----------
async function shopifyGraphQL(query, variables) {
  const r = await fetch(`https://${SHOPIFY_SHOP}/admin/api/${API_VERSION}/graphql.json`, {
    method: 'POST',
    headers: {
      'X-Shopify-Access-Token': SHOPIFY_ADMIN_TOKEN,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ query, variables })
  });
  const data = await r.json().catch(() => ({}));
  return { ok: r.ok, data, status: r.status };
}

async function createDiscountBasic({ code, startsAt, endsAt, percent }) {
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
      title: code,
      startsAt, endsAt,
      customerSelection: { all: true },
      customerGets: {
        value: { percentage: Math.min(1, Math.max(0, percent / 100)) },
        items: { all: true }
      },
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
    }
  `;
  const { ok, data, status } = await shopifyGraphQL(mutation, { id: nodeId });
  if (!ok) throw new Error(`Shopify HTTP ${status}`);
  const errs = data?.data?.discountCodeDelete?.userErrors;
  if (errs?.length) throw new Error(`Delete validation: ${JSON.stringify(errs)}`);
  return true;
}

// ---------- Handler ----------
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
    // prevent CDN/browser caching of responses
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('Access-Control-Allow-Origin', '*');

    // Parse request
    const body = typeof req.body === 'string' ? JSON.parse(req.body || '{}') : (req.body || {});
    const clientExpiresAtIso = body?.expiresAt;
    const customerIdRaw      = body?.customerId || null;
    const customerEmailRaw   = body?.customerEmail || null;

    const cookies = parseCookies(req);
    const browserClaimed = cookies['ty_claimed'] === '1';

    if (REQUIRE_SIGNED_IN && !customerIdRaw && !customerEmailRaw) {
      return res.status(401).json({ error: 'signin_required', message: 'Please sign in to claim this offer.' });
    }

    // Identity hashes
    let customerKeyHash = null;
    if (customerIdRaw) customerKeyHash = hmacHash(`id:${String(customerIdRaw).trim()}`);
    else if (customerEmailRaw) customerKeyHash = hmacHash(`email:${String(customerEmailRaw).trim().toLowerCase()}`);

    const now = Date.now();
    const startsAt = new Date(now);
    const serverDefaultEnd = new Date(now + 48 * 60 * 60 * 1000);

    // Honor earlier client expiry
    let chosenEndsAt = serverDefaultEnd;
    if (clientExpiresAtIso) {
      const clientEndMs = Date.parse(clientExpiresAtIso);
      if (!Number.isNaN(clientEndMs) && clientEndMs > now && clientEndMs < serverDefaultEnd.getTime()) {
        chosenEndsAt = new Date(clientEndMs);
      }
    }

    // Keys & period
    const ip = getClientIp(req);              // UPDATED resolver
    const ipHash = hmacHash(ip);
    const periodStart = getPeriodStart(now);
    const periodEndsAt = getPeriodEnd(now, PERIOD_MONTHS);
    const cy = periodStart.getUTCFullYear();
    const cm = String(periodStart.getUTCMonth() + 1).padStart(2, '0');
    const periodLabel = `${cy}${cm}`;

    const kvKeyActiveIp   = `ty:ip:${ipHash}`;
    const kvKeyEverIp     = `ty:ip:ever:${ipHash}`;
    const kvKeyCustPeriod = customerKeyHash ? `ty:cust:period:${PERIOD_MONTHS}m:${periodLabel}:${customerKeyHash}` : null;
    const kvKeyCustEver   = customerKeyHash ? `ty:cust:ever:${customerKeyHash}` : null;
    const kvKeyGuestPeriod = `ty:guest:period:${PERIOD_MONTHS}m:${periodLabel}:${ipHash}`; // guest + mirror

    // STRICT once
    if (STRICT_ONCE) {
      if (browserClaimed) return res.status(429).json({ error: 'already_claimed', message: 'This offer was already claimed from this browser.' });
      const everIp = await kvGet(kvKeyEverIp);
      if (everIp) return res.status(429).json({ error: 'already_claimed', message: 'This offer was already claimed from your network.' });
      if (customerKeyHash) {
        const everCust = await kvGet(kvKeyCustEver);
        if (everCust) return res.status(429).json({ error: 'already_claimed_customer', message: 'This offer was already claimed on this customer account.' });
      }
    }

    // --------- ATOMIC MONTHLY RESERVATION ---------
    const ttlSecPeriod = secondsUntil(now, periodEndsAt);
    const monthPayload = (marker) => ({
      code: null, marker,
      firstClaimAt: new Date(now).toISOString(),
      periodEndsAt: periodEndsAt.toISOString(),
      nodeId: null
    });

    let reservedKeys = [];
    if (customerKeyHash && kvKeyCustPeriod) {
      const ok1 = await kvSetNxEx(kvKeyCustPeriod, monthPayload('cust-reserve'), ttlSecPeriod);
      if (!ok1) {
        const existing = await kvGet(kvKeyCustPeriod);
        return res.status(429).json({
          error: 'already_claimed_monthly',
          message: 'You have already claimed this offer for the current period.',
          periodEndsAt: periodEndsAt.toISOString(),
          code: existing?.code || undefined,
          reused: true
        });
      }
      reservedKeys.push(kvKeyCustPeriod);

      // Mirror to guest/IP monthly
      const ok2 = await kvSetNxEx(kvKeyGuestPeriod, monthPayload('mirror'), ttlSecPeriod);
      if (!ok2) {
        await kvDel(kvKeyCustPeriod); // release
        const existing = await kvGet(kvKeyGuestPeriod);
        return res.status(429).json({
          error: 'already_claimed_monthly',
          message: 'You have already claimed this offer for the current period.',
          periodEndsAt: periodEndsAt.toISOString(),
          code: existing?.code || undefined,
          reused: true
        });
      }
      reservedKeys.push(kvKeyGuestPeriod);
    } else {
      // Guest path
      const ok = await kvSetNxEx(kvKeyGuestPeriod, monthPayload('guest-reserve'), ttlSecPeriod);
      if (!ok) {
        const existing = await kvGet(kvKeyGuestPeriod);
        return res.status(429).json({
          error: 'already_claimed_monthly',
          message: 'You have already claimed this offer for the current period.',
          periodEndsAt: periodEndsAt.toISOString(),
          code: existing?.code || undefined,
          reused: true
        });
      }
      reservedKeys.push(kvKeyGuestPeriod);
    }

    // --------- Active IP reuse/cooldown ---------
    const existing = await kvGet(kvKeyActiveIp);
    if (existing) {
      const existingEnd = Date.parse(existing.endsAt);
      if (existingEnd > now) {
        return res.status(200).json({
          ok: true, reused: true,
          code: existing.code,
          startsAt: existing.startsAt,
          endsAt: existing.endsAt,
          nodeId: existing.nodeId || null,
        });
      }
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

    // --------- Mint (we hold the monthly reservation) ---------
    let code = null;
    let nodeId = null;
    for (let attempt = 1; attempt <= 5; attempt++) {
      const tryCode = genCode('TY');
      try {
        const id = await createDiscountBasic({
          code: tryCode,
          startsAt: startsAt.toISOString(),
          endsAt:   chosenEndsAt.toISOString(),
          percent:  TY_PERCENT
        });
        code = tryCode;
        nodeId = id;
        break;
      } catch (err) {
        if (String(err?.message || '').includes('Code collision')) continue;
        for (const k of reservedKeys) await kvDel(k); // release reservations
        throw err;
      }
    }
    if (!code) {
      for (const k of reservedKeys) await kvDel(k);
      return res.status(502).json({ error: 'Failed to create discount code' });
    }

    // --------- Write monthly record, cross-check, rollback if conflict ---------
    const monthlyRecord = {
      code,
      nodeId,
      firstClaimAt: new Date(now).toISOString(),
      periodEndsAt: periodEndsAt.toISOString()
    };

    // Write to guest/IP record and (if signed-in) customer record
    await kvSet(kvKeyGuestPeriod, monthlyRecord);
    if (customerKeyHash && kvKeyCustPeriod) await kvSet(kvKeyCustPeriod, monthlyRecord);

    // Re-check guest/IP record to detect conflicts (extremely rare)
    const checkGuest = await kvGet(kvKeyGuestPeriod);
    if (checkGuest && checkGuest.code && checkGuest.code !== code) {
      // Conflict → delete fresh mint, report monthly error, tell FE to hide/cancel any just-shown code
      try { await deleteDiscountByNodeId(nodeId); } catch (_) {}
      return res.status(429).json({
        error: 'already_claimed_monthly',
        message: 'You have already claimed this offer for the current period.',
        periodEndsAt: periodEndsAt.toISOString(),
        code: checkGuest.code,
        revokedNewMint: true,
        reused: true
      });
    }

    // --------- Active IP lock (48h + cooldown) ---------
    const ttlSecActive =
      Math.max(1, Math.ceil((chosenEndsAt.getTime() - now) / 1000)) +
      Math.max(0, Math.floor(TY_COOLDOWN_HOURS * 3600));

    await kvSetEx(kvKeyActiveIp, {
      code,
      startsAt: startsAt.toISOString(),
      endsAt:   chosenEndsAt.toISOString(),
      nodeId
    }, ttlSecActive);

    // Strict once-ever (optional)
    if (STRICT_ONCE) {
      await kvSetExDays(kvKeyEverIp, { code, firstClaimAt: startsAt.toISOString(), endsAt: chosenEndsAt.toISOString(), nodeId }, EVER_TTL_DAYS);
      if (customerKeyHash && kvKeyCustEver) {
        await kvSetExDays(kvKeyCustEver, { code, firstClaimAt: startsAt.toISOString(), endsAt: chosenEndsAt.toISOString(), nodeId }, EVER_TTL_DAYS);
      }
    }

    // Cookie for same-browser damping (will usually be 3rd-party on Shopify → best-effort)
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
      guestLimitedByMonths: !customerKeyHash ? PERIOD_MONTHS : undefined
    });

  } catch (e) {
    console.error('Unhandled error creating discount', e);
    return res.status(500).json({ error: 'Unhandled error', message: e?.message || String(e) });
  }
};
