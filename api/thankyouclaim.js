// api/thankyouclaim.js — CommonJS (Vercel /api/*)
// Enforcement order: IP first (hard), then browser (soft)
//  - Active IP window (48h) + optional cooldown
//  - Guest monthly limit by IP (calendar month, EXAT expiry)
//  - Signed-in monthly limit by customer, mirrored to IP to block browser-swap
//  - Cookie is a secondary damper, or "once ever" if STRICT_ONCE=true
//
// ENV VARS:
//   SHOPIFY_SHOP, SHOPIFY_ADMIN_TOKEN
//   UPSTASH_REDIS_REST_URL, UPSTASH_REDIS_REST_TOKEN
//   IP_HASH_SALT
//   TY_PERCENT               (default 20)
//   TY_COOLDOWN_HOURS        (default 0)
//   PERIOD_MONTHS            (default 1) // calendar months
//   REQUIRE_SIGNED_IN        (default false)
//   STRICT_ONCE              (default false)
//   EVER_TTL_DAYS            (default 0) // 0 = persist
//   REQUIRE_REAL_IP_FOR_GUEST (default false)
//   HASH_IP_WITH_UA          (default false) // reduces POP/CDN IP collisions

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

const REQUIRE_REAL_IP_FOR_GUEST = String(process.env.REQUIRE_REAL_IP_FOR_GUEST || 'false').toLowerCase() === 'true';
const HASH_IP_WITH_UA           = String(process.env.HASH_IP_WITH_UA || 'false').toLowerCase() === 'true';

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
async function kvSetEx(key, value, ttlSeconds) {
  if (!UPSTASH_URL || !UPSTASH_TOKEN) return false;
  const url = `${UPSTASH_URL}/set/${encodeURIComponent(key)}/${encodeURIComponent(JSON.stringify(value))}?EX=${encodeURIComponent(ttlSeconds)}`;
  const r = await fetch(url, { method: 'POST', headers: { Authorization: `Bearer ${UPSTASH_TOKEN}` }});
  return r.ok;
}
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
  if (days <= 0) return kvSet(key, value);
  const ttlSeconds = Math.floor(days * 86400);
  return kvSetEx(key, value, ttlSeconds);
}

// --- EXAT helpers for exact calendar expiry (Upstash supports EXAT) ---
async function kvSetNxExAt(key, value, exatDate) {
  if (!UPSTASH_URL || !UPSTASH_TOKEN) return false;
  const exatSec = Math.floor(exatDate.getTime() / 1000);
  const url = `${UPSTASH_URL}/set/${encodeURIComponent(key)}/${encodeURIComponent(JSON.stringify(value))}?EXAT=${exatSec}&NX=1`;
  const r = await fetch(url, { method: 'POST', headers: { Authorization: `Bearer ${UPSTASH_TOKEN}` } });
  if (!r.ok) return false;
  const data = await r.json().catch(() => null);
  return data?.result === 'OK';
}
async function kvSetExAt(key, value, exatDate) {
  if (!UPSTASH_URL || !UPSTASH_TOKEN) return false;
  const exatSec = Math.floor(exatDate.getTime() / 1000);
  const url = `${UPSTASH_URL}/set/${encodeURIComponent(key)}/${encodeURIComponent(JSON.stringify(value))}?EXAT=${exatSec}`;
  const r = await fetch(url, { method: 'POST', headers: { Authorization: `Bearer ${UPSTASH_TOKEN}` } });
  return r.ok;
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

// Robust client IP resolver — returns { ip, kind }, never a global constant
function getClientIpDetailed(req) {
  const pick = v => (typeof v === 'string' && v.trim()) ? v.trim() : '';

  const cf  = pick(req.headers['cf-connecting-ip']);        if (cf)  return { ip: cf, kind: 'cf'  };
  const tci = pick(req.headers['true-client-ip']);          if (tci) return { ip: tci, kind: 'tci' };
  const vff = pick(req.headers['x-vercel-forwarded-for']);  if (vff) {
    const ip = vff.split(',')[0].trim().replace(/^::ffff:/, '');
    if (ip) return { ip, kind: 'vff' };
  }
  const xff = pick(req.headers['x-forwarded-for']);         if (xff) {
    const parts = xff.split(',').map(s => s.trim()).filter(Boolean).map(s => s.replace(/^::ffff:/, ''));
    for (const ip of parts) { if (!isPrivateIp(ip)) return { ip, kind: 'xff' }; }
    if (parts.length) return { ip: parts[0], kind: 'xff' };
  }
  const xr = pick(req.headers['x-real-ip']);                if (xr)  return { ip: xr.replace(/^::ffff:/, ''), kind: 'xr' };
  const sock = pick(req.socket?.remoteAddress);             if (sock) return { ip: sock.replace(/^::ffff:/, ''), kind: 'sock' };

  // LAST RESORT: per-request pseudo (not universal)
  const ua = pick(req.headers['user-agent']);
  const al = pick(req.headers['accept-language']);
  const pseudo = crypto.createHash('sha1').update(ua + '|' + al).digest('hex').slice(0, 12);
  return { ip: `pseudo:${pseudo}`, kind: 'pseudo' };
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

// Calendar month helpers
function addMonths(date, n) {
  const d = new Date(date);
  const m = d.getMonth();
  d.setMonth(m + n);
  if (d.getMonth() !== ((m + n) % 12 + 12) % 12) d.setDate(0);
  return d;
}
function getPeriodStart(now) { const d = new Date(now); d.setUTCDate(1); d.setUTCHours(0,0,0,0); return d; }
function getPeriodEnd(now, months) { return addMonths(getPeriodStart(now), months); }

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
      customerGets: { value: { percentage: Math.min(1, Math.max(0, percent / 100)) }, items: { all: true } },
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

    // Normalize customer identity (optional, only if provided)
    let customerKeyHash = null;
    if (customerIdRaw) customerKeyHash = hmacHash(`id:${String(customerIdRaw).trim()}`);
    else if (customerEmailRaw) customerKeyHash = hmacHash(`email:${String(customerEmailRaw).trim().toLowerCase()}`);

    const now = Date.now();
    const startsAt = new Date(now);
    const serverDefaultEnd = new Date(now + 48 * 60 * 60 * 1000);

    // Honor earlier client expiry (grab old timer)
    let chosenEndsAt = serverDefaultEnd;
    if (clientExpiresAtIso) {
      const clientEndMs = Date.parse(clientExpiresAtIso);
      if (!Number.isNaN(clientEndMs) && clientEndMs > now && clientEndMs < serverDefaultEnd.getTime()) {
        chosenEndsAt = new Date(clientEndMs);
      }
    }

    // --- IP & period (IP-first) ---
    const ipInfo = getClientIpDetailed(req);         // { ip, kind }
    const hasRealIp = ipInfo.kind !== 'pseudo';

    const uaForHash = (req.headers['user-agent'] || '').toString().slice(0, 200);
    const ipHash = hasRealIp
      ? hmacHash(HASH_IP_WITH_UA ? `${ipInfo.ip}|${uaForHash}` : ipInfo.ip)
      : null;

    const periodStart = getPeriodStart(now);
    const periodEndsAt = getPeriodEnd(now, PERIOD_MONTHS);
    const cy = periodStart.getUTCFullYear();
    const cm = String(periodStart.getUTCMonth() + 1).padStart(2, '0');
    const periodLabel = `${cy}${cm}`;

    // Keys — ALWAYS include the hashed IP when we have it
    const kvKeyActiveIp    = hasRealIp ? `ty:ip:${ipHash}` : null;
    const kvKeyEverIp      = hasRealIp ? `ty:ip:ever:${ipHash}` : null;
    const kvKeyGuestPeriod = hasRealIp ? `ty:guest:period:${PERIOD_MONTHS}m:${periodLabel}:${ipHash}` : null;

    const kvKeyCustPeriod  = customerKeyHash ? `ty:cust:period:${PERIOD_MONTHS}m:${periodLabel}:${customerKeyHash}` : null;
    const kvKeyCustEver    = customerKeyHash ? `ty:cust:ever:${customerKeyHash}` : null;

    // If we can't see a real IP and you want to force sign-in for guests, do it.
    if (!hasRealIp && !customerKeyHash && REQUIRE_REAL_IP_FOR_GUEST) {
      return res.status(401).json({ error: 'signin_required', message: 'Please sign in to claim this offer.' });
    }

    // STRICT once: browser (soft), then IP/customer (hard)
    if (STRICT_ONCE) {
      if (browserClaimed) {
        return res.status(429).json({ error: 'already_claimed', message: 'This offer was already claimed from this browser.' });
      }
      if (hasRealIp) {
        const everIp = await kvGet(kvKeyEverIp);
        if (everIp) return res.status(429).json({ error: 'already_claimed', message: 'This offer was already claimed from your network.' });
      }
      if (customerKeyHash) {
        const everCust = await kvGet(kvKeyCustEver);
        if (everCust) return res.status(429).json({ error: 'already_claimed_customer', message: 'This offer was already claimed on this customer account.' });
      }
    }

    // --------- ATOMIC MONTHLY RESERVATION (IP-first, EXAT at month end) ---------
    const monthPayload = (marker) => ({
      code: null, marker,
      firstClaimAt: new Date(now).toISOString(),
      periodEndsAt: periodEndsAt.toISOString(),
      nodeId: null
    });

    let reservedKeys = [];

    if (customerKeyHash && kvKeyCustPeriod) {
      // Customer monthly (calendar EXAT)
      const ok1 = await kvSetNxExAt(kvKeyCustPeriod, monthPayload('cust-reserve'), periodEndsAt);
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

      // Mirror to IP so switching browsers on same network can’t mint as “guest”
      if (hasRealIp && kvKeyGuestPeriod) {
        const ok2 = await kvSetNxExAt(kvKeyGuestPeriod, monthPayload('mirror'), periodEndsAt);
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
      }
    } else {
      // Guest monthly — only if we truly have a real public IP
      if (hasRealIp && kvKeyGuestPeriod) {
        const ok = await kvSetNxExAt(kvKeyGuestPeriod, monthPayload('guest-reserve'), periodEndsAt);
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
      // If no real IP, skip guest monthly reservation to avoid globally blocking everyone.
    }

    // --------- Active IP reuse/cooldown (48h) ---------
    if (hasRealIp && kvKeyActiveIp) {
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
            ipKind: ipInfo.kind
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
              ipKind: ipInfo.kind
            });
          }
        }
      }
    }

    // --------- Mint (we hold any reservations) ---------
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
        for (const k of reservedKeys) await kvDel(k);
        throw err;
      }
    }
    if (!code) {
      for (const k of reservedKeys) await kvDel(k);
      return res.status(502).json({ error: 'Failed to create discount code' });
    }

    // --------- Persist monthly record(s) (calendar EXAT) + conflict cross-check ---------
    const monthlyRecord = {
      code, nodeId,
      firstClaimAt: new Date(now).toISOString(),
      periodEndsAt: periodEndsAt.toISOString()
    };

    // Overwrite the placeholder "reserve" records with the real code & EXAT
    if (hasRealIp && kvKeyGuestPeriod) await kvSetExAt(kvKeyGuestPeriod, monthlyRecord, periodEndsAt);
    if (customerKeyHash && kvKeyCustPeriod) await kvSetExAt(kvKeyCustPeriod, monthlyRecord, periodEndsAt);

    // Double-check: if a different code is already stored for this month (race), revoke new mint
    if (hasRealIp && kvKeyGuestPeriod) {
      const checkGuest = await kvGet(kvKeyGuestPeriod);
      if (checkGuest && checkGuest.code && checkGuest.code !== code) {
        try { await deleteDiscountByNodeId(nodeId); } catch (_) {}
        return res.status(429).json({
          error: 'already_claimed_monthly',
          message: 'You have already claimed this offer for the current period.',
          periodEndsAt: periodEndsAt.toISOString(),
          code: checkGuest.code,
          revokedNewMint: true,
          reused: true,
          ipKind: ipInfo.kind
        });
      }
    }

    // --------- Active IP lock (48h + cooldown via EX) ---------
    if (hasRealIp && kvKeyActiveIp) {
      const ttlSecActive =
        Math.max(1, Math.ceil((chosenEndsAt.getTime() - now) / 1000)) +
        Math.max(0, Math.floor(TY_COOLDOWN_HOURS * 3600));

      await kvSetEx(kvKeyActiveIp, {
        code,
        startsAt: startsAt.toISOString(),
        endsAt:   chosenEndsAt.toISOString(),
        nodeId
      }, ttlSecActive);
    }

    // Strict once-ever (optional)
    if (STRICT_ONCE && hasRealIp && kvKeyEverIp) {
      await kvSetExDays(kvKeyEverIp, { code, firstClaimAt: startsAt.toISOString(), endsAt: chosenEndsAt.toISOString(), nodeId }, EVER_TTL_DAYS);
      if (customerKeyHash && kvKeyCustEver) {
        await kvSetExDays(kvKeyCustEver, { code, firstClaimAt: startsAt.toISOString(), endsAt: chosenEndsAt.toISOString(), nodeId }, EVER_TTL_DAYS);
      }
    }

    // Browser cookie (soft)
    const cookieMaxAge = STRICT_ONCE ? 10 * 365 * 24 * 3600 : Math.max(1, Math.ceil((chosenEndsAt.getTime() - now) / 1000));
    setCookie(res, 'ty_claimed', '1', { maxAgeSec: cookieMaxAge });

    return res.status(200).json({
      ok: true,
      code,
      startsAt: startsAt.toISOString(),
      endsAt:   chosenEndsAt.toISOString(),
      nodeId,
      customerLimitedByMonths: customerKeyHash ? PERIOD_MONTHS : undefined,
      guestLimitedByMonths: (!customerKeyHash && hasRealIp) ? PERIOD_MONTHS : undefined,
      ipKind: ipInfo.kind // helpful for debugging; remove later if you’d like
    });

  } catch (e) {
    console.error('Unhandled error creating discount', e);
    return res.status(500).json({ error: 'Unhandled error', message: e?.message || String(e) });
  }
};
