// api/thankyouclaim.js — CommonJS (Vercel /api/*) — REST-only Upstash (no deps)
// - Uses NX + EX (relative TTL) for monthly locks (no EXAT)
// - Includes ?connect=1 probe and ?debug=1 dry-run
// - Supports HASH_IP_WITH_UA to reduce POP collisions

const crypto = require('crypto');

// ---------- Env ----------
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

// ---------- Upstash REST helpers ----------
function okUpstash() { return Boolean(UPSTASH_URL && UPSTASH_TOKEN); }

async function kvGet(key) {
  if (!okUpstash() || !key) return null;
  const r = await fetch(`${UPSTASH_URL}/get/${encodeURIComponent(key)}`, {
    headers: { Authorization: `Bearer ${UPSTASH_TOKEN}` },
    cache: 'no-store',
  });
  if (!r.ok) return null;
  const data = await r.json().catch(() => null);
  try { return data?.result ? JSON.parse(data.result) : null; } catch { return data?.result ?? null; }
}
async function kvSet(key, value) {
  if (!okUpstash()) return false;
  const url = `${UPSTASH_URL}/set/${encodeURIComponent(key)}/${encodeURIComponent(JSON.stringify(value))}`;
  const r = await fetch(url, { method: 'POST', headers: { Authorization: `Bearer ${UPSTASH_TOKEN}` } });
  return r.ok;
}
async function kvSetEx(key, value, ttlSeconds) {
  if (!okUpstash()) return false;
  const url = `${UPSTASH_URL}/set/${encodeURIComponent(key)}/${encodeURIComponent(JSON.stringify(value))}?EX=${Math.max(1, Math.floor(ttlSeconds))}`;
  const r = await fetch(url, { method: 'POST', headers: { Authorization: `Bearer ${UPSTASH_TOKEN}` } });
  return r.ok;
}
async function kvSetNxEx(key, value, ttlSeconds) {
  if (!okUpstash()) return false;
  const url = `${UPSTASH_URL}/set/${encodeURIComponent(key)}/${encodeURIComponent(JSON.stringify(value))}?EX=${Math.max(1, Math.floor(ttlSeconds))}&NX=1`;
  const r = await fetch(url, { method: 'POST', headers: { Authorization: `Bearer ${UPSTASH_TOKEN}` } });
  if (!r.ok) return false;
  const data = await r.json().catch(() => null);
  return data?.result === 'OK'; // false if key existed
}
async function kvDel(key) {
  if (!okUpstash() || !key) return false;
  const url = `${UPSTASH_URL}/del/${encodeURIComponent(key)}`;
  const r = await fetch(url, { method: 'POST', headers: { Authorization: `Bearer ${UPSTASH_TOKEN}` } });
  return r.ok;
}
async function kvSetExDays(key, value, days) {
  if (days <= 0) return kvSet(key, value);
  const ttlSeconds = Math.floor(days * 86400);
  return kvSetEx(key, value, ttlSeconds);
}

// Quick probe: set/get/del a temp key using EX=10
async function kvProbe() {
  if (!okUpstash()) throw new Error('Missing UPSTASH_URL/TOKEN');
  const tmp = `ty:probe:${Date.now()}:${Math.random().toString(36).slice(2,8)}`;
  const setUrl = `${UPSTASH_URL}/set/${encodeURIComponent(tmp)}/${encodeURIComponent('ok')}?EX=10`;
  const setR = await fetch(setUrl, { method: 'POST', headers: { Authorization: `Bearer ${UPSTASH_TOKEN}` }});
  if (!setR.ok) throw new Error(`SET failed HTTP ${setR.status}`);
  const getR = await fetch(`${UPSTASH_URL}/get/${encodeURIComponent(tmp)}`, { headers: { Authorization: `Bearer ${UPSTASH_TOKEN}` }});
  const getJ = await getR.json().catch(()=>({}));
  await fetch(`${UPSTASH_URL}/del/${encodeURIComponent(tmp)}`, { method: 'POST', headers: { Authorization: `Bearer ${UPSTASH_TOKEN}` }});
  return getJ?.result === 'ok';
}

// ---------- Utils ----------
function genCode(prefix = 'TY') {
  const pool = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  let four = '';
  for (let i = 0; i < 4; i++) four += pool[Math.floor(Math.random() * pool.length)];
  return `${prefix}-${four}`;
}
function isPrivateIp(ip) {
  return /^10\.|^192\.168\.|^172\.(1[6-9]|2\d|3[0-1])\.|^127\.|^::1$|^fc00:|^fe80:/.test(ip);
}
function getClientIpDetailed(req) {
  const pick = v => (typeof v === 'string' && v.trim()) ? v.trim() : '';
  const cf  = pick(req.headers['cf-connecting-ip']);        if (cf)  return { ip: cf, kind: 'cf'  };
  const tci = pick(req.headers['true-client-ip']);          if (tci) return { ip: tci, kind: 'tci' };
  const vff = pick(req.headers['x-vercel-forwarded-for']);  if (vff) return { ip: vff.split(',')[0].trim().replace(/^::ffff:/, ''), kind: 'vff' };
  const xff = pick(req.headers['x-forwarded-for']);
  if (xff) {
    const parts = xff.split(',').map(s => s.trim()).filter(Boolean).map(s => s.replace(/^::ffff:/, ''));
    for (const ip of parts) { if (!isPrivateIp(ip)) return { ip, kind: 'xff' }; }
    if (parts.length) return { ip: parts[0], kind: 'xff' };
  }
  const xr = pick(req.headers['x-real-ip']);                if (xr)  return { ip: xr.replace(/^::ffff:/, ''), kind: 'xr' };
  const sock = pick(req.socket?.remoteAddress);             if (sock) return { ip: sock.replace(/^::ffff:/, ''), kind: 'sock' };
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
// Calendar helpers
function addMonths(date, n) {
  const d = new Date(date);
  const m = d.getMonth();
  d.setMonth(m + n);
  if (d.getMonth() !== ((m + n) % 12 + 12) % 12) d.setDate(0);
  return d;
}
function getPeriodStart(now) { const d = new Date(now); d.setUTCDate(1); d.setUTCHours(0,0,0,0); return d; }
function getPeriodEnd(now, months) { return addMonths(getPeriodStart(now), months); }
function secondsUntil(fromMs, dateTo) { const ms = Math.max(0, dateTo.getTime() - fromMs); return Math.ceil(ms / 1000); }

// ---------- Shopify helpers ----------
async function shopifyGraphQL(query, variables) {
  const r = await fetch(`https://${SHOPIFY_SHOP}/admin/api/${API_VERSION}/graphql.json`, {
    method: 'POST',
    headers: { 'X-Shopify-Access-Token': SHOPIFY_ADMIN_TOKEN, 'Content-Type': 'application/json' },
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
    }`;
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
    }`;
  const { ok, data, status } = await shopifyGraphQL(mutation, { id: nodeId });
  if (!ok) throw new Error(`Shopify HTTP ${status}`);
  const errs = data?.data?.discountCodeDelete?.userErrors;
  if (errs?.length) throw new Error(`Delete validation: ${JSON.stringify(errs)}`);
  return true;
}

// ---------- Debug helpers ----------
function setDebugHeaders(res, obj = {}) {
  for (const [k, v] of Object.entries(obj)) {
    if (v == null) continue;
    res.setHeader(`X-TY-${k}`, typeof v === 'string' ? v : JSON.stringify(v));
  }
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
function getConnectProbe(req) {
  try {
    const url = req.url ? new URL(req.url, 'http://localhost') : null;
    return url?.searchParams.get('connect') === '1';
  } catch { return false; }
}

// ---------- Handler ----------
module.exports = async (req, res) => {
  // CORS
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

    const body = typeof req.body === 'string' ? JSON.parse(req.body || '{}') : (req.body || {});
    const DEBUG = getDebugFlag(req, body);
    const PROBE = getConnectProbe(req);

    // Probe Upstash connectivity quickly
    if (PROBE) {
      try {
        const ok = await kvProbe();
        return res.status(200).json({ ok, client: 'rest', exMode: 'EX+NX' });
      } catch (e) {
        return res.status(502).json({ ok: false, error: 'connect-failed', message: String(e?.message || e) });
      }
    }

    const clientExpiresAtIso = body?.expiresAt;
    const customerIdRaw      = body?.customerId || null;
    const customerEmailRaw   = body?.customerEmail || null;

    const cookies = parseCookies(req);
    const browserClaimed = cookies['ty_claimed'] === '1';

    if (REQUIRE_SIGNED_IN && !customerIdRaw && !customerEmailRaw) {
      setDebugHeaders(res, { reason: 'signin_required' });
      return res.status(401).json({ error: 'signin_required', reason: 'signin_required' });
    }

    // Customer identity (optional)
    let customerKeyHash = null;
    if (customerIdRaw) customerKeyHash = hmacHash(`id:${String(customerIdRaw).trim()}`);
    else if (customerEmailRaw) customerKeyHash = hmacHash(`email:${String(customerEmailRaw).trim().toLowerCase()}`);

    const now = Date.now();
    const startsAt = new Date(now);
    const serverDefaultEnd = new Date(now + 48 * 60 * 60 * 1000);

    // Honor shorter client expiry
    let chosenEndsAt = serverDefaultEnd;
    if (clientExpiresAtIso) {
      const clientEndMs = Date.parse(clientExpiresAtIso);
      if (!Number.isNaN(clientEndMs) && clientEndMs > now && clientEndMs < serverDefaultEnd.getTime()) {
        chosenEndsAt = new Date(clientEndMs);
      }
    }

    // IP + hash
    const ipInfo = getClientIpDetailed(req);
    const hasRealIp = ipInfo.kind !== 'pseudo';
    const uaForHash = (req.headers['user-agent'] || '').toString().slice(0, 200);
    const ipHash = hasRealIp ? hmacHash(HASH_IP_WITH_UA ? `${ipInfo.ip}|${uaForHash}` : ipInfo.ip) : null;

    // Period + keys
    const periodStart = getPeriodStart(now);
    const periodEndsAt = getPeriodEnd(now, PERIOD_MONTHS);
    const periodLabel = `${periodStart.getUTCFullYear()}${String(periodStart.getUTCMonth() + 1).padStart(2,'0')}`;

    const kvKeyActiveIp    = hasRealIp ? `ty:ip:${ipHash}` : null;
    const kvKeyEverIp      = hasRealIp ? `ty:ip:ever:${ipHash}` : null;
    const kvKeyGuestPeriod = hasRealIp ? `ty:guest:period:${PERIOD_MONTHS}m:${periodLabel}:${ipHash}` : null;
    const kvKeyCustPeriod  = customerKeyHash ? `ty:cust:period:${PERIOD_MONTHS}m:${periodLabel}:${customerKeyHash}` : null;
    const kvKeyCustEver    = customerKeyHash ? `ty:cust:ever:${customerKeyHash}` : null;

    setDebugHeaders(res, {
      ipKind: ipInfo.kind,
      ipHash,
      hashWithUA: String(HASH_IP_WITH_UA),
      periodLabel,
      guestMonthKey: kvKeyGuestPeriod,
      custMonthKey: kvKeyCustPeriod,
      activeIpKey: kvKeyActiveIp,
      upstashUrlHash: (UPSTASH_URL||'').slice(0,40)
    });

    // Guests must have real IP if required
    if (!hasRealIp && !customerKeyHash && REQUIRE_REAL_IP_FOR_GUEST) {
      return res.status(401).json({ error: 'signin_required', reason: 'no-real-ip-and-guest' });
    }

    // Dry-run debug (no writes)
    if (DEBUG) {
      const existingGuest = kvKeyGuestPeriod ? await kvGet(kvKeyGuestPeriod) : null;
      const existingCust  = kvKeyCustPeriod  ? await kvGet(kvKeyCustPeriod)  : null;
      const existingAct   = kvKeyActiveIp    ? await kvGet(kvKeyActiveIp)    : null;
      const existingEverI = kvKeyEverIp      ? await kvGet(kvKeyEverIp)      : null;
      const existingEverC = kvKeyCustEver    ? await kvGet(kvKeyCustEver)    : null;

      const wouldBlock =
        (STRICT_ONCE && (browserClaimed || existingEverI || existingEverC)) ||
        (!!existingCust) ||
        (!!existingGuest) ||
        (existingAct && Date.parse(existingAct.endsAt) > now);

      const reason =
        STRICT_ONCE && browserClaimed ? 'browser-cookie' :
        STRICT_ONCE && existingEverI ? 'ip-ever-lock' :
        STRICT_ONCE && existingEverC ? 'customer-ever-lock' :
        existingCust ? 'monthly-lock-customer' :
        existingGuest ? 'monthly-lock-guest' :
        (existingAct && Date.parse(existingAct.endsAt) > now) ? 'active-ip-reuse' :
        'would-mint';

      setDebugHeaders(res, { debug: '1', wouldBlock: String(wouldBlock), reason });
      return res.status(200).json({
        ok: !wouldBlock,
        debug: true,
        reason,
        keys: { kvKeyGuestPeriod, kvKeyCustPeriod, kvKeyActiveIp, kvKeyEverIp, kvKeyCustEver },
        existing: { guestMonthly: existingGuest, customerMonthly: existingCust, activeIp: existingAct, everIp: existingEverI, everCustomer: existingEverC },
        note: 'No writes performed in debug mode.'
      });
    }

    // STRICT once-ever
    if (STRICT_ONCE) {
      if (browserClaimed) return res.status(429).json({ error: 'already_claimed', reason: 'browser-cookie' });
      if (hasRealIp) {
        const everIp = await kvGet(kvKeyEverIp);
        if (everIp) return res.status(429).json({ error: 'already_claimed', reason: 'ip-ever-lock' });
      }
      if (customerKeyHash) {
        const everCust = await kvGet(kvKeyCustEver);
        if (everCust) return res.status(429).json({ error: 'already_claimed_customer', reason: 'customer-ever-lock' });
      }
    }

    // --------- Monthly reservation (EX + NX with TTL until end-of-month) ---------
    const ttlSecPeriod = secondsUntil(now, periodEndsAt);
    const monthPayload = (marker) => ({
      code: null, marker,
      firstClaimAt: new Date(now).toISOString(),
      periodEndsAt: periodEndsAt.toISOString(),
      nodeId: null
    });

    let reservedKeys = [];

    if (customerKeyHash && kvKeyCustPeriod) {
      let ok1;
      try {
        ok1 = await kvSetNxEx(kvKeyCustPeriod, monthPayload('cust-reserve'), ttlSecPeriod);
      } catch (e) {
        return res.status(502).json({ error: 'kv-write-failed', where: 'customer-monthly', message: String(e?.message || e) });
      }
      if (!ok1) {
        const existing = await kvGet(kvKeyCustPeriod);
        return res.status(429).json({
          error: 'already_claimed_monthly',
          reason: 'monthly-lock-customer',
          periodEndsAt: periodEndsAt.toISOString(),
          code: existing?.code || undefined,
          reused: true
        });
      }
      reservedKeys.push(kvKeyCustPeriod);

      if (hasRealIp && kvKeyGuestPeriod) {
        let ok2;
        try {
          ok2 = await kvSetNxEx(kvKeyGuestPeriod, monthPayload('mirror'), ttlSecPeriod);
        } catch (e) {
          await kvDel(kvKeyCustPeriod);
          return res.status(502).json({ error: 'kv-write-failed', where: 'mirror-guest', message: String(e?.message || e) });
        }
        if (!ok2) {
          await kvDel(kvKeyCustPeriod);
          const existing = await kvGet(kvKeyGuestPeriod);
          return res.status(429).json({
            error: 'already_claimed_monthly',
            reason: 'monthly-lock-guest',
            periodEndsAt: periodEndsAt.toISOString(),
            code: existing?.code || undefined,
            reused: true
          });
        }
        reservedKeys.push(kvKeyGuestPeriod);
      }
    } else {
      if (hasRealIp && kvKeyGuestPeriod) {
        let ok;
        try {
          ok = await kvSetNxEx(kvKeyGuestPeriod, monthPayload('guest-reserve'), ttlSecPeriod);
        } catch (e) {
          return res.status(502).json({ error: 'kv-write-failed', where: 'guest-monthly', message: String(e?.message || e) });
        }
        if (!ok) {
          const existing = await kvGet(kvKeyGuestPeriod);
          return res.status(429).json({
            error: 'already_claimed_monthly',
            reason: 'monthly-lock-guest',
            periodEndsAt: periodEndsAt.toISOString(),
            code: existing?.code || undefined,
            reused: true
          });
        }
        reservedKeys.push(kvKeyGuestPeriod);
      }
    }

    // --------- Active IP reuse/cooldown (48h) ---------
    if (hasRealIp && kvKeyActiveIp) {
      const existing = await kvGet(kvKeyActiveIp);
      if (existing) {
        const existingEnd = Date.parse(existing.endsAt);
        if (existingEnd > now) {
          return res.status(200).json({
            ok: true, reused: true, reason: 'active-ip-reuse',
            code: existing.code, startsAt: existing.startsAt, endsAt: existing.endsAt,
            nodeId: existing.nodeId || null, ipKind: ipInfo.kind
          });
        }
        if (TY_COOLDOWN_HOURS > 0) {
          const cooldownUntil = existingEnd + TY_COOLDOWN_HOURS * 3600 * 1000;
          if (cooldownUntil > now) {
            return res.status(429).json({
              error: 'rate_limited',
              reason: 'cooldown-active',
              message: 'Already claimed from your network. Try again later.',
              code: existing.code, endsAt: existing.endsAt,
              cooldownUntil: new Date(cooldownUntil).toISOString(),
              ipKind: ipInfo.kind
            });
          }
        }
      }
    }

    // --------- Mint ---------
    let code = null, nodeId = null;
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
        for (const k of reservedKeys) await kvDel(k);
        throw err;
      }
    }
    if (!code) {
      for (const k of reservedKeys) await kvDel(k);
      return res.status(502).json({ error: 'Failed to create discount code' });
    }

    // --------- Finalize monthly records (EX with same TTL) ---------
    const monthlyRecord = { code, nodeId, firstClaimAt: new Date(now).toISOString(), periodEndsAt: periodEndsAt.toISOString() };
    const ttlAgain = secondsUntil(Date.now(), periodEndsAt);
    try {
      if (hasRealIp && kvKeyGuestPeriod) await kvSetEx(kvKeyGuestPeriod, monthlyRecord, ttlAgain);
      if (customerKeyHash && kvKeyCustPeriod) await kvSetEx(kvKeyCustPeriod, monthlyRecord, ttlAgain);
    } catch (e) {
      try { await deleteDiscountByNodeId(nodeId); } catch {}
      return res.status(502).json({ error: 'kv-write-failed', where: 'finalize-monthly', message: String(e?.message || e) });
    }

    // --------- Active IP lock (48h + cooldown) ---------
    if (hasRealIp && kvKeyActiveIp) {
      const ttlSecActive =
        Math.max(1, Math.ceil((chosenEndsAt.getTime() - now) / 1000)) +
        Math.max(0, Math.floor(TY_COOLDOWN_HOURS * 3600));
      await kvSetEx(kvKeyActiveIp, {
        code, startsAt: startsAt.toISOString(), endsAt: chosenEndsAt.toISOString(), nodeId
      }, ttlSecActive);
    }

    // --------- Ever locks (optional) ---------
    if (STRICT_ONCE && hasRealIp && kvKeyEverIp) {
      await kvSetExDays(kvKeyEverIp, { code, firstClaimAt: startsAt.toISOString(), endsAt: chosenEndsAt.toISOString(), nodeId }, EVER_TTL_DAYS);
      if (customerKeyHash && kvKeyCustEver) {
        await kvSetExDays(kvKeyCustEver, { code, firstClaimAt: startsAt.toISOString(), endsAt: chosenEndsAt.toISOString(), nodeId }, EVER_TTL_DAYS);
      }
    }

    // Browser cookie (soft)
    const cookieMaxAge = STRICT_ONCE ? 10 * 365 * 24 * 3600 : Math.max(1, Math.ceil((chosenEndsAt.getTime() - now) / 1000));
    setCookie(res, 'ty_claimed', '1', { maxAgeSec: cookieMaxAge });

    setDebugHeaders(res, { reason: 'minted', code, nodeId, endsAt: chosenEndsAt.toISOString(), ipKind: ipInfo.kind });

    return res.status(200).json({
      ok: true, reason: 'minted',
      code,
      startsAt: startsAt.toISOString(),
      endsAt:   chosenEndsAt.toISOString(),
      nodeId,
      customerLimitedByMonths: customerKeyHash ? PERIOD_MONTHS : undefined,
      guestLimitedByMonths: (!customerKeyHash && hasRealIp) ? PERIOD_MONTHS : undefined,
      ipKind: ipInfo.kind
    });

  } catch (e) {
    console.error('Unhandled error creating discount', e);
    setDebugHeaders(res, { reason: 'server-error', error: String(e?.message || e), upstashUrlHash: (UPSTASH_URL||'').slice(0,40) });
    return res.status(500).json({ error: 'Unhandled error', message: e?.message || String(e) });
  }
};
