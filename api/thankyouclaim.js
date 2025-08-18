// api/thankyouclaim.js — CommonJS (Vercel /api/*)
// Household IP lock (IPv4 /24, IPv6 /64) → reuse within 48h; monthly limit; no once-ever.
// Will NOT auto-mint after 48h; can mint again next calendar month.

const crypto = require('crypto');

// ---------- ENV ----------
const SHOPIFY_SHOP        = process.env.SHOPIFY_SHOP;
const SHOPIFY_ADMIN_TOKEN = process.env.SHOPIFY_ADMIN_TOKEN;
const API_VERSION         = process.env.SHOPIFY_API_VERSION || '2025-07';

const KV_URL   = process.env.KV_REST_API_URL || process.env.UPSTASH_REDIS_REST_URL;
const KV_TOKEN = process.env.KV_REST_API_TOKEN || process.env.UPSTASH_REDIS_REST_TOKEN;

const IP_HASH_SALT        = process.env.IP_HASH_SALT || 'change-me-long-random-salt';
const TY_PERCENT          = parseFloat(process.env.TY_PERCENT || '20') || 20;
const TY_COOLDOWN_HOURS   = parseFloat(process.env.TY_COOLDOWN_HOURS || '0') || 0;  // keep 0 as requested
const PERIOD_MONTHS       = Math.max(1, parseInt(process.env.PERIOD_MONTHS || '1', 10)); // monthly limit
const ACTIVE_IP_SCOPE     = String(process.env.ACTIVE_IP_SCOPE || 'household').toLowerCase(); // ← household
const VISITOR_KEY_MODE    = String(process.env.VISITOR_KEY_MODE || 'cookie+ip').toLowerCase();

function assertEnvOrThrow() {
  const missing = [];
  if (!SHOPIFY_SHOP) missing.push('SHOPIFY_SHOP');
  if (!SHOPIFY_ADMIN_TOKEN) missing.push('SHOPIFY_ADMIN_TOKEN');
  if (!KV_URL) missing.push('KV_REST_API_URL or UPSTASH_REDIS_REST_URL');
  if (!KV_TOKEN) missing.push('KV_REST_API_TOKEN or UPSTASH_REDIS_REST_TOKEN');
  if (missing.length) throw new Error(`Missing ENV: ${missing.join(', ')}`);
}

// ---------- KV helpers (provider-agnostic minimal) ----------
async function kvGet(key) {
  const r = await fetch(`${KV_URL}/get/${encodeURIComponent(key)}`, {
    headers: { Authorization: `Bearer ${KV_TOKEN}` },
    cache: 'no-store',
  });
  if (!r.ok) throw new Error(`KV GET ${r.status}`);
  const data = await r.json().catch(()=>null);
  try { return data?.result ? JSON.parse(data.result) : null; } catch { return data?.result ?? null; }
}
async function kvSet(key, value) {
  const r = await fetch(`${KV_URL}/set/${encodeURIComponent(key)}/${encodeURIComponent(JSON.stringify(value))}`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${KV_TOKEN}` }
  });
  if (!r.ok) throw new Error(`KV SET ${r.status}`);
  return true;
}
// Try NX+EX combos for Upstash/Vercel
async function kvSetNxEx(key, value, ttlSeconds) {
  const ttl = encodeURIComponent(ttlSeconds);
  const base = `${KV_URL}/set/${encodeURIComponent(key)}/${encodeURIComponent(JSON.stringify(value))}`;
  const variants = [
    `${base}?EX=${ttl}&NX=true`,
    `${base}?ex=${ttl}&nx=true`,
    `${base}?EX=${ttl}&NX=1`,
    `${base}?EX=${ttl}&NX`
  ];
  for (const url of variants) {
    const r = await fetch(url, { method: 'POST', headers: { Authorization: `Bearer ${KV_TOKEN}` } });
    if (r.status === 400) continue;
    if (!r.ok) throw new Error(`KV NXEX ${r.status}`);
    const data = await r.json().catch(()=>null);
    return data?.result === 'OK';   // true if set (did not exist), null if exists
  }
  throw new Error('KV NXEX variants failed');
}
async function kvDel(key) {
  const r = await fetch(`${KV_URL}/del/${encodeURIComponent(key)}`, {
    method: 'POST', headers: { Authorization: `Bearer ${KV_TOKEN}` }
  });
  if (!r.ok) throw new Error(`KV DEL ${r.status}`);
  return true;
}
async function kvSetEx(key, value, ttlSeconds) {
  const r = await fetch(`${KV_URL}/set/${encodeURIComponent(key)}/${encodeURIComponent(JSON.stringify(value))}?ex=${encodeURIComponent(ttlSeconds)}`, {
    method: 'POST', headers: { Authorization: `Bearer ${KV_TOKEN}` }
  });
  if (!r.ok) throw new Error(`KV SETEX ${r.status}`);
  return true;
}

// ---------- Utils ----------
function parseCookies(req) {
  const h = req.headers.cookie || '';
  return h.split(';').reduce((acc, part) => {
    const [k, ...rest] = part.split('=');
    if (!k || rest.length === 0) return acc;
    acc[k.trim()] = decodeURIComponent(rest.join('=').trim());
    return acc;
  }, {});
}
function setCookie(res, name, value, { maxAgeSec, path='/', httpOnly=true, sameSite='Lax', secure=true } = {}) {
  const parts = [`${name}=${encodeURIComponent(value)}`, `Path=${path}`, `SameSite=${sameSite}`];
  if (httpOnly) parts.push('HttpOnly');
  if (secure) parts.push('Secure');
  if (Number.isFinite(maxAgeSec)) parts.push(`Max-Age=${Math.max(0, Math.floor(maxAgeSec))}`);
  const prev = res.getHeader('Set-Cookie');
  const val = parts.join('; ');
  res.setHeader('Set-Cookie', prev ? (Array.isArray(prev) ? [...prev, val] : [prev, val]) : val);
}
function normalizeIp(ip) { return String(ip || '').replace(/^::ffff:/, ''); }
function isPrivateIp(ip) {
  return /^10\.|^192\.168\.|^172\.(1[6-9]|2\d|3[0-1])\.|^127\.|^::1$|^fc00:|^fe80:/.test(ip);
}
function hmacHash(input, salt = IP_HASH_SALT) {
  return crypto.createHmac('sha256', salt).update(String(input)).digest('hex');
}
function getClientIpDetailed(req) {
  const pick = v => (typeof v === 'string' && v.trim()) ? v.trim() : '';
  const cf  = pick(req.headers['cf-connecting-ip']);        if (cf)  return { ip: normalizeIp(cf), kind: 'cf'  };
  const tci = pick(req.headers['true-client-ip']);          if (tci) return { ip: normalizeIp(tci), kind: 'tci' };
  const vff = pick(req.headers['x-vercel-forwarded-for']);  if (vff) return { ip: normalizeIp(vff.split(',')[0]), kind: 'vff' };
  const xff = pick(req.headers['x-forwarded-for']);
  if (xff) {
    const parts = xff.split(',').map(s => normalizeIp(s.trim())).filter(Boolean);
    for (const ip of parts) if (!isPrivateIp(ip)) return { ip, kind: 'xff' };
    if (parts.length) return { ip: parts[0], kind: 'xff' };
  }
  const xr = pick(req.headers['x-real-ip']);                if (xr)  return { ip: normalizeIp(xr), kind: 'xr' };
  const sock = req.socket?.remoteAddress;                   if (sock) return { ip: normalizeIp(sock), kind: 'sock' };
  return { ip: 'pseudo', kind: 'pseudo' };
}
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
  const clean = normalizeIp(ip);
  const hashes = new Set();
  // exact & legacy exact (IP, IP+UA)
  hashes.add(hmacHash(clean));
  if (ua) hashes.add(hmacHash(`${clean}|${ua}`));
  // household
  if (ACTIVE_IP_SCOPE === 'household') {
    const v4 = ipV4Prefix(clean);
    const v6 = clean.includes(':') ? ipV6Prefix(clean) : null;
    if (v4) hashes.add(hmacHash(`net:${v4}`));
    if (v6) hashes.add(hmacHash(`net:${v6}`));
  }
  return Array.from(hashes);
}
function getPeriodStart(nowMs) { const d = new Date(nowMs); d.setUTCDate(1); d.setUTCHours(0,0,0,0); return d; }
function addMonths(date, n) { const d = new Date(date); const m = d.getMonth(); d.setMonth(m+n); if (d.getMonth() !== ((m+n)%12+12)%12) d.setDate(0); return d; }
function getPeriodEnd(nowMs, months) { return addMonths(getPeriodStart(nowMs), months); }
function secondsUntil(fromMs, toDate) { return Math.max(1, Math.ceil((toDate.getTime() - fromMs)/1000)); }

// ---------- Shopify (GraphQL) ----------
async function shopifyGraphQL(query, variables) {
  const r = await fetch(`https://${SHOPIFY_SHOP}/admin/api/${API_VERSION}/graphql.json`, {
    method: 'POST',
    headers: { 'X-Shopify-Access-Token': SHOPIFY_ADMIN_TOKEN, 'Content-Type': 'application/json' },
    body: JSON.stringify({ query, variables })
  });
  const data = await r.json().catch(()=>({}));
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
      customerGets: { value: { percentage: Math.min(1, Math.max(0, percent/100)) }, items: { all: true } },
      usageLimit: 1,
      appliesOncePerCustomer: true,
      combinesWith: { orderDiscounts: false, productDiscounts: true, shippingDiscounts: true },
      code
    }
  };
  const { ok, data, status } = await shopifyGraphQL(mutation, variables);
  if (!ok) throw new Error(`Shopify HTTP ${status}`);
  const errs = data?.data?.discountCodeBasicCreate?.userErrors || [];
  if (errs.length) {
    const exists = errs.find(e => String(e.message||'').toLowerCase().includes('already exists'));
    if (exists) throw new Error('Code collision');
    throw new Error(`Shopify validation: ${JSON.stringify(errs)}`);
  }
  const node = data?.data?.discountCodeBasicCreate?.codeDiscountNode;
  if (!node) throw new Error('No codeDiscountNode');
  return node.id;
}
function genCode(prefix = 'TY') {
  const pool = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'; // no 0/O/1/I
  let four = '';
  for (let i=0;i<4;i++) four += pool[Math.floor(Math.random()*pool.length)];
  return `${prefix}-${four}`;
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

  try { assertEnvOrThrow(); }
  catch (e) { return res.status(500).json({ error: 'server_misconfig', message: String(e?.message||e) }); }

  try {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Cache-Control', 'no-store');

    const body = typeof req.body === 'string' ? JSON.parse(req.body || '{}') : (req.body || {});
    const clientExpiresAtIso = body?.expiresAt; // optional from countdown component

    const now = Date.now();
    const startsAt = new Date(now);

    // Default 48h; allow client to pass an earlier “expiresAt” (never later)
    const serverEnd = new Date(now + 48*3600*1000);
    let endsAt = serverEnd;
    if (clientExpiresAtIso) {
      const c = Date.parse(clientExpiresAtIso);
      if (!Number.isNaN(c) && c > now && c < serverEnd.getTime()) endsAt = new Date(c);
    }

    // Identify network
    const ipInfo = getClientIpDetailed(req);
    const ua = (req.headers['user-agent'] || '').toString().slice(0,200);
    const hasRealIp = ipInfo.kind !== 'pseudo';

    // Build active IP keys for household scope
    const activeHashes = hasRealIp ? buildActiveIpHashes(ipInfo.ip, ua) : [];
    const activeKeys = activeHashes.map(h => `ty:ip:${h}`);

    // Monthly keys (calendar month)
    const periodStart = getPeriodStart(now);
    const periodEnd   = getPeriodEnd(now, PERIOD_MONTHS);
    const ttlMonth    = secondsUntil(now, periodEnd);
    const label = `${periodStart.getUTCFullYear()}${String(periodStart.getUTCMonth()+1).padStart(2,'0')}`;

    // We’ll key monthly by the visitor network (household IP hash union w/ cookie+ip) to be conservative.
    // Use a stable “visitor” hash (cookie+ip) + month label so it won’t mint again this month.
    const cookies = parseCookies(req);
    let vid = cookies['ty_vid'];
    if (!vid || !/^[a-z0-9-]{12,}$/.test(vid)) {
      vid = `${Date.now().toString(36)}-${Math.random().toString(36).slice(2,10)}`;
      setCookie(res, 'ty_vid', vid, { maxAgeSec: 365*24*3600, httpOnly: true, sameSite: 'Lax', secure: true });
    }
    const visitorHash = hmacHash(`vid:${vid}|ip:${hasRealIp ? ipInfo.ip : 'noip'}`);
    const monthKey = `ty:month:${PERIOD_MONTHS}m:${label}:${visitorHash}`;

    // ---------- 1) Active IP reuse FIRST ----------
    if (hasRealIp && activeKeys.length) {
      for (const k of activeKeys) {
        const ex = await kvGet(k).catch(()=>null);
        if (!ex) continue;
        const t = Date.parse(ex.endsAt || '');
        if (t > now) {
          // Mirror to all household keys so every device stays aligned
          const ttlLeft = Math.max(1, Math.ceil((t - now)/1000)) + Math.max(0, Math.floor(TY_COOLDOWN_HOURS*3600));
          for (const mk of activeKeys) { try { await kvSetEx(mk, ex, ttlLeft); } catch {} }
          return res.status(200).json({ ok:true, reused:true, reason:'active-ip-reuse', code: ex.code, startsAt: ex.startsAt, endsAt: ex.endsAt });
        }
        // Optional cooldown (kept 0 per your ask)
        if (TY_COOLDOWN_HOURS > 0) {
          const cooldownUntil = t + TY_COOLDOWN_HOURS*3600*1000;
          if (cooldownUntil > now) {
            return res.status(429).json({ error:'rate_limited', reason:'cooldown-active', endsAt: new Date(t).toISOString(), cooldownUntil: new Date(cooldownUntil).toISOString() });
          }
        }
      }
    }

    // ---------- 2) Monthly limit (no remint this month) ----------
    const reserved = await kvSetNxEx(monthKey, { code:null, start: new Date(now).toISOString(), periodEndsAt: periodEnd.toISOString() }, ttlMonth);
    if (!reserved) {
      const existing = await kvGet(monthKey).catch(()=>null);
      // If they had a code earlier in the month, surface it; otherwise just block.
      if (existing?.code) {
        return res.status(429).json({ error:'already_claimed_monthly', reason:'monthly-lock', periodEndsAt: periodEnd.toISOString(), code: existing.code, reused:true });
      }
      return res.status(429).json({ error:'already_claimed_monthly', reason:'monthly-lock', periodEndsAt: periodEnd.toISOString(), reused:true });
    }

    // ---------- 3) Mint new code (48h) ----------
    let code=null, nodeId=null;
    for (let i=0;i<5;i++) {
      const tryCode = genCode('TY');
      try {
        const id = await createDiscountBasic({
          code: tryCode,
          startsAt: startsAt.toISOString(),
          endsAt:   endsAt.toISOString(),
          percent:  TY_PERCENT
        });
        code = tryCode; nodeId = id; break;
      } catch (e) {
        if (String(e?.message||'').includes('Code collision')) continue;
        await kvDel(monthKey).catch(()=>{});
        throw e;
      }
    }
    if (!code) { await kvDel(monthKey).catch(()=>{}); return res.status(502).json({ error:'discount_create_failed' }); }

    // Persist code into month key (so they can’t mint again in same month)
    await kvSet(monthKey, { code, nodeId, start: startsAt.toISOString(), periodEndsAt: periodEnd.toISOString() });

    // Write active IP lock through expiry (so household reuses)
    if (hasRealIp && activeKeys.length) {
      const ttlActive = Math.max(1, Math.ceil((endsAt.getTime() - now)/1000)) + Math.max(0, Math.floor(TY_COOLDOWN_HOURS*3600));
      const payload = { code, startsAt: startsAt.toISOString(), endsAt: endsAt.toISOString(), nodeId };
      for (const k of activeKeys) { try { await kvSetEx(k, payload, ttlActive); } catch {} }
    }

    // Soft cookie so the same browser “feels” claimed too
    setCookie(res, 'ty_claimed', '1', { maxAgeSec: Math.max(1, Math.ceil((endsAt.getTime() - now)/1000)) });

    return res.status(200).json({
      ok: true, reason: 'minted',
      code, startsAt: startsAt.toISOString(), endsAt: endsAt.toISOString(),
      periodEndsAt: periodEnd.toISOString(), reused: false
    });

  } catch (e) {
    console.error('thankyouclaim error', e);
    return res.status(500).json({ error: 'server_error', message: e?.message || String(e) });
  }
};
