// api/thankyouclaim.js — CommonJS (Vercel /api/*)
// Per-visitor monthly limit + optional strict-once; supports Upstash Redis REST or Vercel KV REST.
// Active-IP reuse is handled FIRST so a previously minted code is returned even if monthly reservation would fail.

// --- Required ENVs ---
// KV (choose one pair):
//   UPSTASH_REDIS_REST_URL, UPSTASH_REDIS_REST_TOKEN
//   or KV_REST_API_URL, KV_REST_API_TOKEN
// Shopify:
//   SHOPIFY_SHOP, SHOPIFY_ADMIN_TOKEN
//   SHOPIFY_API_VERSION (optional; default '2025-07')

// --- Optional behavior ENVs ---
/*
IP_HASH_SALT
TY_PERCENT               (default 20)
TY_COOLDOWN_HOURS        (default 0)
PERIOD_MONTHS            (default 1)
REQUIRE_SIGNED_IN        (default false)
STRICT_ONCE              (default false)
EVER_TTL_DAYS            (default 0)
REQUIRE_REAL_IP_FOR_GUEST (default false)
HASH_IP_WITH_UA          (default false)
VISITOR_KEY_MODE         (default "cookie+ip") // "cookie" | "ip" | "cookie+ip"
*/

const crypto = require('crypto');

// ----- Shopify -----
const SHOPIFY_SHOP        = process.env.SHOPIFY_SHOP;
const SHOPIFY_ADMIN_TOKEN = process.env.SHOPIFY_ADMIN_TOKEN;
const API_VERSION         = process.env.SHOPIFY_API_VERSION || '2025-07';

// ----- KV / Redis (Upstash or Vercel) -----
const KV_URL   = process.env.KV_REST_API_URL || process.env.UPSTASH_REDIS_REST_URL;
const KV_TOKEN = process.env.KV_REST_API_TOKEN || process.env.UPSTASH_REDIS_REST_TOKEN;

// Decide param style based on host
function kvStyle(url) {
  const u = (url || '').toLowerCase();
  // Vercel KV uses *.vercel-storage.com (sometimes without "kv." prefix)
  if (u.includes('vercel-storage.com')) return 'vercel'; // ex=, nx=true
  if (u.includes('.upstash.io'))       return 'upstash'; // EX=, NX=1
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

// ----- Env guard -----
function assertEnvOrThrow() {
  const missing = [];
  if (!SHOPIFY_SHOP) missing.push('SHOPIFY_SHOP');
  if (!SHOPIFY_ADMIN_TOKEN) missing.push('SHOPIFY_ADMIN_TOKEN');
  if (!KV_URL) missing.push('KV_REST_API_URL or UPSTASH_REDIS_REST_URL');
  if (!KV_TOKEN) missing.push('KV_REST_API_TOKEN or UPSTASH_REDIS_REST_TOKEN');
  if (missing.length) throw new Error(`Missing ENV: ${missing.join(', ')}`);
}

// ----- KV helpers -----
async function kvGet(key) {
  if (!KV_URL || !KV_TOKEN || !key) return null;
  const r = await fetch(`${KV_URL}/get/${encodeURIComponent(key)}`, {
    headers: { Authorization: `Bearer ${KV_TOKEN}` }, cache: 'no-store'
  });
  if (!r.ok) throw new Error(`KV GET failed: ${r.status}`);
  const data = await r.json().catch(() => null);
  try { return data?.result ? JSON.parse(data.result) : null; } catch { return data?.result ?? null; }
}

async function kvSetEx(key, value, ttlSeconds) {
  const ttl = encodeURIComponent(ttlSeconds);
  const url = KV_STYLE === 'upstash'
    ? `${KV_URL}/set/${encodeURIComponent(key)}/${encodeURIComponent(JSON.stringify(value))}?EX=${ttl}`
    : `${KV_URL}/set/${encodeURIComponent(key)}/${encodeURIComponent(JSON.stringify(value))}?ex=${ttl}`;
  const r = await fetch(url, { method:'POST', headers:{ Authorization:`Bearer ${KV_TOKEN}` }});
  if (!r.ok) throw new Error(`KV SET EX failed: ${r.status}`);
  const data = await r.json().catch(()=> ({}));
  if (data?.error) throw new Error(`KV error: ${data.error}`);
  return true;
}

async function kvSetNxEx(key, value, ttlSeconds) {
  const ttl = encodeURIComponent(ttlSeconds);
  const url = KV_STYLE === 'upstash'
    ? `${KV_URL}/set/${encodeURIComponent(key)}/${encodeURIComponent(JSON.stringify(value))}?EX=${ttl}&NX=1`
    : `${KV_URL}/set/${encodeURIComponent(key)}/${encodeURIComponent(JSON.stringify(value))}?ex=${ttl}&nx=true`;
  const r = await fetch(url, { method:'POST', headers:{ Authorization:`Bearer ${KV_TOKEN}` }});
  if (!r.ok) throw new Error(`KV SET NX EX failed: ${r.status}`);
  const data = await r.json().catch(()=> null);
  return data?.result === 'OK';
}

async function kvDel(key) {
  const r = await fetch(`${KV_URL}/del/${encodeURIComponent(key)}`, {
    method:'POST', headers:{ Authorization:`Bearer ${KV_TOKEN}` }
  });
  if (!r.ok) throw new Error(`KV DEL failed: ${r.status}`);
  return true;
}

async function kvSet(key, value) {
  const r = await fetch(`${KV_URL}/set/${encodeURIComponent(key)}/${encodeURIComponent(JSON.stringify(value))}`, {
    method:'POST', headers:{ Authorization:`Bearer ${KV_TOKEN}` }
  });
  if (!r.ok) throw new Error(`KV SET failed: ${r.status}`);
  const data = await r.json().catch(()=> ({}));
  if (data?.error) throw new Error(`KV error: ${data.error}`);
  return true;
}

async function kvSetExDays(key, value, days) {
  if (days <= 0) return kvSet(key, value);
  return kvSetEx(key, Math.max(1, Math.floor(days * 86400)) && value, Math.max(1, Math.floor(days * 86400)));
}

// ----- Utils -----
function genCode(prefix = 'TY') {
  const pool = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'; // no 0/O/1/I
  let four = ''; for (let i=0;i<4;i++) four += pool[Math.floor(Math.random()*pool.length)];
  return `${prefix}-${four}`;
}
function isPrivateIp(ip){ return /^10\.|^192\.168\.|^172\.(1[6-9]|2\d|3[0-1])\.|^127\.|^::1$|^fc00:|^fe80:/.test(ip); }
function getClientIpDetailed(req){
  const pick = v => (typeof v==='string' && v.trim()) ? v.trim() : '';
  const cf  = pick(req.headers['cf-connecting-ip']);       if (cf)  return { ip: cf, kind:'cf' };
  const tci = pick(req.headers['true-client-ip']);         if (tci) return { ip: tci, kind:'tci' };
  const vff = pick(req.headers['x-vercel-forwarded-for']); if (vff) return { ip: vff.split(',')[0].trim().replace(/^::ffff:/,''), kind:'vff' };
  const xff = pick(req.headers['x-forwarded-for']);
  if (xff){
    const parts = xff.split(',').map(s=>s.trim()).filter(Boolean).map(s=>s.replace(/^::ffff:/,''));
    for (const ip of parts){ if (!isPrivateIp(ip)) return { ip, kind:'xff' }; }
    if (parts.length) return { ip: parts[0], kind:'xff' };
  }
  const xr = pick(req.headers['x-real-ip']);               if (xr)  return { ip: xr.replace(/^::ffff:/,''), kind:'xr' };
  const sock = pick(req.socket?.remoteAddress);            if (sock) return { ip: sock.replace(/^::ffff:/,''), kind:'sock' };
  return { ip:'pseudo', kind:'pseudo' };
}
function hmacHash(input, salt=IP_HASH_SALT){ return crypto.createHmac('sha256', salt).update(String(input)).digest('hex'); }
function parseCookies(req){
  const h = req.headers.cookie || '';
  return h.split(';').reduce((acc, part)=>{
    const [k, ...rest] = part.split('=');
    if (!k || rest.length===0) return acc;
    acc[k.trim()] = decodeURIComponent(rest.join('=').trim());
    return acc;
  },{});
}
function appendHeader(res, name, value){
  const prev = res.getHeader(name);
  if (!prev) return res.setHeader(name, value);
  if (Array.isArray(prev)) return res.setHeader(name, prev.concat(value));
  return res.setHeader(name, [prev, value]);
}
function setCookie(res, name, value, {maxAgeSec, path='/', httpOnly=true, sameSite='Lax', secure=true}={}){
  const parts = [`${name}=${encodeURIComponent(value)}`, `Path=${path}`, `SameSite=${sameSite}`];
  if (httpOnly) parts.push('HttpOnly'); if (secure) parts.push('Secure');
  if (Number.isFinite(maxAgeSec)) parts.push(`Max-Age=${Math.max(0, Math.floor(maxAgeSec))}`);
  appendHeader(res, 'Set-Cookie', parts.join('; '));
}
function addMonths(d, n){ const x=new Date(d), m=x.getMonth(); x.setMonth(m+n); if (x.getMonth()!==((m+n)%12+12)%12) x.setDate(0); return x; }
function getPeriodStart(nowMs){ const d = new Date(nowMs); d.setUTCDate(1); d.setUTCHours(0,0,0,0); return d; }
function getPeriodEnd(nowMs, months){ return addMonths(getPeriodStart(nowMs), months); }
function secondsUntil(fromMs, to){ return Math.max(1, Math.ceil((to.getTime()-fromMs)/1000)); }

// ----- Visitor identity -----
function getOrCreateVisitorId(req, res){
  const cookies = parseCookies(req);
  let vid = cookies['ty_vid'];
  if (!vid || !/^[a-z0-9-]{12,}$/.test(vid)){
    vid = `${Date.now().toString(36)}-${Math.random().toString(36).slice(2,10)}`;
    setCookie(res, 'ty_vid', vid, { maxAgeSec: 365*24*3600, httpOnly:true, sameSite:'Lax', secure:true });
  }
  return vid;
}
function makeVisitorHash({mode, vid, hasRealIp, ip, ua}){
  if (mode==='cookie') return hmacHash(`vid:${vid}`);
  if (mode==='ip'){
    const ipBase = hasRealIp ? (HASH_IP_WITH_UA ? `${ip}|${ua}` : ip) : 'noip';
    return hmacHash(`ip:${ipBase}`);
  }
  const ipPart = hasRealIp ? (HASH_IP_WITH_UA ? `${ip}|${ua}` : ip) : 'noip';
  return hmacHash(`vid:${vid}|ip:${ipPart}`);
}

// ----- Shopify GraphQL -----
async function shopifyGraphQL(query, variables){
  const r = await fetch(`https://${SHOPIFY_SHOP}/admin/api/${API_VERSION}/graphql.json`, {
    method:'POST',
    headers:{ 'X-Shopify-Access-Token': SHOPIFY_ADMIN_TOKEN, 'Content-Type':'application/json' },
    body: JSON.stringify({ query, variables })
  });
  const data = await r.json().catch(()=> ({}));
  return { ok:r.ok, data, status:r.status };
}
async function createDiscountBasic({ code, startsAt, endsAt, percent }){
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
  if (errs?.length){
    const exists = errs.find(e => String(e.message||'').toLowerCase().includes('already exists'));
    if (exists) throw new Error('Code collision');
    throw new Error(`Shopify validation: ${JSON.stringify(errs)}`);
  }
  const node = data?.data?.discountCodeBasicCreate?.codeDiscountNode;
  if (!node) throw new Error('No codeDiscountNode returned');
  return node.id;
}
async function deleteDiscountByNodeId(nodeId){
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
function setDebugHeaders(res, obj = {}){
  for (const [k,v] of Object.entries(obj)) if (v != null)
    res.setHeader(`X-TY-${k}`, typeof v==='string' ? v : JSON.stringify(v));
  res.setHeader('Access-Control-Expose-Headers',
    ['X-TY-ipKind','X-TY-ipHash','X-TY-visitorHash','X-TY-visitorMode','X-TY-guestMonthKey','X-TY-custMonthKey','X-TY-activeIpKey','X-TY-reason'].join(', ')
  );
}
function getDebugFlag(req, body){
  try{
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
  if (req.method === 'OPTIONS'){
    res.setHeader('Access-Control-Allow-Origin','*');
    res.setHeader('Access-Control-Allow-Methods','POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers','Content-Type, Authorization');
    return res.status(204).end();
  }
  if (req.method !== 'POST') return res.status(405).json({ error:'Method not allowed' });

  // Env guard
  try { assertEnvOrThrow(); }
  catch(e){
    res.setHeader('Cache-Control','no-store');
    res.setHeader('Access-Control-Allow-Origin','*');
    setDebugHeaders(res, { reason:'server_misconfig', error:String(e?.message||e), apiVersion:API_VERSION, shop:SHOPIFY_SHOP });
    return res.status(500).json({ error:'server_misconfig', message:String(e?.message||e) });
  }

  try {
    res.setHeader('Cache-Control','no-store');
    res.setHeader('Access-Control-Allow-Origin','*');

    const body = typeof req.body === 'string' ? JSON.parse(req.body||'{}') : (req.body||{});
    const DEBUG = getDebugFlag(req, body);

    const clientExpiresAtIso = body?.expiresAt;
    const customerIdRaw      = body?.customerId || null;
    const customerEmailRaw   = body?.customerEmail || null;

    const cookies = parseCookies(req);
    const browserClaimed = cookies['ty_claimed'] === '1';

    if (REQUIRE_SIGNED_IN && !customerIdRaw && !customerEmailRaw) {
      setDebugHeaders(res, { reason:'signin_required' });
      return res.status(401).json({ error:'signin_required', reason:'signin_required' });
    }

    let customerKeyHash = null;
    if (customerIdRaw) customerKeyHash = hmacHash(`id:${String(customerIdRaw).trim()}`);
    else if (customerEmailRaw) customerKeyHash = hmacHash(`email:${String(customerEmailRaw).trim().toLowerCase()}`);

    const now = Date.now();
    const startsAt = new Date(now);
    const serverDefaultEnd = new Date(now + 48*3600*1000);

    let chosenEndsAt = serverDefaultEnd;
    if (clientExpiresAtIso){
      const clientEndMs = Date.parse(clientExpiresAtIso);
      if (!Number.isNaN(clientEndMs) && clientEndMs > now && clientEndMs < serverDefaultEnd.getTime())
        chosenEndsAt = new Date(clientEndMs);
    }

    // Identity
    const ipInfo   = getClientIpDetailed(req);
    const hasRealIp = ipInfo.kind !== 'pseudo';
    const uaForHash = (req.headers['user-agent'] || '').toString().slice(0,200);
    const ipHash    = hasRealIp ? hmacHash(HASH_IP_WITH_UA ? `${ipInfo.ip}|${uaForHash}` : ipInfo.ip) : null;

    const visitorId   = getOrCreateVisitorId(req, res);
    const visitorHash = makeVisitorHash({ mode:VISITOR_KEY_MODE, vid:visitorId, hasRealIp, ip:ipInfo.ip, ua:uaForHash });

    const periodStart = getPeriodStart(now);
    const periodEndsAt = getPeriodEnd(now, PERIOD_MONTHS);
    const ttlSecPeriod = secondsUntil(now, periodEndsAt);
    const cy = periodStart.getUTCFullYear();
    const cm = String(periodStart.getUTCMonth()+1).padStart(2,'0');
    const periodLabel = `${cy}${cm}`;

    // Keys
    const kvKeyActiveIp    = hasRealIp ? `ty:ip:${ipHash}` : null;
    const kvKeyEverIp      = hasRealIp ? `ty:ip:ever:${ipHash}` : null;
    const kvKeyGuestPeriod = `ty:guest:period:${PERIOD_MONTHS}m:${periodLabel}:${visitorHash}`;
    const kvKeyCustPeriod  = customerKeyHash ? `ty:cust:period:${PERIOD_MONTHS}m:${periodLabel}:${customerKeyHash}` : null;
    const kvKeyCustEver    = customerKeyHash ? `ty:cust:ever:${customerKeyHash}` : null;

    setDebugHeaders(res, {
      ipKind: ipInfo.kind, ipHash, visitorHash, visitorMode: VISITOR_KEY_MODE,
      guestMonthKey: kvKeyGuestPeriod, custMonthKey: kvKeyCustPeriod, activeIpKey: kvKeyActiveIp
    });

    if (!hasRealIp && !customerKeyHash && REQUIRE_REAL_IP_FOR_GUEST) {
      setDebugHeaders(res, { reason:'no-real-ip-and-guest' });
      return res.status(401).json({ error:'signin_required', reason:'no-real-ip-and-guest' });
    }

    // -------- DEBUG (no writes) --------
    if (DEBUG){
      const existingGuest = await kvGet(kvKeyGuestPeriod).catch(e=>({kvError:String(e?.message||e)}));
      const existingCust  = kvKeyCustPeriod ? await kvGet(kvKeyCustPeriod).catch(e=>({kvError:String(e?.message||e)})) : null;
      const existingAct   = kvKeyActiveIp ? await kvGet(kvKeyActiveIp).catch(e=>({kvError:String(e?.message||e)})) : null;
      const existingEverI = kvKeyEverIp ? await kvGet(kvKeyEverIp).catch(e=>({kvError:String(e?.message||e)})) : null;
      const existingEverC = kvKeyCustEver ? await kvGet(kvKeyCustEver).catch(e=>({kvError:String(e?.message||e)})) : null;

      const activeOk = existingAct && existingAct.endsAt && Date.parse(existingAct.endsAt) > now;

      const wouldBlock =
        (STRICT_ONCE && (browserClaimed || (existingEverI && !existingEverI.kvError) || (existingEverC && !existingEverC.kvError))) ||
        (!!existingCust && !existingCust.kvError) ||
        (!!existingGuest && !existingGuest.kvError) ||
        activeOk;

      const reason =
        STRICT_ONCE && browserClaimed ? 'browser-cookie' :
        STRICT_ONCE && existingEverI && !existingEverI.kvError ? 'ip-ever-lock' :
        STRICT_ONCE && existingEverC && !existingEverC.kvError ? 'customer-ever-lock' :
        existingCust && !existingCust.kvError ? 'monthly-lock-customer' :
        existingGuest && !existingGuest.kvError ? 'monthly-lock-guest' :
        activeOk ? 'active-ip-reuse' : 'would-mint';

      setDebugHeaders(res, { debug:'1', wouldBlock:String(wouldBlock), reason, kvStyle:KV_STYLE });
      return res.status(200).json({
        ok: !wouldBlock, debug:true, reason,
        keys:{ kvKeyGuestPeriod, kvKeyCustPeriod, kvKeyActiveIp, kvKeyEverIp, kvKeyCustEver },
        existing:{ guestMonthly:existingGuest, customerMonthly:existingCust, activeIp:existingAct, everIp:existingEverI, everCustomer:existingEverC },
        note:'No writes performed in debug mode.'
      });
    }

    // -------- Active IP reuse (DO THIS FIRST) --------
    if (hasRealIp && kvKeyActiveIp){
      try{
        const existing = await kvGet(kvKeyActiveIp);
        if (existing){
          const existingEnd = Date.parse(existing.endsAt);
          if (existingEnd > now){
            return res.status(200).json({
              ok:true, reused:true, reason:'active-ip-reuse',
              code: existing.code, startsAt: existing.startsAt, endsAt: existing.endsAt,
              nodeId: existing.nodeId || null, ipKind: ipInfo.kind
            });
          }
          if (TY_COOLDOWN_HOURS > 0){
            const cooldownUntil = existingEnd + TY_COOLDOWN_HOURS*3600*1000;
            if (cooldownUntil > now){
              return res.status(429).json({
                error:'rate_limited', reason:'cooldown-active',
                message:'Already claimed from your network. Try again later.',
                code: existing.code, endsAt: existing.endsAt,
                cooldownUntil: new Date(cooldownUntil).toISOString(),
                ipKind: ipInfo.kind
              });
            }
          }
        }
      } catch (e){
        // If KV read flaked, continue—monthly reservation may still work.
        setDebugHeaders(res, { ipReuseReadError: String(e?.message||e) });
      }
    }

    // -------- STRICT once (optional) --------
    if (STRICT_ONCE){
      if (browserClaimed) return res.status(429).json({ error:'already_claimed', reason:'browser-cookie' });
      if (hasRealIp && kvKeyEverIp){
        const everIp = await kvGet(kvKeyEverIp);
        if (everIp) return res.status(429).json({ error:'already_claimed', reason:'ip-ever-lock' });
      }
      if (customerKeyHash && kvKeyCustEver){
        const everCust = await kvGet(kvKeyCustEver);
        if (everCust) return res.status(429).json({ error:'already_claimed_customer', reason:'customer-ever-lock' });
      }
    }

    // -------- Monthly reservation (NX+EX) --------
    const monthPayload = (marker)=>({
      code:null, marker,
      firstClaimAt: new Date(now).toISOString(),
      periodEndsAt: periodEndsAt.toISOString(),
      nodeId:null
    });
    let reservedKeys = [];
    try{
      if (customerKeyHash && kvKeyCustPeriod){
        const ok1 = await kvSetNxEx(kvKeyCustPeriod, monthPayload('cust-reserve'), ttlSecPeriod);
        if (!ok1){
          const existing = await kvGet(kvKeyCustPeriod);
          return res.status(429).json({
            error:'already_claimed_monthly', reason:'monthly-lock-customer',
            periodEndsAt: periodEndsAt.toISOString(),
            code: existing?.code || undefined, reused:true
          });
        }
        reservedKeys.push(kvKeyCustPeriod);
        const ok2 = await kvSetNxEx(kvKeyGuestPeriod, monthPayload('mirror'), ttlSecPeriod);
        if (!ok2){
          try{ await kvDel(kvKeyCustPeriod); }catch{}
          const existing = await kvGet(kvKeyGuestPeriod);
          return res.status(429).json({
            error:'already_claimed_monthly', reason:'monthly-lock-guest',
            periodEndsAt: periodEndsAt.toISOString(),
            code: existing?.code || undefined, reused:true
          });
        }
        reservedKeys.push(kvKeyGuestPeriod);
      } else {
        const ok = await kvSetNxEx(kvKeyGuestPeriod, monthPayload('guest-reserve'), ttlSecPeriod);
        if (!ok){
          const existing = await kvGet(kvKeyGuestPeriod);
          return res.status(429).json({
            error:'already_claimed_monthly', reason:'monthly-lock-guest',
            periodEndsAt: periodEndsAt.toISOString(),
            code: existing?.code || undefined, reused:true
          });
        }
        reservedKeys.push(kvKeyGuestPeriod);
      }
    } catch(kvErr){
      for (const k of reservedKeys){ try{ await kvDel(k); }catch{} }
      setDebugHeaders(res, { reason:'kv-failure', kvError:String(kvErr?.message||kvErr), kvStyle:KV_STYLE });
      return res.status(500).json({ error:'kv_unavailable', message:String(kvErr?.message||kvErr) });
    }

    // -------- Mint code via Shopify --------
    let code = null, nodeId = null;
    for (let attempt=1; attempt<=5; attempt++){
      const tryCode = genCode('TY');
      try{
        const id = await createDiscountBasic({
          code: tryCode,
          startsAt: startsAt.toISOString(),
          endsAt:   chosenEndsAt.toISOString(),
          percent:  TY_PERCENT
        });
        code = tryCode; nodeId = id; break;
      } catch(err){
        if (String(err?.message||'').includes('Code collision')) continue;
        for (const k of reservedKeys){ try{ await kvDel(k); }catch{} }
        throw err;
      }
    }
    if (!code){
      for (const k of reservedKeys){ try{ await kvDel(k); }catch{} }
      return res.status(502).json({ error:'Failed to create discount code' });
    }

    // Persist monthly record
    const monthlyRecord = { code, nodeId, firstClaimAt: new Date(now).toISOString(), periodEndsAt: periodEndsAt.toISOString() };
    await kvSet(kvKeyGuestPeriod, monthlyRecord);
    if (customerKeyHash && kvKeyCustPeriod) await kvSet(kvKeyCustPeriod, monthlyRecord);

    // Race defense: if guest key ends up with a different code, revoke the new mint
    const checkGuest = await kvGet(kvKeyGuestPeriod);
    if (checkGuest && checkGuest.code && checkGuest.code !== code){
      try{ await deleteDiscountByNodeId(nodeId); }catch{}
      return res.status(429).json({
        error:'already_claimed_monthly', reason:'monthly-lock-race',
        periodEndsAt: periodEndsAt.toISOString(),
        code: checkGuest.code, revokedNewMint:true, reused:true, ipKind: ipInfo.kind
      });
    }

    // Active IP lock through code expiry (+ cooldown if any)
    if (hasRealIp && kvKeyActiveIp){
      const ttlSecActive =
        Math.max(1, Math.ceil((chosenEndsAt.getTime() - now) / 1000)) +
        Math.max(0, Math.floor(TY_COOLDOWN_HOURS * 3600));
      await kvSetEx(kvKeyActiveIp, {
        code, startsAt: startsAt.toISOString(), endsAt: chosenEndsAt.toISOString(), nodeId
      }, ttlSecActive);
    }

    // Optional "once ever"
    if (STRICT_ONCE && hasRealIp && kvKeyEverIp){
      await kvSetExDays(kvKeyEverIp, { code, firstClaimAt: startsAt.toISOString(), endsAt: chosenEndsAt.toISOString(), nodeId }, EVER_TTL_DAYS);
      if (customerKeyHash && kvKeyCustEver){
        await kvSetExDays(kvKeyCustEver, { code, firstClaimAt: startsAt.toISOString(), endsAt: chosenEndsAt.toISOString(), nodeId }, EVER_TTL_DAYS);
      }
    }

    // Soft browser cookie
    const cookieMaxAge = STRICT_ONCE ? 10*365*24*3600 : Math.max(1, Math.ceil((chosenEndsAt.getTime()-now)/1000));
    setCookie(res, 'ty_claimed', '1', { maxAgeSec: cookieMaxAge });

    setDebugHeaders(res, { reason:'minted', code, nodeId, endsAt: chosenEndsAt.toISOString(), ipKind: ipInfo.kind, apiVersion: API_VERSION, kvStyle: KV_STYLE });

    return res.status(200).json({
      ok:true, reason:'minted',
      code, startsAt: startsAt.toISOString(), endsAt: chosenEndsAt.toISOString(),
      nodeId, customerLimitedByMonths: customerKeyHash ? PERIOD_MONTHS : undefined,
      guestLimitedByMonths: PERIOD_MONTHS, ipKind: ipInfo.kind
    });

  } catch(e){
    console.error('Unhandled error creating discount', e);
    setDebugHeaders(res, { reason:'server-error', error:String(e?.message||e), apiVersion: API_VERSION });
    return res.status(500).json({ error:'Unhandled error', message: e?.message || String(e) });
  }
};
