<script>
(() => {
  // =========================
  // CONFIG (same as before)
  // =========================
  const HOURS = 48; // exact lifetime for the offer
  const API_URL = 'https://everlymade.vercel.app/api/thankyouclaim';
  const LOCAL_CODE_KEY = 'qr_lp_claim_v1';      // cached { code, expiresAt }
  const LOCAL_DEADLINE_KEY = 'qr_deadline_v2';  // cached raw deadline (ms)
  const DISPLAY_TZ = 'America/Chicago';         // set your display timezone

  // =========================
  // DOM handles (same IDs)
  // =========================
  const el = {
    d:  document.getElementById('qr-day'),
    h:  document.getElementById('qr-hour'),
    m:  document.getElementById('qr-min'),
    s:  document.getElementById('qr-sec'),
    code: document.getElementById('qr-code'),
    msg:  document.getElementById('qr-msg'),
    apply: document.getElementById('qr-apply'),
    copy:  document.getElementById('qr-copy'),
    // if your theme also has a <countdown-timer> custom element, we’ll sync it too:
    timerEl: document.querySelector('countdown-timer')
  };

  // =========================
  // Helpers (same style)
  // =========================
  const pad = n => String(n).padStart(2,'0');
  const nowMs = () => Date.now();

  function fmtInTZ(ms){
    try {
      return new Intl.DateTimeFormat(undefined, {
        timeZone: DISPLAY_TZ,
        dateStyle: 'medium',
        timeStyle: 'short',
        timeZoneName: 'short'
      }).format(new Date(ms));
    } catch {
      return new Date(ms).toLocaleString();
    }
  }

  function setMsg(text){
    if (el.msg) el.msg.textContent = text || '';
  }

  function paintDigits(diffMs){
    const s = Math.max(0, Math.floor(diffMs/1000));
    const d = Math.floor(s/86400);
    const h = Math.floor((s%86400)/3600);
    const m = Math.floor((s%3600)/60);
    const sec = s%60;
    el.d && (el.d.textContent = pad(d));
    el.h && (el.h.textContent = pad(h));
    el.m && (el.m.textContent = pad(m));
    el.s && (el.s.textContent = pad(sec));
  }

  function syncCustomTimer(tsMs){
    if (!el.timerEl || !tsMs) return;
    try { el.timerEl.setAttribute('expires-at', new Date(tsMs).toISOString()); } catch {}
  }

  function saveDeadline(ms){
    try { localStorage.setItem(LOCAL_DEADLINE_KEY, String(ms)); } catch {}
  }

  function loadDeadline(){
    try {
      const saved = parseInt(localStorage.getItem(LOCAL_DEADLINE_KEY) || '0', 10);
      return Number.isFinite(saved) ? saved : 0;
    } catch { return 0; }
  }

  function saveCodeCache(code, expiresAtIso){
    try { localStorage.setItem(LOCAL_CODE_KEY, JSON.stringify({ code, expiresAt: expiresAtIso })); } catch {}
  }

  function loadCodeCache(){
    try { return JSON.parse(localStorage.getItem(LOCAL_CODE_KEY) || 'null'); } catch { return null; }
  }

  // ======================================
  // 1) Establish an immediate local end
  // ======================================
  let end = nowMs() + HOURS*60*60*1000; // fallback 48h from now

  // if a prior deadline is saved and is close to 48h window, reuse it (prevents flicker)
  const prior = loadDeadline();
  if (prior > nowMs() && Math.abs(prior - end) < 10*60*1000) {
    end = prior;
  } else {
    saveDeadline(end);
  }

  // Paint right away
  paintDigits(end - nowMs());
  syncCustomTimer(end);

  // Drive the digits like before
  const tmr = setInterval(() => {
    const diff = end - nowMs();
    paintDigits(diff);
    if (diff <= 0) {
      setMsg('Offer expired.');
      if (el.apply) el.apply.disabled = true;
      clearInterval(tmr);
    }
  }, 250);

  // ====================================================
  // 2) Claim/Reclaim (with server-sync of true endsAt)
  // ====================================================
  async function claim() {
    // If we already created a code for this visitor and it hasn't expired, reuse it
    const saved = loadCodeCache();
    const savedEndMs = Date.parse(saved?.expiresAt || '');
    if (saved && saved.code && savedEndMs > nowMs()) {
      console.info('[thankyouclaim] using cached code', saved.code, 'exp:', saved.expiresAt);
      if (el.code) el.code.textContent = saved.code;
      setMsg('Code created. Expires at ' + fmtInTZ(savedEndMs));
      // make sure our timer is synced to cached expiry
      end = savedEndMs;
      saveDeadline(end);
      syncCustomTimer(end);
      return saved;
    }

    // Ask your API to mint / return a code. We send our current local end,
    // but the server may return an earlier endsAt (for IP-lock consistency).
    const body = { expiresAt: new Date(end).toISOString() };
    console.info('[thankyouclaim] POST', API_URL, body);

    let r, data = {};
    try {
      r = await fetch(API_URL, {
        method:'POST',
        headers:{'Content-Type':'application/json'},
        body: JSON.stringify(body)
      });
      try { data = await r.json(); } catch {}
      console.info('[thankyouclaim] response', r?.status, data);
    } catch (e) {
      console.warn('[thankyouclaim] network error', e);
      setMsg('Could not create code.');
      if (el.apply) el.apply.disabled = true;
      return null;
    }

    // Friendly handling for IP cooldown/rate-limit
    if (r.status === 429) {
      const serverEnd = Date.parse(data?.endsAt || data?.expiresAt || '');
      if (data?.code && el.code) el.code.textContent = data.code;
      if (serverEnd) {
        end = serverEnd;             // <-- CRITICAL: always trust server
        saveDeadline(end);
        syncCustomTimer(end);
        setMsg((data?.message || 'This offer was already claimed from your network.') + ' Expires at ' + fmtInTZ(end));
      } else {
        setMsg(data?.message || 'This offer was already claimed from your network.');
      }
      // allow applying if we have a code
      if (el.apply && data?.code) el.apply.disabled = false;
      return null;
    }

    if (!r.ok || !data?.code) {
      setMsg('Could not create code' + (r?.status ? ` (${r.status})` : ''));
      if (el.apply) el.apply.disabled = true;
      return null;
    }

    // ---- SUCCESS: show code + sync timer to server-provided endsAt ----
    const serverEnd = Date.parse(data.endsAt || data.expiresAt || end);
    if (el.code) el.code.textContent = data.code;
    end = serverEnd;                 // <-- CRITICAL: always trust server
    saveDeadline(end);
    syncCustomTimer(end);

    setMsg('Code created. Expires at ' + fmtInTZ(end));
    saveCodeCache(data.code, new Date(end).toISOString());
    return data;
  }

  claim();

  // =========================
  // Buttons (same as before)
  // =========================
  el.apply && el.apply.addEventListener('click', () => {
    const saved = loadCodeCache();
    const code  = (saved && saved.code) || (el.code?.textContent || '').trim();
    if (!code || code.includes('—')) return;
    window.location.href = `/discount/${encodeURIComponent(code)}?redirect=/collections/all`;
  });

  el.copy && el.copy.addEventListener('click', async () => {
    const code = (el.code?.textContent || '').trim();
    if (!code || code.includes('—')) return;
    try {
      await navigator.clipboard.writeText(code);
      el.copy.textContent='Copied!';
      setTimeout(()=> el.copy.textContent='Copy code', 1200);
    } catch(e){}
  });
})();
</script>
