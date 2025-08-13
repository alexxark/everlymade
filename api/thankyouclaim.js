<script>
(() => {
  // ====== CONFIG ======
  const HOURS = 48;                               // local fallback window
  const API_URL = 'https://everlymade.vercel.app/api/thankyouclaim';
  const DISPLAY_TZ = 'America/Los_Angeles';       // change if you want a different timezone
  const PERSIST = true;                           // persist the countdown per browser

  // versioned keys so old local data won't break new logic
  const KEY_VER = 'v3';
  const DEADLINE_KEY = `countdown_deadline_${KEY_VER}`;
  const CODE_KEY = `qr_claim_${KEY_VER}`;

  // ====== DOM ======
  const timerEl = document.querySelector('countdown-timer');
  const el = {
    code:  document.getElementById('qr-code'),
    msg:   document.getElementById('qr-msg'),
    apply: document.getElementById('qr-apply'),
    copy:  document.getElementById('qr-copy'),
  };

  function fmt(ms){
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

  function setTimer(ms){
    if (timerEl && ms && !Number.isNaN(ms)) {
      timerEl.setAttribute('expires-at', new Date(ms).toISOString());
      if (PERSIST) localStorage.setItem(DEADLINE_KEY, String(ms));
    }
  }

  function setMsg(s){ if (el.msg) el.msg.textContent = s || ''; }

  // ====== 1) Bootstrap local deadline (used only for initial UI) ======
  const now = Date.now();
  const fallbackEnd = now + HOURS * 60 * 60 * 1000;

  let endAt = fallbackEnd;

  if (PERSIST) {
    const saved = parseInt(localStorage.getItem(DEADLINE_KEY) || '0', 10);
    // only reuse a saved deadline if it is in the future and roughly matches a 48h window
    if (saved > now && Math.abs(saved - fallbackEnd) < 10 * 60 * 1000) {
      endAt = saved;
    } else {
      localStorage.setItem(DEADLINE_KEY, String(endAt));
    }
  }

  // Paint the UI immediately with our best guess
  setTimer(endAt);

  // ====== 2) Call API and ALWAYS sync to server endsAt ======
  (async () => {
    let bodyExpires = null;
    try {
      const cached = JSON.parse(localStorage.getItem(CODE_KEY) || 'null');
      // prefer any cached code's expiry to avoid extending the window
      bodyExpires = cached?.expiresAt || new Date(endAt).toISOString();
    } catch {
      bodyExpires = new Date(endAt).toISOString();
    }

    const r = await fetch(API_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ expiresAt: bodyExpires })
    });

    let data = {};
    try { data = await r.json(); } catch {}

    // Handle rate limit (same IP, cooldown) gracefully
    if (r.status === 429) {
      if (data?.endsAt) setTimer(Date.parse(data.endsAt));
      if (data?.code && el.code) el.code.textContent = data.code;
      setMsg(data?.message || 'This offer was already claimed from your network.');
      // leave Apply enabled so user can still apply the returned code
      if (el.apply) el.apply.disabled = false;
      return;
    }

    if (!r.ok || !data?.code || !(data.endsAt || data.expiresAt)) {
      setMsg(`Could not create code${r.status ? ` (${r.status})` : ''}.`);
      if (el.apply) el.apply.disabled = true;
      return;
    }

    // TRUST THE SERVER: sync countdown and cache
    const serverEndMs = Date.parse(data.endsAt || data.expiresAt);
    setTimer(serverEndMs);

    if (el.code) el.code.textContent = data.code;
    setMsg('Code created. Expires at ' + fmt(serverEndMs));

    try {
      localStorage.setItem(CODE_KEY, JSON.stringify({
        code: data.code,
        expiresAt: new Date(serverEndMs).toISOString()
      }));
    } catch {}
  })();

  // ====== 3) Buttons ======
  if (el.apply) {
    el.apply.addEventListener('click', () => {
      let code = (el.code?.textContent || '').trim();
      if (!code || code.includes('—')) {
        try {
          const saved = JSON.parse(localStorage.getItem(CODE_KEY) || 'null');
          code = saved?.code || '';
        } catch {}
      }
      if (!code) return;
      window.location.href = `/discount/${encodeURIComponent(code)}?redirect=/collections/all`;
    });
  }

  if (el.copy) {
    el.copy.addEventListener('click', async () => {
      const code = (el.code?.textContent || '').trim();
      if (!code || code.includes('—')) return;
      try {
        await navigator.clipboard.writeText(code);
        el.copy.textContent = 'Copied!';
        setTimeout(() => el.copy.textContent = 'Copy code', 1200);
      } catch {}
    });
  }
})();
</script>
