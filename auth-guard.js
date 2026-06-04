/*!
 * SSO Auth Guard v2 — fail-OPEN khi local session còn hạn.
 * Sửa lỗi "treo Đang xác thực phiên đăng nhập...":
 *  - Nếu server trả [] (RLS chặn / row chưa sync) -> KHÔNG xoá auth, vẫn cho vào.
 *  - Chỉ redirect khi local thiếu/hết hạn HOẶC server xác nhận expires_at đã hết.
 *  - Mọi nhánh đều gọi reveal() để tránh kẹt overlay.
 */
(function () {
  var SUPABASE_URL = 'https://edsowiramriosgwfuewg.supabase.co';
  var SUPABASE_ANON_KEY = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImVkc293aXJhbXJpb3Nnd2Z1ZXdnIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NzgyNDMzMDgsImV4cCI6MjA5MzgxOTMwOH0.aocvFLnJrl5LFPdxDf9zbhvT6HT7NpCEMFtiUr_M3gM';
  var AUTH_KEY = 'itHub_sso_auth';
  var USER_KEY = 'itHub_sso_user';
  var SESSION_KEY = 'itHub_sso_session';
  var LOGIN_URL = './index.html';
  var FETCH_TIMEOUT_MS = 5000;

  try {
    var styleEl = document.createElement('style');
    styleEl.id = '__sso_guard_style';
    styleEl.textContent =
      'html.__sso_guard_pending body{visibility:hidden!important;}' +
      '#__sso_guard_overlay{position:fixed;inset:0;z-index:2147483647;background:#0a0e1a;' +
      'display:flex;align-items:center;justify-content:center;color:#9fb3d1;' +
      'font:14px/1.4 system-ui,-apple-system,Segoe UI,Roboto,sans-serif;}' +
      '#__sso_guard_overlay .__sp{width:28px;height:28px;border:3px solid #1f2a44;' +
      'border-top-color:#4f8cff;border-radius:50%;animation:__sp_spin 0.9s linear infinite;margin-right:12px;}' +
      '@keyframes __sp_spin{to{transform:rotate(360deg);}}';
    (document.head || document.documentElement).appendChild(styleEl);
    document.documentElement.classList.add('__sso_guard_pending');
  } catch (e) {}

  function showOverlay(msg) {
    function _add() {
      if (document.getElementById('__sso_guard_overlay')) return;
      var d = document.createElement('div');
      d.id = '__sso_guard_overlay';
      d.innerHTML = '<div class="__sp"></div><span>' + (msg || 'Đang xác thực...') + '</span>';
      (document.body || document.documentElement).appendChild(d);
    }
    if (document.body) _add();
    else document.addEventListener('DOMContentLoaded', _add);
  }

  function reveal() {
    document.documentElement.classList.remove('__sso_guard_pending');
    var o = document.getElementById('__sso_guard_overlay');
    if (o && o.parentNode) o.parentNode.removeChild(o);
  }

  function clearAuth() {
    try {
      localStorage.removeItem(AUTH_KEY);
      localStorage.removeItem(USER_KEY);
      localStorage.removeItem(SESSION_KEY);
    } catch (e) {}
  }

  function redirectLogin(reason) {
    clearAuth();
    try { console.warn('[auth-guard] redirect:', reason); } catch (e) {}
    var here = location.pathname.split('/').pop() || '';
    var qs = here ? ('?next=' + encodeURIComponent(here)) : '';
    try { location.replace(LOGIN_URL + qs); } catch (e) { location.href = LOGIN_URL; }
  }

  showOverlay('Đang xác thực phiên đăng nhập...');

  // ===== 1) CHECK LOCAL =====
  var auth = null;
  try {
    var raw = localStorage.getItem(AUTH_KEY);
    if (raw) auth = JSON.parse(raw);
  } catch (e) {}

  if (!auth || !auth.email || !auth.exp) {
    return redirectLogin('no-local-auth');
  }
  if (Date.now() > Number(auth.exp)) {
    return redirectLogin('local-expired');
  }

  // Nếu chưa có sessionToken (user login từ phiên bản cũ) -> KHÔNG kick,
  // cho vào dựa trên local exp (tránh vòng lặp redirect).
  if (!auth.sessionToken) {
    try { console.warn('[auth-guard] missing sessionToken, allowing via local exp'); } catch (e) {}
    return reveal();
  }

  // ===== 2) VALIDATE VỚI SUPABASE (best-effort, fail-OPEN) =====
  var url = SUPABASE_URL + '/rest/v1/sso_sessions'
    + '?select=email,expires_at'
    + '&email=eq.' + encodeURIComponent(auth.email)
    + '&session_token=eq.' + encodeURIComponent(auth.sessionToken)
    + '&limit=1';

  var ctrl = (typeof AbortController !== 'undefined') ? new AbortController() : null;
  var done = false;
  var timer = setTimeout(function () {
    if (done) return;
    done = true;
    if (ctrl) { try { ctrl.abort(); } catch (e) {} }
    try { console.warn('[auth-guard] validate timeout, fallback to local'); } catch (e) {}
    reveal();
  }, FETCH_TIMEOUT_MS);

  fetch(url, {
    headers: {
      'apikey': SUPABASE_ANON_KEY,
      'Authorization': 'Bearer ' + SUPABASE_ANON_KEY,
      'Accept': 'application/json'
    },
    signal: ctrl ? ctrl.signal : undefined,
    cache: 'no-store'
  })
    .then(function (r) {
      if (!r.ok) throw new Error('HTTP ' + r.status);
      return r.json();
    })
    .then(function (rows) {
      if (done) return; done = true; clearTimeout(timer);

      // KHÔNG kick nếu server trả mảng rỗng — có thể do RLS chặn anon
      // hoặc row chưa sync. Local đã hợp lệ (exp + sessionToken).
      if (!Array.isArray(rows) || rows.length === 0) {
        try { console.warn('[auth-guard] no row returned (likely RLS), keeping local session'); } catch (e) {}
        return reveal();
      }
      var row = rows[0];
      // CHỈ kick khi server XÁC NHẬN expires_at đã hết.
      if (row.expires_at && new Date(row.expires_at).getTime() < Date.now()) {
        return redirectLogin('session-expired');
      }
      // OK -> background cập nhật last_seen (không chặn)
      try {
        fetch(SUPABASE_URL + '/rest/v1/sso_sessions'
              + '?email=eq.' + encodeURIComponent(auth.email)
              + '&session_token=eq.' + encodeURIComponent(auth.sessionToken), {
          method: 'PATCH',
          headers: {
            'apikey': SUPABASE_ANON_KEY,
            'Authorization': 'Bearer ' + SUPABASE_ANON_KEY,
            'Content-Type': 'application/json',
            'Prefer': 'return=minimal'
          },
          body: JSON.stringify({ last_seen: new Date().toISOString() })
        }).catch(function () {});
      } catch (e) {}
      reveal();
    })
    .catch(function (err) {
      if (done) return; done = true; clearTimeout(timer);
      try { console.warn('[auth-guard] online check failed, fallback to local:', err); } catch (e) {}
      reveal();
    });
})();
