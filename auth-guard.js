/*!
 * SSO Auth Guard — chèn ở đầu <head> của mọi sub-page.
 * 1) Ẩn body ngay khi tải để tránh "flash" nội dung
 * 2) Check localStorage itHub_sso_auth (email + exp + sessionToken)
 * 3) Validate session_token với bảng sso_sessions trên Supabase
 *    -> Nếu không hợp lệ: xoá localStorage & redirect về index.html
 */
(function () {
  // ===== CẤU HÌNH =====
  var SUPABASE_URL = 'https://edsowiramriosgwfuewg.supabase.co';
  var SUPABASE_ANON_KEY = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImVkc293aXJhbXJpb3Nnd2Z1ZXdnIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NzgyNDMzMDgsImV4cCI6MjA5MzgxOTMwOH0.aocvFLnJrl5LFPdxDf9zbhvT6HT7NpCEMFtiUr_M3gM';
  var AUTH_KEY = 'itHub_sso_auth';
  var USER_KEY = 'itHub_sso_user';
  var SESSION_KEY = 'itHub_sso_session';
  var LOGIN_URL = './index.html';

  // ===== ẨN TRANG NGAY (tránh flash nội dung khi chưa xác thực) =====
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
    // Lưu lại trang đang truy cập để (tuỳ) quay lại sau khi đăng nhập
    var here = location.pathname.split('/').pop() || '';
    var qs = here ? ('?next=' + encodeURIComponent(here)) : '';
    location.replace(LOGIN_URL + qs);
  }

  showOverlay('Đang xác thực phiên đăng nhập...');

  // ===== 1) CHECK LOCAL =====
  var auth = null;
  try {
    var raw = localStorage.getItem(AUTH_KEY);
    if (raw) auth = JSON.parse(raw);
  } catch (e) {}

  if (!auth || !auth.email || !auth.exp || !auth.sessionToken) {
    return redirectLogin('no-local-auth');
  }
  if (Date.now() > Number(auth.exp)) {
    return redirectLogin('local-expired');
  }

  // ===== 2) VALIDATE VỚI SUPABASE (sso_sessions) =====
  var url = SUPABASE_URL + '/rest/v1/sso_sessions'
    + '?select=email,expires_at'
    + '&email=eq.' + encodeURIComponent(auth.email)
    + '&session_token=eq.' + encodeURIComponent(auth.sessionToken)
    + '&limit=1';

  var ctrl = (typeof AbortController !== 'undefined') ? new AbortController() : null;
  var timer = setTimeout(function () { if (ctrl) ctrl.abort(); }, 8000);

  fetch(url, {
    headers: {
      'apikey': SUPABASE_ANON_KEY,
      'Authorization': 'Bearer ' + SUPABASE_ANON_KEY,
      'Accept': 'application/json',
      'x-session-token': auth.sessionToken
    },
    signal: ctrl ? ctrl.signal : undefined,
    cache: 'no-store'
  })
    .then(function (r) {
      clearTimeout(timer);
      if (!r.ok) throw new Error('HTTP ' + r.status);
      return r.json();
    })
    .then(function (rows) {
      if (!Array.isArray(rows) || rows.length === 0) {
        return redirectLogin('session-not-found');
      }
      var row = rows[0];
      if (!row.expires_at || new Date(row.expires_at).getTime() < Date.now()) {
        return redirectLogin('session-expired');
      }
      // OK -> cập nhật last_seen (background, không chặn)
      try {
        fetch(SUPABASE_URL + '/rest/v1/sso_sessions'
              + '?email=eq.' + encodeURIComponent(auth.email)
              + '&session_token=eq.' + encodeURIComponent(auth.sessionToken), {
          method: 'PATCH',
          headers: {
            'apikey': SUPABASE_ANON_KEY,
            'Authorization': 'Bearer ' + SUPABASE_ANON_KEY,
            'Content-Type': 'application/json',
            'Prefer': 'return=minimal',
            'x-session-token': auth.sessionToken
          },
          body: JSON.stringify({ last_seen: new Date().toISOString() })
        }).catch(function () {});
      } catch (e) {}
      reveal();
    })
    .catch(function (err) {
      clearTimeout(timer);
      // Lỗi mạng: vẫn cho vào dựa trên local (đã check exp ở trên) để không khoá user offline.
      // Nếu muốn STRICT, đổi dòng dưới thành: redirectLogin('network-' + err);
      try { console.warn('[auth-guard] online check failed, fallback to local:', err); } catch (e) {}
      reveal();
    });
})();
