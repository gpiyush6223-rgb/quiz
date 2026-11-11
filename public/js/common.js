// Shared helpers for all pages
const App = (() => {
  const TOKEN_KEY = 'quiz_token', USER_KEY = 'quiz_user';
  const getToken = () => localStorage.getItem(TOKEN_KEY);
  const getUser = () => { try { return JSON.parse(localStorage.getItem(USER_KEY)); } catch { return null; } };
  const setSession = (token, user) => { localStorage.setItem(TOKEN_KEY, token); localStorage.setItem(USER_KEY, JSON.stringify(user)); };
  const logout = () => { localStorage.removeItem(TOKEN_KEY); localStorage.removeItem(USER_KEY); location.href = '/'; };

  async function api(method, url, body, opts = {}) {
    const headers = { 'Content-Type': 'application/json' };
    const t = getToken(); if (t) headers.Authorization = 'Bearer ' + t;
    const res = await fetch(url, { method, headers, body: body === undefined ? undefined : JSON.stringify(body), keepalive: !!opts.keepalive });
    if (opts.raw) { if (!res.ok) throw new Error((await res.json().catch(() => ({}))).error || 'Request failed'); return res; }
    const data = await res.json().catch(() => ({}));
    if (res.status === 401 && getToken() && !url.includes('/auth/')) { logout(); throw new Error(data.error || 'Session expired'); }
    if (!res.ok) throw new Error(data.error || 'Request failed');
    return data;
  }
  const get = (u) => api('GET', u), post = (u, b = {}) => api('POST', u, b), put = (u, b) => api('PUT', u, b), del = (u) => api('DELETE', u, {}), patch = (u, b) => api('PATCH', u, b);

  // Page guard: redirects if not logged in as the right role
  function guard(role) {
    const u = getUser();
    if (!getToken() || !u || u.role !== role) { location.href = '/'; return null; }
    return u;
  }

  const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const toDate = (s) => (s ? new Date(/Z|[+-]\d\d:?\d\d$/.test(s) ? s : s.replace(' ', 'T') + 'Z') : null);
  const fmt = (s) => { const d = toDate(s); return d ? d.toLocaleString([], { dateStyle: 'medium', timeStyle: 'short' }) : '-'; };
  const fmtDur = (sec) => { if (sec == null) return '-'; const m = Math.floor(sec / 60), s = sec % 60; return `${m}m ${String(s).padStart(2, '0')}s`; };
  const toLocalInput = (iso) => { if (!iso) return ''; const d = new Date(iso); d.setMinutes(d.getMinutes() - d.getTimezoneOffset()); return d.toISOString().slice(0, 16); };
  const fromLocalInput = (v) => (v ? new Date(v).toISOString() : null);

  function toast(msg, ms = 2800) {
    const t = document.createElement('div'); t.className = 'toast'; t.textContent = msg; document.body.appendChild(t);
    setTimeout(() => t.remove(), ms);
  }
  function modal(html, { wide = false } = {}) {
    const ov = document.createElement('div'); ov.className = 'overlay';
    ov.innerHTML = `<div class="modal ${wide ? 'wide' : ''}">${html}</div>`;
    ov.addEventListener('mousedown', (e) => { if (e.target === ov) ov.remove(); });
    document.body.appendChild(ov);
    return { el: ov.firstElementChild, close: () => ov.remove() };
  }
  function confirmBox(message, okLabel = 'Yes') {
    return new Promise((resolve) => {
      const m = modal(`<h3>Please confirm</h3><p>${esc(message)}</p><div class="row" style="justify-content:flex-end"><button class="btn ghost" id="cb-no">Cancel</button><button class="btn danger" id="cb-yes">${esc(okLabel)}</button></div>`);
      m.el.querySelector('#cb-no').onclick = () => { m.close(); resolve(false); };
      m.el.querySelector('#cb-yes').onclick = () => { m.close(); resolve(true); };
    });
  }
  function topbar(user, extra = '') {
    return `<div class="topbar"><div class="brand">Quiz<span>Hub</span></div><span class="badge">${esc(user.role)}</span>${extra}<div class="spacer"></div>
      <span class="muted small">${esc(user.name)}</span><button class="btn ghost sm" id="pw-btn">Password</button><button class="btn ghost sm" id="logout-btn">Log out</button></div>`;
  }
  function wireTopbar() {
    document.getElementById('logout-btn').onclick = logout;
    document.getElementById('pw-btn').onclick = () => {
      const m = modal(`<h3>Change password</h3><label>Current password</label><input type="password" id="pw1"><label>New password</label><input type="password" id="pw2">
        <div class="row" style="justify-content:flex-end;margin-top:14px"><button class="btn ghost" id="pwc">Cancel</button><button class="btn" id="pws">Save</button></div>`);
      m.el.querySelector('#pwc').onclick = m.close;
      m.el.querySelector('#pws').onclick = async () => {
        try { await post('/api/me/password', { current: m.el.querySelector('#pw1').value, next: m.el.querySelector('#pw2').value }); m.close(); toast('Password updated'); }
        catch (e) { toast(e.message); }
      };
    };
  }
  async function downloadCSV(url, filename) {
    const res = await api('GET', url, undefined, { raw: true });
    const blob = await res.blob(); const a = document.createElement('a');
    a.href = URL.createObjectURL(blob); a.download = filename; a.click(); URL.revokeObjectURL(a.href);
  }
  const VIOLATION_LABELS = { tab_switch: 'Switched tab', window_blur: 'Left the window', fullscreen_exit: 'Exited fullscreen', page_exit: 'Tried to close/leave page', left_page: 'Closed/reloaded the page', copy_paste: 'Copy / paste / cut', right_click: 'Right-click', devtools: 'Dev-tools / shortcut keys', print_screen: 'Print / screenshot key', other: 'Other' };
  return { api, get, post, put, del, patch, guard, getUser, getToken, setSession, logout, esc, fmt, fmtDur, toLocalInput, fromLocalInput, toast, modal, confirmBox, topbar, wireTopbar, downloadCSV, VIOLATION_LABELS, toDate };
})();
