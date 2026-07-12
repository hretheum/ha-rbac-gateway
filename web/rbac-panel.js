// ha-rbac-gateway admin panel — a dependency-free custom element for HA's sidebar.
// Registered via panel_custom; talks to the gateway's /rbac-admin/api (cross-origin,
// with the admin's HA token). Themed with HA CSS variables.
class RbacPanel extends HTMLElement {
  constructor() {
    super();
    this.attachShadow({ mode: "open" });
    this._ctx = null;
    this._policy = null;
    this._selectedUser = null;
    this._ready = false;
    this._busy = false;
  }

  set panel(panel) {
    this._panel = panel;
  }

  set hass(hass) {
    this._hass = hass;
    if (!this._ready) {
      this._ready = true;
      this._boot();
    }
  }

  get _base() {
    const cfg = (this._panel && this._panel.config) || {};
    return cfg.gateway_base || `${location.protocol}//${location.hostname}:8124`;
  }

  get _token() {
    const a = this._hass && this._hass.auth;
    return (a && ((a.data && a.data.access_token) || a.accessToken)) || "";
  }

  async _api(path, opts = {}) {
    const res = await fetch(this._base + "/rbac-admin/api" + path, {
      ...opts,
      headers: {
        Authorization: "Bearer " + this._token,
        "Content-Type": "application/json",
        ...(opts.headers || {}),
      },
    });
    const body = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(body.message || body.error || `HTTP ${res.status}`);
    return body;
  }

  async _boot() {
    this._renderShell();
    try {
      this._ctx = await this._api("/context");
      this._fillUsers();
    } catch (e) {
      this._error(`Could not reach the gateway admin API at ${this._base} — ${e.message}`);
    }
  }

  // -- rendering ----------------------------------------------------------

  _renderShell() {
    this.shadowRoot.innerHTML = `
      <style>
        :host { display: block; background: var(--primary-background-color); min-height: 100%; }
        .wrap { max-width: 900px; margin: 0 auto; padding: 16px; box-sizing: border-box; }
        .card { background: var(--card-background-color, #fff); color: var(--primary-text-color);
          border-radius: 12px; padding: 16px 20px; margin-bottom: 16px;
          box-shadow: var(--ha-card-box-shadow, 0 2px 4px rgba(0,0,0,.15)); }
        h1 { font-size: 20px; margin: 4px 0 16px; display:flex; align-items:center; gap:10px; }
        h2 { font-size: 15px; margin: 18px 0 8px; color: var(--secondary-text-color);
          text-transform: uppercase; letter-spacing: .04em; }
        label.row { display:flex; align-items:center; gap:10px; padding:4px 0;
          border-bottom: 1px solid var(--divider-color); }
        label.row:last-child { border-bottom: none; }
        .name { flex: 1; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
        .eid { color: var(--secondary-text-color); font-size: 12px; }
        select, input, button { font: inherit; color: var(--primary-text-color);
          background: var(--secondary-background-color, #f0f0f0);
          border: 1px solid var(--divider-color); border-radius: 8px; padding: 8px 10px; }
        button.primary { background: var(--primary-color); color: var(--text-primary-color, #fff);
          border: none; cursor: pointer; padding: 10px 18px; }
        button.primary:disabled { opacity: .5; cursor: default; }
        .list { max-height: 260px; overflow: auto; }
        .muted { color: var(--secondary-text-color); }
        .toast { position: sticky; bottom: 0; padding: 10px 14px; border-radius: 8px; margin-top: 8px; }
        .toast.ok { background: rgba(76,175,80,.15); color: var(--success-color, #4caf50); }
        .toast.err { background: rgba(244,67,54,.15); color: var(--error-color, #f44336); }
        .pick { display:flex; gap:8px; margin: 6px 0; }
        .pick input { flex:1; }
        .chip-remove { cursor:pointer; color: var(--error-color, #f44336); background:none; border:none; }
        .access { min-width: 96px; }
      </style>
      <div class="wrap">
        <div class="card">
          <h1>🛡️ RBAC — dashboard &amp; entity access</h1>
          <div class="muted">Pick a non-admin user, choose what they may see and control, then save. Admins are never restricted.</div>
          <div style="margin-top:12px">
            <select id="user"><option value="">Loading users…</option></select>
          </div>
        </div>
        <div id="editor"></div>
        <div id="msg"></div>
      </div>`;
    this.shadowRoot.getElementById("user").addEventListener("change", (e) => {
      if (e.target.value) this._selectUser(e.target.value);
      else this.shadowRoot.getElementById("editor").innerHTML = "";
    });
  }

  _fillUsers() {
    const sel = this.shadowRoot.getElementById("user");
    const users = this._ctx.users.filter((u) => !u.is_admin);
    sel.innerHTML =
      `<option value="">— select a user —</option>` +
      users.map((u) => `<option value="${esc(u.id)}">${esc(u.name)}</option>`).join("") +
      (this._ctx.users.some((u) => u.is_admin)
        ? `<optgroup label="admins (not restrictable)">` +
          this._ctx.users.filter((u) => u.is_admin)
            .map((u) => `<option value="" disabled>${esc(u.name)}</option>`).join("") +
          `</optgroup>`
        : "");
  }

  async _selectUser(userId) {
    this._selectedUser = userId;
    this._msg("");
    try {
      this._policy = await this._api("/policies/" + encodeURIComponent(userId));
    } catch (e) {
      this._error(e.message);
      return;
    }
    this._renderEditor();
  }

  _renderEditor() {
    const p = this._policy;
    const chosenDash = new Set(dashAll(p));
    const ent = index(p.entities);
    const areaAcc = index(p.areas);
    const domAcc = index(p.domains);

    const dashRows = this._ctx.dashboards.map((d) => `
      <label class="row"><input type="checkbox" data-dash="${esc(d.url_path)}"
        ${chosenDash.has(d.url_path) ? "checked" : ""}>
        <span class="name">${esc(d.title || d.url_path)}</span>
        <span class="eid">${esc(d.url_path)}</span></label>`).join("");

    const areaRows = this._ctx.areas.map((a) => this._ruleRow("area", a.id, a.name, areaAcc.get(a.id))).join("");
    const domRows = this._ctx.domains.map((dom) => this._ruleRow("domain", dom, dom, domAcc.get(dom))).join("");

    const e = this.shadowRoot.getElementById("editor");
    e.innerHTML = `
      <div class="card">
        <h2>Default dashboard</h2>
        <select id="default"><option value="">— none —</option>${
          this._ctx.dashboards.map((d) => `<option value="${esc(d.url_path)}" ${
            p.dashboards && p.dashboards.default === d.url_path ? "selected" : ""
          }>${esc(d.title || d.url_path)}</option>`).join("")
        }</select>
        <h2>Dashboards this user may open</h2>
        <div class="list">${dashRows || '<div class="muted">No storage dashboards found.</div>'}</div>
      </div>
      <div class="card">
        <h2>Areas</h2><div class="list">${areaRows || '<div class="muted">No areas.</div>'}</div>
        <h2>Domains</h2><div class="list">${domRows}</div>
      </div>
      <div class="card">
        <h2>Individual entities</h2>
        <div class="pick">
          <input id="entfilter" list="entlist" placeholder="Search entity to add…">
          <datalist id="entlist">${
            this._ctx.entities.slice(0, 1000).map((x) =>
              `<option value="${esc(x.id)}">${esc(x.name)}</option>`).join("")
          }</datalist>
          <button id="entadd">Add</button>
        </div>
        <div class="list" id="entsel"></div>
      </div>
      <div class="card">
        <button class="primary" id="save">Save &amp; apply</button>
        <button id="revoke" style="margin-left:8px;cursor:pointer">Revoke all access</button>
        <div id="msg2"></div>
      </div>`;

    this._entRows = new Map();
    for (const it of p.entities) this._addEntity(it.id, it.access);

    this.shadowRoot.getElementById("entadd").addEventListener("click", () => {
      const v = this.shadowRoot.getElementById("entfilter").value.trim();
      if (v) { this._addEntity(v, "read"); this.shadowRoot.getElementById("entfilter").value = ""; }
    });
    this.shadowRoot.getElementById("save").addEventListener("click", () => this._save());
    this.shadowRoot.getElementById("revoke").addEventListener("click", () => this._revoke());
  }

  _ruleRow(kind, id, name, access) {
    const on = access !== undefined;
    return `<label class="row">
      <input type="checkbox" data-${kind}="${esc(id)}" ${on ? "checked" : ""}>
      <span class="name">${esc(name)}</span>
      <select class="access" data-${kind}-acc="${esc(id)}">
        <option value="read" ${access === "read" ? "selected" : ""}>read</option>
        <option value="control" ${access === "control" ? "selected" : ""}>control</option>
      </select></label>`;
  }

  _addEntity(id, access) {
    if (this._entRows.has(id)) return;
    const box = this.shadowRoot.getElementById("entsel");
    const meta = this._ctx.entities.find((x) => x.id === id);
    const row = document.createElement("label");
    row.className = "row";
    row.innerHTML = `
      <span class="name">${esc(meta ? meta.name : id)} <span class="eid">${esc(id)}</span></span>
      <select class="access">
        <option value="read" ${access === "read" ? "selected" : ""}>read</option>
        <option value="control" ${access === "control" ? "selected" : ""}>control</option>
      </select>
      <button class="chip-remove" title="remove">✕</button>`;
    row.querySelector(".chip-remove").addEventListener("click", () => {
      this._entRows.delete(id); row.remove();
    });
    this._entRows.set(id, row);
    box.appendChild(row);
  }

  // -- save / revoke ------------------------------------------------------

  _collect() {
    const q = (s) => [...this.shadowRoot.querySelectorAll(s)];
    const checked = (kind) => q(`input[data-${kind}]:checked`).map((c) => {
      const id = c.getAttribute(`data-${kind}`);
      const acc = this.shadowRoot.querySelector(`select[data-${kind}-acc="${cssEsc(id)}"]`);
      return { id, access: acc ? acc.value : "read" };
    });
    const entities = [...this._entRows.entries()].map(([id, row]) => ({
      id, access: row.querySelector("select").value,
    }));
    const dashboards = q("input[data-dash]:checked").map((c) => c.getAttribute("data-dash"));
    const def = this.shadowRoot.getElementById("default").value || null;
    if (def && !dashboards.includes(def)) dashboards.push(def);
    return {
      user: { id: this._selectedUser },
      entities,
      areas: checked("area"),
      domains: checked("domain"),
      dashboards: { default: def, allowed: dashboards },
    };
  }

  async _save() {
    if (this._busy) return;
    this._busy = true;
    this._msg("");
    try {
      await this._api("/policies/" + encodeURIComponent(this._selectedUser), {
        method: "PUT", body: JSON.stringify(this._collect()),
      });
      this._msg("Saved and applied — the change is live.", "ok");
    } catch (e) {
      this._msg("Save failed: " + e.message, "err");
    } finally {
      this._busy = false;
    }
  }

  async _revoke() {
    if (!confirm("Remove this user's policy entirely? They will be locked out of the gateway.")) return;
    try {
      await this._api("/policies/" + encodeURIComponent(this._selectedUser), { method: "DELETE" });
      this._policy = { user: { id: this._selectedUser }, entities: [], areas: [], domains: [],
        dashboards: { default: null, allowed: [] } };
      this._renderEditor();
      this._msg("Policy removed — user is now locked out.", "ok");
    } catch (e) {
      this._msg("Revoke failed: " + e.message, "err");
    }
  }

  _msg(text, kind) {
    const el = this.shadowRoot.getElementById("msg2") || this.shadowRoot.getElementById("msg");
    el.innerHTML = text ? `<div class="toast ${kind || ""}">${esc(text)}</div>` : "";
  }

  _error(text) {
    const el = this.shadowRoot.getElementById("msg");
    if (el) el.innerHTML = `<div class="toast err">${esc(text)}</div>`;
  }
}

function esc(s) {
  return String(s == null ? "" : s).replace(/[&<>"']/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}
function cssEsc(s) { return String(s).replace(/["\\]/g, "\\$&"); }
function index(list) {
  const m = new Map();
  for (const it of list || []) m.set(it.id, it.access);
  return m;
}
function dashAll(p) {
  const d = (p && p.dashboards) || {};
  const out = new Set(d.allowed || []);
  if (d.default) out.add(d.default);
  return out;
}

customElements.define("rbac-panel", RbacPanel);
