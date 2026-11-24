(() => {
  const I18N = {
    zh: {
      loading: "加载中…",
      logout: "退出登录",
      setupTitle: "初始化自建中转服务",
      setupDesc: "设置管理员密码后即可连接你的 Octopus 桌面端和手机端。",
      setupTokenLabel: "一次性初始化口令（见服务端启动日志）",
      ownerNameLabel: "显示名称",
      passwordLabel: "管理员密码（至少 8 位）",
      generateKeyCheck: "同时生成访问密钥（用于客户端免浏览器一键接入）",
      setupSubmit: "完成初始化",
      setupDoneTitle: "初始化完成",
      setupDoneKeyHint: "请立即保存下面的访问密钥或一键配置链接（仅显示一次）：",
      goDashboard: "进入控制台",
      loginTitle: "登录中转控制台",
      loginDesc: "输入此自建中转服务的管理员密码。",
      loginSubmit: "登录",
      keyOnlyHint: "当前服务仅开启了访问密钥模式（未设置管理员密码），请在 Octopus 客户端直接使用访问密钥或配置链接连接。",
      deviceTitle: "确认新设备登录",
      deviceDesc: "核对下方代码与 Octopus 应用内显示的一致后再点击允许。",
      codeLabel: "设备验证码",
      codePlaceholder: "例如 WDJB-MJHT",
      lookupCode: "查询设备",
      approve: "允许此设备登录",
      deny: "拒绝",
      deviceApproved: "已允许该设备登录，现在可以关闭此页面并回到 Octopus。",
      deviceDenied: "已拒绝该设备的登录请求。",
      deviceUnknown: "验证码无效或已过期，请在 Octopus 应用内重新发起登录。",
      deviceLimit: "已达到最大设备数量上限，请先在控制台移除不再使用的设备。",
      knownDevice: "已登记设备（重新授权）",
      kindDesktop: "桌面端",
      kindPhone: "手机端",
      statHosts: "在线主机",
      statTunnels: "活跃隧道",
      statTraffic: "本月转发流量",
      statDevices: "已授权设备",
      unlimited: "不限",
      quickConnectTitle: "快捷接入与访问密钥",
      quickConnectDesc: "使用访问密钥或一键配置链接，可在桌面端与手机端跳过浏览器直接完成绑定。",
      serverAddress: "中转服务地址",
      accessKeyStatus: "访问密钥状态",
      enabled: "已启用",
      disabled: "未启用",
      envManaged: "由环境变量管理",
      generateKey: "生成访问密钥",
      rotateKey: "轮换访问密钥",
      disableKey: "停用访问密钥",
      keyOnceWarning: "明文访问密钥仅展示这一次，刷新页面后将不再显示。已有设备不受轮换影响。",
      accessKeyLabel: "访问密钥",
      setupLinkLabel: "一键配置链接（复制到 Octopus 自定义服务输入框）",
      copy: "复制",
      copied: "已复制",
      devicesTitle: "已授权设备",
      devicesEmpty: "还没有设备登录此中转服务。",
      online: "在线",
      offline: "离线",
      passwordAccess: "支持访问密码",
      lastSeen: "最近活跃",
      remove: "移除",
      signOutAll: "全部设备下线",
      confirmRemove: "确定移除该设备并立即断开其连接？",
      confirmSignOutAll: "确定登出所有设备并断开所有连接？",
      confirmDisableKey: "确定停用访问密钥？之后只能通过密码和浏览器设备码登录。",
      settingsTitle: "实例设置",
      saveName: "保存名称",
      currentPassword: "当前密码",
      newPassword: "新密码（至少 8 位）",
      changePassword: "修改密码",
      passwordUpdated: "密码已更新",
      nameUpdated: "名称已更新",
      passwordEnvNote: "当前密码由环境变量 RELAY_PASSWORD 托管，如需修改请更新环境变量并重启服务。",
      accessKeyEnvNote: "当前访问密钥由环境变量 RELAY_ACCESS_KEY 托管。",
      err_invalid_password: "密码错误。",
      err_weak_password: "密码至少需要 8 位字符。",
      err_invalid_setup_token: "初始化口令错误，请检查服务端启动日志。",
      err_setup_completed: "服务端已完成初始化，请直接登录。",
      err_invalid_name: "显示名称无效。",
      err_too_many_requests: "请求过于频繁，请稍后再试。",
      err_unknown: "操作失败，请重试。",
    },
    en: {
      loading: "Loading…",
      logout: "Sign out",
      setupTitle: "Set up Octopus Relay",
      setupDesc: "Create an owner password to connect your Octopus desktop and mobile apps.",
      setupTokenLabel: "One-time setup token (printed in server startup logs)",
      ownerNameLabel: "Display name",
      passwordLabel: "Owner password (min 8 characters)",
      generateKeyCheck: "Also generate an Access Key for browser-free client sign-in",
      setupSubmit: "Complete setup",
      setupDoneTitle: "Setup complete",
      setupDoneKeyHint: "Save this Access Key or one-click setup link now (shown once):",
      goDashboard: "Open dashboard",
      loginTitle: "Sign in to Relay Console",
      loginDesc: "Enter the owner password for this self-hosted relay.",
      loginSubmit: "Sign in",
      keyOnlyHint: "This relay is running in Access-Key-only mode without a web password. Sign in directly from Octopus using your Access Key.",
      deviceTitle: "Approve device sign-in",
      deviceDesc: "Make sure this code matches the one shown in Octopus before approving.",
      codeLabel: "Verification code",
      codePlaceholder: "e.g. WDJB-MJHT",
      lookupCode: "Check code",
      approve: "Approve device",
      deny: "Deny",
      deviceApproved: "Device approved. You can close this tab and return to Octopus.",
      deviceDenied: "Sign-in request denied.",
      deviceUnknown: "This code is invalid or expired. Start sign-in again from Octopus.",
      deviceLimit: "Device limit reached. Remove an old device from the dashboard first.",
      knownDevice: "Existing device (re-authorizing)",
      kindDesktop: "Desktop",
      kindPhone: "Phone",
      statHosts: "Online hosts",
      statTunnels: "Active tunnels",
      statTraffic: "Monthly traffic",
      statDevices: "Devices",
      unlimited: "Unlimited",
      quickConnectTitle: "Quick connect & Access Key",
      quickConnectDesc: "Use an Access Key or setup link to sign in directly in Octopus desktop & mobile without a browser.",
      serverAddress: "Relay URL",
      accessKeyStatus: "Access Key",
      enabled: "Enabled",
      disabled: "Disabled",
      envManaged: "Managed by env",
      generateKey: "Generate Access Key",
      rotateKey: "Rotate Access Key",
      disableKey: "Disable Access Key",
      keyOnceWarning: "Shown once only. Rotating does not disconnect already authorized devices.",
      accessKeyLabel: "Access Key",
      setupLinkLabel: "One-click setup link (paste into Octopus custom server field)",
      copy: "Copy",
      copied: "Copied",
      devicesTitle: "Authorized devices",
      devicesEmpty: "No devices signed in yet.",
      online: "Online",
      offline: "Offline",
      passwordAccess: "Access password",
      lastSeen: "Last active",
      remove: "Remove",
      signOutAll: "Sign out all devices",
      confirmRemove: "Remove this device and disconnect it immediately?",
      confirmSignOutAll: "Sign out all devices and close active connections?",
      confirmDisableKey: "Disable Access Key sign-in?",
      settingsTitle: "Owner settings",
      saveName: "Save name",
      currentPassword: "Current password",
      newPassword: "New password (min 8 characters)",
      changePassword: "Update password",
      passwordUpdated: "Password updated",
      nameUpdated: "Name updated",
      passwordEnvNote: "Password is managed by RELAY_PASSWORD. Update the environment variable and restart to change it.",
      accessKeyEnvNote: "Access Key is managed by RELAY_ACCESS_KEY.",
      err_invalid_password: "Incorrect password.",
      err_weak_password: "Password must be at least 8 characters.",
      err_invalid_setup_token: "Invalid setup token. Check the server startup logs.",
      err_setup_completed: "Setup is already complete. Please sign in.",
      err_invalid_name: "Invalid display name.",
      err_too_many_requests: "Too many requests. Try again shortly.",
      err_unknown: "Request failed. Please try again.",
    },
  };

  let lang = localStorage.getItem("or_lang") || (navigator.language.startsWith("zh") ? "zh" : "en");
  const t = (k) => (I18N[lang] && I18N[lang][k]) || I18N.en[k] || k;
  const errText = (code) => t("err_" + code) || t("err_unknown");

  const app = document.getElementById("app");
  const brandName = document.getElementById("brand-name");
  const brandVersion = document.getElementById("brand-version");
  const langToggle = document.getElementById("lang-toggle");
  const navLogout = document.getElementById("nav-logout");
  const toastEl = document.getElementById("toast");

  let toastTimer = null;
  function showToast(msg) {
    toastEl.textContent = msg;
    toastEl.classList.remove("hidden");
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => toastEl.classList.add("hidden"), 2200);
  }

  function esc(s) {
    return String(s ?? "")
      .replaceAll("&", "&amp;")
      .replaceAll("<", "&lt;")
      .replaceAll(">", "&gt;")
      .replaceAll('"', "&quot;")
      .replaceAll("'", "&#39;");
  }

  function formatBytes(bytes) {
    if (!bytes) return "0 B";
    const units = ["B", "KB", "MB", "GB", "TB"];
    let i = 0;
    let val = bytes;
    while (val >= 1024 && i < units.length - 1) {
      val /= 1024;
      i++;
    }
    return (i === 0 ? val : val.toFixed(1)) + " " + units[i];
  }

  function formatTime(iso) {
    if (!iso) return "";
    try {
      return new Date(iso).toLocaleString();
    } catch {
      return iso;
    }
  }

  function safeReturnPath() {
    const p = new URLSearchParams(location.search).get("return");
    if (p && p.startsWith("/") && !p.startsWith("//")) return p;
    return "/account";
  }

  async function api(method, url, body) {
    const opts = { method, credentials: "same-origin", headers: {} };
    if (body !== undefined) {
      opts.headers["Content-Type"] = "application/json";
      opts.body = JSON.stringify(body);
    }
    const res = await fetch(url, opts);
    if (res.status === 204) return { ok: true, status: 204, data: null };
    let data = null;
    try {
      data = await res.json();
    } catch {}
    return { ok: res.ok, status: res.status, data };
  }

  async function copyText(text) {
    try {
      await navigator.clipboard.writeText(text);
      showToast(t("copied"));
    } catch {
      const ta = document.createElement("textarea");
      ta.value = text;
      document.body.appendChild(ta);
      ta.select();
      document.execCommand("copy");
      ta.remove();
      showToast(t("copied"));
    }
  }

  function updateHeader(status) {
    if (status) {
      brandName.textContent = status.serverName || "Octopus Relay";
      document.title = status.serverName || "Octopus Relay";
      brandVersion.textContent = status.version ? "v" + status.version : "";
      navLogout.classList.toggle("hidden", !status.signedIn);
    }
    langToggle.textContent = lang === "zh" ? "EN" : "中文";
    navLogout.textContent = t("logout");
  }

  langToggle.addEventListener("click", () => {
    lang = lang === "zh" ? "en" : "zh";
    localStorage.setItem("or_lang", lang);
    boot();
  });

  navLogout.addEventListener("click", async () => {
    await api("POST", "/api/auth/logout", {});
    location.href = "/login";
  });

  function renderSetup(status) {
    const tokenFromUrl = new URLSearchParams(location.search).get("token") || "";
    app.innerHTML = `
      <div class="card center-card">
        <h1>${esc(t("setupTitle"))}</h1>
        <p class="muted">${esc(t("setupDesc"))}</p>
        <div id="setup-err" class="alert alert-danger hidden"></div>
        <form id="setup-form">
          <div class="field">
            <label for="setup-token">${esc(t("setupTokenLabel"))}</label>
            <input id="setup-token" type="text" required value="${esc(tokenFromUrl)}" autocomplete="off" />
          </div>
          <div class="field">
            <label for="setup-name">${esc(t("ownerNameLabel"))}</label>
            <input id="setup-name" type="text" value="Owner" maxlength="64" />
          </div>
          <div class="field">
            <label for="setup-pwd">${esc(t("passwordLabel"))}</label>
            <input id="setup-pwd" type="password" required minlength="8" autocomplete="new-password" />
          </div>
          <label class="checkbox-row">
            <input id="setup-gen-key" type="checkbox" checked />
            <span>${esc(t("generateKeyCheck"))}</span>
          </label>
          <button type="submit" class="btn btn-primary btn-block" id="setup-btn">${esc(t("setupSubmit"))}</button>
        </form>
      </div>`;

    const form = document.getElementById("setup-form");
    const err = document.getElementById("setup-err");
    form.addEventListener("submit", async (e) => {
      e.preventDefault();
      err.classList.add("hidden");
      const btn = document.getElementById("setup-btn");
      btn.disabled = true;
      const res = await api("POST", "/api/setup", {
        setupToken: document.getElementById("setup-token").value.trim(),
        ownerName: document.getElementById("setup-name").value.trim(),
        password: document.getElementById("setup-pwd").value,
        generateAccessKey: document.getElementById("setup-gen-key").checked,
      });
      btn.disabled = false;
      if (!res.ok) {
        err.textContent = errText(res.data?.error);
        err.classList.remove("hidden");
        return;
      }
      if (res.data?.accessKey) {
        app.innerHTML = `
          <div class="card center-card">
            <h1>${esc(t("setupDoneTitle"))}</h1>
            <div class="alert alert-warn">${esc(t("setupDoneKeyHint"))}</div>
            <div class="secret-box">
              <div class="muted">${esc(t("accessKeyLabel"))}</div>
              <div class="mono" style="margin:6px 0 8px">${esc(res.data.accessKey)}</div>
              <button type="button" class="btn btn-sm" id="copy-key">${esc(t("copy"))}</button>
            </div>
            <div class="secret-box">
              <div class="muted">${esc(t("setupLinkLabel"))}</div>
              <div class="mono" style="margin:6px 0 8px">${esc(res.data.setupLink)}</div>
              <button type="button" class="btn btn-sm" id="copy-link">${esc(t("copy"))}</button>
            </div>
            <a class="btn btn-primary btn-block" href="/account">${esc(t("goDashboard"))}</a>
          </div>`;
        document.getElementById("copy-key").addEventListener("click", () => copyText(res.data.accessKey));
        document.getElementById("copy-link").addEventListener("click", () => copyText(res.data.setupLink));
      } else {
        location.href = "/account";
      }
    });
  }

  function renderLogin(status) {
    if (!status.passwordEnabled) {
      app.innerHTML = `
        <div class="card center-card">
          <h1>${esc(status.serverName)}</h1>
          <div class="alert alert-warn">${esc(t("keyOnlyHint"))}</div>
        </div>`;
      return;
    }

    app.innerHTML = `
      <div class="card center-card">
        <h1>${esc(t("loginTitle"))}</h1>
        <p class="muted">${esc(t("loginDesc"))}</p>
        <div id="login-err" class="alert alert-danger hidden"></div>
        <form id="login-form">
          <div class="field">
            <label for="login-pwd">${esc(t("passwordLabel"))}</label>
            <input id="login-pwd" type="password" required autocomplete="current-password" autofocus />
          </div>
          <button type="submit" class="btn btn-primary btn-block" id="login-btn">${esc(t("loginSubmit"))}</button>
        </form>
      </div>`;

    const form = document.getElementById("login-form");
    const err = document.getElementById("login-err");
    form.addEventListener("submit", async (e) => {
      e.preventDefault();
      err.classList.add("hidden");
      const btn = document.getElementById("login-btn");
      btn.disabled = true;
      const res = await api("POST", "/api/auth/login", {
        password: document.getElementById("login-pwd").value,
      });
      btn.disabled = false;
      if (!res.ok) {
        err.textContent = errText(res.data?.error);
        err.classList.remove("hidden");
        return;
      }
      location.href = safeReturnPath();
    });
  }

  async function renderDevice() {
    const initialCode = new URLSearchParams(location.search).get("code") || "";

    async function showLookup(code, errorMsg) {
      app.innerHTML = `
        <div class="card center-card">
          <h1>${esc(t("deviceTitle"))}</h1>
          <p class="muted">${esc(t("deviceDesc"))}</p>
          ${errorMsg ? `<div class="alert alert-danger">${esc(errorMsg)}</div>` : ""}
          <form id="code-form">
            <div class="field">
              <label for="code-input">${esc(t("codeLabel"))}</label>
              <input id="code-input" type="text" required value="${esc(code)}" placeholder="${esc(t("codePlaceholder"))}" autocomplete="off" />
            </div>
            <button type="submit" class="btn btn-primary btn-block">${esc(t("lookupCode"))}</button>
          </form>
        </div>`;
      document.getElementById("code-form").addEventListener("submit", (e) => {
        e.preventDefault();
        loadCode(document.getElementById("code-input").value.trim());
      });
    }

    async function loadCode(code) {
      if (!code) {
        showLookup("", null);
        return;
      }
      const res = await api("GET", "/api/device-login?code=" + encodeURIComponent(code));
      if (res.status === 401) {
        location.href = "/login?return=" + encodeURIComponent(location.pathname + location.search);
        return;
      }
      if (!res.ok) {
        showLookup(code, t("deviceUnknown"));
        return;
      }
      const d = res.data;
      const kind = d.kind === "phone" ? t("kindPhone") : t("kindDesktop");
      const meta = [kind, d.platform, d.appVersion ? "v" + d.appVersion : null, d.ip].filter(Boolean).join(" · ");
      app.innerHTML = `
        <div class="card center-card">
          <h1>${esc(t("deviceTitle"))}</h1>
          <p class="muted">${esc(t("deviceDesc"))}</p>
          <div class="code-display">${esc(d.userCode)}</div>
          <div class="secret-box">
            <div class="device-title">
              <span>${esc(d.deviceName)}</span>
              ${d.known ? `<span class="badge badge-info">${esc(t("knownDevice"))}</span>` : ""}
            </div>
            <div class="device-meta">${esc(meta)}</div>
            <div class="device-meta mono">${esc(d.deviceId)}</div>
          </div>
          <div id="device-err" class="alert alert-danger hidden"></div>
          <div class="row">
            <button type="button" class="btn btn-primary" style="flex:1" id="btn-approve">${esc(t("approve"))}</button>
            <button type="button" class="btn" id="btn-deny">${esc(t("deny"))}</button>
          </div>
        </div>`;

      const err = document.getElementById("device-err");
      document.getElementById("btn-approve").addEventListener("click", async () => {
        const ans = await api("POST", "/api/device-login/approve", { code: d.userCode });
        if (ans.ok) {
          app.innerHTML = `<div class="card center-card"><div class="alert alert-success">${esc(t("deviceApproved"))}</div><a class="btn btn-block" href="/account">${esc(t("goDashboard"))}</a></div>`;
        } else if (ans.data?.error === "device_limit") {
          err.textContent = t("deviceLimit");
          err.classList.remove("hidden");
        } else {
          err.textContent = t("deviceUnknown");
          err.classList.remove("hidden");
        }
      });

      document.getElementById("btn-deny").addEventListener("click", async () => {
        await api("POST", "/api/device-login/deny", { code: d.userCode });
        app.innerHTML = `<div class="card center-card"><div class="alert alert-warn">${esc(t("deviceDenied"))}</div><a class="btn btn-block" href="/account">${esc(t("goDashboard"))}</a></div>`;
      });
    }

    await loadCode(initialCode);
  }

  let revealedKey = null;

  async function renderDashboard() {
    const res = await api("GET", "/api/dashboard");
    if (res.status === 401) {
      location.href = "/login?return=/account";
      return;
    }
    if (!res.ok) {
      app.innerHTML = `<div class="card center-card"><div class="alert alert-danger">${esc(t("err_unknown"))}</div></div>`;
      return;
    }

    const d = res.data;
    const trafficText = d.stats.monthlyLimitBytes > 0
      ? `${formatBytes(d.stats.monthlyBytes)} / ${formatBytes(d.stats.monthlyLimitBytes)}`
      : formatBytes(d.stats.monthlyBytes);

    const devicesHtml = d.devices.length === 0
      ? `<p class="muted">${esc(t("devicesEmpty"))}</p>`
      : `<div class="device-list">${d.devices.map((dev) => {
          const kind = dev.kind === "phone" ? t("kindPhone") : t("kindDesktop");
          const meta = [dev.platform, dev.appVersion ? "v" + dev.appVersion : null, dev.lastIp, `${t("lastSeen")}: ${formatTime(dev.lastSeenAt)}`]
            .filter(Boolean).join(" · ");
          return `
            <div class="device-item">
              <div>
                <div class="device-title">
                  <span>${esc(dev.name)}</span>
                  <span class="badge badge-muted">${esc(kind)}</span>
                  <span class="badge ${dev.online ? "badge-success" : "badge-muted"}">${esc(dev.online ? t("online") : t("offline"))}</span>
                  ${dev.passwordAccess ? `<span class="badge badge-info">${esc(t("passwordAccess"))}</span>` : ""}
                </div>
                <div class="device-meta">${esc(meta)}</div>
                <div class="device-meta mono">${esc(dev.id)}</div>
              </div>
              <button type="button" class="btn btn-danger btn-sm" data-remove="${esc(dev.id)}">${esc(t("remove"))}</button>
            </div>`;
        }).join("")}</div>`;

    const keyRevealHtml = revealedKey ? `
      <div class="alert alert-warn" style="margin-top:12px">${esc(t("keyOnceWarning"))}</div>
      <div class="secret-box">
        <div class="row-between">
          <span class="muted">${esc(t("accessKeyLabel"))}</span>
          <button type="button" class="btn btn-sm" id="copy-new-key">${esc(t("copy"))}</button>
        </div>
        <div class="mono" style="margin-top:6px">${esc(revealedKey.accessKey)}</div>
      </div>
      <div class="secret-box">
        <div class="row-between">
          <span class="muted">${esc(t("setupLinkLabel"))}</span>
          <button type="button" class="btn btn-sm" id="copy-new-link">${esc(t("copy"))}</button>
        </div>
        <div class="mono" style="margin-top:6px">${esc(revealedKey.setupLink)}</div>
      </div>` : "";

    app.innerHTML = `
      <div class="stats-grid">
        <div class="stat"><div class="stat-label">${esc(t("statHosts"))}</div><div class="stat-value">${d.stats.onlineHosts}</div></div>
        <div class="stat"><div class="stat-label">${esc(t("statTunnels"))}</div><div class="stat-value">${d.stats.activeTunnels}</div></div>
        <div class="stat"><div class="stat-label">${esc(t("statTraffic"))}</div><div class="stat-value">${esc(trafficText)}</div></div>
        <div class="stat"><div class="stat-label">${esc(t("statDevices"))}</div><div class="stat-value">${d.deviceCount} / ${d.maxDevices}</div></div>
      </div>

      <section class="card">
        <div class="card-header">
          <div>
            <h2>${esc(t("quickConnectTitle"))}</h2>
            <p class="muted" style="margin:0">${esc(t("quickConnectDesc"))}</p>
          </div>
        </div>
        <div class="secret-box">
          <div class="row-between">
            <div>
              <div class="muted">${esc(t("serverAddress"))}</div>
              <div class="mono">${esc(d.publicUrl)}</div>
            </div>
            <button type="button" class="btn btn-sm" id="copy-url">${esc(t("copy"))}</button>
          </div>
        </div>
        <div class="row-between">
          <div class="row">
            <span class="muted">${esc(t("accessKeyStatus"))}:</span>
            <span class="badge ${d.accessKeyEnabled ? "badge-success" : "badge-muted"}">${esc(d.accessKeyEnabled ? t("enabled") : t("disabled"))}</span>
            ${d.accessKeyHint ? `<span class="mono muted">${esc(d.accessKeyHint)}</span>` : ""}
            ${d.accessKeyManagedByEnv ? `<span class="badge badge-warn">${esc(t("envManaged"))}</span>` : ""}
          </div>
          ${d.accessKeyManagedByEnv ? "" : `
            <div class="row">
              <button type="button" class="btn btn-primary btn-sm" id="btn-rotate-key">${esc(d.accessKeyEnabled ? t("rotateKey") : t("generateKey"))}</button>
              ${d.accessKeyEnabled && d.passwordEnabled ? `<button type="button" class="btn btn-danger btn-sm" id="btn-disable-key">${esc(t("disableKey"))}</button>` : ""}
            </div>`}
        </div>
        ${d.accessKeyManagedByEnv ? `<p class="muted" style="margin-top:8px">${esc(t("accessKeyEnvNote"))}</p>` : ""}
        ${keyRevealHtml}
      </section>

      <section class="card">
        <div class="card-header">
          <h2>${esc(t("devicesTitle"))} (${d.deviceCount})</h2>
          ${d.devices.length > 0 ? `<button type="button" class="btn btn-danger btn-sm" id="btn-signout-all">${esc(t("signOutAll"))}</button>` : ""}
        </div>
        ${devicesHtml}
      </section>

      <section class="card">
        <h2>${esc(t("settingsTitle"))}</h2>
        <div class="split-forms" style="margin-top:12px">
          <form id="rename-form">
            <div class="field">
              <label for="owner-name">${esc(t("ownerNameLabel"))}</label>
              <input id="owner-name" type="text" required maxlength="64" value="${esc(d.account.name)}" />
            </div>
            <button type="submit" class="btn btn-sm">${esc(t("saveName"))}</button>
          </form>
          ${d.passwordManagedByEnv
            ? `<div class="muted">${esc(t("passwordEnvNote"))}</div>`
            : `<form id="pwd-form">
                 <div id="pwd-err" class="alert alert-danger hidden"></div>
                 <div class="field">
                   <label for="cur-pwd">${esc(t("currentPassword"))}</label>
                   <input id="cur-pwd" type="password" required autocomplete="current-password" />
                 </div>
                 <div class="field">
                   <label for="new-pwd">${esc(t("newPassword"))}</label>
                   <input id="new-pwd" type="password" required minlength="8" autocomplete="new-password" />
                 </div>
                 <button type="submit" class="btn btn-sm">${esc(t("changePassword"))}</button>
               </form>`}
        </div>
      </section>`;

    document.getElementById("copy-url").addEventListener("click", () => copyText(d.publicUrl));
    if (revealedKey) {
      document.getElementById("copy-new-key").addEventListener("click", () => copyText(revealedKey.accessKey));
      document.getElementById("copy-new-link").addEventListener("click", () => copyText(revealedKey.setupLink));
    }

    const rotateBtn = document.getElementById("btn-rotate-key");
    if (rotateBtn) {
      rotateBtn.addEventListener("click", async () => {
        const ans = await api("POST", "/api/access-key/rotate", {});
        if (ans.ok) {
          revealedKey = ans.data;
          await renderDashboard();
        } else {
          showToast(errText(ans.data?.error));
        }
      });
    }

    const disableBtn = document.getElementById("btn-disable-key");
    if (disableBtn) {
      disableBtn.addEventListener("click", async () => {
        if (!confirm(t("confirmDisableKey"))) return;
        const ans = await api("POST", "/api/access-key/disable", {});
        if (ans.ok) {
          revealedKey = null;
          await renderDashboard();
        } else {
          showToast(errText(ans.data?.error));
        }
      });
    }

    document.querySelectorAll("[data-remove]").forEach((btn) => {
      btn.addEventListener("click", async () => {
        if (!confirm(t("confirmRemove"))) return;
        const id = btn.getAttribute("data-remove");
        const ans = await api("DELETE", "/api/devices/" + encodeURIComponent(id));
        if (ans.ok) await renderDashboard();
      });
    });

    const signOutAllBtn = document.getElementById("btn-signout-all");
    if (signOutAllBtn) {
      signOutAllBtn.addEventListener("click", async () => {
        if (!confirm(t("confirmSignOutAll"))) return;
        await api("POST", "/api/auth/signout-all", {});
        location.href = "/login";
      });
    }

    document.getElementById("rename-form").addEventListener("submit", async (e) => {
      e.preventDefault();
      const ans = await api("PATCH", "/api/account", { name: document.getElementById("owner-name").value.trim() });
      showToast(ans.ok ? t("nameUpdated") : errText(ans.data?.error));
    });

    const pwdForm = document.getElementById("pwd-form");
    if (pwdForm) {
      pwdForm.addEventListener("submit", async (e) => {
        e.preventDefault();
        const err = document.getElementById("pwd-err");
        err.classList.add("hidden");
        const ans = await api("POST", "/api/account/password", {
          currentPassword: document.getElementById("cur-pwd").value,
          newPassword: document.getElementById("new-pwd").value,
        });
        if (ans.ok) {
          pwdForm.reset();
          showToast(t("passwordUpdated"));
        } else {
          err.textContent = errText(ans.data?.error);
          err.classList.remove("hidden");
        }
      });
    }
  }

  async function boot() {
    const res = await api("GET", "/api/status");
    if (!res.ok) {
      app.innerHTML = `<div class="card center-card"><div class="alert alert-danger">${esc(t("err_unknown"))}</div></div>`;
      return;
    }

    const status = res.data;
    updateHeader(status);
    const path = location.pathname;

    if (status.needsSetup) {
      if (path !== "/setup") {
        history.replaceState(null, "", "/setup" + location.search);
      }
      renderSetup(status);
      return;
    }

    if (path === "/setup") {
      location.href = status.signedIn ? "/account" : "/login";
      return;
    }

    if (!status.signedIn) {
      if (path === "/device") {
        location.href = "/login?return=" + encodeURIComponent(location.pathname + location.search);
        return;
      }
      if (path !== "/login") {
        history.replaceState(null, "", "/login");
      }
      renderLogin(status);
      return;
    }

    if (path === "/login" || path === "/") {
      history.replaceState(null, "", "/account");
      await renderDashboard();
      return;
    }

    if (path === "/device") {
      await renderDevice();
      return;
    }

    await renderDashboard();
  }

  boot();
})();
