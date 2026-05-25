const STORAGE = {
  token: "simple-config-service.token",
  auth: "simple-config-service.auth",
  projectKeys: "simple-config-service.project-private-keys",
};

const state = {
  token: localStorage.getItem(STORAGE.token) || "",
  auth: readJSON(localStorage.getItem(STORAGE.auth), null),
  view: "configs",
  notice: null,
  projects: [],
  configs: [],
  versions: [],
  selectedConfigId: "",
  editingConfig: null,
  userPublicKey: null,
  projectKeys: readJSON(localStorage.getItem(STORAGE.projectKeys), {}) || {},
  decrypted: {},
  filters: {
    project_id: "",
    application: "",
    environment: "",
    limit: "50",
    offset: "0",
  },
  health: "checking",
};

const app = document.getElementById("app");
const encoder = new TextEncoder();
const decoder = new TextDecoder();

boot();

async function boot() {
  const path = window.location.pathname;
  if (path === "/") {
    window.location.replace(hasSession() ? "/home" : "/login");
    return;
  }
  if (path === "/login") {
    if (hasSession()) {
      window.location.replace("/home");
      return;
    }
    renderLogin();
    return;
  }
  if (path === "/register") {
    if (hasSession()) {
      window.location.replace("/home");
      return;
    }
    renderRegister();
    return;
  }
  if (path !== "/home") {
    window.location.replace(hasSession() ? "/home" : "/login");
    return;
  }
  if (!hasSession()) {
    clearSession();
    window.location.replace("/login");
    return;
  }
  renderShell();
  await initializeHome();
}

async function initializeHome() {
  await Promise.allSettled([loadHealth(), loadProjects(), loadUserPublicKey(false)]);
  await loadConfigs();
  renderShell();
}

function renderLogin() {
  app.innerHTML = `
    <main class="auth-screen">
      <section class="auth-panel">
        <h1 class="auth-title">配置中心</h1>
        <p class="auth-subtitle">登录后管理项目、配置、密钥和版本。</p>
        ${renderNotice()}
        <form id="login-form" class="form-grid">
          <label class="field">
            <span>用户名</span>
            <input class="input" name="username" autocomplete="username" required>
          </label>
          <label class="field">
            <span>密码</span>
            <input class="input" name="password" type="password" autocomplete="current-password" required>
          </label>
          <button class="button" type="submit">登录</button>
        </form>
        <p class="auth-switch">没有账号？<a href="/register">注册</a></p>
      </section>
    </main>`;
}

function renderRegister() {
  app.innerHTML = `
    <main class="auth-screen">
      <section class="auth-panel">
        <h1 class="auth-title">注册账号</h1>
        <p class="auth-subtitle">邀请码由服务管理员提供。</p>
        ${renderNotice()}
        <form id="register-form" class="form-grid">
          <label class="field">
            <span>用户名</span>
            <input class="input" name="username" autocomplete="username" required minlength="3" maxlength="64">
          </label>
          <label class="field">
            <span>密码</span>
            <input class="input" name="password" type="password" autocomplete="new-password" required minlength="8">
          </label>
          <label class="field">
            <span>邀请码</span>
            <input class="input" name="invite_code" required>
          </label>
          <label class="field">
            <span>用户 RSA 私钥</span>
            <textarea class="textarea pem" name="rsa_private_key" placeholder="留空时由服务端生成"></textarea>
          </label>
          <div class="button-row">
            <button class="button" type="submit">注册并登录</button>
            <a class="button secondary" href="/login">返回登录</a>
          </div>
        </form>
      </section>
    </main>`;
}

function renderShell() {
  const user = state.auth?.user;
  app.innerHTML = `
    <div class="shell">
      <aside class="sidebar">
        <div class="brand">
          <p class="brand-name">配置中心</p>
          <p class="brand-meta">${escapeHTML(user?.username || "")}</p>
        </div>
        <nav class="nav">
          ${navButton("configs", "配置")}
          ${navButton("projects", "项目")}
          ${navButton("keys", "密钥")}
        </nav>
        <div class="sidebar-footer">
          <button class="button ghost" data-action="refresh-token">刷新令牌</button>
          <button class="button ghost" data-action="logout">退出</button>
        </div>
      </aside>
      <main class="main">
        <header class="topbar">
          <div>
            <h1>${viewTitle()}</h1>
            <p class="topbar-meta">用户 ID：<span class="mono">${escapeHTML(user?.id || "")}</span></p>
          </div>
          <div class="topbar-actions">
            ${healthPill()}
            <button class="button secondary" data-action="reload">重新加载</button>
          </div>
        </header>
        ${renderNotice()}
        ${renderView()}
      </main>
    </div>`;
}

function navButton(view, label) {
  return `<button class="nav-button ${state.view === view ? "active" : ""}" data-view="${view}">${label}</button>`;
}

function viewTitle() {
  if (state.view === "projects") return "项目管理";
  if (state.view === "keys") return "密钥管理";
  return "配置首页";
}

function healthPill() {
  if (state.health === "ok") return `<span class="pill ok">服务正常</span>`;
  if (state.health === "error") return `<span class="pill err">服务异常</span>`;
  return `<span class="pill warn">检查中</span>`;
}

function renderNotice() {
  if (!state.notice) return "";
  const kind = state.notice.kind === "error" ? " error" : "";
  return `<div class="notice${kind}">${escapeHTML(state.notice.text)}</div>`;
}

function renderView() {
  if (state.view === "projects") return renderProjectsView();
  if (state.view === "keys") return renderKeysView();
  return renderConfigsView();
}

function renderConfigsView() {
  return `
    <div class="workspace-grid">
      <section class="panel wide">
        <div class="panel-head">
          <div>
            <h2 class="panel-title">配置列表</h2>
            <p class="panel-subtitle">按项目、应用、环境和分页查询。</p>
          </div>
        </div>
        <div class="panel-body stack">
          ${renderConfigFilters()}
          ${renderConfigTable()}
        </div>
      </section>
      <section class="panel">
        <div class="panel-head">
          <div>
            <h2 class="panel-title">${state.editingConfig ? "更新配置" : "创建配置"}</h2>
            <p class="panel-subtitle">${state.editingConfig ? "更新会生成新的配置版本。" : "配置值会在浏览器端加密后提交。"}</p>
          </div>
          ${state.editingConfig ? `<button class="button secondary small" data-action="cancel-edit">取消编辑</button>` : ""}
        </div>
        <div class="panel-body">
          ${renderConfigForm()}
        </div>
      </section>
      <section class="panel">
        <div class="panel-head">
          <div>
            <h2 class="panel-title">版本历史</h2>
            <p class="panel-subtitle">${state.selectedConfigId ? `配置 ID：${escapeHTML(state.selectedConfigId)}` : "选择一条配置查看版本。"}</p>
          </div>
        </div>
        <div class="panel-body">
          ${renderVersions()}
        </div>
      </section>
    </div>`;
}

function renderConfigFilters() {
  return `
    <form id="config-filter-form" class="filters">
      <label class="field">
        <span>项目</span>
        <select class="select" name="project_id">
          <option value="">全部项目</option>
          ${state.projects.map((project) => option(project.id, project.name, state.filters.project_id)).join("")}
        </select>
      </label>
      <label class="field">
        <span>应用</span>
        <input class="input" name="application" value="${escapeHTML(state.filters.application)}" placeholder="项目名或应用名">
      </label>
      <label class="field">
        <span>环境</span>
        <input class="input" name="environment" value="${escapeHTML(state.filters.environment)}" placeholder="prod">
      </label>
      <label class="field">
        <span>Limit</span>
        <input class="input" name="limit" type="number" min="1" max="100" value="${escapeHTML(state.filters.limit)}">
      </label>
      <label class="field">
        <span>Offset</span>
        <input class="input" name="offset" type="number" min="0" value="${escapeHTML(state.filters.offset)}">
      </label>
      <button class="button" type="submit">查询</button>
    </form>`;
}

function renderConfigTable() {
  if (!state.configs.length) {
    return `<div class="empty">暂无配置。</div>`;
  }
  const rows = state.configs.map((config) => `
    <tr>
      <td>
        <div>${escapeHTML(config.project_name || config.application || "")}</div>
        <div class="mono clip">${escapeHTML(config.project_id || "")}</div>
      </td>
      <td><span class="mono">${escapeHTML(config.key)}</span></td>
      <td>${escapeHTML(config.environment)}</td>
      <td>${statusPill(config.status)}</td>
      <td>v${Number(config.version || 0)}</td>
      <td>${formatDate(config.updated_at)}</td>
      <td>${renderValuePreview(config)}</td>
      <td class="actions">
        <div class="button-row">
          <button class="button secondary small" data-action="edit-config" data-id="${escapeAttr(config.id)}">编辑</button>
          <button class="button secondary small" data-action="load-versions" data-id="${escapeAttr(config.id)}">版本</button>
          <button class="button secondary small" data-action="decrypt-config" data-id="${escapeAttr(config.id)}">解密</button>
          <button class="button danger small" data-action="delete-config" data-id="${escapeAttr(config.id)}">删除</button>
        </div>
      </td>
    </tr>`).join("");

  return `
    <div class="table-wrap">
      <table class="table">
        <thead>
          <tr>
            <th>项目</th>
            <th>Key</th>
            <th>环境</th>
            <th>状态</th>
            <th>版本</th>
            <th>更新</th>
            <th>值</th>
            <th>操作</th>
          </tr>
        </thead>
        <tbody>${rows}</tbody>
      </table>
    </div>`;
}

function renderValuePreview(config) {
  const key = decryptKey(config);
  const value = state.decrypted[key];
  if (value !== undefined) {
    return `<div class="value-box"><div class="value-preview mono">${escapeHTML(value)}</div></div>`;
  }
  const payload = config.encrypted_value || {};
  return `
    <div class="value-box">
      <div class="value-preview mono">${escapeHTML(payload.algorithm || "")}</div>
      <div class="mono clip">${escapeHTML(payload.key_id || payload.value_ciphertext || "")}</div>
    </div>`;
}

function renderConfigForm() {
  const config = state.editingConfig || {};
  return `
    <form id="config-form" class="form-grid">
      <input type="hidden" name="id" value="${escapeAttr(config.id || "")}">
      <label class="field">
        <span>项目</span>
        <select class="select" name="project_id" required>
          <option value="">选择项目</option>
          ${state.projects.map((project) => option(project.id, project.name, config.project_id || state.filters.project_id)).join("")}
        </select>
      </label>
      <div class="row">
        <label class="field">
          <span>Key</span>
          <input class="input" name="key" value="${escapeHTML(config.key || "")}" required>
        </label>
        <label class="field">
          <span>环境</span>
          <input class="input" name="environment" value="${escapeHTML(config.environment || state.filters.environment)}" required>
        </label>
      </div>
      <label class="field">
        <span>描述</span>
        <input class="input" name="description" value="${escapeHTML(config.description || "")}">
      </label>
      <label class="field">
        <span>状态</span>
        <select class="select" name="status">
          ${option("enabled", "enabled", config.status || "enabled")}
          ${option("disabled", "disabled", config.status || "enabled")}
        </select>
      </label>
      <label class="field">
        <span>配置值</span>
        <textarea class="textarea" name="value" required>${escapeHTML(config.prefillValue || "")}</textarea>
      </label>
      <button class="button" type="submit">${state.editingConfig ? "更新配置" : "创建配置"}</button>
    </form>`;
}

function renderVersions() {
  if (!state.selectedConfigId) {
    return `<div class="empty">未选择配置。</div>`;
  }
  if (!state.versions.length) {
    return `<div class="empty">暂无版本记录。</div>`;
  }
  const rows = state.versions.map((version) => `
    <tr>
      <td>v${Number(version.version || 0)}</td>
      <td>${statusPill(version.status)}</td>
      <td>${formatDate(version.updated_at || version.created_at)}</td>
      <td>${renderValuePreview(version)}</td>
      <td class="actions">
        <div class="button-row">
          <button class="button secondary small" data-action="decrypt-version" data-version="${escapeAttr(version.version)}">解密</button>
          <button class="button secondary small" data-action="rollback-version" data-version="${escapeAttr(version.version)}">回滚</button>
        </div>
      </td>
    </tr>`).join("");
  return `
    <div class="table-wrap">
      <table class="table">
        <thead>
          <tr>
            <th>版本</th>
            <th>状态</th>
            <th>时间</th>
            <th>值</th>
            <th>操作</th>
          </tr>
        </thead>
        <tbody>${rows}</tbody>
      </table>
    </div>`;
}

function renderProjectsView() {
  const selectedID = state.filters.project_id || state.projects[0]?.id || "";
  const selected = state.projects.find((project) => project.id === selectedID) || state.projects[0] || null;
  return `
    <div class="two-column">
      <section class="panel">
        <div class="panel-head">
          <div>
            <h2 class="panel-title">项目列表</h2>
            <p class="panel-subtitle">项目公钥用于返回配置密文。</p>
          </div>
          <button class="button secondary small" data-action="reload-projects">刷新</button>
        </div>
        <div class="panel-body">
          ${renderProjectTable()}
        </div>
      </section>
      <div class="stack">
        <section class="panel">
          <div class="panel-head">
            <div>
              <h2 class="panel-title">创建项目</h2>
              <p class="panel-subtitle">可生成一对项目密钥，也可粘贴已有公钥。</p>
            </div>
          </div>
          <div class="panel-body">
            ${renderProjectForm()}
          </div>
        </section>
        <section class="panel">
          <div class="panel-head">
            <div>
              <h2 class="panel-title">项目密钥</h2>
              <p class="panel-subtitle">${selected ? escapeHTML(selected.name) : "暂无项目"}</p>
            </div>
          </div>
          <div class="panel-body">
            ${renderProjectKeyTools(selected)}
          </div>
        </section>
      </div>
    </div>`;
}

function renderProjectTable() {
  if (!state.projects.length) {
    return `<div class="empty">暂无项目。</div>`;
  }
  const rows = state.projects.map((project) => `
    <tr>
      <td>
        <strong>${escapeHTML(project.name)}</strong>
        <div class="mono clip">${escapeHTML(project.id)}</div>
      </td>
      <td>${escapeHTML(project.description || "")}</td>
      <td><span class="mono">${escapeHTML(project.rsa_public_key_fingerprint || "")}</span></td>
      <td>${formatDate(project.updated_at)}</td>
      <td class="actions">
        <div class="button-row">
          <button class="button secondary small" data-action="select-project" data-id="${escapeAttr(project.id)}">选择</button>
          <button class="button secondary small" data-action="filter-project" data-id="${escapeAttr(project.id)}">查配置</button>
        </div>
      </td>
    </tr>`).join("");
  return `
    <div class="table-wrap">
      <table class="table">
        <thead>
          <tr>
            <th>项目</th>
            <th>描述</th>
            <th>公钥指纹</th>
            <th>更新</th>
            <th>操作</th>
          </tr>
        </thead>
        <tbody>${rows}</tbody>
      </table>
    </div>`;
}

function renderProjectForm() {
  return `
    <form id="project-form" class="form-grid">
      <label class="field">
        <span>名称</span>
        <input class="input" name="name" required maxlength="128">
      </label>
      <label class="field">
        <span>描述</span>
        <input class="input" name="description">
      </label>
      <label class="field">
        <span>RSA 公钥</span>
        <textarea class="textarea pem" name="rsa_public_key" required></textarea>
      </label>
      <label class="field">
        <span>生成的私钥</span>
        <textarea class="textarea pem" name="generated_private_key" readonly></textarea>
      </label>
      <div class="button-row">
        <button class="button secondary" type="button" data-action="generate-project-key">生成密钥对</button>
        <button class="button" type="submit">创建项目</button>
      </div>
    </form>`;
}

function renderProjectKeyTools(project) {
  if (!project) {
    return `<div class="empty">创建项目后可管理项目密钥。</div>`;
  }
  return `
    <form id="project-public-key-form" class="form-grid">
      <input type="hidden" name="project_id" value="${escapeAttr(project.id)}">
      <label class="field">
        <span>替换项目公钥</span>
        <textarea class="textarea pem" name="rsa_public_key">${escapeHTML(project.rsa_public_key || "")}</textarea>
      </label>
      <div class="button-row">
        <button class="button secondary" type="button" data-action="generate-replacement-key">生成新密钥对</button>
        <button class="button" type="submit">更新公钥</button>
      </div>
    </form>
    <form id="project-private-key-form" class="form-grid" style="margin-top: 16px;">
      <input type="hidden" name="project_id" value="${escapeAttr(project.id)}">
      <label class="field">
        <span>项目私钥</span>
        <textarea class="textarea pem" name="rsa_private_key">${escapeHTML(state.projectKeys[project.id] || "")}</textarea>
      </label>
      <div class="button-row">
        <button class="button secondary" type="submit">保存到浏览器</button>
        <button class="button danger" type="button" data-action="clear-project-private-key" data-id="${escapeAttr(project.id)}">清除私钥</button>
      </div>
    </form>`;
}

function renderKeysView() {
  const publicKey = state.userPublicKey || {};
  return `
    <div class="two-column">
      <section class="panel">
        <div class="panel-head">
          <div>
            <h2 class="panel-title">用户公钥</h2>
            <p class="panel-subtitle">${escapeHTML(publicKey.key_id || "尚未加载")}</p>
          </div>
          <button class="button secondary small" data-action="load-user-key">刷新</button>
        </div>
        <div class="panel-body form-grid">
          <label class="field">
            <span>算法</span>
            <input class="input" value="${escapeHTML(publicKey.algorithm || "")}" readonly>
          </label>
          <label class="field">
            <span>RSA 公钥</span>
            <textarea class="textarea pem" readonly>${escapeHTML(publicKey.rsa_public_key || "")}</textarea>
          </label>
        </div>
      </section>
      <section class="panel">
        <div class="panel-head">
          <div>
            <h2 class="panel-title">轮换用户 RSA 私钥</h2>
            <p class="panel-subtitle">留空提交时由服务端生成新私钥。</p>
          </div>
        </div>
        <div class="panel-body">
          <form id="rotate-user-key-form" class="form-grid">
            <label class="field">
              <span>新私钥</span>
              <textarea class="textarea pem" name="rsa_private_key"></textarea>
            </label>
            <button class="button" type="submit">轮换密钥</button>
          </form>
        </div>
      </section>
    </div>`;
}

document.addEventListener("submit", async (event) => {
  const form = event.target;
  if (!(form instanceof HTMLFormElement)) return;
  event.preventDefault();

  await withFormLock(form, async () => {
    if (form.id === "login-form") return submitLogin(form);
    if (form.id === "register-form") return submitRegister(form);
    if (form.id === "config-filter-form") return submitConfigFilters(form);
    if (form.id === "config-form") return submitConfig(form);
    if (form.id === "project-form") return submitProject(form);
    if (form.id === "project-public-key-form") return submitProjectPublicKey(form);
    if (form.id === "project-private-key-form") return submitProjectPrivateKey(form);
    if (form.id === "rotate-user-key-form") return submitRotateUserKey(form);
  });
});

document.addEventListener("click", async (event) => {
  const viewButton = event.target.closest("[data-view]");
  if (viewButton) {
    state.view = viewButton.dataset.view;
    state.notice = null;
    renderShell();
    return;
  }

  const button = event.target.closest("[data-action]");
  if (!button) return;
  const action = button.dataset.action;
  await withButtonLock(button, async () => {
    if (action === "logout") return logout();
    if (action === "refresh-token") return refreshToken();
    if (action === "reload") return initializeHome();
    if (action === "reload-projects") return loadProjectsAndRender();
    if (action === "load-user-key") return loadUserKeyAndRender();
    if (action === "generate-project-key") return generateProjectKeyForForm("project-form");
    if (action === "generate-replacement-key") return generateProjectKeyForForm("project-public-key-form");
    if (action === "cancel-edit") return cancelEdit();
    if (action === "edit-config") return editConfig(button.dataset.id);
    if (action === "delete-config") return deleteConfig(button.dataset.id);
    if (action === "load-versions") return loadVersionsAndRender(button.dataset.id);
    if (action === "decrypt-config") return decryptConfigAndRender(button.dataset.id);
    if (action === "decrypt-version") return decryptVersionAndRender(button.dataset.version);
    if (action === "rollback-version") return rollbackVersion(button.dataset.version);
    if (action === "select-project") return selectProject(button.dataset.id);
    if (action === "filter-project") return filterProject(button.dataset.id);
    if (action === "clear-project-private-key") return clearProjectPrivateKey(button.dataset.id);
  });
});

async function submitLogin(form) {
  try {
    const body = formValues(form);
    const response = await api("/api/login", { method: "POST", body });
    storeAuth(response);
    window.location.replace("/home");
  } catch (error) {
    showError(error.message);
    renderLogin();
  }
}

async function submitRegister(form) {
  try {
    const body = formValues(form);
    const response = await api("/api/register", { method: "POST", body });
    storeAuth(response);
    window.location.replace("/home");
  } catch (error) {
    showError(error.message);
    renderRegister();
  }
}

async function submitConfigFilters(form) {
  state.filters = { ...state.filters, ...formValues(form) };
  await loadConfigs();
  showNotice("配置列表已更新。");
  renderShell();
}

async function submitConfig(form) {
  try {
    const values = formValues(form);
    const plaintext = values.value || "";
    const userKey = await getUserPublicKey();
    const encryptedValue = await encryptEnvelope(userKey.rsa_public_key, plaintext, userKey.key_id);
    const body = {
      project_id: values.project_id,
      key: values.key,
      environment: values.environment,
      description: values.description,
      status: values.status,
      encrypted_value: encryptedValue,
    };
    if (values.id) {
      await api(`/api/configs/${encodeURIComponent(values.id)}`, { method: "PUT", body });
      showNotice("配置已更新。");
    } else {
      await api("/api/configs", { method: "POST", body });
      showNotice("配置已创建。");
    }
    state.editingConfig = null;
    state.decrypted = {};
    await loadConfigs();
    renderShell();
  } catch (error) {
    showError(error.message);
    renderShell();
  }
}

async function submitProject(form) {
  try {
    const values = formValues(form);
    const response = await api("/api/projects", {
      method: "POST",
      body: {
        name: values.name,
        description: values.description,
        rsa_public_key: values.rsa_public_key,
      },
    });
    if (values.generated_private_key) {
      state.projectKeys[response.id] = values.generated_private_key;
      saveProjectKeys();
    }
    state.filters.project_id = response.id;
    showNotice("项目已创建。");
    await loadProjects();
    renderShell();
  } catch (error) {
    showError(error.message);
    renderShell();
  }
}

async function submitProjectPublicKey(form) {
  try {
    const values = formValues(form);
    await api(`/api/projects/${encodeURIComponent(values.project_id)}/rsa-public-key`, {
      method: "PUT",
      body: { rsa_public_key: values.rsa_public_key },
    });
    const privateKeyField = document
      .getElementById("project-private-key-form")
      ?.querySelector("[name='rsa_private_key']");
    const privateKey = privateKeyField?.value?.trim();
    if (privateKey) {
      state.projectKeys[values.project_id] = privateKey;
      saveProjectKeys();
    }
    showNotice("项目公钥已更新。");
    await loadProjects();
    state.decrypted = {};
    renderShell();
  } catch (error) {
    showError(error.message);
    renderShell();
  }
}

async function submitProjectPrivateKey(form) {
  const values = formValues(form);
  if (!values.project_id) return;
  if (values.rsa_private_key.trim()) {
    state.projectKeys[values.project_id] = values.rsa_private_key.trim();
  } else {
    delete state.projectKeys[values.project_id];
  }
  saveProjectKeys();
  showNotice("项目私钥已保存。");
  renderShell();
}

async function submitRotateUserKey(form) {
  try {
    const values = formValues(form);
    const response = await api("/api/users/me/rsa-private-key", {
      method: "PUT",
      body: { rsa_private_key: values.rsa_private_key },
    });
    state.userPublicKey = response;
    showNotice("用户 RSA 密钥已轮换。");
    renderShell();
  } catch (error) {
    showError(error.message);
    renderShell();
  }
}

async function logout() {
  try {
    await api("/api/logout", { method: "POST" });
  } catch (_) {
  } finally {
    clearSession();
    window.location.replace("/login");
  }
}

async function refreshToken() {
  try {
    const response = await api("/api/refresh", { method: "POST" });
    storeAuth(response);
    showNotice("令牌已刷新。");
    renderShell();
  } catch (error) {
    showError(error.message);
    renderShell();
  }
}

async function loadHealth() {
  try {
    const response = await fetch("/healthz");
    state.health = response.ok ? "ok" : "error";
  } catch (_) {
    state.health = "error";
  }
}

async function loadProjects() {
  const response = await api("/api/projects");
  state.projects = response.projects || [];
}

async function loadProjectsAndRender() {
  try {
    await loadProjects();
    showNotice("项目列表已更新。");
  } catch (error) {
    showError(error.message);
  }
  renderShell();
}

async function loadConfigs() {
  const params = new URLSearchParams();
  if (state.filters.project_id) {
    params.set("project_id", state.filters.project_id);
  } else if (state.filters.application) {
    params.set("application", state.filters.application);
  }
  if (state.filters.environment) params.set("environment", state.filters.environment);
  if (state.filters.limit) params.set("limit", state.filters.limit);
  if (state.filters.offset) params.set("offset", state.filters.offset);
  const response = await api(`/api/configs?${params.toString()}`);
  state.configs = response.configs || [];
}

async function loadUserPublicKey(showMessage = true) {
  const response = await api("/api/users/me/public-key");
  state.userPublicKey = response;
  if (showMessage) showNotice("用户公钥已更新。");
}

async function loadUserKeyAndRender() {
  try {
    await loadUserPublicKey(true);
  } catch (error) {
    showError(error.message);
  }
  renderShell();
}

async function getUserPublicKey() {
  if (!state.userPublicKey?.rsa_public_key) {
    await loadUserPublicKey(false);
  }
  return state.userPublicKey;
}

async function loadVersionsAndRender(id) {
  try {
    state.selectedConfigId = id;
    const response = await api(`/api/configs/${encodeURIComponent(id)}/versions`);
    state.versions = response.versions || [];
    showNotice("版本历史已加载。");
  } catch (error) {
    showError(error.message);
  }
  renderShell();
}

async function editConfig(id) {
  const config = state.configs.find((item) => item.id === id);
  if (!config) return;
  const prefillValue = state.decrypted[decryptKey(config)] || "";
  state.editingConfig = { ...config, prefillValue };
  state.view = "configs";
  state.notice = null;
  renderShell();
}

async function deleteConfig(id) {
  if (!window.confirm("确认删除这条配置？")) return;
  try {
    await api(`/api/configs/${encodeURIComponent(id)}`, { method: "DELETE" });
    if (state.selectedConfigId === id) {
      state.selectedConfigId = "";
      state.versions = [];
    }
    showNotice("配置已删除。");
    await loadConfigs();
  } catch (error) {
    showError(error.message);
  }
  renderShell();
}

function cancelEdit() {
  state.editingConfig = null;
  state.notice = null;
  renderShell();
}

async function decryptConfigAndRender(id) {
  try {
    const config = state.configs.find((item) => item.id === id);
    if (!config) throw new Error("配置不存在。");
    await decryptItem(config);
    showNotice("配置值已解密。");
  } catch (error) {
    showError(error.message);
  }
  renderShell();
}

async function decryptVersionAndRender(version) {
  try {
    const item = state.versions.find((entry) => String(entry.version) === String(version));
    if (!item) throw new Error("版本不存在。");
    await decryptItem(item);
    showNotice("版本值已解密。");
  } catch (error) {
    showError(error.message);
  }
  renderShell();
}

async function decryptItem(item) {
  const privateKey = state.projectKeys[item.project_id];
  if (!privateKey) throw new Error("请先在项目密钥中保存对应项目私钥。");
  const plaintext = await decryptEnvelope(privateKey, item.encrypted_value);
  state.decrypted[decryptKey(item)] = plaintext;
}

async function rollbackVersion(version) {
  if (!state.selectedConfigId) return;
  if (!window.confirm(`确认回滚到 v${version}？`)) return;
  try {
    await api(`/api/configs/${encodeURIComponent(state.selectedConfigId)}/rollback`, {
      method: "POST",
      body: { version: Number(version) },
    });
    showNotice("配置已回滚。");
    await loadConfigs();
    await loadVersionsAndRender(state.selectedConfigId);
  } catch (error) {
    showError(error.message);
    renderShell();
  }
}

function selectProject(id) {
  state.filters.project_id = id;
  state.view = "projects";
  state.notice = null;
  renderShell();
}

async function filterProject(id) {
  state.filters.project_id = id;
  state.view = "configs";
  await loadConfigs();
  showNotice("已按项目筛选配置。");
  renderShell();
}

function clearProjectPrivateKey(id) {
  delete state.projectKeys[id];
  saveProjectKeys();
  state.decrypted = {};
  showNotice("项目私钥已清除。");
  renderShell();
}

async function generateProjectKeyForForm(formID) {
  try {
    const form = document.getElementById(formID);
    if (!form) return;
    const pair = await generateRSAKeyPair();
    const publicField = form.querySelector("[name='rsa_public_key']");
    const privateField = form.querySelector("[name='generated_private_key']");
    if (publicField) publicField.value = pair.publicKeyPEM;
    if (privateField) privateField.value = pair.privateKeyPEM;
    if (formID === "project-public-key-form") {
      const privateKeyForm = document.getElementById("project-private-key-form");
      const privateTextarea = privateKeyForm?.querySelector("[name='rsa_private_key']");
      if (privateTextarea) privateTextarea.value = pair.privateKeyPEM;
    }
    showNotice("密钥对已生成。");
  } catch (error) {
    showError(error.message);
    renderShell();
  }
}

async function api(path, options = {}) {
  const headers = { ...(options.headers || {}) };
  let body = options.body;
  if (body && typeof body !== "string") {
    headers["Content-Type"] = "application/json";
    body = JSON.stringify(body);
  }
  if (state.token) {
    headers.Authorization = `Bearer ${state.token}`;
  }
  const response = await fetch(path, { ...options, headers, body });
  if (response.status === 204) return null;
  const contentType = response.headers.get("content-type") || "";
  const data = contentType.includes("application/json") ? await response.json() : await response.text();
  if (!response.ok) {
    if (response.status === 401) {
      clearSession();
      if (window.location.pathname !== "/login") window.location.replace("/login");
    }
    throw new Error(formatAPIError(data, response.status));
  }
  return data;
}

function formatAPIError(data, status) {
  if (data && typeof data === "object") {
    return `${data.field ? `${data.field}: ` : ""}${data.error || `HTTP ${status}`}`;
  }
  return data || `HTTP ${status}`;
}

function storeAuth(response) {
  state.token = response.access_token;
  state.auth = { user: response.user, expires_at: response.expires_at };
  localStorage.setItem(STORAGE.token, state.token);
  localStorage.setItem(STORAGE.auth, JSON.stringify(state.auth));
}

function clearSession() {
  state.token = "";
  state.auth = null;
  localStorage.removeItem(STORAGE.token);
  localStorage.removeItem(STORAGE.auth);
}

function hasSession() {
  if (!state.token || !state.auth?.expires_at) return false;
  return new Date(state.auth.expires_at).getTime() > Date.now();
}

function saveProjectKeys() {
  localStorage.setItem(STORAGE.projectKeys, JSON.stringify(state.projectKeys));
}

function formValues(form) {
  const values = {};
  for (const [key, value] of new FormData(form).entries()) {
    values[key] = typeof value === "string" ? value : value;
  }
  return values;
}

async function withFormLock(form, task) {
  const buttons = [...form.querySelectorAll("button")];
  buttons.forEach((button) => (button.disabled = true));
  try {
    await task();
  } finally {
    buttons.forEach((button) => (button.disabled = false));
  }
}

async function withButtonLock(button, task) {
  button.disabled = true;
  try {
    await task();
  } finally {
    button.disabled = false;
  }
}

function showNotice(text) {
  state.notice = { kind: "ok", text };
}

function showError(text) {
  state.notice = { kind: "error", text };
}

function statusPill(status) {
  const kind = status === "enabled" ? "ok" : "warn";
  return `<span class="pill ${kind}">${escapeHTML(status || "")}</span>`;
}

function option(value, label, selected) {
  return `<option value="${escapeAttr(value)}" ${String(value) === String(selected) ? "selected" : ""}>${escapeHTML(label)}</option>`;
}

function formatDate(value) {
  if (!value) return "";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "";
  return date.toLocaleString();
}

function decryptKey(item) {
  return `${item.id}:v${item.version}`;
}

function readJSON(value, fallback) {
  try {
    return value ? JSON.parse(value) : fallback;
  } catch (_) {
    return fallback;
  }
}

function escapeHTML(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function escapeAttr(value) {
  return escapeHTML(value);
}

async function encryptEnvelope(publicKeyPEM, plaintext, keyID) {
  ensureCrypto();
  const publicKey = await importPublicKey(publicKeyPEM);
  const dataKey = crypto.getRandomValues(new Uint8Array(32));
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const aesKey = await crypto.subtle.importKey("raw", dataKey, "AES-GCM", false, ["encrypt"]);
  const valueCiphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce }, aesKey, encoder.encode(plaintext));
  const encryptedDataKey = await crypto.subtle.encrypt({ name: "RSA-OAEP" }, publicKey, dataKey);
  dataKey.fill(0);
  return {
    value_ciphertext: bytesToBase64(new Uint8Array(valueCiphertext)),
    encrypted_data_key: bytesToBase64(new Uint8Array(encryptedDataKey)),
    nonce: bytesToBase64(nonce),
    algorithm: "RSA-OAEP-SHA256+A256GCM",
    key_id: keyID || "",
  };
}

async function decryptEnvelope(privateKeyPEM, payload) {
  ensureCrypto();
  const privateKey = await importPrivateKey(privateKeyPEM);
  const encryptedDataKey = base64ToBytes(payload.encrypted_data_key);
  const dataKey = await crypto.subtle.decrypt({ name: "RSA-OAEP" }, privateKey, encryptedDataKey);
  const aesKey = await crypto.subtle.importKey("raw", dataKey, "AES-GCM", false, ["decrypt"]);
  const plaintext = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: base64ToBytes(payload.nonce) },
    aesKey,
    base64ToBytes(payload.value_ciphertext),
  );
  return decoder.decode(plaintext);
}

async function generateRSAKeyPair() {
  ensureCrypto();
  const keyPair = await crypto.subtle.generateKey(
    {
      name: "RSA-OAEP",
      modulusLength: 3072,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: "SHA-256",
    },
    true,
    ["encrypt", "decrypt"],
  );
  const publicKey = await crypto.subtle.exportKey("spki", keyPair.publicKey);
  const privateKey = await crypto.subtle.exportKey("pkcs8", keyPair.privateKey);
  return {
    publicKeyPEM: arrayBufferToPEM(publicKey, "PUBLIC KEY"),
    privateKeyPEM: arrayBufferToPEM(privateKey, "PRIVATE KEY"),
  };
}

async function importPublicKey(pem) {
  return crypto.subtle.importKey(
    "spki",
    pemToArrayBuffer(pem),
    { name: "RSA-OAEP", hash: "SHA-256" },
    false,
    ["encrypt"],
  );
}

async function importPrivateKey(pem) {
  return crypto.subtle.importKey(
    "pkcs8",
    pemToArrayBuffer(pem),
    { name: "RSA-OAEP", hash: "SHA-256" },
    false,
    ["decrypt"],
  );
}

function pemToArrayBuffer(pem) {
  const base64 = pem
    .replace(/-----BEGIN [^-]+-----/g, "")
    .replace(/-----END [^-]+-----/g, "")
    .replace(/\s/g, "");
  return base64ToBytes(base64);
}

function arrayBufferToPEM(buffer, label) {
  const base64 = bytesToBase64(new Uint8Array(buffer));
  const lines = base64.match(/.{1,64}/g) || [];
  return `-----BEGIN ${label}-----\n${lines.join("\n")}\n-----END ${label}-----\n`;
}

function base64ToBytes(value) {
  const binary = atob(value);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

function bytesToBase64(bytes) {
  let binary = "";
  const chunk = 0x8000;
  for (let i = 0; i < bytes.length; i += chunk) {
    binary += String.fromCharCode(...bytes.subarray(i, i + chunk));
  }
  return btoa(binary);
}

function ensureCrypto() {
  if (!window.crypto?.subtle) {
    throw new Error("当前浏览器环境不可用 WebCrypto。");
  }
}
