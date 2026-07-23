"use strict";

const HANDOFF_STEP_GROUPS = [
  ["账号接力", [
    ["old_login", "旧子号登录"],
    ["invite", "校验成员并邀请新号"],
    ["old_leave", "旧子号退出并确认"],
    ["new_login", "新子号注册入组"],
    ["member_verify", "复核活跃成员 ≤ 2"],
  ]],
  ["凭据导出", [
    ["pat", "新子号创建 PAT"],
    ["cpa", "导出 CPA"],
    ["sub2api_export", "导出 Sub2 JSON"],
  ]],
  ["可选交付", [
    ["push", "推送 CPA"],
    ["push_sub2api", "推送 Sub2API"],
  ]],
];

const RESCUE_STEP_GROUPS = [
  ["应急提拉", [
    ["owner_login", "母号登录 Team"],
    ["rescue_clear", "清退并确认只剩母号"],
    ["rescue_invite", "母号邀请新子号"],
    ["new_login", "新子号注册入组"],
    ["rescue_verify", "复核母号 + 新子号"],
  ]],
  ["凭据导出", [
    ["pat", "新子号创建 PAT"],
    ["cpa", "导出 CPA"],
    ["sub2api_export", "导出 Sub2 JSON"],
  ]],
  ["可选交付", [
    ["push", "推送 CPA"],
    ["push_sub2api", "推送 Sub2API"],
  ]],
];

const STEP_DEFINITIONS = [
  ...HANDOFF_STEP_GROUPS.flatMap(([, steps]) => steps),
  ...RESCUE_STEP_GROUPS.flatMap(([, steps]) => steps),
].filter(([step], index, items) => items.findIndex(([candidate]) => candidate === step) === index);

const STEP_LABELS = Object.fromEntries(STEP_DEFINITIONS);

function stepGroupsForRun(run) {
  const result = runResultObject(run);
  return safeString(firstValue(run, ["kind"], result?.mode)) === "rescue"
    ? RESCUE_STEP_GROUPS
    : HANDOFF_STEP_GROUPS;
}
const STEP_STATE_LABELS = {
  pending: "待执行",
  queued: "待执行",
  active: "执行中",
  running: "执行中",
  done: "完成",
  succeeded: "完成",
  skipped: "跳过",
  cancelled: "已停止",
  error: "失败",
  failed: "失败",
};

const WORKSPACE_STATUS = {
  needs_account: ["待分配", "warning"],
  ready: ["可执行", "success"],
  queued: ["排队中", "accent"],
  running: ["运行中", "info"],
  failed: ["失败", "danger"],
  paused: ["已暂停", "neutral"],
};

const TEAM_STATUS = {
  needs_account: ["可换班", "success"],
  ready: ["可换班", "success"],
  queued: ["排队中", "accent"],
  running: ["换班中", "info"],
  failed: ["失败", "danger"],
  paused: ["已暂停", "neutral"],
  setup: ["待配置", "warning"],
};

const ACCOUNT_STATUS = {
  available: ["可用", "success"],
  bound_current: ["当前绑定", "accent"],
  bound_next: ["下一账号", "info"],
  protected: ["长期保留", "success"],
  exited_pending: ["退出待处理", "warning"],
  used: ["已用完", "neutral"],
  retired: ["已退役", "neutral"],
  disabled: ["已停用", "danger"],
};

const INVENTORY_STATUS = {
  available: ["可用", "success"],
  disabled: ["已禁用", "danger"],
  exhausted: ["已耗尽", "warning"],
};

const ICLOUD_MAILBOX_STATUS = {
  unchecked: ["待检测", "warning"],
  ready: ["可用", "success"],
  disabled: ["已停用", "neutral"],
  session_invalid: ["Session 失效", "danger"],
  imap_invalid: ["IMAP 失效", "danger"],
};

const ICLOUD_ALIAS_STATUS = {
  active: ["启用", "success"],
  inactive: ["停用", "danger"],
};

const CONFIG_STATUS = {
  configured: ["已配置", "success"],
  dynamic: ["动态链", "accent"],
  degraded: ["待刷新", "warning"],
  missing: ["未配置", "danger"],
};

const PROXY_STATUS = {
  configured: ["独立 S5", "success"],
  inherited: ["全局 / 直连", "neutral"],
};

const RUN_STATUS = {
  queued: ["排队中", "accent"],
  running: ["运行中", "info"],
  stopping: ["正在停止", "warning"],
  succeeded: ["成功", "success"],
  failed: ["失败", "danger"],
  cancelled: ["已停止", "neutral"],
};

const QUEUE_STATUS = {
  queued: "等待执行",
  pending: "等待执行",
  running: "运行中",
  stopping: "正在停止",
  failed: "失败",
  completed: "已完成",
  succeeded: "已完成",
  cancelled: "已停止",
};

const VIEW_NAMES = new Set(["spaces", "accounts", "runs", "settings"]);
const ACTIVE_RUN_STATES = new Set(["running", "stopping"]);
const ACTIVE_QUEUE_STATES = new Set(["queued", "pending", "running", "stopping"]);
const MAX_DIAGNOSTIC_ROWS = 300;
const MAX_QUEUE_LOG_ROWS = 300;
const MAX_EVENT_MEMORY = 1000;
const ACCOUNT_PAGE_SIZE = 50;
const MOBILE_ACCOUNT_PAGE_SIZE = 20;
const INVENTORY_SEARCH_LIMIT = 20;
const INVENTORY_SEARCH_DELAY = 300;
const DEFAULT_LOCAL_CLASH_PROXY = "http://127.0.0.1:7897";
const CHAIN_PROXY_MODE = "clash_chain";

const dateTimeFormatter = new Intl.DateTimeFormat("zh-CN", {
  month: "2-digit",
  day: "2-digit",
  hour: "2-digit",
  minute: "2-digit",
  second: "2-digit",
  hour12: false,
});
const timeFormatter = new Intl.DateTimeFormat("zh-CN", {
  hour: "2-digit",
  minute: "2-digit",
  second: "2-digit",
  hour12: false,
});
const numberFormatter = new Intl.NumberFormat("zh-CN");

const state = {
  requestToken: "",
  view: "spaces",
  workspaces: [],
  accounts: [],
  runs: [],
  queue: {items: [], paused: false},
  settings: {},
  openbrowserStatus: null,
  migration: null,
  migrationBlocked: false,
  selectedWorkspaceIds: new Set(),
  pendingAccountRefreshIds: new Set(),
  filters: {
    workspaceSearch: "",
    workspaceStatus: "all",
    accountSearch: "",
    accountStatus: "all",
    runSearch: "",
    runState: "all",
    runDateFrom: "",
  },
  errors: {},
  settingsDirty: false,
  sub2apiGroups: [],
  clearSecrets: new Set(),
  queueExpanded: false,
  queueLogView: {key: "", follow: true, scrollTop: 0},
  accountPage: 1,
  accountView: "used",
  inventoryResults: [],
  inventoryQuery: "",
  inventoryStatus: "available",
  inventoryLoading: false,
  inventoryError: "",
  inventoryDirty: false,
  inventorySearchTimer: null,
  inventoryRequestController: null,
  inventorySearchSequence: 0,
  icloudMailboxes: [],
  icloudMailboxesLoaded: false,
  icloudMailboxesLoading: false,
  icloudMailboxesError: "",
  icloudAliases: [],
  icloudTeamOwners: [],
  remoteIcloudAliases: [],
  proxyChainNodes: [],
  sharedClashProxy: DEFAULT_LOCAL_CLASH_PROXY,
  activeIcloudMailboxId: "",
  activeIcloudCaptureMailboxId: "",
  icloudHmeCaptureStatus: null,
  icloudHmeCapturePollTimer: null,
  icloudHmeCaptureHandled: new Set(),
  icloudTeamImportAliases: [],
  icloudTeamImportMailboxId: "",
  icloudTeamImportLoading: false,
  icloudTeamImportProxyMode: CHAIN_PROXY_MODE,
  pendingIcloudTeamImport: null,
  activeRunId: null,
  activeRun: null,
  activeRunEvents: [],
  eventSource: null,
  lastEventSequence: 0,
};
let requestTokenRefreshPromise = null;

const comboboxes = new Map(["current", "next"].map((role) => [role, {
  role,
  selected: null,
  original: null,
  query: "",
  inventoryResults: [],
  loading: false,
  error: "",
  open: false,
  activeIndex: -1,
  searchTimer: null,
  requestController: null,
  searchSequence: 0,
}]));

class ApiError extends Error {
  constructor(message, {status = 0, code = "request_failed", fields = null} = {}) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.code = code;
    this.fields = fields;
  }
}

const byId = (id) => document.getElementById(id);

function element(tag, options = {}, children = []) {
  const node = document.createElement(tag);
  if (options.className) node.className = options.className;
  if (options.text !== undefined && options.text !== null) node.textContent = String(options.text);
  if (options.dataset) {
    for (const [name, value] of Object.entries(options.dataset)) {
      if (value !== undefined && value !== null) node.dataset[name] = String(value);
    }
  }
  if (options.attrs) {
    for (const [name, value] of Object.entries(options.attrs)) {
      if (value === false || value === null || value === undefined) continue;
      node.setAttribute(name, value === true ? "" : String(value));
    }
  }
  const list = Array.isArray(children) ? children : [children];
  for (const child of list) {
    if (child === null || child === undefined) continue;
    node.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }
  return node;
}

function actionButton(label, action, dataset = {}, className = "text-action") {
  return element("button", {
    className,
    text: label,
    dataset: {action, ...dataset},
    attrs: {type: "button"},
  });
}

function statusBadge(status, definitions) {
  const [label, tone] = definitions[status] || [status || "未知", "neutral"];
  return element("span", {
    className: "status-badge",
    text: label,
    dataset: {tone},
  });
}

function safeString(value, fallback = "") {
  if (value === null || value === undefined) return fallback;
  return String(value);
}

function booleanValue(value) {
  if (typeof value === "boolean") return value;
  if (typeof value === "number") return value !== 0;
  return ["1", "true", "yes", "on"].includes(safeString(value).trim().toLowerCase());
}

function firstValue(object, keys, fallback = "") {
  if (!object || typeof object !== "object") return fallback;
  for (const key of keys) {
    const value = object[key];
    if (value !== null && value !== undefined && value !== "") return value;
  }
  return fallback;
}

function asList(payload, keys = []) {
  if (Array.isArray(payload)) return payload;
  if (!payload || typeof payload !== "object") return [];
  for (const key of [...keys, "items", "data", "results"]) {
    if (Array.isArray(payload[key])) return payload[key];
  }
  return [];
}

function normalizeQueue(payload) {
  if (Array.isArray(payload)) return {items: payload, paused: false, credentialRefresh: null};
  const source = payload && typeof payload === "object" ? payload : {};
  return {
    items: asList(source, ["queue", "queue_items"]),
    paused: Boolean(firstValue(source, ["paused", "is_paused"], false)),
    credentialRefresh: (
      source.credential_refresh && typeof source.credential_refresh === "object"
        ? source.credential_refresh
        : null
    ),
    runOperation: (
      source.run_operation && typeof source.run_operation === "object"
        ? source.run_operation
        : null
    ),
  };
}

function normalizedError(payload, status) {
  const source = payload && typeof payload === "object" ? payload : {};
  const detail = source.detail;
  const fields = source.fields || source.field_errors || (detail && detail.fields) || null;
  let message = "";
  if (typeof detail === "string") message = detail;
  if (!message && detail && typeof detail === "object") {
    message = safeString(firstValue(detail, ["message", "detail", "error"]));
  }
  if (!message) message = safeString(firstValue(source, ["message", "error"]));
  if (!message && fields && typeof fields === "object") {
    message = safeString(Object.values(fields).find((value) => safeString(value)));
  }
  if (!message) message = `请求失败 (${status})`;
  const code = safeString(firstValue(source, ["code", "error_code"], firstValue(detail, ["code"], "request_failed")));
  return new ApiError(message, {status, code, fields});
}

async function refreshRequestToken() {
  if (requestTokenRefreshPromise) return requestTokenRefreshPromise;
  requestTokenRefreshPromise = (async () => {
    const response = await fetch("/api/bootstrap", {
      cache: "no-store",
      credentials: "same-origin",
    });
    const payload = await response.json();
    if (!response.ok) throw normalizedError(payload, response.status);
    const token = safeString(firstValue(payload, ["request_token", "csrf_token", "token"]));
    if (!token) throw new ApiError("本地服务未返回请求令牌", {code: "missing_request_token"});
    state.requestToken = token;
    return token;
  })();
  try {
    return await requestTokenRefreshPromise;
  } finally {
    requestTokenRefreshPromise = null;
  }
}

async function api(path, options = {}) {
  const controller = new AbortController();
  const timeout = Number(options.timeout || 20000);
  let timedOut = false;
  const timer = window.setTimeout(() => {
    timedOut = true;
    controller.abort();
  }, timeout);
  const headers = new Headers(options.headers || {});
  headers.set("Accept", "application/json");
  if (state.requestToken) headers.set("X-Workflow-Token", state.requestToken);

  let body = options.body;
  if (body !== undefined && body !== null && !(body instanceof FormData) && typeof body !== "string") {
    headers.set("Content-Type", "application/json");
    body = JSON.stringify(body);
  }

  if (options.signal) {
    if (options.signal.aborted) controller.abort();
    options.signal.addEventListener("abort", () => controller.abort(), {once: true});
  }

  try {
    const response = await fetch(path, {
      method: options.method || "GET",
      headers,
      body,
      signal: controller.signal,
      cache: "no-store",
      credentials: "same-origin",
    });
    if (response.status === 204) return null;
    const contentType = response.headers.get("content-type") || "";
    let payload = null;
    if (contentType.includes("application/json")) {
      payload = await response.json();
    } else {
      const text = await response.text();
      payload = text ? {detail: text} : null;
    }
    if (!response.ok) {
      const error = normalizedError(payload, response.status);
      if (
        response.status === 403
        && error.code === "invalid_request_token"
        && !options.requestTokenRetried
      ) {
        await refreshRequestToken();
        connectEvents();
        return api(path, {...options, requestTokenRetried: true});
      }
      throw error;
    }
    return payload;
  } catch (error) {
    if (error?.name === "AbortError") {
      if (!timedOut && options.signal?.aborted) {
        throw new ApiError("请求已取消", {code: "request_cancelled"});
      }
      throw new ApiError("请求超时，请检查本地服务后重试", {code: "request_timeout"});
    }
    throw error;
  } finally {
    window.clearTimeout(timer);
  }
}

function isMigrationError(error) {
  const code = safeString(error?.code).toLowerCase();
  const message = safeString(error?.message).toLowerCase();
  return error?.status === 503 && (code.includes("migration") || message.includes("迁移") || message.includes("cleanup"));
}

function setConnection(connectionState, label) {
  const container = byId("connection-status");
  container.dataset.state = connectionState;
  byId("connection-label").textContent = label;
}

function showToast(message, level = "info") {
  const region = byId("toast-region");
  const toast = element("div", {className: "toast", text: message, dataset: {level}});
  region.append(toast);
  while (region.children.length > 3) region.firstElementChild.remove();
  window.setTimeout(() => toast.remove(), 3600);
}

function showMigrationBlocked(message, migration = null) {
  state.migrationBlocked = true;
  state.migration = migration || state.migration;
  byId("migration-message").textContent = message || "普通操作已锁定，完成清理后即可继续。";
  byId("migration-banner").hidden = false;
}

function clearMigrationBlocked() {
  state.migrationBlocked = false;
  byId("migration-banner").hidden = true;
}

function ensureMutable() {
  if (!state.migrationBlocked) return true;
  showToast("迁移清理完成前不能修改数据", "error");
  return false;
}

function currentViewFromHash() {
  const candidate = window.location.hash.replace(/^#/, "");
  return VIEW_NAMES.has(candidate) ? candidate : "spaces";
}

function selectView(viewName) {
  state.view = VIEW_NAMES.has(viewName) ? viewName : "spaces";
  for (const view of document.querySelectorAll("[data-view]")) {
    const active = view.dataset.view === state.view;
    view.classList.toggle("is-active", active);
    view.hidden = !active;
  }
  for (const link of document.querySelectorAll("[data-view-link]")) {
    const active = link.dataset.viewLink === state.view;
    link.classList.toggle("is-active", active);
    if (active) link.setAttribute("aria-current", "page");
    else link.removeAttribute("aria-current");
  }
}

function formatDate(value) {
  if (!value) return "-";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? safeString(value) : dateTimeFormatter.format(date);
}

function formatTime(value) {
  if (!value) return "--:--:--";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? "--:--:--" : timeFormatter.format(date);
}

function formatDuration(run) {
  const direct = Number(firstValue(run, ["duration_seconds", "duration"], 0));
  if (Number.isFinite(direct) && direct > 0) return `${numberFormatter.format(Math.round(direct))} 秒`;
  const start = new Date(firstValue(run, ["started_at", "created_at"], ""));
  const end = new Date(firstValue(run, ["finished_at", "updated_at"], ""));
  if (Number.isNaN(start.getTime()) || Number.isNaN(end.getTime())) return "-";
  const seconds = Math.max(0, Math.round((end.getTime() - start.getTime()) / 1000));
  return `${numberFormatter.format(seconds)} 秒`;
}

function shortId(value) {
  const text = safeString(value, "-");
  return text.length > 16 ? `${text.slice(0, 8)}…${text.slice(-4)}` : text;
}

function workspaceId(workspace) {
  return safeString(firstValue(workspace, ["id", "workspace_id"]));
}

function workspaceUid(workspace) {
  return safeString(firstValue(workspace, ["workspace_uid", "uid", "external_id"]), "-");
}

function workspaceName(workspace) {
  return safeString(firstValue(workspace, ["name", "workspace_name"], "未命名空间"));
}

function accountId(account) {
  return safeString(firstValue(account, ["id", "account_id"]));
}

function accountEmail(account) {
  return safeString(firstValue(account, ["email", "account_email", "primary_email"], "未提供邮箱"));
}

function runId(run) {
  return safeString(firstValue(run, ["id", "run_id"]));
}

function findAccount(id) {
  return state.accounts.find((account) => accountId(account) === safeString(id));
}

function findWorkspace(id) {
  return state.workspaces.find((workspace) => workspaceId(workspace) === safeString(id));
}

function workspaceAccountLabel(workspace, role) {
  const nested = workspace?.[`${role}_account`];
  if (nested && typeof nested === "object") return accountEmail(nested);
  const explicit = firstValue(workspace, [`${role}_email`, `${role}_account_email`]);
  if (explicit) return safeString(explicit);
  const id = firstValue(workspace, [`${role}_account_id`]);
  const account = findAccount(id);
  return account ? accountEmail(account) : "未分配";
}

function workspaceSearchText(workspace) {
  return [
    workspaceName(workspace),
    workspaceUid(workspace),
    workspaceAccountLabel(workspace, "current"),
    workspaceAccountLabel(workspace, "next"),
    safeString(firstValue(workspace, ["owner_email"])),
  ].join(" ").toLocaleLowerCase("zh-CN");
}

function pendingIcloudTeamOwners() {
  return state.icloudTeamOwners.filter(
    (owner) => owner.state === "active" && !owner.workspace_id,
  );
}

function availableChildrenForOwner(ownerId) {
  return state.accounts.filter((account) => (
    safeString(account.icloud_owner_alias_id) === safeString(ownerId)
    && safeString(account.status) === "available"
    && !account.icloud_used_at
  ));
}

function workspaceMatchesTeamFilter(workspace) {
  const filter = state.filters.workspaceStatus;
  const status = safeString(firstValue(workspace, ["status", "state"]));
  if (filter === "all") return true;
  if (filter === "ready") {
    return Boolean(workspace.owner_alias_id) && ["needs_account", "ready"].includes(status);
  }
  if (filter === "needs_account") {
    return !workspace.owner_alias_id || !booleanValue(workspace.owner_proxy_configured);
  }
  return status === filter;
}

function filteredWorkspaces() {
  const search = state.filters.workspaceSearch.trim().toLocaleLowerCase("zh-CN");
  return state.workspaces.filter((workspace) => {
    return workspaceMatchesTeamFilter(workspace)
      && (!search || workspaceSearchText(workspace).includes(search));
  });
}

function loadingOrErrorRow(columnCount, resource, emptyMessage) {
  const error = state.errors[resource];
  const row = element("tr", {className: error ? "error-row" : "empty-row"});
  const cell = element("td", {
    text: error ? `${error}。请刷新页面或检查本地服务。` : emptyMessage,
    attrs: {colspan: columnCount},
  });
  row.append(cell);
  return row;
}

function labeledCell(label, child, className = "") {
  const cell = element("td", {className, attrs: {"data-label": label}});
  if (child instanceof Node) cell.append(child);
  else cell.textContent = safeString(child, "-");
  return cell;
}

function primarySecondary(primary, secondary = "") {
  const wrap = element("div");
  wrap.append(element("span", {className: "cell-primary", text: primary}));
  if (secondary) wrap.append(element("span", {className: "cell-secondary", text: secondary}));
  return wrap;
}

function renderWorkspaceMetrics() {
  const pendingOwners = pendingIcloudTeamOwners();
  const counts = {
    total: state.workspaces.length + pendingOwners.length,
    ready: 0,
    needs: pendingOwners.length,
    attention: 0,
  };
  for (const workspace of state.workspaces) {
    const status = safeString(firstValue(workspace, ["status", "state"]));
    if (workspace.owner_alias_id && ["needs_account", "ready"].includes(status)) counts.ready += 1;
    if (!workspace.owner_alias_id || !booleanValue(workspace.owner_proxy_configured)) counts.needs += 1;
    if (status === "failed" || status === "paused") counts.attention += 1;
  }
  byId("metric-total").textContent = numberFormatter.format(counts.total);
  byId("metric-ready").textContent = numberFormatter.format(counts.ready);
  byId("metric-needs-account").textContent = numberFormatter.format(counts.needs);
  byId("metric-attention").textContent = numberFormatter.format(counts.attention);
}

function renderWorkspaceTable() {
  renderWorkspaceMetrics();
  const body = byId("workspace-table-body");
  const visible = filteredWorkspaces();
  const search = state.filters.workspaceSearch.trim().toLocaleLowerCase("zh-CN");
  const pendingOwners = pendingIcloudTeamOwners().filter((owner) => {
    if (!["all", "needs_account"].includes(state.filters.workspaceStatus)) return false;
    const children = availableChildrenForOwner(owner.id);
    const text = [
      owner.label,
      owner.email,
      ...children.map(accountEmail),
    ].join(" ").toLocaleLowerCase("zh-CN");
    return !search || text.includes(search);
  });

  body.replaceChildren();
  if (!visible.length && !pendingOwners.length) {
    body.append(loadingOrErrorRow(7, "workspaces", state.workspaces.length || state.icloudTeamOwners.length ? "没有符合筛选条件的 Team" : "尚未导入 Team"));
  } else {
    const fragment = document.createDocumentFragment();
    for (const owner of pendingOwners) {
      const children = availableChildrenForOwner(owner.id);
      const candidate = children.length === 1 ? accountEmail(children[0]) : "待选择";
      const row = element("tr", {dataset: {icloudOwnerId: safeString(owner.id)}});
      row.append(labeledCell("Team", primarySecondary("待建立 Team", safeString(owner.label))));
      row.append(labeledCell("母号", primarySecondary(safeString(owner.email), owner.proxy_configured ? "链路已配置" : "链路未配置")));
      row.append(labeledCell("Workspace ID", element("span", {className: "empty-value", text: "待填写"})));
      row.append(labeledCell("当前子号", element("span", {className: candidate === "待选择" ? "empty-value" : "cell-primary", text: candidate, attrs: {title: candidate}})));
      row.append(labeledCell("换班统计", primarySecondary("尚未接力", `已用完 ${numberFormatter.format(Number(owner.used_child_count || 0))}`)));
      row.append(labeledCell("状态 / 最近运行", statusBadge("setup", TEAM_STATUS)));
      const actions = element("div", {className: "row-actions"});
      actions.append(actionButton("继续导入", "open-icloud-team-import", {ownerId: owner.id}, "button button--primary button--small"));
      row.append(labeledCell("操作", actions, "actions-cell"));
      fragment.append(row);
    }
    for (const workspace of visible) {
      const id = workspaceId(workspace);
      const status = safeString(firstValue(workspace, ["status", "state"], "needs_account"));
      const row = element("tr", {dataset: {workspaceId: id}});

      const rotationCount = Number(firstValue(workspace, ["rotation_count"], 0));
      const ownerEmail = safeString(firstValue(workspace, ["owner_email"]));
      row.append(labeledCell("Team", primarySecondary(
        workspaceName(workspace),
        ownerEmail ? "2 人硬上限" : "通用空间",
      )));
      row.append(labeledCell("母号", ownerEmail
        ? primarySecondary(ownerEmail, booleanValue(workspace.owner_proxy_configured) ? "链路已配置" : "链路未配置")
        : element("span", {className: "empty-value", text: "未绑定"})));

      const uid = workspaceUid(workspace);
      const uidNode = element("span", {className: "cell-code", text: shortId(uid), attrs: {title: uid}});
      row.append(labeledCell("Workspace ID", uidNode));

      const current = workspaceAccountLabel(workspace, "current");
      const next = workspaceAccountLabel(workspace, "next");
      row.append(labeledCell("当前子号", element("span", {className: current === "未分配" ? "empty-value" : "cell-primary", text: current, attrs: {title: current}})));
      row.append(labeledCell("换班统计", primarySecondary(
        `接力 ${numberFormatter.format(rotationCount)} 次`,
        `已用完 ${numberFormatter.format(Number(workspace.used_child_count || 0))}`,
      )));

      const lastRunId = safeString(firstValue(workspace, ["last_run_id"]));
      const lastRunRecord = state.runs.find((run) => runId(run) === lastRunId);
      const lastState = safeString(
        firstValue(
          workspace,
          ["last_run_state", "last_state", "last_result"],
          firstValue(lastRunRecord, ["state", "status"]),
        ),
      );
      const lastTime = firstValue(
        workspace,
        ["last_run_at", "last_finished_at"],
        firstValue(lastRunRecord, ["finished_at", "updated_at"], firstValue(workspace, ["updated_at"])),
      );
      const stateAndRun = element("div", {className: "team-state-cell"}, [
        statusBadge(
          status,
          ownerEmail && lastRunRecord && runKindLabel(lastRunRecord) === "母号提拉"
            ? {
              ...TEAM_STATUS,
              queued: ["提拉排队", "accent"],
              running: ["提拉中", "info"],
              failed: ["提拉失败", "danger"],
            }
            : ownerEmail ? TEAM_STATUS : WORKSPACE_STATUS,
        ),
        element("span", {className: "cell-secondary", text: lastState ? `${RUN_STATUS[lastState]?.[0] || lastState} · ${formatDate(lastTime)}` : "尚未运行"}),
      ]);
      const lastError = safeString(firstValue(workspace, ["last_error", "redacted_error"]));
      if (lastError) stateAndRun.append(element("span", {className: "cell-error", text: lastError, attrs: {title: lastError}}));
      row.append(labeledCell("状态 / 最近运行", stateAndRun));

      const actions = element("div", {className: "row-actions"});
      if (workspace.owner_alias_id) {
        if (["needs_account", "ready"].includes(status)) {
          actions.append(actionButton("一键换班", "replace-icloud-child", {workspaceId: id}, "button button--primary button--small"));
        }
        if (status === "failed") {
          const failedKind = safeString(firstValue(lastRunRecord, ["kind"]), "handoff");
          actions.append(actionButton(
            failedKind === "rescue" ? "重试提拉" : "重试换班",
            "retry-workspace",
            {workspaceId: id},
            "button button--primary button--small",
          ));
        }
        actions.append(actionButton("编辑配置", "open-icloud-owner-proxy", {aliasId: safeString(workspace.owner_alias_id)}));
        if (!["queued", "running"].includes(status)) {
          actions.append(actionButton("提拉", "rescue-icloud-child", {workspaceId: id}, "text-action text-action--danger"));
        }
      } else {
        if (status === "ready" && next !== "未分配") {
          actions.append(actionButton("额度用完", "advance-workspace", {workspaceId: id}));
        }
        if (status === "failed") actions.append(actionButton("重试", "retry-workspace", {workspaceId: id}));
        actions.append(actionButton("编辑", "edit-workspace", {workspaceId: id}));
      }
      if (lastRunId) actions.append(actionButton("详情", "open-run-detail", {runId: lastRunId}));
      row.append(labeledCell("操作", actions, "actions-cell"));
      fragment.append(row);
    }
    body.append(fragment);
  }
}

function accountBindingLabel(account) {
  const binding = accountBinding(account);
  return binding ? workspaceName(binding.workspace) : "未绑定";
}

function accountBinding(account) {
  const direct = firstValue(account, ["workspace_name", "bound_workspace_name"]);
  const directId = firstValue(account, ["workspace_id", "bound_workspace_id"]);
  const directRole = safeString(firstValue(account, ["workspace_role", "bound_role", "role"]));
  if (directId) {
    const workspace = findWorkspace(directId);
    if (workspace) return {workspace, role: directRole || (safeString(workspace.current_account_id) === accountId(account) ? "current" : "next")};
  }
  const accountIdentifier = accountId(account);
  const workspace = state.workspaces.find((candidate) => {
    return safeString(candidate.current_account_id) === accountIdentifier || safeString(candidate.next_account_id) === accountIdentifier;
  });
  if (workspace) {
    return {
      workspace,
      role: safeString(workspace.current_account_id) === accountIdentifier ? "current" : "next",
    };
  }
  if (direct) return {workspace: {name: safeString(direct), id: safeString(directId)}, role: directRole};
  return null;
}

function renderAccountMetrics() {
  let available = 0;
  let pending = 0;
  let used = 0;
  let bound = 0;
  for (const account of state.accounts) {
    const status = safeString(firstValue(account, ["status", "state"]));
    if (status === "available") available += 1;
    if (status === "exited_pending") pending += 1;
    if (account.icloud_used_at) used += 1;
    if (status === "bound_current" || status === "bound_next") bound += 1;
  }
  byId("account-metric-total").textContent = numberFormatter.format(state.accounts.length);
  byId("account-metric-available").textContent = numberFormatter.format(available);
  byId("account-metric-pending").textContent = numberFormatter.format(pending);
  byId("account-metric-used").textContent = numberFormatter.format(used);
  byId("account-metric-bound").textContent = numberFormatter.format(bound);
}

function accountDisplayStatus(account) {
  return account?.icloud_used_at ? "used" : safeString(firstValue(account, ["status", "state"], "available"));
}

function filteredAccounts() {
  const search = state.filters.accountSearch.trim().toLocaleLowerCase("zh-CN");
  return state.accounts.filter((account) => {
    const status = accountDisplayStatus(account);
    const statusMatch = state.filters.accountStatus === "all" || status === state.filters.accountStatus;
    const haystack = `${accountEmail(account)} ${safeString(account.primary_email)} ${accountBindingLabel(account)}`.toLocaleLowerCase("zh-CN");
    return statusMatch && (!search || haystack.includes(search));
  });
}

function accountPageSize() {
  return window.matchMedia("(max-width: 820px)").matches ? MOBILE_ACCOUNT_PAGE_SIZE : ACCOUNT_PAGE_SIZE;
}

function renderAccountTable() {
  renderAccountMetrics();
  const body = byId("account-table-body");
  const visible = filteredAccounts();
  const pageSize = accountPageSize();
  const totalPages = Math.max(1, Math.ceil(visible.length / pageSize));
  state.accountPage = Math.min(Math.max(1, state.accountPage), totalPages);
  const startIndex = (state.accountPage - 1) * pageSize;
  const pageAccounts = visible.slice(startIndex, startIndex + pageSize);
  body.replaceChildren();
  if (!pageAccounts.length) {
    body.append(loadingOrErrorRow(8, "accounts", state.accounts.length ? "没有符合筛选条件的账号" : "尚未分配任何子号"));
  } else {
    const fragment = document.createDocumentFragment();
    for (const account of pageAccounts) {
      const id = accountId(account);
      const rawStatus = safeString(firstValue(account, ["status", "state"], "available"));
      const status = accountDisplayStatus(account);
      const row = element("tr", {dataset: {accountId: id}});
      const email = accountEmail(account);
      row.append(labeledCell("邮箱", element("span", {className: "cell-primary", text: email, attrs: {title: email}})));
      row.append(labeledCell("主邮箱", element("span", {className: "cell-secondary", text: safeString(account.primary_email, email), attrs: {title: safeString(account.primary_email, email)}})));
      row.append(labeledCell("状态", statusBadge(status, ACCOUNT_STATUS)));
      row.append(labeledCell("代理", statusBadge(account.proxy_configured ? "configured" : "inherited", PROXY_STATUS)));
      row.append(labeledCell("绑定空间", accountBindingLabel(account)));
      const source = safeString(firstValue(account, ["source"], "import"));
      const sourceLabel = source === "icloud_hme"
        ? `iCloud HME${account.icloud_owner_email ? ` · ${safeString(account.icloud_owner_email)}` : ""}`
        : source;
      row.append(labeledCell("来源", sourceLabel));
      row.append(labeledCell("更新时间", formatDate(firstValue(account, ["updated_at", "created_at"]))));
      const actions = element("div", {className: "row-actions"});
      const binding = accountBinding(account);
      const refreshing = state.pendingAccountRefreshIds.has(id) || (
        safeString(state.queue.credentialRefresh?.state) === "running"
        && safeString(state.queue.credentialRefresh?.account_id) === id
      );
      const appendRefreshAction = (mode) => {
        const refreshButton = actionButton(
          refreshing ? "刷新中…" : "刷新",
          "refresh-imported-child",
          {accountId: id, refreshMode: mode},
        );
        refreshButton.disabled = refreshing;
        if (refreshing) refreshButton.setAttribute("aria-busy", "true");
        actions.append(refreshButton);
      };
      if (
        source === "icloud_hme"
        && safeString(account.icloud_role) === "rotating_child"
      ) {
        if (rawStatus === "bound_current") {
          appendRefreshAction("current");
        } else if (rawStatus === "bound_next" && safeString(binding?.workspace?.status) === "failed") {
          appendRefreshAction("failed-next");
        }
      }
      if (status !== "used") actions.append(actionButton("代理", "open-account-proxy", {accountId: id}));
      if (binding && ["bound_current", "bound_next"].includes(rawStatus)) {
        actions.append(actionButton("不可用", "invalidate-bound-account", {
          accountId: id,
          failureType: "alias_disabled",
        }));
        actions.append(actionButton("封禁邮箱", "invalidate-bound-account", {
          accountId: id,
          failureType: "mailbox_credentials_invalid",
        }, "text-action text-action--danger"));
      } else if (rawStatus === "exited_pending" || rawStatus === "disabled") {
        actions.append(actionButton("重新启用", "set-account-status", {accountId: id, status: "available"}));
      }
      if (!binding && (rawStatus === "exited_pending" || rawStatus === "available")) {
        actions.append(actionButton("退役", "set-account-status", {accountId: id, status: "retired"}, "text-action text-action--danger"));
      }
      if (!binding && rawStatus === "available") {
        actions.append(actionButton("停用", "set-account-status", {accountId: id, status: "disabled"}));
      }
      if (!actions.children.length) actions.append(element("span", {className: "empty-value", text: "-"}));
      row.append(labeledCell("操作", actions, "actions-cell"));
      fragment.append(row);
    }
    body.append(fragment);
  }

  const visibleStart = visible.length ? startIndex + 1 : 0;
  const visibleEnd = Math.min(startIndex + pageAccounts.length, visible.length);
  byId("account-page-summary").textContent = `第 ${numberFormatter.format(visibleStart)}-${numberFormatter.format(visibleEnd)} 条，共 ${numberFormatter.format(visible.length)} 条`;
  byId("account-page-indicator").textContent = `${numberFormatter.format(state.accountPage)} / ${numberFormatter.format(totalPages)}`;
  document.querySelector('[data-action="account-page-prev"]').disabled = state.accountPage <= 1;
  document.querySelector('[data-action="account-page-next"]').disabled = state.accountPage >= totalPages;
}

function changeAccountPage(delta) {
  const totalPages = Math.max(1, Math.ceil(filteredAccounts().length / accountPageSize()));
  const nextPage = Math.min(Math.max(1, state.accountPage + delta), totalPages);
  if (nextPage === state.accountPage) return;
  state.accountPage = nextPage;
  renderAccountTable();
  byId("view-accounts").querySelector(".table-toolbar").scrollIntoView({block: "start"});
}

function inventoryId(item) {
  return safeString(firstValue(item, ["id", "inventory_id"]));
}

function inventoryEmail(item) {
  return safeString(firstValue(item, ["primary_email", "email"], "未知邮箱"));
}

function inventoryAliasNumber(item) {
  return Number(firstValue(item, ["next_alias_number", "next_alias"], 0));
}

function inventoryAliasEmail(item) {
  const primary = inventoryEmail(item);
  const aliasNumber = inventoryAliasNumber(item);
  const at = primary.lastIndexOf("@");
  if (at <= 0 || aliasNumber < 1 || aliasNumber > 5) return "无可分配子号";
  return `${primary.slice(0, at)}+${aliasNumber}${primary.slice(at)}`;
}

function renderAccountView() {
  const used = state.accountView === "used";
  const inventory = state.accountView === "inventory";
  const icloud = state.accountView === "icloud";
  byId("account-used-panel").hidden = !used;
  byId("account-inventory-panel").hidden = !inventory;
  byId("account-icloud-panel").hidden = !icloud;
  for (const tab of document.querySelectorAll("[data-account-view]")) {
    const active = tab.dataset.accountView === state.accountView;
    tab.classList.toggle("is-active", active);
    tab.setAttribute("aria-selected", String(active));
    tab.tabIndex = active ? 0 : -1;
  }
  if (used) renderAccountTable();
  else if (inventory) renderInventoryTable();
  else renderIcloudMailboxTable();
}

function selectAccountView(view) {
  state.accountView = ["used", "inventory", "icloud"].includes(view) ? view : "used";
  if (state.accountView !== "inventory") {
    cancelInventorySearch();
  }
  if (state.accountView === "inventory" && state.inventoryDirty && state.inventoryQuery.trim()) {
    scheduleInventorySearch({immediate: true});
  }
  if (state.accountView === "icloud" && !state.icloudMailboxesLoaded) {
    void loadIcloudMailboxes();
  }
  renderAccountView();
}

function icloudMailboxId(mailbox) {
  return safeString(firstValue(mailbox, ["id", "mailbox_id"]));
}

function findIcloudMailbox(id) {
  return state.icloudMailboxes.find((mailbox) => icloudMailboxId(mailbox) === safeString(id));
}

async function loadIcloudTeamOwners() {
  const payload = await api("/api/icloud-team-owners");
  state.icloudTeamOwners = asList(payload, ["owners", "icloud_team_owners"]);
  return state.icloudTeamOwners;
}

async function loadProxyChainConfig() {
  const payload = await api("/api/proxy-chains/nodes");
  state.proxyChainNodes = asList(payload, ["nodes"])
    .map((value) => safeString(value))
    .filter(Boolean);
  state.sharedClashProxy = safeString(
    firstValue(payload, ["local_proxy"]),
    state.proxyChainNodes[0] || DEFAULT_LOCAL_CLASH_PROXY,
  );
  return payload;
}

function icloudTeamImportForm() {
  return byId("icloud-team-import-form");
}

function selectedIcloudTeamImportAlias(field) {
  const form = icloudTeamImportForm();
  const email = safeString(form.elements.namedItem(field)?.value).toLowerCase();
  return state.icloudTeamImportAliases.find(
    (item) => safeString(item.email).toLowerCase() === email.toLowerCase(),
  );
}

function icloudTeamImportDraft(form = icloudTeamImportForm()) {
  const values = {};
  for (const name of [
    "name",
    "workspace_uid",
    "mailbox_id",
    "owner_email",
    "current_child_email",
    "owner_proxy",
    "owner_proxy_source_url",
    "owner_proxy_bootstrap",
  ]) {
    values[name] = safeString(form.elements.namedItem(name)?.value);
  }
  return {
    values,
    ownerId: safeString(form.dataset.pendingOwnerId),
    proxyMode: state.icloudTeamImportProxyMode,
  };
}

function renderIcloudTeamImportMailboxOptions(selected = "") {
  const select = icloudTeamImportForm().elements.namedItem("mailbox_id");
  const previous = safeString(selected || select.value);
  select.replaceChildren(element("option", {text: "选择 iCloud", attrs: {value: ""}}));
  for (const mailbox of state.icloudMailboxes) {
    const status = safeString(mailbox.status, "unchecked");
    select.append(element("option", {
      text: `${safeString(mailbox.name)} · ${ICLOUD_MAILBOX_STATUS[status]?.[0] || status}`,
      attrs: {value: icloudMailboxId(mailbox), disabled: status === "disabled"},
    }));
  }
  select.value = previous;
  if (!select.value && state.icloudMailboxes.length === 1) {
    select.value = icloudMailboxId(state.icloudMailboxes[0]);
  }
}

function setIcloudTeamImportProxyMode() {
  state.icloudTeamImportProxyMode = CHAIN_PROXY_MODE;
  const form = icloudTeamImportForm();
  form.elements.namedItem("owner_proxy_mode").value = state.icloudTeamImportProxyMode;
  updateIcloudTeamImportSubmitState();
}

function eligibleIcloudTeamOwners() {
  return state.icloudTeamImportAliases.filter((item) => (
    Boolean(item.active)
    && (!item.imported || item.imported_role === "team_owner")
    && !item.workspace_id
  ));
}

function eligibleIcloudTeamChildren(ownerEmail) {
  const normalizedOwner = safeString(ownerEmail).toLowerCase();
  return state.icloudTeamImportAliases.filter((item) => {
    if (!item.active || safeString(item.email).toLowerCase() === normalizedOwner) return false;
    if (item.workspace_id) return false;
    if (!item.imported) return true;
    if (item.imported_role !== "rotating_child") return false;
    if (item.used_at || safeString(item.account_status, "available") !== "available") return false;
    const parent = safeString(item.parent_owner_email).toLowerCase();
    return !parent || parent === normalizedOwner;
  });
}

function renderIcloudTeamImportSelectors({preferredOwner = "", preferredChild = ""} = {}) {
  const form = icloudTeamImportForm();
  const ownerSelect = form.elements.namedItem("owner_email");
  const childSelect = form.elements.namedItem("current_child_email");
  const oldOwner = safeString(preferredOwner || ownerSelect.value);
  const oldChild = safeString(preferredChild || childSelect.value);
  const owners = eligibleIcloudTeamOwners();
  ownerSelect.replaceChildren(element("option", {text: "选择 Team 母号", attrs: {value: ""}}));
  for (const item of owners) {
    ownerSelect.append(element("option", {
      text: `${safeString(item.label, item.email)} · ${safeString(item.email)}${item.imported ? " · 已接管" : ""}`,
      attrs: {value: safeString(item.email)},
    }));
  }
  ownerSelect.disabled = !owners.length;
  ownerSelect.value = oldOwner;
  if (!ownerSelect.value && owners.length === 1) ownerSelect.value = safeString(owners[0].email);

  const children = eligibleIcloudTeamChildren(ownerSelect.value);
  childSelect.replaceChildren(element("option", {text: "选择当前子号", attrs: {value: ""}}));
  for (const item of children) {
    childSelect.append(element("option", {
      text: `${safeString(item.label, item.email)} · ${safeString(item.email)}${item.imported ? " · 已接管" : ""}`,
      attrs: {value: safeString(item.email)},
    }));
  }
  childSelect.disabled = !ownerSelect.value || !children.length;
  childSelect.value = oldChild;
  if (!childSelect.value && children.length === 1) childSelect.value = safeString(children[0].email);
  updateIcloudTeamImportSubmitState();
}

function renderIcloudTeamImportSnapshot() {
  const body = byId("icloud-team-alias-table-body");
  body.replaceChildren();
  if (state.icloudTeamImportLoading) {
    body.append(element("tr", {className: "loading-row"}, [
      element("td", {attrs: {colspan: "4"}}, [
        element("span", {className: "inline-loader", attrs: {"aria-hidden": "true"}}),
        "正在读取 iCloud Alias…",
      ]),
    ]));
    return;
  }
  if (!state.icloudTeamImportAliases.length) {
    body.append(element("tr", {className: "empty-row"}, [
      element("td", {text: "尚未读取 iCloud", attrs: {colspan: "4"}}),
    ]));
    return;
  }
  const fragment = document.createDocumentFragment();
  for (const item of state.icloudTeamImportAliases) {
    const row = element("tr");
    row.append(labeledCell("隐藏邮箱", element("span", {className: "cell-primary", text: safeString(item.email), attrs: {title: safeString(item.email)}})));
    row.append(labeledCell("标签", element("span", {className: "cell-secondary", text: safeString(item.label, "-")})));
    row.append(labeledCell("远端", statusBadge(item.active ? "active" : "inactive", ICLOUD_ALIAS_STATUS)));
    let localPrimary = "未接管";
    let localSecondary = "仅展示，不会自动导入";
    if (item.imported) {
      localPrimary = item.imported_role === "team_owner" ? "已接管母号" : "已接管子号";
      localSecondary = safeString(item.workspace_name)
        || (item.parent_owner_email ? `归属 ${safeString(item.parent_owner_email)}` : "尚未建立 Team");
    }
    row.append(labeledCell("本地状态", primarySecondary(localPrimary, localSecondary)));
    fragment.append(row);
  }
  body.append(fragment);
}

function updateIcloudTeamImportSubmitState() {
  const form = icloudTeamImportForm();
  const submit = byId("icloud-team-import-submit");
  const owner = selectedIcloudTeamImportAlias("owner_email");
  const source = safeString(form.elements.namedItem("owner_proxy_source_url").value).trim();
  const savedProxy = Boolean(owner?.proxy_configured);
  const proxyReady = savedProxy || Boolean(source);
  byId("icloud-team-import-proxy-status").textContent = savedProxy
    ? (source ? "将更新已保存链路" : "已配置，可留空复用")
    : proxyReady ? "待保存" : "未配置";
  const workspaceUid = safeString(form.elements.namedItem("workspace_uid").value).trim();
  submit.disabled = state.icloudTeamImportLoading || !(
    safeString(form.elements.namedItem("name").value).trim()
    && safeString(form.elements.namedItem("mailbox_id").value)
    && safeString(form.elements.namedItem("owner_email").value)
    && safeString(form.elements.namedItem("current_child_email").value)
    && proxyReady
  );
  if (!state.icloudTeamImportLoading) {
    submit.textContent = workspaceUid ? "导入 Team" : "识别并导入";
  }
}

function resetIcloudTeamWorkspaceLookup() {
  const form = icloudTeamImportForm();
  form.elements.namedItem("workspace_uid").value = "";
  byId("icloud-team-workspace-status").textContent = "待识别";
}

async function openIcloudTeamImport(ownerId = "", {draft = null, autoLoad = false} = {}) {
  if (!ensureMutable()) return;
  await Promise.all([
    loadIcloudMailboxes(),
    loadIcloudTeamOwners(),
    loadProxyChainConfig(),
  ]);
  const form = icloudTeamImportForm();
  form.reset();
  fieldError("icloud-team-import-error", "");
  state.icloudTeamImportAliases = [];
  state.icloudTeamImportMailboxId = "";
  state.icloudTeamImportLoading = false;
  form.dataset.pendingOwnerId = safeString(ownerId || draft?.ownerId);
  const owner = findIcloudTeamOwner(form.dataset.pendingOwnerId);
  const values = draft?.values || {};
  form.elements.namedItem("name").value = safeString(values.name || owner?.label || "");
  form.elements.namedItem("workspace_uid").value = safeString(values.workspace_uid);
  byId("icloud-team-workspace-status").textContent = values.workspace_uid
    ? "已识别 · 2 人"
    : "待识别";
  renderIcloudTeamImportMailboxOptions(values.mailbox_id || owner?.mailbox_id || "");
  form.elements.namedItem("owner_proxy_bootstrap").value = safeString(
    values.owner_proxy_bootstrap,
    state.sharedClashProxy,
  );
  form.elements.namedItem("owner_proxy_source_url").value = safeString(values.owner_proxy_source_url);
  setIcloudTeamImportProxyMode();
  renderIcloudTeamImportSnapshot();
  renderIcloudTeamImportSelectors();
  byId("icloud-team-alias-count").textContent = "0 个";
  byId("icloud-team-import-status").textContent = "尚未读取";
  const dialog = byId("icloud-team-import-dialog");
  if (!dialog.open) dialog.showModal();
  if (autoLoad || owner) {
    await loadIcloudTeamImportAliases({
      preferredOwner: values.owner_email || owner?.email || "",
      preferredChild: values.current_child_email || "",
    });
  }
}

async function startIcloudTeamImportCapture(form = icloudTeamImportForm()) {
  const mailboxId = safeString(form.elements.namedItem("mailbox_id").value);
  const mailbox = findIcloudMailbox(mailboxId);
  if (!mailbox) throw new ApiError("请选择 iCloud 资源池", {code: "mailbox_missing"});
  state.pendingIcloudTeamImport = icloudTeamImportDraft(form);
  byId("icloud-team-import-dialog").close();
  await openIcloudHmeCapture(mailbox);
}

async function loadIcloudTeamImportAliases({preferredOwner = "", preferredChild = ""} = {}) {
  const form = icloudTeamImportForm();
  const mailboxId = safeString(form.elements.namedItem("mailbox_id").value);
  if (!mailboxId) {
    fieldError("icloud-team-import-error", "请选择 iCloud 资源池");
    return;
  }
  fieldError("icloud-team-import-error", "");
  state.icloudTeamImportLoading = true;
  state.icloudTeamImportAliases = [];
  state.icloudTeamImportMailboxId = mailboxId;
  renderIcloudTeamImportSnapshot();
  updateIcloudTeamImportSubmitState();
  byId("icloud-team-import-status").textContent = "正在读取…";
  try {
    const payload = await api(`/api/icloud-mailboxes/${encodeURIComponent(mailboxId)}/remote-aliases`, {timeout: 45000});
    state.icloudTeamImportAliases = asList(payload, ["aliases", "remote_aliases"]);
    state.icloudTeamImportLoading = false;
    renderIcloudTeamImportSnapshot();
    renderIcloudTeamImportSelectors({preferredOwner, preferredChild});
    const count = state.icloudTeamImportAliases.length;
    byId("icloud-team-alias-count").textContent = `${numberFormatter.format(count)} 个`;
    byId("icloud-team-import-status").textContent = `已读取 ${numberFormatter.format(count)} 个 Alias`;
    state.pendingIcloudTeamImport = null;
  } catch (error) {
    state.icloudTeamImportLoading = false;
    renderIcloudTeamImportSnapshot();
    updateIcloudTeamImportSubmitState();
    if (error?.code === "icloud_session_invalid") {
      await startIcloudTeamImportCapture(form);
      return;
    }
    byId("icloud-team-import-status").textContent = "读取失败";
    fieldError("icloud-team-import-error", error?.message || String(error));
    throw error;
  }
}

async function handleIcloudTeamImport(form) {
  if (!ensureMutable()) return;
  fieldError("icloud-team-import-error", "");
  const owner = selectedIcloudTeamImportAlias("owner_email");
  const mode = CHAIN_PROXY_MODE;
  const source = safeString(form.elements.namedItem("owner_proxy_source_url").value).trim();
  const shouldConfigureProxy = !owner?.proxy_configured || Boolean(source);
  const body = {
    mailbox_id: safeString(form.elements.namedItem("mailbox_id").value),
    name: safeString(form.elements.namedItem("name").value).trim(),
    workspace_uid: safeString(form.elements.namedItem("workspace_uid").value).trim(),
    owner_email: safeString(form.elements.namedItem("owner_email").value),
    current_child_email: safeString(form.elements.namedItem("current_child_email").value),
    owner_proxy_mode: shouldConfigureProxy ? mode : null,
    owner_proxy: "",
    owner_proxy_source_url: shouldConfigureProxy ? source : "",
    owner_proxy_bootstrap: shouldConfigureProxy
      ? safeString(form.elements.namedItem("owner_proxy_bootstrap").value).trim()
      : "",
  };
  state.icloudTeamImportLoading = true;
  updateIcloudTeamImportSubmitState();
  try {
    if (!body.workspace_uid) {
      byId("icloud-team-workspace-status").textContent = "正在识别…";
      byId("icloud-team-import-submit").textContent = "正在识别 Team…";
      const lookup = await api("/api/icloud-teams/workspace/lookup", {
        method: "POST",
        body: {
          mailbox_id: body.mailbox_id,
          owner_email: body.owner_email,
          current_child_email: body.current_child_email,
          owner_proxy_mode: body.owner_proxy_mode,
          owner_proxy: body.owner_proxy,
          owner_proxy_source_url: body.owner_proxy_source_url,
          owner_proxy_bootstrap: body.owner_proxy_bootstrap,
        },
        timeout: 180000,
      });
      const workspaceUid = safeString(lookup?.workspace_uid).trim();
      if (!workspaceUid || lookup?.verified !== true || Number(lookup?.member_count) !== 2) {
        throw new ApiError("Team 自动识别结果未通过两人校验", {code: "workspace_lookup_failed"});
      }
      body.workspace_uid = workspaceUid;
      form.elements.namedItem("workspace_uid").value = workspaceUid;
      byId("icloud-team-workspace-status").textContent = "已识别 · 2 人";
      byId("icloud-team-import-submit").textContent = "正在导入…";
    }
    const result = await api("/api/icloud-teams/import", {
      method: "POST",
      body,
      timeout: 60000,
    });
    byId("icloud-team-import-dialog").close();
    state.icloudTeamImportAliases = [];
    state.pendingIcloudTeamImport = null;
    state.icloudMailboxesLoaded = false;
    await Promise.all([
      loadIcloudTeamOwners(),
      loadIcloudMailboxes({force: true}),
      refreshResources(["workspaces", "accounts", "runs"]),
    ]);
    showToast(result.created ? "Team 已导入" : "Team 已存在，已复用原配置", "success");
  } catch (error) {
    if (error?.code === "icloud_session_invalid") {
      await startIcloudTeamImportCapture(form);
      return;
    }
    fieldError("icloud-team-import-error", error?.message || String(error));
    throw error;
  } finally {
    state.icloudTeamImportLoading = false;
    updateIcloudTeamImportSubmitState();
  }
}

function findIcloudTeamOwner(id) {
  return state.icloudTeamOwners.find((owner) => safeString(owner.id) === safeString(id));
}

async function loadIcloudMailboxes({force = false} = {}) {
  if (state.icloudMailboxesLoading) return;
  if (state.icloudMailboxesLoaded && !force) return;
  state.icloudMailboxesLoading = true;
  state.icloudMailboxesError = "";
  renderIcloudMailboxTable();
  try {
    const payload = await api("/api/icloud-mailboxes");
    state.icloudMailboxes = asList(payload, ["mailboxes", "icloud_mailboxes"]);
    state.icloudMailboxesLoaded = true;
  } catch (error) {
    state.icloudMailboxesError = error?.message || String(error);
  } finally {
    state.icloudMailboxesLoading = false;
    renderIcloudMailboxTable();
  }
}

function renderIcloudMailboxTable() {
  const body = byId("icloud-mailbox-table-body");
  const status = byId("icloud-mailbox-status");
  if (!body || !status) return;
  body.replaceChildren();
  if (state.icloudMailboxesLoading) {
    const row = element("tr", {className: "loading-row"});
    row.append(element("td", {attrs: {colspan: "8"}}, [
      element("span", {className: "inline-loader", attrs: {"aria-hidden": "true"}}),
      "正在载入 iCloud 资源池…",
    ]));
    body.append(row);
    status.textContent = "正在载入…";
    return;
  }
  if (state.icloudMailboxesError) {
    body.append(element("tr", {className: "error-row"}, [
      element("td", {text: state.icloudMailboxesError, attrs: {colspan: "8"}}),
    ]));
    status.textContent = "载入失败";
    return;
  }
  if (!state.icloudMailboxes.length) {
    body.append(element("tr", {className: "empty-row"}, [
      element("td", {text: "尚未添加 iCloud 资源池", attrs: {colspan: "8"}}),
    ]));
    status.textContent = "0 个资源池";
    return;
  }
  const fragment = document.createDocumentFragment();
  for (const mailbox of state.icloudMailboxes) {
    const id = icloudMailboxId(mailbox);
    const mailboxStatus = safeString(firstValue(mailbox, ["status"], "unchecked"));
    const name = safeString(firstValue(mailbox, ["name"], "未命名母号"));
    const forwarding = safeString(firstValue(mailbox, ["forwarding_email"], "-"));
    const failure = safeString(firstValue(mailbox, ["failure_message", "failure_code"]));
    const row = element("tr", {dataset: {icloudMailboxId: id}});
    row.append(labeledCell("资源池", primarySecondary(name, forwarding)));
    const statusCell = element("div", {}, [statusBadge(mailboxStatus, ICLOUD_MAILBOX_STATUS)]);
    if (failure) statusCell.append(element("span", {className: "cell-error", text: failure, attrs: {title: failure}}));
    row.append(labeledCell("状态", statusCell));
    row.append(labeledCell("受管 Alias", primarySecondary(
      numberFormatter.format(Number(mailbox.alias_count || 0)),
      `${numberFormatter.format(Number(mailbox.owner_count || 0))} 母号 · ${numberFormatter.format(Number(mailbox.used_count || 0))} 已用完`,
    )));
    row.append(labeledCell("HME Session", statusBadge(mailbox.session_configured ? "configured" : "missing", CONFIG_STATUS)));
    row.append(labeledCell("IMAP", statusBadge(mailbox.imap_configured ? "configured" : "missing", CONFIG_STATUS)));
    row.append(labeledCell("HME / IMAP S5", statusBadge(mailbox.proxy_configured ? "configured" : "missing", CONFIG_STATUS)));
    row.append(labeledCell("最近检测", formatDate(mailbox.last_checked_at)));
    const actions = element("div", {className: "row-actions"});
    const check = actionButton("检测", "check-icloud-mailbox", {mailboxId: id});
    check.disabled = mailboxStatus === "disabled";
    actions.append(check);
    const capture = actionButton("登录更新 HME", "open-icloud-hme-capture", {mailboxId: id});
    capture.disabled = mailboxStatus === "disabled";
    actions.append(capture);
    const sync = actionButton("同步 Alias", "open-icloud-sync", {mailboxId: id});
    sync.disabled = mailboxStatus !== "ready";
    actions.append(sync);
    const aliases = actionButton("Alias", "open-icloud-aliases", {mailboxId: id});
    aliases.disabled = Number(mailbox.alias_count || 0) < 1;
    actions.append(aliases);
    actions.append(actionButton("编辑", "open-icloud-mailbox", {mailboxId: id}));
    actions.append(actionButton(
      mailboxStatus === "disabled" ? "启用" : "停用",
      "toggle-icloud-mailbox",
      {mailboxId: id, status: mailboxStatus === "disabled" ? "unchecked" : "disabled"},
      mailboxStatus === "disabled" ? "text-action" : "text-action text-action--danger",
    ));
    row.append(labeledCell("操作", actions, "actions-cell"));
    fragment.append(row);
  }
  body.append(fragment);
  status.textContent = `${numberFormatter.format(state.icloudMailboxes.length)} 个资源池`;
}

function icloudSyncOwnerChoices() {
  const choices = new Map();
  for (const owner of state.icloudTeamOwners) {
    if (
      safeString(owner.mailbox_id) === state.activeIcloudMailboxId
      && owner.state === "active"
    ) {
      choices.set(safeString(owner.email), safeString(owner.email));
    }
  }
  for (const item of state.remoteIcloudAliases) {
    if (item.selectionRole === "team_owner") {
      choices.set(safeString(item.email), safeString(item.email));
    }
  }
  return [...choices.keys()].sort((left, right) => left.localeCompare(right));
}

function renderIcloudSyncRows() {
  const body = byId("icloud-sync-table-body");
  body.replaceChildren();
  if (!state.remoteIcloudAliases.length) {
    body.append(element("tr", {className: "empty-row"}, [
      element("td", {text: "iCloud 当前没有可同步的 Alias", attrs: {colspan: "7"}}),
    ]));
    return;
  }
  const ownerChoices = icloudSyncOwnerChoices();
  const fragment = document.createDocumentFragment();
  for (const item of state.remoteIcloudAliases) {
    const row = element("tr", {dataset: {icloudSyncEmail: safeString(item.email)}});
    row.append(labeledCell("隐藏邮箱", primarySecondary(safeString(item.email), safeString(item.label))));
    row.append(labeledCell("远端", statusBadge(item.active ? "active" : "inactive", ICLOUD_ALIAS_STATUS)));

    const roleSelect = element("select", {
      dataset: {icloudImportRole: safeString(item.email)},
      attrs: {"aria-label": `${safeString(item.email)} 接管角色`},
    }, [
      element("option", {text: "忽略", attrs: {value: "ignore"}}),
      element("option", {text: "Team 母号（仅归属）", attrs: {value: "team_owner"}}),
      element("option", {text: "当前子号", attrs: {value: "rotating_child"}}),
    ]);
    roleSelect.value = safeString(item.selectionRole, "ignore");
    roleSelect.disabled = Boolean(item.imported) || !item.active;
    row.append(labeledCell("接管为", roleSelect));

    const parentSelect = element("select", {
      dataset: {icloudParentOwner: safeString(item.email)},
      attrs: {"aria-label": `${safeString(item.email)} 归属母号`},
    }, [element("option", {text: "选择母号", attrs: {value: ""}})]);
    for (const ownerEmail of ownerChoices) {
      if (ownerEmail !== item.email) {
        parentSelect.append(element("option", {text: ownerEmail, attrs: {value: ownerEmail}}));
      }
    }
    parentSelect.value = safeString(item.parentOwnerEmail);
    parentSelect.disabled = item.selectionRole !== "rotating_child" || Boolean(item.imported);
    row.append(labeledCell("归属母号（被动锚点）", parentSelect));

    row.append(labeledCell("链路类型", primarySecondary("Clash 两跳", "共享第一跳")));

    const proxyInput = element("input", {
      dataset: {icloudOwnerProxy: safeString(item.email)},
      attrs: {
        type: "password",
        maxlength: "8192",
        placeholder: item.imported
          ? "已接管"
          : "代理 URL 或 curl 命令",
        autocomplete: "new-password",
        spellcheck: "false",
        "aria-label": `${safeString(item.email)} CliProxy 或代理链接`,
      },
    });
    proxyInput.value = safeString(item.ownerProxy);
    proxyInput.disabled = item.selectionRole !== "team_owner" || Boolean(item.imported);
    row.append(labeledCell("代理链接", proxyInput));

    const sharedClash = element("input", {
      attrs: {
        type: "text",
        value: state.sharedClashProxy,
        readonly: "",
        "aria-label": `${safeString(item.email)} 统一 Clash 前置`,
      },
    });
    sharedClash.disabled = item.selectionRole !== "team_owner";
    row.append(labeledCell("Clash 第一跳", sharedClash));
    fragment.append(row);
  }
  body.append(fragment);
}

async function openIcloudSync(mailbox) {
  if (!mailbox) return;
  state.activeIcloudMailboxId = icloudMailboxId(mailbox);
  state.remoteIcloudAliases = [];
  fieldError("icloud-sync-error", "");
  const form = byId("icloud-sync-form");
  form.reset();
  form.elements.namedItem("mailbox_id").value = state.activeIcloudMailboxId;
  byId("icloud-sync-title").textContent = `${safeString(mailbox.name)} · 同步 Alias`;
  byId("icloud-sync-table-body").replaceChildren(element("tr", {className: "loading-row"}, [
    element("td", {attrs: {colspan: "7"}}, [
      element("span", {className: "inline-loader", attrs: {"aria-hidden": "true"}}),
      "正在读取 iCloud Alias…",
    ]),
  ]));
  byId("icloud-sync-dialog").showModal();
  try {
    await Promise.all([loadIcloudTeamOwners(), loadProxyChainConfig()]);
    const payload = await api(`/api/icloud-mailboxes/${encodeURIComponent(state.activeIcloudMailboxId)}/remote-aliases`);
    const existingOwnerById = new Map(state.icloudTeamOwners.map((owner) => [safeString(owner.id), owner]));
    state.remoteIcloudAliases = asList(payload, ["aliases", "remote_aliases"]).map((item) => ({
      ...item,
      selectionRole: item.imported ? safeString(item.imported_role) : "ignore",
      parentOwnerEmail: item.parent_owner_alias_id
        ? safeString(existingOwnerById.get(safeString(item.parent_owner_alias_id))?.email)
        : "",
      ownerProxy: "",
      ownerProxyMode: CHAIN_PROXY_MODE,
      ownerProxyBootstrap: state.sharedClashProxy,
    }));
    renderIcloudSyncRows();
  } catch (error) {
    byId("icloud-sync-table-body").replaceChildren(element("tr", {className: "error-row"}, [
      element("td", {text: error?.message || String(error), attrs: {colspan: "7"}}),
    ]));
  }
}

async function handleIcloudSync(form) {
  if (!ensureMutable()) return;
  fieldError("icloud-sync-error", "");
  const selected = state.remoteIcloudAliases.filter(
    (item) => !item.imported && item.selectionRole !== "ignore",
  );
  if (!selected.length) {
    fieldError("icloud-sync-error", "请至少选择一个未接管 Alias");
    return;
  }
  const items = [];
  for (const item of selected) {
    if (item.selectionRole === "team_owner" && !safeString(item.ownerProxy).trim()) {
      fieldError("icloud-sync-error", `请填写母号 ${safeString(item.email)} 的完整代理链接`);
      return;
    }
    if (item.selectionRole === "rotating_child" && !safeString(item.parentOwnerEmail)) {
      fieldError("icloud-sync-error", `请选择子号 ${safeString(item.email)} 归属的母号`);
      return;
    }
    items.push({
      email: safeString(item.email),
      role: item.selectionRole,
      parent_owner_email: item.selectionRole === "rotating_child" ? safeString(item.parentOwnerEmail) : null,
      owner_proxy: "",
      owner_proxy_mode: item.selectionRole === "team_owner"
        ? CHAIN_PROXY_MODE
        : "direct",
      owner_proxy_source_url: item.selectionRole === "team_owner"
        ? safeString(item.ownerProxy).trim()
        : "",
      owner_proxy_bootstrap: item.selectionRole === "team_owner"
        ? state.sharedClashProxy
        : "",
    });
  }
  await api(`/api/icloud-mailboxes/${encodeURIComponent(state.activeIcloudMailboxId)}/aliases/import`, {
    method: "POST",
    body: {items},
  });
  byId("icloud-sync-dialog").close();
  state.remoteIcloudAliases = [];
  state.icloudMailboxesLoaded = false;
  await Promise.all([
    loadIcloudTeamOwners(),
    loadIcloudMailboxes({force: true}),
    refreshResources(["accounts", "workspaces"]),
  ]);
  showToast(`已接管 ${numberFormatter.format(items.length)} 个 Alias`, "success");
}

function renderInventoryTable() {
  const body = byId("inventory-table-body");
  const status = byId("inventory-search-status");
  body.replaceChildren();
  if (!state.inventoryQuery.trim()) {
    body.append(loadingOrErrorRow(5, "inventory", "输入邮箱搜索库存"));
    status.textContent = "输入邮箱后搜索，最多显示 20 条";
    return;
  }
  if (state.inventoryLoading) {
    const row = element("tr", {className: "loading-row"});
    row.append(element("td", {attrs: {colspan: "5"}}, [
      element("span", {className: "inline-loader", attrs: {"aria-hidden": "true"}}),
      "正在搜索库存…",
    ]));
    body.append(row);
    status.textContent = "正在搜索…";
    return;
  }
  if (state.inventoryError) {
    const row = element("tr", {className: "error-row"});
    row.append(element("td", {text: `${state.inventoryError}。请修改关键词后重试。`, attrs: {colspan: "5"}}));
    body.append(row);
    status.textContent = "搜索失败";
    return;
  }
  if (!state.inventoryResults.length) {
    body.append(loadingOrErrorRow(5, "inventory", "未找到匹配的邮箱库存"));
    status.textContent = "0 条结果";
    return;
  }
  const fragment = document.createDocumentFragment();
  for (const item of state.inventoryResults.slice(0, INVENTORY_SEARCH_LIMIT)) {
    const itemStatus = safeString(firstValue(item, ["status", "state"], "available"));
    const aliasNumber = inventoryAliasNumber(item);
    const row = element("tr", {dataset: {inventoryId: inventoryId(item)}});
    row.append(labeledCell("主邮箱", element("span", {className: "cell-primary", text: inventoryEmail(item), attrs: {title: inventoryEmail(item)}})));
    row.append(labeledCell("状态", statusBadge(itemStatus, INVENTORY_STATUS)));
    row.append(labeledCell("下一个子号", element("span", {className: "cell-code", text: aliasNumber >= 1 && aliasNumber <= 5 ? `+${aliasNumber}` : "-"})));
    const failure = safeString(firstValue(item, ["failure_message", "redacted_failure", "failure_code"], "-"));
    row.append(labeledCell("最近失效", element("span", {className: failure === "-" ? "empty-value" : "cell-error", text: failure, attrs: {title: failure}})));
    const actions = element("div", {className: "row-actions"});
    const allocate = actionButton("分配子号", "open-inventory-allocation", {inventoryId: inventoryId(item)});
    allocate.disabled = itemStatus !== "available" || aliasNumber < 1 || aliasNumber > 5;
    actions.append(allocate);
    row.append(labeledCell("操作", actions, "actions-cell"));
    fragment.append(row);
  }
  body.append(fragment);
  status.textContent = `${numberFormatter.format(state.inventoryResults.length)} 条结果，最多显示 ${INVENTORY_SEARCH_LIMIT} 条`;
}

function cancelInventorySearch() {
  if (state.inventorySearchTimer) window.clearTimeout(state.inventorySearchTimer);
  state.inventorySearchTimer = null;
  state.inventoryRequestController?.abort();
  state.inventoryRequestController = null;
  state.inventoryLoading = false;
  state.inventorySearchSequence += 1;
}

function scheduleInventorySearch({immediate = false} = {}) {
  cancelInventorySearch();
  const query = state.inventoryQuery.trim();
  if (!query) {
    state.inventoryResults = [];
    state.inventoryError = "";
    renderInventoryTable();
    return;
  }
  state.inventoryLoading = true;
  renderInventoryTable();
  state.inventorySearchTimer = window.setTimeout(() => {
    state.inventorySearchTimer = null;
    searchInventory().catch(() => {});
  }, immediate ? 0 : INVENTORY_SEARCH_DELAY);
}

async function searchInventory() {
  const query = state.inventoryQuery.trim();
  if (!query) return;
  const sequence = ++state.inventorySearchSequence;
  const controller = new AbortController();
  state.inventoryRequestController = controller;
  state.inventoryLoading = true;
  state.inventoryError = "";
  renderInventoryTable();
  const params = new URLSearchParams({query, limit: String(INVENTORY_SEARCH_LIMIT)});
  if (state.inventoryStatus !== "all") params.set("status", state.inventoryStatus);
  try {
    const payload = await api(`/api/mailbox-inventory?${params.toString()}`, {signal: controller.signal});
    if (sequence !== state.inventorySearchSequence) return;
    state.inventoryResults = asList(payload, ["inventory", "mailbox_inventory"]).slice(0, INVENTORY_SEARCH_LIMIT);
    state.inventoryDirty = false;
  } catch (error) {
    if (error?.code === "request_cancelled" || sequence !== state.inventorySearchSequence) return;
    state.inventoryError = error?.message || String(error);
    state.inventoryResults = [];
  } finally {
    if (sequence === state.inventorySearchSequence) {
      state.inventoryLoading = false;
      state.inventoryRequestController = null;
      renderInventoryTable();
    }
  }
}

function runWorkspaceLabel(run) {
  const direct = firstValue(run, ["workspace_name", "name"]);
  if (direct) return safeString(direct);
  const workspace = findWorkspace(firstValue(run, ["workspace_id"]));
  return workspace ? workspaceName(workspace) : shortId(firstValue(run, ["workspace_uid_snapshot", "workspace_id"], "未知空间"));
}

function runAccountSnapshot(run) {
  const current = safeString(firstValue(run, ["current_email_snapshot", "current_email"], "未知账号"));
  const next = safeString(firstValue(run, ["next_email_snapshot", "next_email"], "未知账号"));
  return [current, next];
}

function runKindLabel(run) {
  return safeString(firstValue(run, ["kind"], runResultObject(run)?.mode)) === "rescue"
    ? "母号提拉"
    : "子号换班";
}

function filteredRuns() {
  const search = state.filters.runSearch.trim().toLocaleLowerCase("zh-CN");
  const from = state.filters.runDateFrom ? new Date(`${state.filters.runDateFrom}T00:00:00`) : null;
  return state.runs.filter((run) => {
    const runState = safeString(firstValue(run, ["state", "status"]));
    if (state.filters.runState !== "all" && runState !== state.filters.runState) return false;
    if (from) {
      const created = new Date(firstValue(run, ["started_at", "created_at"], ""));
      if (!Number.isNaN(created.getTime()) && created < from) return false;
    }
    const [current, next] = runAccountSnapshot(run);
    const haystack = `${runId(run)} ${runWorkspaceLabel(run)} ${current} ${next}`.toLocaleLowerCase("zh-CN");
    return !search || haystack.includes(search);
  });
}

function renderRunTable() {
  const body = byId("run-table-body");
  const visible = filteredRuns();
  body.replaceChildren();
  if (!visible.length) {
    body.append(loadingOrErrorRow(7, "runs", state.runs.length ? "没有符合筛选条件的运行记录" : "尚无运行记录"));
    return;
  }
  const fragment = document.createDocumentFragment();
  for (const run of visible) {
    const id = runId(run);
    const runState = safeString(firstValue(run, ["state", "status"], "queued"));
    const [current, next] = runAccountSnapshot(run);
    const row = element("tr", {dataset: {runId: id}});
    const rescue = runKindLabel(run) === "母号提拉";
    row.append(labeledCell("空间", primarySecondary(runWorkspaceLabel(run), `${runKindLabel(run)} · ${shortId(id)}`)));
    row.append(labeledCell("账号快照", primarySecondary(
      rescue ? `故障：${current}` : current,
      `${rescue ? "新子号" : "下一账号"}：${next}`,
    )));
    row.append(labeledCell("结果", statusBadge(runState, RUN_STATUS)));
    const step = safeString(firstValue(run, ["current_step", "step"]));
    row.append(labeledCell("当前阶段", STEP_LABELS[step] || (runState === "succeeded" ? "全部完成" : step || "等待开始")));
    row.append(labeledCell("开始时间", formatDate(firstValue(run, ["started_at", "created_at"]))));
    row.append(labeledCell("耗时", formatDuration(run)));
    const actions = element("div", {className: "row-actions"}, [actionButton("查看", "open-run-detail", {runId: id})]);
    row.append(labeledCell("详情", actions, "actions-cell"));
    fragment.append(row);
  }
  body.append(fragment);
}

function queueItemState(item) {
  return safeString(firstValue(item, ["state", "status"], "queued"));
}

function queueItemRunId(item) {
  return safeString(firstValue(item, ["run_id", "id"]));
}

function queueItemWorkspaceName(item) {
  const direct = firstValue(item, ["workspace_name", "name"]);
  if (direct) return safeString(direct);
  const run = item.run && typeof item.run === "object" ? item.run : state.runs.find((candidate) => runId(candidate) === queueItemRunId(item));
  if (run) return runWorkspaceLabel(run);
  const workspace = findWorkspace(firstValue(item, ["workspace_id"]));
  return workspace ? workspaceName(workspace) : "未知空间";
}

function activeQueueItems() {
  return state.queue.items
    .filter((item) => ACTIVE_QUEUE_STATES.has(queueItemState(item)))
    .sort((left, right) => Number(firstValue(left, ["position"], 0)) - Number(firstValue(right, ["position"], 0)));
}

function queueLogMessage(record) {
  const message = safeString(firstValue(record, ["message"]));
  return {
    "stage active": "阶段开始",
    "stage done": "阶段完成",
    "stage skipped": "阶段跳过",
    "stage error": "阶段失败",
    "stage cancelled": "阶段停止",
  }[message] || message;
}

function queueLogLevel(record) {
  const level = safeString(firstValue(record, ["level"], "info"));
  return {
    error: "错误",
    warning: "警告",
    success: "成功",
    info: "信息",
  }[level] || level;
}

function queueOperationLog(operation, operationKey) {
  const records = Array.isArray(operation?.logs)
    ? operation.logs.slice(-MAX_QUEUE_LOG_ROWS)
    : [];
  const frame = element("div", {className: "queue-log-frame"});
  const toolbar = element("div", {className: "queue-log-toolbar"}, [
    element("strong", {text: "实时详细日志"}),
    element("span", {text: `${numberFormatter.format(records.length)} 条`}),
  ]);
  const followButton = element("button", {
    className: "queue-log-follow",
    text: "↓",
    attrs: {
      type: "button",
      title: "回到最新日志",
      "aria-label": "回到最新日志",
    },
  });
  toolbar.append(followButton);
  const log = element("div", {
    className: "queue-operation-log",
    dataset: {operationLog: operationKey},
    attrs: {
      tabindex: "0",
      role: "log",
      "aria-label": "实时详细执行日志",
      "aria-live": "polite",
      "aria-relevant": "additions",
    },
  });
  if (!records.length) {
    log.append(element("div", {className: "queue-log-line", dataset: {level: "info"}}, [
      element("time", {text: "--:--:--"}),
      element("span", {className: "queue-log-stage", text: "系统"}),
      element("span", {className: "queue-log-level", text: "信息"}),
      element("span", {className: "queue-log-message", text: "等待详细日志"}),
    ]));
  } else {
    for (const record of records) {
      const step = safeString(firstValue(record, ["step"]));
      const stage = STEP_LABELS[step] || step || "系统";
      log.append(element("div", {
        className: "queue-log-line",
        dataset: {level: safeString(firstValue(record, ["level"], "info"))},
      }, [
        element("time", {text: formatTime(firstValue(record, ["created_at", "timestamp"]))}),
        element("span", {className: "queue-log-stage", text: stage, attrs: {title: stage}}),
        element("span", {className: "queue-log-level", text: queueLogLevel(record)}),
        element("span", {className: "queue-log-message", text: queueLogMessage(record)}),
      ]));
    }
  }
  const syncFollowState = () => {
    const follow = log.scrollHeight - log.scrollTop - log.clientHeight <= 24;
    state.queueLogView = {key: operationKey, follow, scrollTop: log.scrollTop};
    followButton.dataset.paused = String(!follow);
  };
  log.addEventListener("scroll", syncFollowState, {passive: true});
  followButton.addEventListener("click", () => {
    log.scrollTop = log.scrollHeight;
    syncFollowState();
    log.focus({preventScroll: true});
  });
  frame.append(toolbar, log);
  return frame;
}

function captureQueueLogView(list) {
  const log = list.querySelector("[data-operation-log]");
  if (!log || log.clientHeight <= 0) return;
  const follow = log.scrollHeight - log.scrollTop - log.clientHeight <= 24;
  state.queueLogView = {
    key: safeString(log.dataset.operationLog),
    follow,
    scrollTop: log.scrollTop,
  };
}

function restoreQueueLogView(list) {
  const log = list.querySelector("[data-operation-log]");
  if (!log) {
    state.queueLogView = {key: "", follow: true, scrollTop: 0};
    return;
  }
  const key = safeString(log.dataset.operationLog);
  const sameOperation = state.queueLogView.key === key;
  const follow = !sameOperation || state.queueLogView.follow;
  log.scrollTop = follow
    ? log.scrollHeight
    : Math.min(state.queueLogView.scrollTop, Math.max(0, log.scrollHeight - log.clientHeight));
  state.queueLogView = {key, follow, scrollTop: log.scrollTop};
  const followButton = log.parentElement?.querySelector(".queue-log-follow");
  if (followButton) followButton.dataset.paused = String(!follow);
}

function runOperationQueueEntry(operation) {
  const runIdentifier = safeString(operation.run_id);
  const run = state.runs.find((candidate) => runId(candidate) === runIdentifier) || {
    id: runIdentifier,
    kind: operation.kind,
  };
  const operationState = safeString(operation.state, "running");
  const manualLoginState = safeString(operation.manual_login_state);
  const manualLoginLabels = {
    profile_started: "正在打开隔离环境",
    automating_login: "正在自动登录",
    submitting_email: "正在提交新账号邮箱",
    waiting_for_otp: "正在等待邮箱验证码",
    submitting_otp: "正在提交邮箱验证码",
    submitting_profile: "正在填写账号姓名",
    wrong_account: "OpenBrowser 环境中已登录其他账号",
    waiting_for_team: "等待进入目标 Team",
    verified: "登录与 Team 已确认",
    profile_stopped: "登录环境已关闭",
  };
  const entry = element("li", {
    className: "queue-item queue-item--refresh",
    dataset: {state: operationState},
  });
  entry.append(element("span", {className: "queue-position", text: "W"}));
  const copy = element("div", {className: "queue-item__copy"}, [
    element("strong", {text: `${runKindLabel(run)} · ${runWorkspaceLabel(run)}`}),
    element("span", {
      text: operation.current_step === "new_login" && manualLoginLabels[manualLoginState]
        ? manualLoginLabels[manualLoginState]
        : operation.current_step
        ? `${RUN_STATUS[operationState]?.[0] || operationState} / ${STEP_LABELS[operation.current_step] || operation.current_step}`
        : RUN_STATUS[operationState]?.[0] || operationState,
    }),
  ]);
  copy.append(queueOperationLog(operation, `run:${runIdentifier}`));
  const operationError = safeString(operation.error);
  if (operationError) copy.append(element("span", {className: "queue-refresh-error", text: operationError}));
  const actions = element("div", {className: "queue-item__actions"});
  if (ACTIVE_RUN_STATES.has(operationState)) {
    const stop = actionButton("■", "stop-run", {runId: runIdentifier}, "queue-icon-button queue-icon-button--danger");
    stop.setAttribute("aria-label", `停止 ${runWorkspaceLabel(run)}`);
    actions.append(stop);
  }
  entry.append(copy, actions);
  return entry;
}

function renderQueue() {
  const drawer = byId("queue-drawer");
  const body = byId("queue-body");
  const wasExpanded = !body.hidden;
  drawer.dataset.expanded = String(state.queueExpanded);
  const toggle = drawer.querySelector("[data-action='toggle-queue']");
  toggle.setAttribute("aria-expanded", String(state.queueExpanded));

  const items = activeQueueItems();
  const runOperation = state.queue.runOperation;
  const running = items.find((item) => ACTIVE_RUN_STATES.has(queueItemState(item)));
  const refresh = state.queue.credentialRefresh;
  const refreshRunning = safeString(refresh?.state) === "running";
  const refreshAccount = refresh ? findAccount(refresh.account_id) : null;
  const refreshLabel = refreshAccount ? accountEmail(refreshAccount) : "当前子号";
  const pendingCount = items.filter((item) => ["queued", "pending"].includes(queueItemState(item))).length;
  byId("queue-summary").textContent = `${numberFormatter.format(pendingCount)} 项待执行`;
  byId("queue-running-summary").textContent = refreshRunning
    ? `正在刷新令牌：${refreshLabel}`
    : running
      ? `正在运行：${queueItemWorkspaceName(running)}`
      : state.queue.paused ? "队列已暂停" : "当前无运行任务";
  byId("queue-state").textContent = state.queue.paused
    ? "队列已暂停，不会领取新任务。"
    : refreshRunning
      ? "当前子号凭据刷新中；完成前不会领取接力任务。"
      : running ? "全局顺序执行中，每次仅运行 1 个空间。" : "队列就绪。";
  byId("queue-pause-button").textContent = state.queue.paused ? "继续队列" : "暂停队列";

  const list = byId("queue-list");
  if (wasExpanded) captureQueueLogView(list);
  body.hidden = !state.queueExpanded;
  list.replaceChildren();
  if (!items.length && !refresh && !runOperation) {
    state.queueLogView = {key: "", follow: true, scrollTop: 0};
    list.append(element("li", {className: "empty-state", text: state.errors.queue || "队列为空"}));
    return;
  }
  const fragment = document.createDocumentFragment();
  if (runOperation) fragment.append(runOperationQueueEntry(runOperation));
  if (refresh) {
    const refreshState = safeString(refresh.state, "running");
    const entry = element("li", {
      className: "queue-item queue-item--refresh",
      dataset: {state: refreshState},
    });
    entry.append(element("span", {className: "queue-position", text: "R"}));
    const copy = element("div", {className: "queue-item__copy"}, [
      element("strong", {text: `子号令牌刷新 · ${refreshLabel}`}),
      element("span", {
        text: refresh.current_step
          ? `${refreshState === "running" ? "执行中" : RUN_STATUS[refreshState]?.[0] || refreshState} / ${STEP_LABELS[refresh.current_step] || refresh.current_step}`
          : refreshState === "running"
          ? "执行中"
          : refreshState === "succeeded"
            ? refresh.reused ? "已完成 · 重复请求未新建令牌" : "已完成"
            : "执行失败",
      }),
    ]);
    copy.append(queueOperationLog(refresh, `refresh:${safeString(refresh.account_id)}`));
    const refreshError = safeString(refresh.error);
    if (refreshError) copy.append(element("span", {className: "queue-refresh-error", text: refreshError}));
    const outputPath = safeString(refresh.result?.sub2api_path);
    if (outputPath) copy.append(element("span", {className: "queue-refresh-output", text: `JSON：${outputPath}`}));
    entry.append(copy, element("div", {className: "queue-item__actions"}));
    fragment.append(entry);
  }
  const visibleItems = items.filter(
    (item) => queueItemRunId(item) !== safeString(runOperation?.run_id),
  );
  visibleItems.forEach((item, index) => {
    const itemState = queueItemState(item);
    const itemId = safeString(firstValue(item, ["id", "queue_item_id"]));
    const runIdentifier = queueItemRunId(item);
    const run = item.run && typeof item.run === "object"
      ? item.run
      : state.runs.find((candidate) => runId(candidate) === runIdentifier);
    const entry = element("li", {className: "queue-item", dataset: {state: itemState, queueItemId: itemId}});
    entry.append(element("span", {className: "queue-position", text: String(index + 1)}));
    entry.append(element("div", {className: "queue-item__copy"}, [
      element("strong", {text: queueItemWorkspaceName(item)}),
      element("span", {text: `${runKindLabel(run)} · ${QUEUE_STATUS[itemState] || itemState} · ${shortId(runIdentifier)}`}),
    ]));
    const actions = element("div", {className: "queue-item__actions"});
    if (["queued", "pending"].includes(itemState)) {
      const up = actionButton("↑", "move-queue-item", {queueItemId: itemId, direction: "up"}, "queue-icon-button");
      up.setAttribute("aria-label", `上移 ${queueItemWorkspaceName(item)}`);
      up.disabled = index === 0;
      const down = actionButton("↓", "move-queue-item", {queueItemId: itemId, direction: "down"}, "queue-icon-button");
      down.setAttribute("aria-label", `下移 ${queueItemWorkspaceName(item)}`);
      down.disabled = index === visibleItems.length - 1 || ACTIVE_RUN_STATES.has(queueItemState(visibleItems[index + 1]));
      actions.append(up, down);
    }
    if (ACTIVE_RUN_STATES.has(itemState)) {
      const stop = actionButton("■", "stop-run", {runId: runIdentifier}, "queue-icon-button queue-icon-button--danger");
      stop.setAttribute("aria-label", `停止 ${queueItemWorkspaceName(item)}`);
      actions.append(stop);
    }
    entry.append(actions);
    fragment.append(entry);
  });
  list.append(fragment);
  if (state.queueExpanded) restoreQueueLogView(list);
}

function configuredSecret(secrets, keys, fallback) {
  for (const key of keys) {
    if (Object.prototype.hasOwnProperty.call(secrets, key)) return booleanValue(secrets[key]);
  }
  return Boolean(fallback);
}

function safeSettings(payload, previous = {}) {
  const source = payload && typeof payload === "object" ? payload : {};
  const settings = source.values && typeof source.values === "object"
    ? source.values
    : source.settings && typeof source.settings === "object"
      ? source.settings
      : source;
  const secrets = source.secrets && typeof source.secrets === "object" ? source.secrets : source;
  return {
    output_dir: safeString(firstValue(settings, ["output_dir", "output_directory"])),
    pat_name: safeString(firstValue(settings, ["pat_name"])),
    pat_ttl: firstValue(settings, ["pat_ttl", "pat_ttl_seconds"], ""),
    invite_settle_seconds: firstValue(settings, ["invite_settle_seconds"], ""),
    openbrowser_base_url: safeString(firstValue(settings, ["openbrowser_base_url"])),
    openbrowser_profile_ids: safeString(firstValue(settings, ["openbrowser_profile_ids"])),
    openbrowser_manual_timeout_seconds: firstValue(settings, ["openbrowser_manual_timeout_seconds"], ""),
    management_url: safeString(firstValue(settings, ["management_base_url", "management_url"])),
    management_filename: safeString(firstValue(settings, ["management_remote_name", "management_filename", "remote_filename"])),
    management_push: booleanValue(firstValue(settings, ["management_push", "push_management"], false)),
    management_overwrite: booleanValue(firstValue(settings, ["management_replace", "management_overwrite", "overwrite_management"], false)),
    sub2api_url: safeString(firstValue(settings, ["sub2api_base_url", "sub2api_url"])),
    sub2api_email: safeString(firstValue(settings, ["sub2api_email"])),
    sub2api_push: booleanValue(firstValue(settings, ["sub2api_push", "push_sub2api"], false)),
    sub2api_concurrency: firstValue(settings, ["sub2api_concurrency"], 9999),
    sub2api_priority: firstValue(settings, ["sub2api_priority"], ""),
    sub2api_load_factor: firstValue(settings, ["sub2api_load_factor"], 9999),
    sub2api_all_groups: booleanValue(firstValue(settings, ["sub2api_all_groups"], true)),
    sub2api_group_id: firstValue(settings, ["sub2api_group_id"], ""),
    proxy_configured: configuredSecret(secrets, ["proxy", "proxy_configured", "proxy_present"], previous.proxy_configured),
    openbrowser_api_key_configured: configuredSecret(secrets, ["openbrowser_api_key", "openbrowser_api_key_configured"], previous.openbrowser_api_key_configured),
    management_api_key_configured: configuredSecret(secrets, ["management_api_key", "management_api_key_configured", "management_key_present"], previous.management_api_key_configured),
    sub2api_password_configured: configuredSecret(secrets, ["sub2api_password", "sub2api_password_configured", "sub2api_password_present"], previous.sub2api_password_configured),
    sub2api_api_key_configured: configuredSecret(secrets, ["sub2api_api_key", "sub2api_api_key_configured", "sub2api_api_key_present"], previous.sub2api_api_key_configured),
    sub2api_totp_secret_configured: configuredSecret(secrets, ["sub2api_totp_secret", "sub2api_totp_secret_configured", "sub2api_totp_secret_present"], previous.sub2api_totp_secret_configured),
    last_backup_path: safeString(firstValue(settings, ["last_backup_path", "backup_path"])),
    last_backup_at: firstValue(settings, ["last_backup_at"]),
  };
}

function safeOpenBrowserStatus(payload) {
  const source = payload && typeof payload === "object" ? payload : {};
  return {
    configured: Boolean(source.configured),
    connected: Boolean(source.connected),
    state: safeString(firstValue(source, ["state"], "not_configured")),
    version: safeString(firstValue(source, ["version"])),
    poolSize: Number(firstValue(source, ["pool_size"], 0)) || 0,
    availableCount: Number(firstValue(source, ["available_count"], 0)) || 0,
    boundCount: Number(firstValue(source, ["bound_count"], 0)) || 0,
    runningCount: Number(firstValue(source, ["running_count"], 0)) || 0,
    missingCount: Number(firstValue(source, ["missing_count"], 0)) || 0,
  };
}

function safeSub2APIGroups(payload) {
  return asList(payload, ["groups"])
    .map((item) => ({
      id: Number(firstValue(item, ["id"], 0)),
      name: safeString(firstValue(item, ["name"])).trim(),
      platform: safeString(firstValue(item, ["platform"])).trim().toLowerCase(),
      status: safeString(firstValue(item, ["status"], "active")).trim().toLowerCase(),
      is_exclusive: booleanValue(firstValue(item, ["is_exclusive"], false)),
    }))
    .filter((item) => Number.isInteger(item.id) && item.id > 0 && item.name);
}

function renderSub2APIGroupOptions(form, selectedValue) {
  const control = form.elements.namedItem("sub2api_group_id");
  if (!(control instanceof HTMLSelectElement)) return;
  const selected = safeString(selectedValue);
  const fragment = document.createDocumentFragment();
  fragment.append(element("option", {text: "默认分组", attrs: {value: ""}}));
  let selectedExists = !selected;
  for (const group of state.sub2apiGroups) {
    const compatible = group.platform === "openai" && group.status === "active";
    const isSelected = String(group.id) === selected;
    const label = [
      group.name,
      group.platform ? group.platform.toUpperCase() : "未指定平台",
      `ID ${group.id}`,
      group.status && group.status !== "active" ? group.status : "",
    ].filter(Boolean).join(" · ");
    const option = element("option", {
      text: label,
      attrs: {value: group.id, disabled: !compatible && !isSelected},
    });
    if (isSelected) selectedExists = true;
    fragment.append(option);
  }
  if (selected && !selectedExists) {
    fragment.append(element("option", {
      text: `已保存分组 · ID ${selected}`,
      attrs: {value: selected},
    }));
  }
  if (!state.sub2apiGroups.length) {
    fragment.append(element("option", {
      text: state.errors.sub2apiGroups ? "分组加载失败" : "没有可用分组",
      attrs: {disabled: true},
    }));
  }
  control.replaceChildren(fragment);
  control.value = selectedExists ? selected : "";
}

function syncSub2APIGroupMode(form = byId("settings-form")) {
  const allGroups = form.elements.namedItem("sub2api_all_groups");
  const group = form.elements.namedItem("sub2api_group_id");
  if (allGroups instanceof HTMLInputElement && group instanceof HTMLSelectElement) {
    group.disabled = allGroups.checked;
  }
}

function renderSecretControls(form = byId("settings-form")) {
  const values = state.settings;
  const secretDefinitions = [
    ["proxy", "proxy-secret-state", "proxy_configured"],
    ["openbrowser_api_key", "openbrowser-secret-state", "openbrowser_api_key_configured"],
    ["management_api_key", "management-secret-state", "management_api_key_configured"],
    ["sub2api_password", "sub2api-secret-state", "sub2api_password_configured"],
    ["sub2api_api_key", "sub2api-api-key-secret-state", "sub2api_api_key_configured"],
    ["sub2api_totp_secret", "sub2api-totp-secret-state", "sub2api_totp_secret_configured"],
  ];
  for (const [secret, statusId, configuredKey] of secretDefinitions) {
    const clearing = state.clearSecrets.has(secret);
    byId(statusId).textContent = clearing ? "保存时清除" : values[configuredKey] ? "已安全保存" : "未设置";
    const button = document.querySelector(`[data-action="toggle-secret-clear"][data-secret="${secret}"]`);
    if (button) {
      button.textContent = clearing ? "撤销清除" : "清除已保存值";
      button.closest(".secret-state-row").dataset.clearing = String(clearing);
      button.disabled = !clearing && !values[configuredKey];
    }
    const input = form.elements.namedItem(secret);
    if (input) input.disabled = clearing;
  }
}

function renderOpenBrowserStatus() {
  const row = byId("openbrowser-status")?.closest(".openbrowser-status-row");
  if (!row) return;
  const status = state.openbrowserStatus;
  if (!status) {
    row.dataset.state = "not_configured";
    byId("openbrowser-status").textContent = "尚未检测";
    return;
  }
  row.dataset.state = status.state;
  if (status.state === "not_configured") {
    byId("openbrowser-status").textContent = "尚未配置";
  } else if (status.state === "unavailable") {
    byId("openbrowser-status").textContent = "Local API 无法连接";
  } else {
    const version = status.version ? ` · v${status.version}` : "";
    const missing = status.missingCount ? ` · 缺失 ${status.missingCount}` : "";
    const running = status.runningCount ? ` · 运行中 ${status.runningCount}` : "";
    byId("openbrowser-status").textContent = `可用 ${status.availableCount} / ${status.poolSize} · 已绑定 ${status.boundCount}${running}${missing}${version}`;
  }
}

function renderSettings({force = false} = {}) {
  if (state.settingsDirty && !force) return;
  const form = byId("settings-form");
  const values = state.settings;
  const textFields = [
    "output_dir",
    "pat_name",
    "pat_ttl",
    "invite_settle_seconds",
    "openbrowser_base_url",
    "openbrowser_profile_ids",
    "openbrowser_manual_timeout_seconds",
    "management_url",
    "management_filename",
    "sub2api_url",
    "sub2api_email",
    "sub2api_concurrency",
    "sub2api_load_factor",
    "sub2api_priority",
  ];
  for (const name of textFields) {
    const control = form.elements.namedItem(name);
    if (control) control.value = values[name] ?? "";
  }
  for (const name of ["management_push", "management_overwrite", "sub2api_all_groups", "sub2api_push"]) {
    const control = form.elements.namedItem(name);
    if (control) control.checked = Boolean(values[name]);
  }
  renderSub2APIGroupOptions(form, values.sub2api_group_id);
  syncSub2APIGroupMode(form);
  for (const name of ["proxy", "openbrowser_api_key", "management_api_key", "sub2api_password", "sub2api_api_key", "sub2api_totp_secret"]) {
    const control = form.elements.namedItem(name);
    if (control) control.value = "";
  }
  renderSecretControls(form);
  renderOpenBrowserStatus();
  byId("backup-status").textContent = values.last_backup_path
    ? `最近备份：${values.last_backup_path}${values.last_backup_at ? ` · ${formatDate(values.last_backup_at)}` : ""}`
    : "尚未创建备份";
}

function renderAll() {
  renderWorkspaceTable();
  renderAccountView();
  renderRunTable();
  renderQueue();
  renderSettings();
}

function updateResource(name, payload) {
  state.errors[name] = "";
  if (name === "workspaces") state.workspaces = asList(payload, ["workspaces"]);
  if (name === "accounts") state.accounts = asList(payload, ["accounts"]);
  if (name === "runs") state.runs = asList(payload, ["runs"]);
  if (name === "queue") state.queue = normalizeQueue(payload);
  if (name === "settings") state.settings = safeSettings(payload, state.settings);
  if (name === "openbrowserStatus") state.openbrowserStatus = safeOpenBrowserStatus(payload);
  if (name === "sub2apiGroups") state.sub2apiGroups = safeSub2APIGroups(payload);
  if (name === "icloudTeamOwners") state.icloudTeamOwners = asList(payload, ["owners", "icloud_team_owners"]);
  if (name === "icloudMailboxes") {
    state.icloudMailboxes = asList(payload, ["mailboxes", "icloud_mailboxes"]);
    state.icloudMailboxesLoaded = true;
  }
}

async function loadResource(name, path, {optional = false} = {}) {
  try {
    const payload = await api(path);
    if (name === "migration") {
      applyMigration(payload);
    } else {
      updateResource(name, payload);
    }
    return payload;
  } catch (error) {
    if (optional && error?.status === 404) return null;
    if (isMigrationError(error)) showMigrationBlocked(error.message);
    state.errors[name] = error?.message || String(error);
    return null;
  }
}

async function refreshResources(names) {
  const paths = {
    workspaces: "/api/workspaces",
    accounts: "/api/accounts",
    runs: "/api/runs",
    queue: "/api/queue",
    settings: "/api/settings",
    openbrowserStatus: "/api/openbrowser/status",
    sub2apiGroups: "/api/sub2api/groups",
    icloudTeamOwners: "/api/icloud-team-owners",
    icloudMailboxes: "/api/icloud-mailboxes",
  };
  await Promise.all(names.map((name) => loadResource(name, paths[name])));
  renderAll();
}

function applyMigration(payload) {
  if (!payload || typeof payload !== "object") return;
  state.migration = payload;
  const status = safeString(firstValue(payload, ["status", "state"]));
  const blocked = Boolean(firstValue(payload, ["blocked", "cleanup_blocked"], false)) || status === "cleanup_blocked";
  if (blocked) {
    showMigrationBlocked(safeString(firstValue(payload, ["message", "detail"], "迁移清理尚未完成。")), payload);
  } else if (["complete", "completed", "cleanup_complete", "ready"].includes(status)) {
    clearMigrationBlocked();
  }
}

function upsertById(list, item, identifier) {
  if (!item || typeof item !== "object") return list;
  const id = identifier(item);
  if (!id) return list;
  const index = list.findIndex((candidate) => identifier(candidate) === id);
  if (index === -1) return [item, ...list];
  const next = list.slice();
  next[index] = {...next[index], ...item};
  return next;
}

function applySnapshot(payload) {
  const source = payload?.snapshot && typeof payload.snapshot === "object" ? payload.snapshot : payload;
  if (!source || typeof source !== "object") return;
  if (Array.isArray(source.workspaces)) updateResource("workspaces", source.workspaces);
  if (Array.isArray(source.accounts)) updateResource("accounts", source.accounts);
  if (Array.isArray(source.runs)) updateResource("runs", source.runs);
  if (source.queue || Array.isArray(source.queue_items)) updateResource("queue", source.queue || {items: source.queue_items, paused: source.queue_paused});
  if (source.settings) updateResource("settings", source.settings);
  if (source.migration) applyMigration(source.migration);
  renderAll();
}

function appendActiveRunEvent(record) {
  if (!record || typeof record !== "object") return;
  const recordRunId = safeString(firstValue(record, ["run_id"]));
  if (state.activeRunId && recordRunId && recordRunId !== state.activeRunId) return;
  state.activeRunEvents.push(record);
  if (state.activeRunEvents.length > MAX_EVENT_MEMORY) {
    state.activeRunEvents.splice(0, state.activeRunEvents.length - MAX_EVENT_MEMORY);
  }
  if (byId("run-dialog").open) renderRunDetail(state.activeRun, state.activeRunEvents);
}

function invalidateInventoryResults() {
  state.inventoryDirty = true;
  if (state.accountView === "inventory" && state.inventoryQuery.trim()) {
    scheduleInventorySearch({immediate: true});
  }
  for (const [role, combo] of comboboxes) {
    if (byId("workspace-dialog").open && combo.open && combo.query.trim()) {
      scheduleComboboxSearch(role, {immediate: true});
    }
  }
}

function reconcileEvent(eventType, payload, sequence) {
  if (sequence && eventType !== "reset" && sequence <= state.lastEventSequence) return;
  if (sequence) state.lastEventSequence = Math.max(state.lastEventSequence, sequence);

  if (eventType === "reset") {
    applySnapshot(payload);
    return;
  }

  const source = payload && typeof payload === "object" ? payload : {};
  if (source.snapshot) applySnapshot(source.snapshot);
  if (source.workspace) state.workspaces = upsertById(state.workspaces, source.workspace, workspaceId);
  if (source.account) state.accounts = upsertById(state.accounts, source.account, accountId);
  if (source.run) state.runs = upsertById(state.runs, source.run, runId);
  if (source.queue) state.queue = normalizeQueue(source.queue);
  if (source.settings) state.settings = safeSettings(source.settings);
  if (source.migration) applyMigration(source.migration);

  const sourceType = safeString(firstValue(source, ["type", "event_type", "kind"]));
  const inventoryChanged = eventType === "inventory_changed" || sourceType === "inventory_changed";
  if (inventoryChanged) invalidateInventoryResults();

  const record = inventoryChanged ? null : source.record || source.event || (["run_event", "message"].includes(eventType) ? source : null);
  if (record) appendActiveRunEvent(record);
  renderAll();
}

function parseEvent(event, eventType) {
  let payload = {};
  try {
    payload = JSON.parse(event.data || "{}");
  } catch (_) {
    return;
  }
  const sequence = Number(event.lastEventId || firstValue(payload, ["seq", "sequence", "id"], 0));
  reconcileEvent(eventType, payload, Number.isFinite(sequence) ? sequence : 0);
}

function connectEvents() {
  if (state.eventSource) state.eventSource.close();
  const query = new URLSearchParams({token: state.requestToken});
  if (state.lastEventSequence) query.set("after", String(state.lastEventSequence));
  const source = new EventSource(`/api/events?${query.toString()}`);
  state.eventSource = source;
  source.addEventListener("open", () => setConnection("connected", "本地服务已连接"));
  source.addEventListener("error", () => {
    setConnection("recovering", "正在恢复连接…");
    void refreshRequestToken()
      .then(() => {
        if (state.eventSource === source) connectEvents();
      })
      .catch(() => {});
  });
  for (const eventType of ["reset", "run_event", "queue", "workspace", "account", "run", "settings", "migration", "inventory_changed"]) {
    source.addEventListener(eventType, (event) => parseEvent(event, eventType));
  }
  source.addEventListener("message", (event) => parseEvent(event, "message"));
}

function comboboxInput(role) {
  return document.querySelector(`[data-combobox-input="${role}"]`);
}

function comboboxList(role) {
  return byId(`workspace-${role}-options`);
}

function comboboxStatus(role) {
  return byId(`workspace-${role}-status`);
}

function accountChoice(account, detail = "已用账号") {
  return {
    kind: "account",
    id: accountId(account),
    label: accountEmail(account),
    detail,
    status: safeString(firstValue(account, ["status", "state"], "available")),
    disabled: false,
  };
}

function inventoryChoice(item) {
  const aliasNumber = inventoryAliasNumber(item);
  const itemStatus = safeString(firstValue(item, ["status", "state"], "available"));
  return {
    kind: "inventory",
    id: inventoryId(item),
    label: inventoryEmail(item),
    detail: aliasNumber >= 1 && aliasNumber <= 5 ? `库存 · 将分配 +${aliasNumber}` : "库存 · 无可分配子号",
    aliasNumber,
    status: itemStatus,
    disabled: itemStatus !== "available" || aliasNumber < 1 || aliasNumber > 5,
  };
}

function comboboxChoices(role) {
  const combo = comboboxes.get(role);
  const query = combo.query.trim().toLocaleLowerCase("zh-CN");
  const choices = [];
  const ownerAliasId = safeString(byId("workspace-form")?.elements.namedItem("owner_alias_id")?.value);
  const seen = new Set();
  const add = (choice) => {
    const key = `${choice.kind}:${choice.id}`;
    if (!choice.id || seen.has(key)) return;
    seen.add(key);
    choices.push(choice);
  };
  if (combo.original) add({...combo.original, detail: "当前绑定"});
  if (combo.selected) add(combo.selected);
  for (const account of state.accounts) {
    const id = accountId(account);
    const status = safeString(firstValue(account, ["status", "state"]));
    const isPinned = combo.original?.id === id || combo.selected?.id === id;
    if (status !== "available" && !isPinned) continue;
    if (ownerAliasId && safeString(account.icloud_owner_alias_id) !== ownerAliasId && !isPinned) continue;
    const email = accountEmail(account);
    const haystack = `${email} ${safeString(account.primary_email)}`.toLocaleLowerCase("zh-CN");
    if (query && !haystack.includes(query)) continue;
    add(accountChoice(account));
    if (choices.filter((choice) => choice.kind === "account").length >= 8) break;
  }
  if (!ownerAliasId) {
    for (const item of combo.inventoryResults.slice(0, INVENTORY_SEARCH_LIMIT)) add(inventoryChoice(item));
  }
  return choices;
}

function syncComboboxHiddenValues(role) {
  const combo = comboboxes.get(role);
  const form = byId("workspace-form");
  form.elements.namedItem(`${role}_account_id`).value = combo.selected?.kind === "account" ? combo.selected.id : "";
  form.elements.namedItem(`${role}_inventory_id`).value = combo.selected?.kind === "inventory" ? combo.selected.id : "";
}

function renderCombobox(role) {
  const combo = comboboxes.get(role);
  const input = comboboxInput(role);
  const list = comboboxList(role);
  const status = comboboxStatus(role);
  const choices = comboboxChoices(role);
  const clearButton = document.querySelector(`[data-action="clear-combobox"][data-role="${role}"]`);
  if (clearButton) clearButton.disabled = !combo.selected && !combo.query;
  syncComboboxHiddenValues(role);
  input.setAttribute("aria-expanded", String(combo.open));
  list.hidden = !combo.open;
  list.replaceChildren();

  if (combo.open) {
    if (!choices.length) {
      const message = combo.loading ? "正在搜索库存…" : combo.error ? combo.error : combo.query.trim() ? "未找到匹配账号或库存" : "没有可用账号，输入邮箱搜索库存";
      list.append(element("li", {className: "empty-state", text: message, attrs: {role: "presentation"}}));
      combo.activeIndex = -1;
    } else {
      combo.activeIndex = Math.min(Math.max(combo.activeIndex, -1), choices.length - 1);
      const fragment = document.createDocumentFragment();
      choices.forEach((choice, index) => {
        const optionId = `workspace-${role}-option-${index}`;
        const option = element("button", {
          className: "combobox-option",
          dataset: {action: "select-combobox-option", role, index},
          attrs: {
            id: optionId,
            type: "button",
            role: "option",
            "aria-selected": String(index === combo.activeIndex),
          },
        }, [
          element("span", {className: "combobox-option__copy"}, [
            element("strong", {text: choice.label}),
            element("small", {text: choice.detail}),
          ]),
          element("span", {className: "combobox-option__kind", text: choice.kind === "account" ? "账号" : "库存"}),
        ]);
        option.disabled = choice.disabled;
        fragment.append(element("li", {attrs: {role: "presentation"}}, [option]));
      });
      list.append(fragment);
    }
  }

  if (combo.activeIndex >= 0 && choices[combo.activeIndex]) {
    input.setAttribute("aria-activedescendant", `workspace-${role}-option-${combo.activeIndex}`);
  } else {
    input.removeAttribute("aria-activedescendant");
  }
  status.dataset.state = combo.error ? "error" : combo.selected ? "selected" : "idle";
  status.textContent = combo.error
    ? combo.error
    : combo.selected
      ? `${combo.selected.kind === "account" ? "已选账号" : "提交时分配"}：${combo.selected.label}${combo.selected.kind === "inventory" ? ` +${combo.selected.aliasNumber}` : ""}`
      : combo.loading
        ? "正在搜索库存…"
        : "可选择已用账号，或输入主邮箱搜索库存";
}

function cancelComboboxSearch(role, {invalidate = true} = {}) {
  const combo = comboboxes.get(role);
  if (combo.searchTimer) window.clearTimeout(combo.searchTimer);
  combo.searchTimer = null;
  combo.requestController?.abort();
  combo.requestController = null;
  combo.loading = false;
  if (invalidate) combo.searchSequence += 1;
}

function scheduleComboboxSearch(role, {immediate = false} = {}) {
  const combo = comboboxes.get(role);
  cancelComboboxSearch(role);
  if (!combo.query.trim()) {
    combo.inventoryResults = [];
    combo.error = "";
    renderCombobox(role);
    return;
  }
  combo.searchTimer = window.setTimeout(() => {
    combo.searchTimer = null;
    searchComboboxInventory(role).catch(() => {});
  }, immediate ? 0 : INVENTORY_SEARCH_DELAY);
}

async function searchComboboxInventory(role) {
  const combo = comboboxes.get(role);
  const query = combo.query.trim();
  if (!query) return;
  const sequence = ++combo.searchSequence;
  const controller = new AbortController();
  combo.requestController = controller;
  combo.loading = true;
  combo.error = "";
  renderCombobox(role);
  const params = new URLSearchParams({query, status: "available", limit: String(INVENTORY_SEARCH_LIMIT)});
  try {
    const payload = await api(`/api/mailbox-inventory?${params.toString()}`, {signal: controller.signal});
    if (sequence !== combo.searchSequence) return;
    combo.inventoryResults = asList(payload, ["inventory", "mailbox_inventory"]).slice(0, INVENTORY_SEARCH_LIMIT);
  } catch (error) {
    if (error?.code === "request_cancelled" || sequence !== combo.searchSequence) return;
    combo.error = error?.message || String(error);
    combo.inventoryResults = [];
  } finally {
    if (sequence === combo.searchSequence) {
      combo.loading = false;
      combo.requestController = null;
      renderCombobox(role);
    }
  }
}

function selectComboboxChoice(role, index) {
  const combo = comboboxes.get(role);
  const choice = comboboxChoices(role)[index];
  if (!choice || choice.disabled) return;
  combo.selected = choice;
  combo.query = choice.label;
  combo.open = false;
  combo.activeIndex = -1;
  comboboxInput(role).value = choice.label;
  cancelComboboxSearch(role);
  renderCombobox(role);
  comboboxInput(role).focus();
}

function clearCombobox(role) {
  const combo = comboboxes.get(role);
  cancelComboboxSearch(role);
  combo.selected = null;
  combo.query = "";
  combo.inventoryResults = [];
  combo.error = "";
  combo.open = true;
  combo.activeIndex = -1;
  const input = comboboxInput(role);
  input.value = "";
  renderCombobox(role);
  input.focus();
}

function moveComboboxActive(role, direction) {
  const combo = comboboxes.get(role);
  const choices = comboboxChoices(role);
  const available = choices.map((choice, index) => choice.disabled ? -1 : index).filter((index) => index >= 0);
  if (!available.length) return;
  const currentPosition = available.indexOf(combo.activeIndex);
  const nextPosition = currentPosition < 0
    ? direction > 0 ? 0 : available.length - 1
    : (currentPosition + direction + available.length) % available.length;
  combo.activeIndex = available[nextPosition];
  combo.open = true;
  renderCombobox(role);
  byId(`workspace-${role}-option-${combo.activeIndex}`)?.scrollIntoView({block: "nearest"});
}

function resetComboboxes() {
  for (const [role, combo] of comboboxes) {
    cancelComboboxSearch(role);
    combo.selected = null;
    combo.original = null;
    combo.query = "";
    combo.inventoryResults = [];
    combo.error = "";
    combo.open = false;
    combo.activeIndex = -1;
    const input = comboboxInput(role);
    if (input) input.value = "";
    if (input) renderCombobox(role);
  }
}

function initializeCombobox(role, accountIdentifier) {
  const combo = comboboxes.get(role);
  cancelComboboxSearch(role);
  const account = findAccount(accountIdentifier);
  const selected = account ? accountChoice(account, "当前绑定") : null;
  combo.selected = selected;
  combo.original = selected;
  combo.query = selected?.label || "";
  combo.inventoryResults = [];
  combo.error = "";
  combo.open = false;
  combo.activeIndex = -1;
  comboboxInput(role).value = combo.query;
  renderCombobox(role);
}

function renderWorkspaceOwnerOptions(selectedId = "") {
  const select = byId("workspace-form").elements.namedItem("owner_alias_id");
  select.replaceChildren(element("option", {text: "普通空间（不绑定 iCloud 母号）", attrs: {value: ""}}));
  for (const owner of state.icloudTeamOwners) {
    const workspaceLabel = owner.workspace_name ? ` · ${safeString(owner.workspace_name)}` : "";
    select.append(element("option", {
      text: `${safeString(owner.email)}${workspaceLabel}`,
      attrs: {value: safeString(owner.id)},
    }));
  }
  select.value = safeString(selectedId);
}

async function openWorkspaceDialog(workspace = null) {
  await loadIcloudTeamOwners();
  const dialog = byId("workspace-dialog");
  const form = byId("workspace-form");
  byId("workspace-dialog-title").textContent = workspace ? "编辑空间" : "新增空间";
  form.elements.namedItem("workspace_id").value = workspace ? workspaceId(workspace) : "";
  form.elements.namedItem("version").value = workspace ? safeString(firstValue(workspace, ["version"], 1)) : "";
  form.elements.namedItem("name").value = workspace ? workspaceName(workspace) : "";
  const uidControl = form.elements.namedItem("workspace_uid");
  uidControl.value = workspace ? workspaceUid(workspace) : "";
  uidControl.readOnly = Boolean(workspace);
  uidControl.setAttribute("aria-readonly", String(Boolean(workspace)));
  renderWorkspaceOwnerOptions(firstValue(workspace, ["owner_alias_id"]));
  initializeCombobox("current", firstValue(workspace, ["current_account_id"]));
  initializeCombobox("next", firstValue(workspace, ["next_account_id"]));
  byId("workspace-form-error").hidden = true;
  dialog.showModal();
}

function closeDialog(button) {
  const dialog = button.closest("dialog");
  if (dialog) dialog.close();
}

function stageStatesFromRun(run, events) {
  const explicit = run?.stages && typeof run.stages === "object" ? run.stages : {};
  const result = {};
  for (const [step] of STEP_DEFINITIONS) result[step] = safeString(explicit[step], "pending");
  for (const event of events) {
    const step = safeString(firstValue(event, ["step", "stage"]));
    if (!step || !(step in result)) continue;
    const eventState = safeString(firstValue(event, ["state", "status"]));
    if (eventState) result[step] = eventState;
    else if (firstValue(event, ["level"]) === "error") result[step] = "failed";
  }
  const current = safeString(firstValue(run, ["current_step", "step"]));
  const runState = safeString(firstValue(run, ["state", "status"]));
  if (current && result[current] === "pending" && ACTIVE_RUN_STATES.has(runState)) result[current] = "running";
  if (runState === "succeeded") {
    const output = runResultObject(run);
    for (const [step] of STEP_DEFINITIONS) {
      if (step === "sub2api_export") {
        result[step] = firstValue(output, ["sub2api_path", "sub2api_export_path"]) ? "done" : "skipped";
      } else if (["member_verify", "rescue_verify"].includes(step)) {
        result[step] = output.member_guard?.verified ? "done" : "skipped";
      } else if (step === "push") {
        result[step] = output.push ? "done" : "skipped";
      } else if (step === "push_sub2api") {
        result[step] = output.sub2api ? "done" : "skipped";
      } else {
        result[step] = "done";
      }
    }
  }
  return result;
}

function runResultObject(run) {
  const result = run?.result || run?.result_json || {};
  if (result && typeof result === "object") return result;
  try {
    const parsed = JSON.parse(result);
    return parsed && typeof parsed === "object" ? parsed : {};
  } catch (_) {
    return {};
  }
}

function deliveryResultText(value) {
  if (!value) return "未启用";
  if (typeof value !== "object") return safeString(value, "-");
  const action = safeString(firstValue(value, ["action", "status"], "已执行"));
  const verified = firstValue(value, ["verified"], null);
  if (verified === true) return `${action} · 已验证`;
  if (verified === false) return `${action} · 未验证`;
  return action;
}

function renderRunDetail(run, events = []) {
  const container = byId("run-detail-content");
  container.replaceChildren();
  if (!run) {
    container.append(element("div", {className: "inline-error", text: state.errors.runDetail || "运行详情不可用"}));
    return;
  }

  const id = runId(run);
  const runState = safeString(firstValue(run, ["state", "status"], "queued"));
  const [current, next] = runAccountSnapshot(run);
  const result = runResultObject(run);
  const runKind = safeString(firstValue(run, ["kind"], result?.mode), "handoff");
  const isRescue = runKind === "rescue";
  const memberGuard = firstValue(result, ["member_guard"], null);
  const memberGuardText = memberGuard?.verified
    ? `${numberFormatter.format(Number(memberGuard.active_members || 0))} / 2 · 已复核`
    : "2 人硬上限";
  byId("run-dialog-title").textContent = runWorkspaceLabel(run);
  const identity = element("div", {className: "run-identity"});
  const identityItems = [
    ["运行类型", element("strong", {text: isRescue ? "母号提拉" : "子号换班"})],
    ["运行状态", statusBadge(runState, RUN_STATUS)],
    ["运行 ID", element("strong", {className: "cell-code", text: shortId(id), attrs: {title: id}})],
    [isRescue ? "故障子号快照" : "当前账号快照", element("strong", {text: current, attrs: {title: current}})],
    ["新子号快照", element("strong", {text: next, attrs: {title: next}})],
    ["活跃成员", element("strong", {text: memberGuardText})],
  ];
  for (const [label, value] of identityItems) {
    const item = element("div", {}, [element("span", {text: label}), value]);
    identity.append(item);
  }
  container.append(identity);

  const stageSection = element("section", {className: "stage-section"}, [element("h3", {text: "自动化闭环"})]);
  const stageGroups = element("div", {className: "stage-groups"});
  const stageStates = stageStatesFromRun(run, events);
  let stageIndex = 0;
  for (const [groupLabel, steps] of stepGroupsForRun(run)) {
    const group = element("section", {className: "stage-group"}, [
      element("h4", {text: groupLabel}),
    ]);
    const stageList = element("ol", {className: "stage-list"});
    for (const [step, label] of steps) {
      const stageState = stageStates[step];
      stageIndex += 1;
      stageList.append(element("li", {className: "stage-item", dataset: {state: stageState}}, [
        element("span", {className: "stage-index", text: String(stageIndex).padStart(2, "0")}),
        element("span", {className: "stage-name", text: label}),
        element("span", {className: "stage-state", text: STEP_STATE_LABELS[stageState] || stageState}),
      ]));
    }
    group.append(stageList);
    stageGroups.append(group);
  }
  stageSection.append(stageGroups);
  container.append(stageSection);

  const redactedError = safeString(firstValue(run, ["redacted_error", "error"]));
  if (redactedError) container.append(element("div", {className: "inline-error", text: redactedError}));

  const important = events.filter((record) => !Boolean(record.routine)).slice(-8).reverse();
  const eventSection = element("section", {className: "event-section"}, [element("h3", {text: "关键事件"})]);
  const eventList = element("ol", {className: "event-list"});
  if (!important.length) {
    eventList.append(element("li", {className: "empty-state", text: "暂无关键事件"}));
  } else {
    for (const record of important) {
      eventList.append(element("li", {dataset: {level: firstValue(record, ["level"], "info")}}, [
        element("time", {text: formatDate(firstValue(record, ["created_at", "timestamp"]))}),
        element("span", {text: safeString(firstValue(record, ["message"], ""))}),
      ]));
    }
  }
  eventSection.append(eventList);
  container.append(eventSection);

  const details = element("details", {className: "diagnostics"});
  details.append(element("summary", {text: `详细诊断 · ${numberFormatter.format(events.length)} 条` }));
  const log = element("div", {className: "diagnostic-log", attrs: {tabindex: "0", "aria-label": "详细诊断日志"}});
  const visibleEvents = events.slice(-MAX_DIAGNOSTIC_ROWS);
  if (!visibleEvents.length) {
    log.append(element("div", {className: "log-line"}, [element("time", {text: "--:--:--"}), element("span", {text: "暂无诊断日志"})]));
  } else {
    for (const record of visibleEvents) {
      log.append(element("div", {className: "log-line", dataset: {level: firstValue(record, ["level"], "info")}}, [
        element("time", {text: formatDate(firstValue(record, ["created_at", "timestamp"]))}),
        element("span", {text: safeString(firstValue(record, ["message"], ""))}),
      ]));
    }
  }
  details.append(log);
  container.append(details);

  const outputs = [
    ["CPA 文件", firstValue(result, ["cpa_path", "output_path"], firstValue(run, ["cpa_path"]))],
    ["Sub2API 文件", firstValue(result, ["sub2api_path", "sub2api_export_path"], firstValue(run, ["sub2api_path"]))],
    ["CPA 推送", deliveryResultText(firstValue(result, ["push", "management_status", "push_status"], null))],
    ["Sub2API 推送", deliveryResultText(firstValue(result, ["sub2api", "sub2api_status"], null))],
  ];
  const outputSection = element("section", {className: "output-section"}, [element("h3", {text: "输出"})]);
  const outputList = element("dl", {className: "run-output"});
  for (const [label, value] of outputs) {
    outputList.append(element("div", {}, [element("dt", {text: label}), element("dd", {text: safeString(value, "-")})]));
  }
  outputSection.append(outputList);
  container.append(outputSection);

  const footer = byId("run-dialog-footer");
  footer.replaceChildren(actionButton("关闭", "close-dialog", {}, "button"));
  if (ACTIVE_RUN_STATES.has(runState)) {
    footer.append(actionButton("停止运行", "stop-run", {runId: id}, "button button--danger"));
  } else if (runState === "failed") {
    const workspaceIdentifier = safeString(firstValue(run, ["workspace_id"]));
    if (workspaceIdentifier) footer.append(actionButton("重试空间", "retry-workspace", {workspaceId: workspaceIdentifier}, "button button--primary"));
  }
}

async function openRunDetail(id) {
  state.activeRunId = id;
  state.activeRun = null;
  state.activeRunEvents = [];
  byId("run-detail-content").replaceChildren(element("div", {className: "loading-block"}, [
    element("span", {className: "inline-loader", attrs: {"aria-hidden": "true"}}),
    "正在载入运行详情…",
  ]));
  byId("run-dialog").showModal();
  try {
    const payload = await api(`/api/runs/${encodeURIComponent(id)}`);
    const run = payload?.run && typeof payload.run === "object" ? payload.run : payload;
    const events = asList(payload, ["events", "run_events", "logs"]);
    state.activeRun = run;
    state.activeRunEvents = events.slice(-MAX_EVENT_MEMORY);
    renderRunDetail(run, state.activeRunEvents);
  } catch (error) {
    state.errors.runDetail = error?.message || String(error);
    renderRunDetail(null);
  }
}

function fieldError(containerId, message) {
  const container = byId(containerId);
  container.textContent = message;
  container.hidden = !message;
}

async function withBusy(button, task) {
  if (!button) return task();
  const originalDisabled = button.disabled;
  button.disabled = true;
  button.setAttribute("aria-busy", "true");
  try {
    return await task();
  } catch (error) {
    if (isMigrationError(error)) showMigrationBlocked(error.message);
    showToast(error?.message || String(error), "error");
    throw error;
  } finally {
    button.removeAttribute("aria-busy");
    button.disabled = originalDisabled;
  }
}

async function chooseLocalPath(kind, current = "") {
  const payload = await api("/api/dialog", {
    method: "POST",
    body: {kind, current},
  });
  return safeString(firstValue(payload, ["path"]));
}

async function enqueueSelected() {
  if (!ensureMutable()) return;
  const workspaceIds = [...state.selectedWorkspaceIds];
  if (!workspaceIds.length) return;
  await api("/api/queue", {method: "POST", body: {workspace_ids: workspaceIds}});
  state.selectedWorkspaceIds.clear();
  await refreshResources(["workspaces", "runs", "queue"]);
  showToast(`${numberFormatter.format(workspaceIds.length)} 个空间已加入队列`, "success");
}

async function retryWorkspace(id) {
  if (!ensureMutable()) return;
  await api(`/api/workspaces/${encodeURIComponent(id)}/retry`, {method: "POST", body: {}});
  await refreshResources(["workspaces", "runs", "queue"]);
  showToast("重试任务已加入队列", "success");
}

async function refreshImportedChild(id, mode) {
  if (!ensureMutable()) return;
  if (state.pendingAccountRefreshIds.has(id)) {
    showToast("该子号正在刷新，请等待当前操作完成", "info");
    return;
  }
  state.pendingAccountRefreshIds.add(id);
  state.queueExpanded = true;
  renderAccountTable();
  renderQueue();
  try {
    let path = null;
    if (mode !== "current") {
      path = await chooseLocalPath("json", "");
      if (!path) return;
    } else {
      showToast("正在重新登录并生成新令牌，请稍候…", "info");
    }
    const result = await api(`/api/accounts/${encodeURIComponent(id)}/refresh`, {
      method: "POST",
      body: path ? {path} : {},
    });
    await refreshResources(["accounts", "workspaces", "runs", "queue"]);
    if (mode === "current") {
      const prefix = result.reused ? "刚才已完成，未重复创建令牌" : "新令牌 JSON 已导出";
      showToast(`${prefix}：${safeString(result.sub2api_path)}`, "success");
    } else {
      showToast("已确认新 token，失败任务已重新入队", "success");
    }
  } finally {
    state.pendingAccountRefreshIds.delete(id);
    renderAccountTable();
  }
}

async function updateAccountStatus(id, nextStatus) {
  if (!ensureMutable()) return;
  if (nextStatus === "retired" && !window.confirm("退役后该账号不会再用于空间绑定。确认继续？")) return;
  await api(`/api/accounts/${encodeURIComponent(id)}/status`, {method: "PATCH", body: {status: nextStatus}});
  await refreshResources(["accounts", "workspaces"]);
  showToast("账号状态已更新", "success");
}

async function stopRun(id) {
  if (!ensureMutable()) return;
  if (!window.confirm("确认停止当前运行？已完成的阶段检查点会保留。")) return;
  await api(`/api/runs/${encodeURIComponent(id)}/stop`, {method: "POST", body: {}});
  await refreshResources(["workspaces", "runs", "queue"]);
  showToast("已请求停止运行", "success");
}

async function moveQueueItem(id, direction) {
  if (!ensureMutable()) return;
  const items = activeQueueItems();
  const index = items.findIndex((item) => safeString(firstValue(item, ["id", "queue_item_id"])) === id);
  const target = direction === "up" ? index - 1 : index + 1;
  if (index < 0 || target < 0 || target >= items.length) return;
  [items[index], items[target]] = [items[target], items[index]];
  const itemIds = items.map((item) => safeString(firstValue(item, ["id", "queue_item_id"])));
  await api("/api/queue/order", {method: "PATCH", body: {queue_item_ids: itemIds}});
  await refreshResources(["queue"]);
}

async function toggleQueuePause() {
  if (!ensureMutable()) return;
  const paused = !state.queue.paused;
  await api("/api/queue/pause", {method: "POST", body: {paused}});
  await refreshResources(["queue"]);
  showToast(paused ? "队列已暂停" : "队列已继续", "success");
}

async function retryMigrationCleanup() {
  let payload;
  try {
    payload = await api("/api/migration/cleanup", {method: "POST", body: {}});
  } catch (error) {
    if (error?.status !== 404) throw error;
    payload = await api("/api/migration/cleanup/retry", {method: "POST", body: {}});
  }
  applyMigration(payload);
  if (!state.migrationBlocked) {
    await refreshResources(["workspaces", "accounts", "runs", "queue", "settings"]);
    showToast("迁移清理已完成", "success");
  }
}

async function createBackup() {
  if (!ensureMutable()) return;
  const payload = await api("/api/backups", {method: "POST", body: {}});
  const path = safeString(firstValue(payload, ["path", "backup_path"]), "备份已创建");
  byId("backup-status").textContent = `最近备份：${path}`;
  showToast("加密备份已创建", "success");
}

async function restoreBackup() {
  if (!ensureMutable()) return;
  const path = await chooseLocalPath("backup", "");
  if (!path) return;
  if (!window.confirm("恢复会替换当前本地数据库，且队列必须已暂停。确认继续？")) return;
  await api("/api/backups/restore", {method: "POST", body: {path}});
  await refreshResources(["workspaces", "accounts", "runs", "queue", "settings"]);
  renderSettings({force: true});
  showToast("备份恢复完成", "success");
}

async function handleWorkspaceSubmit(form) {
  if (!ensureMutable()) return;
  fieldError("workspace-form-error", "");
  const values = Object.fromEntries(new FormData(form).entries());
  if (!safeString(values.name).trim() || !safeString(values.workspace_uid).trim()) {
    fieldError("workspace-form-error", "空间名称和 Workspace ID 不能为空");
    const firstInvalid = !safeString(values.name).trim() ? form.elements.namedItem("name") : form.elements.namedItem("workspace_uid");
    firstInvalid.focus();
    return;
  }
  const current = comboboxes.get("current").selected;
  const next = comboboxes.get("next").selected;
  const ownerAliasId = safeString(values.owner_alias_id).trim();
  if (!current || (!ownerAliasId && !next)) {
    fieldError("workspace-form-error", ownerAliasId ? "请选择当前子号（实际执行账号）" : "请明确选择当前账号和下一账号");
    comboboxInput(!current ? "current" : "next").focus();
    return;
  }
  if (ownerAliasId && current.kind !== "account") {
    fieldError("workspace-form-error", "iCloud 母号空间的当前执行账号必须来自已接管子号 Alias");
    comboboxInput("current").focus();
    return;
  }
  if (ownerAliasId && safeString(findAccount(current.id)?.icloud_owner_alias_id) !== ownerAliasId) {
    fieldError("workspace-form-error", "当前执行子号不属于所选归属母号");
    comboboxInput("current").focus();
    return;
  }
  if (current.kind === "account" && next?.kind === "account" && current.id === next.id) {
    fieldError("workspace-form-error", "当前账号和下一账号不能相同");
    return;
  }
  const payload = {
    name: safeString(values.name).trim(),
    owner_alias_id: ownerAliasId || null,
  };
  if (current.kind === "account") payload.current_account_id = current.id;
  else payload.current_inventory_id = current.id;
  if (next?.kind === "account") payload.next_account_id = next.id;
  else if (next?.kind === "inventory") payload.next_inventory_id = next.id;
  const id = safeString(values.workspace_id);
  if (id) {
    payload.version = Number(values.version || 1);
    if (!next) payload.clear_next_account = true;
    await api(`/api/workspaces/${encodeURIComponent(id)}`, {method: "PATCH", body: payload});
  } else {
    payload.workspace_uid = safeString(values.workspace_uid).trim();
    await api("/api/workspaces", {method: "POST", body: payload});
  }
  byId("workspace-dialog").close();
  await refreshResources(["workspaces", "accounts"]);
  showToast(id ? "空间已更新" : "空间已添加", "success");
}

async function handleAccountImport(form) {
  if (!ensureMutable()) return;
  fieldError("account-import-error", "");
  const path = safeString(new FormData(form).get("path")).trim();
  if (!path) {
    fieldError("account-import-error", "请选择 Outlook / Hotmail TXT 文件");
    return;
  }
  const payload = await api("/api/accounts/import", {method: "POST", body: {path}});
  byId("account-import-dialog").close();
  form.reset();
  const imported = Number(firstValue(payload, ["imported", "created"], 0));
  const existing = Number(firstValue(payload, ["existing", "unchanged"], 0));
  const invalid = Number(firstValue(payload, ["invalid", "rejected"], 0));
  state.inventoryDirty = true;
  if (state.accountView === "inventory" && state.inventoryQuery.trim()) scheduleInventorySearch({immediate: true});
  showToast(`库存导入完成：新增 ${numberFormatter.format(imported)}，已存在 ${numberFormatter.format(existing)}，无效 ${numberFormatter.format(invalid)}`, "success");
}

function openInventoryAllocation(item) {
  if (!item) return;
  const dialog = byId("account-allocation-dialog");
  const form = byId("account-allocation-form");
  form.elements.namedItem("inventory_id").value = inventoryId(item);
  byId("allocation-primary-email").textContent = inventoryEmail(item);
  byId("allocation-next-alias").textContent = inventoryAliasEmail(item);
  fieldError("account-allocation-error", "");
  dialog.showModal();
}

function openAccountProxyDialog(account) {
  if (!account) return;
  const dialog = byId("account-proxy-dialog");
  const form = byId("account-proxy-form");
  form.reset();
  form.elements.namedItem("account_id").value = accountId(account);
  byId("account-proxy-email").textContent = accountEmail(account);
  byId("account-proxy-state").textContent = account.proxy_configured ? "已配置独立代理" : "继承全局代理";
  const clearButton = form.querySelector('[data-action="clear-account-proxy"]');
  clearButton.disabled = !account.proxy_configured;
  fieldError("account-proxy-error", "");
  dialog.showModal();
  form.elements.namedItem("proxy").focus();
}

async function handleAccountProxySubmit(form) {
  if (!ensureMutable()) return;
  fieldError("account-proxy-error", "");
  const data = new FormData(form);
  const accountIdentifier = safeString(data.get("account_id"));
  const proxy = safeString(data.get("proxy")).trim();
  if (!accountIdentifier || !proxy) {
    fieldError("account-proxy-error", "请输入完整的代理地址");
    return;
  }
  await api(`/api/accounts/${encodeURIComponent(accountIdentifier)}/proxy`, {
    method: "PUT",
    body: {proxy},
  });
  byId("account-proxy-dialog").close();
  await refreshResources(["accounts"]);
  showToast("账号代理已保存", "success");
}

async function clearAccountProxy(form) {
  if (!ensureMutable()) return;
  const accountIdentifier = safeString(form.elements.namedItem("account_id").value);
  const account = findAccount(accountIdentifier);
  if (!accountIdentifier || !account?.proxy_configured) return;
  if (!window.confirm(`清除 ${accountEmail(account)} 的独立代理？`)) return;
  await api(`/api/accounts/${encodeURIComponent(accountIdentifier)}/proxy`, {
    method: "PUT",
    body: {proxy: ""},
  });
  byId("account-proxy-dialog").close();
  await refreshResources(["accounts"]);
  showToast("账号代理已清除", "success");
}

function openIcloudMailboxDialog(mailbox = null) {
  const dialog = byId("icloud-mailbox-dialog");
  const form = byId("icloud-mailbox-form");
  form.reset();
  const editing = Boolean(mailbox);
  byId("icloud-mailbox-dialog-title").textContent = editing ? "编辑 iCloud 资源池" : "添加 iCloud 资源池";
  form.elements.namedItem("mailbox_id").value = editing ? icloudMailboxId(mailbox) : "";
  form.elements.namedItem("name").value = editing ? safeString(mailbox.name) : "";
  form.elements.namedItem("forwarding_email").value = editing ? safeString(mailbox.forwarding_email) : "";
  const sessionInput = form.elements.namedItem("session_import");
  sessionInput.value = "";
  sessionInput.required = !editing;
  sessionInput.placeholder = editing ? "未更改" : "";
  for (const name of ["imap_host", "imap_username", "imap_folder"]) {
    const input = form.elements.namedItem(name);
    input.value = editing ? "" : name === "imap_folder" ? "INBOX" : "";
    input.required = !editing;
    input.placeholder = editing ? "未更改" : "";
  }
  const port = form.elements.namedItem("imap_port");
  port.value = editing ? "" : "993";
  port.required = !editing;
  port.placeholder = editing ? "未更改" : "";
  const password = form.elements.namedItem("imap_password");
  password.value = "";
  password.required = !editing;
  password.placeholder = editing ? "未更改" : "";
  const proxy = form.elements.namedItem("proxy");
  proxy.value = "";
  proxy.placeholder = editing && mailbox.proxy_configured ? "未更改" : "socks5h://user:password@host:port";
  const clearControl = byId("icloud-clear-proxy-control");
  clearControl.hidden = !editing || !mailbox.proxy_configured;
  form.elements.namedItem("clear_proxy").checked = false;
  fieldError("icloud-mailbox-form-error", "");
  dialog.showModal();
  form.elements.namedItem("name").focus();
}

async function handleIcloudMailboxSubmit(form) {
  if (!ensureMutable()) return;
  fieldError("icloud-mailbox-form-error", "");
  const data = new FormData(form);
  const id = safeString(data.get("mailbox_id")).trim();
  const name = safeString(data.get("name")).trim();
  const forwardingEmail = safeString(data.get("forwarding_email")).trim();
  if (!name || !forwardingEmail) {
    fieldError("icloud-mailbox-form-error", "资源池名称和转发邮箱不能为空");
    return;
  }
  const payload = {name, forwarding_email: forwardingEmail};
  const textFields = ["session_import", "imap_host", "imap_username", "imap_password", "imap_folder", "proxy"];
  for (const field of textFields) {
    const value = safeString(data.get(field));
    const clean = field === "imap_password" ? value : value.trim();
    if (clean) payload[field] = clean;
  }
  const port = safeString(data.get("imap_port")).trim();
  if (port) payload.imap_port = Number(port);
  if (data.get("clear_proxy") === "on") payload.clear_proxy = true;
  if (!id) {
    const required = ["session_import", "imap_host", "imap_username", "imap_password", "imap_folder"];
    const missing = required.find((field) => !payload[field]);
    if (missing || !payload.imap_port) {
      fieldError("icloud-mailbox-form-error", "iCloud Session 和 IMAP 配置不能为空");
      return;
    }
  }
  let saved;
  try {
    saved = await api(id ? `/api/icloud-mailboxes/${encodeURIComponent(id)}` : "/api/icloud-mailboxes", {
      method: id ? "PATCH" : "POST",
      body: payload,
      timeout: 30000,
    });
  } catch (error) {
    fieldError("icloud-mailbox-form-error", error?.message || String(error));
    throw error;
  }
  byId("icloud-mailbox-dialog").close();
  state.icloudMailboxesLoaded = false;
  await loadIcloudMailboxes({force: true});
  showToast(
    id && safeString(saved?.status) === "unchecked"
      ? "iCloud 资源池已更新，需重新检测"
      : id
        ? "iCloud 资源池已更新"
        : "iCloud 资源池已安全保存",
    "success",
  );
}

async function checkIcloudMailbox(id) {
  if (!ensureMutable()) return;
  try {
    const result = await api(`/api/icloud-mailboxes/${encodeURIComponent(id)}/check`, {
      method: "POST",
      body: {},
      timeout: 45000,
    });
    showToast(`资源池检测通过，iCloud 当前有 ${numberFormatter.format(Number(result.remote_alias_count || 0))} 个 Alias`, "success");
  } finally {
    state.icloudMailboxesLoaded = false;
    await loadIcloudMailboxes({force: true});
  }
}

const ICLOUD_HME_CAPTURE_STATE = {
  idle: "尚未启动",
  starting: "正在启动",
  waiting_login: "等待登录",
  verifying: "正在验证",
  cancelling: "正在取消",
  captured: "捕获成功",
  failed: "捕获失败",
  cancelled: "已取消",
};

function stopIcloudHmeCapturePolling() {
  if (state.icloudHmeCapturePollTimer !== null) {
    window.clearTimeout(state.icloudHmeCapturePollTimer);
    state.icloudHmeCapturePollTimer = null;
  }
}

function renderIcloudHmeCaptureStatus(status) {
  const source = status && typeof status === "object" ? status : {};
  const captureState = safeString(source.state, "idle");
  const active = Boolean(source.active);
  state.icloudHmeCaptureStatus = source;
  byId("icloud-hme-capture-state").textContent = ICLOUD_HME_CAPTURE_STATE[captureState] || captureState;
  byId("icloud-hme-capture-message").textContent = safeString(source.message, "等待启动登录窗口");
  byId("icloud-hme-capture-progress").dataset.state = captureState;
  byId("icloud-hme-capture-loader").hidden = !active;
  byId("icloud-hme-capture-cancel").hidden = !active;
  const error = captureState === "failed" ? safeString(source.message) : "";
  fieldError("icloud-hme-capture-error", error);
}

async function validateCapturedIcloudSession(mailboxId) {
  let valid = false;
  try {
    const result = await api(`/api/icloud-mailboxes/${encodeURIComponent(mailboxId)}/check`, {
      method: "POST",
      body: {},
      timeout: 45000,
    });
    showToast(
      `HME Session 已更新，iCloud 当前有 ${numberFormatter.format(Number(result.remote_alias_count || 0))} 个 Alias`,
      "success",
    );
    valid = true;
  } catch (error) {
    showToast(`HME Session 已保存，但资源池检测失败：${error?.message || String(error)}`, "error");
  } finally {
    state.icloudMailboxesLoaded = false;
    await loadIcloudMailboxes({force: true});
  }
  return valid;
}

async function handleIcloudHmeCaptureCompletion(mailboxId, status) {
  const key = `${mailboxId}:${safeString(status.finished_at, status.state)}`;
  if (state.icloudHmeCaptureHandled.has(key)) return;
  state.icloudHmeCaptureHandled.add(key);
  if (status.state === "captured") {
    const valid = await validateCapturedIcloudSession(mailboxId);
    const draft = state.pendingIcloudTeamImport;
    if (valid && draft && safeString(draft.values?.mailbox_id) === safeString(mailboxId)) {
      byId("icloud-hme-capture-dialog").close();
      await openIcloudTeamImport(draft.ownerId, {draft, autoLoad: true});
    }
  } else if (status.state === "failed") {
    showToast(status.message || "HME Session 自动捕获失败", "error");
  }
}

function scheduleIcloudHmeCapturePoll(mailboxId) {
  stopIcloudHmeCapturePolling();
  state.icloudHmeCapturePollTimer = window.setTimeout(() => {
    state.icloudHmeCapturePollTimer = null;
    pollIcloudHmeCapture(mailboxId).catch((error) => {
      fieldError("icloud-hme-capture-error", error?.message || String(error));
    });
  }, 700);
}

async function pollIcloudHmeCapture(mailboxId) {
  if (state.activeIcloudCaptureMailboxId !== safeString(mailboxId)) return;
  const status = await api(`/api/icloud-mailboxes/${encodeURIComponent(mailboxId)}/hme-capture`);
  renderIcloudHmeCaptureStatus(status);
  if (status.active) {
    scheduleIcloudHmeCapturePoll(mailboxId);
  } else {
    await handleIcloudHmeCaptureCompletion(mailboxId, status);
  }
}

async function openIcloudHmeCapture(mailbox) {
  if (!ensureMutable() || !mailbox) return;
  const mailboxId = icloudMailboxId(mailbox);
  state.activeIcloudCaptureMailboxId = mailboxId;
  stopIcloudHmeCapturePolling();
  byId("icloud-hme-capture-mailbox").textContent = safeString(mailbox.name);
  fieldError("icloud-hme-capture-error", "");
  renderIcloudHmeCaptureStatus({state: "starting", active: true, message: "正在打开 iCloud 登录窗口"});
  byId("icloud-hme-capture-dialog").showModal();
  try {
    let status = await api(`/api/icloud-mailboxes/${encodeURIComponent(mailboxId)}/hme-capture`);
    if (!status.active) {
      status = await api(`/api/icloud-mailboxes/${encodeURIComponent(mailboxId)}/hme-capture`, {
        method: "POST",
        body: {},
      });
    }
    renderIcloudHmeCaptureStatus(status);
    if (status.active) scheduleIcloudHmeCapturePoll(mailboxId);
    else await handleIcloudHmeCaptureCompletion(mailboxId, status);
  } catch (error) {
    renderIcloudHmeCaptureStatus({
      state: "failed",
      active: false,
      message: error?.message || String(error),
    });
    throw error;
  }
}

async function cancelIcloudHmeCapture() {
  const mailboxId = state.activeIcloudCaptureMailboxId;
  if (!mailboxId) return;
  const status = await api(`/api/icloud-mailboxes/${encodeURIComponent(mailboxId)}/hme-capture/cancel`, {
    method: "POST",
    body: {},
  });
  renderIcloudHmeCaptureStatus(status);
  if (status.active) scheduleIcloudHmeCapturePoll(mailboxId);
}

async function toggleIcloudMailbox(id, nextStatus) {
  if (!ensureMutable()) return;
  const mailbox = findIcloudMailbox(id);
  if (!mailbox) return;
  const action = nextStatus === "disabled" ? "停用" : "启用";
  if (!window.confirm(`${action} iCloud 资源池 ${safeString(mailbox.name)}？`)) return;
  await api(`/api/icloud-mailboxes/${encodeURIComponent(id)}/status`, {
    method: "PATCH",
    body: {status: nextStatus},
  });
  state.icloudMailboxesLoaded = false;
  await loadIcloudMailboxes({force: true});
  showToast(nextStatus === "disabled" ? "iCloud 资源池已停用" : "iCloud 资源池已启用，需重新检测", "success");
}

function openIcloudGenerateDialog(mailbox) {
  if (!mailbox) return;
  const form = byId("icloud-generate-form");
  form.reset();
  form.elements.namedItem("mailbox_id").value = icloudMailboxId(mailbox);
  form.elements.namedItem("count").value = "1";
  form.elements.namedItem("label_prefix").value = "Team Workflow";
  byId("icloud-generate-mailbox").textContent = safeString(mailbox.name);
  byId("icloud-generate-forwarding").textContent = safeString(mailbox.forwarding_email);
  fieldError("icloud-generate-error", "");
  byId("icloud-generate-dialog").showModal();
  form.elements.namedItem("count").focus();
}

async function handleIcloudGenerate(form) {
  if (!ensureMutable()) return;
  fieldError("icloud-generate-error", "");
  const data = new FormData(form);
  const id = safeString(data.get("mailbox_id"));
  const count = Number(data.get("count"));
  const labelPrefix = safeString(data.get("label_prefix")).trim();
  if (!id || !Number.isInteger(count) || count < 1 || count > 20 || !labelPrefix) {
    fieldError("icloud-generate-error", "生成数量或标签无效");
    return;
  }
  let result;
  try {
    result = await api(`/api/icloud-mailboxes/${encodeURIComponent(id)}/aliases`, {
      method: "POST",
      body: {count, label_prefix: labelPrefix},
      timeout: Math.min(900000, 30000 + count * 40000),
    });
  } catch (error) {
    fieldError("icloud-generate-error", error?.message || String(error));
    throw error;
  }
  byId("icloud-generate-dialog").close();
  state.icloudMailboxesLoaded = false;
  await Promise.all([loadIcloudMailboxes({force: true}), refreshResources(["accounts"])]);
  const created = Number(result.created || 0);
  showToast(
    result.stopped
      ? `已生成 ${numberFormatter.format(created)} 个，后续请求已停止`
      : `已生成 ${numberFormatter.format(created)} 个 iCloud 隐藏邮箱`,
    result.stopped ? "info" : "success",
  );
}

function renderIcloudAliases() {
  const body = byId("icloud-alias-table-body");
  body.replaceChildren();
  if (!state.icloudAliases.length) {
    body.append(element("tr", {className: "empty-row"}, [
      element("td", {text: "该资源池尚无已接管的隐藏邮箱", attrs: {colspan: "7"}}),
    ]));
    return;
  }
  const fragment = document.createDocumentFragment();
  for (const alias of state.icloudAliases) {
    const row = element("tr", {dataset: {icloudAliasId: safeString(alias.id)}});
    row.append(labeledCell("隐藏邮箱", primarySecondary(safeString(alias.email), safeString(alias.label))));
    const isOwner = alias.role === "team_owner";
    const role = primarySecondary(
      isOwner ? "Team 母号" : "轮换子号（执行账号）",
      isOwner ? "正常不操作，仅应急提拉" : `归属 ${safeString(alias.owner_email, "未指定")}`,
    );
    row.append(labeledCell("角色 / 归属", role));
    const localStatus = isOwner ? "protected" : alias.used_at ? "used" : safeString(alias.account_status, "available");
    const usage = primarySecondary(
      safeString(alias.workspace_name, isOwner ? "未绑定空间" : "未绑定"),
      isOwner
        ? `当前 ${safeString(alias.current_child_email, "未分配")} · 已用完 ${numberFormatter.format(Number(alias.used_child_count || 0))}`
        : ACCOUNT_STATUS[localStatus]?.[0] || localStatus,
    );
    row.append(labeledCell("空间 / 使用状态", usage));
    row.append(labeledCell("远端", statusBadge(safeString(alias.state), ICLOUD_ALIAS_STATUS)));
    const proxyState = alias.proxy_mode === CHAIN_PROXY_MODE
      ? alias.proxy_chain?.healthy ? "dynamic" : "degraded"
      : alias.proxy_configured ? "configured" : "missing";
    row.append(labeledCell("子号默认链路", statusBadge(proxyState, CONFIG_STATUS)));
    row.append(labeledCell("创建时间", formatDate(alias.created_at)));
    const actions = element("div", {className: "row-actions"});
    const bound = ["bound_current", "bound_next"].includes(safeString(alias.account_status));
    if (isOwner) {
      actions.append(actionButton("编辑配置", "open-icloud-owner-proxy", {aliasId: safeString(alias.id)}));
    } else {
      const target = alias.state === "active" ? "inactive" : "active";
      const button = actionButton(
        target === "active" ? "启用" : "停用",
        "set-icloud-alias-state",
        {aliasId: safeString(alias.id), state: target},
        target === "active" ? "text-action" : "text-action text-action--danger",
      );
      button.disabled = bound;
      actions.append(button);
    }
    row.append(labeledCell("操作", actions, "actions-cell"));
    fragment.append(row);
  }
  body.append(fragment);
}

async function openIcloudAliases(mailbox) {
  if (!mailbox) return;
  state.activeIcloudMailboxId = icloudMailboxId(mailbox);
  state.icloudAliases = [];
  byId("icloud-alias-title").textContent = `${safeString(mailbox.name)} · Alias`;
  const body = byId("icloud-alias-table-body");
  body.replaceChildren(element("tr", {className: "loading-row"}, [
    element("td", {attrs: {colspan: "7"}}, [
      element("span", {className: "inline-loader", attrs: {"aria-hidden": "true"}}),
      "正在载入隐藏邮箱…",
    ]),
  ]));
  byId("icloud-alias-dialog").showModal();
  try {
    const payload = await api(`/api/icloud-mailboxes/${encodeURIComponent(state.activeIcloudMailboxId)}/aliases`);
    state.icloudAliases = asList(payload, ["aliases", "icloud_aliases"]);
    renderIcloudAliases();
  } catch (error) {
    body.replaceChildren(element("tr", {className: "error-row"}, [
      element("td", {text: error?.message || String(error), attrs: {colspan: "7"}}),
    ]));
  }
}

async function setIcloudAliasState(aliasId, nextState) {
  if (!ensureMutable()) return;
  const alias = state.icloudAliases.find((item) => safeString(item.id) === safeString(aliasId));
  if (!alias) return;
  const action = nextState === "active" ? "启用" : "停用";
  if (!window.confirm(`${action}隐藏邮箱 ${safeString(alias.email)}？`)) return;
  await api(`/api/icloud-aliases/${encodeURIComponent(aliasId)}/state`, {
    method: "PATCH",
    body: {state: nextState},
  });
  const payload = await api(`/api/icloud-mailboxes/${encodeURIComponent(state.activeIcloudMailboxId)}/aliases`);
  state.icloudAliases = asList(payload, ["aliases", "icloud_aliases"]);
  state.icloudMailboxesLoaded = false;
  await Promise.all([refreshResources(["accounts"]), loadIcloudMailboxes({force: true})]);
  renderIcloudAliases();
  showToast(`隐藏邮箱已${action}`, "success");
}

async function openIcloudOwnerProxyDialog(aliasId) {
  const owner = state.icloudAliases.find((item) => safeString(item.id) === safeString(aliasId))
    || findIcloudTeamOwner(aliasId);
  if (!owner || owner.role !== "team_owner") return;
  const form = byId("icloud-owner-proxy-form");
  form.reset();
  try {
    await loadProxyChainConfig();
  } catch (error) {
    fieldError("icloud-owner-proxy-error", error?.message || String(error));
    return;
  }
  form.elements.namedItem("alias_id").value = safeString(owner.id);
  byId("icloud-owner-proxy-email").textContent = safeString(owner.email);
  const chained = owner.proxy_mode === CHAIN_PROXY_MODE;
  byId("icloud-owner-proxy-state").textContent = chained
    ? owner.proxy_chain?.healthy
      ? "Clash -> 上游代理中继已连接"
      : owner.proxy_chain?.relay_running
        ? "中继已启动，上游代理待刷新"
        : "Clash 两跳中继未启动"
    : owner.proxy_configured
      ? "旧直连配置已保存"
      : "未配置";
  form.elements.namedItem("source_url").placeholder = chained
    ? "未更改"
    : "代理 URL 或 curl 命令";
  form.elements.namedItem("bootstrap").value = state.sharedClashProxy;
  form.elements.namedItem("mode").value = CHAIN_PROXY_MODE;
  fieldError("icloud-owner-proxy-error", "");
  byId("icloud-owner-proxy-dialog").showModal();
}

async function handleIcloudOwnerProxySubmit(form) {
  if (!ensureMutable()) return;
  fieldError("icloud-owner-proxy-error", "");
  const aliasId = safeString(form.elements.namedItem("alias_id").value);
  const mode = CHAIN_PROXY_MODE;
  const sourceUrl = safeString(form.elements.namedItem("source_url").value).trim();
  const bootstrap = safeString(form.elements.namedItem("bootstrap").value).trim();
  const owner = state.icloudAliases.find((item) => safeString(item.id) === aliasId)
    || findIcloudTeamOwner(aliasId);
  if (!aliasId || !owner) return;
  const existingChained = owner.proxy_mode === CHAIN_PROXY_MODE;
  if (!sourceUrl && !existingChained) {
    fieldError("icloud-owner-proxy-error", "请输入代理 URL 或 curl -x / --socks5 命令");
    return;
  }
  if (!bootstrap) {
    fieldError("icloud-owner-proxy-error", "统一 Clash 前置不可用");
    return;
  }
  await api(`/api/icloud-team-owners/${encodeURIComponent(aliasId)}/proxy`, {
    method: "PUT",
    body: {mode, source_url: sourceUrl, bootstrap},
  });
  byId("icloud-owner-proxy-dialog").close();
  await Promise.all([
    loadIcloudTeamOwners(),
    refreshResources(["workspaces", "accounts"]),
  ]);
  if (state.activeIcloudMailboxId) {
    const payload = await api(`/api/icloud-mailboxes/${encodeURIComponent(state.activeIcloudMailboxId)}/aliases`);
    state.icloudAliases = asList(payload, ["aliases", "icloud_aliases"]);
    renderIcloudAliases();
  }
  showToast("代理链接已保存，并统一使用 Clash 第一跳", "success");
}

async function clearIcloudOwnerProxy(form) {
  if (!ensureMutable()) return;
  const aliasId = safeString(form.elements.namedItem("alias_id").value);
  if (!aliasId || !window.confirm("清除后无法现场创建下一子号，且名下子号将失去默认链路，确认继续？")) return;
  await api(`/api/icloud-team-owners/${encodeURIComponent(aliasId)}/proxy`, {
    method: "PUT",
    body: {mode: "direct", proxy: ""},
  });
  byId("icloud-owner-proxy-dialog").close();
  await Promise.all([
    loadIcloudTeamOwners(),
    refreshResources(["workspaces", "accounts"]),
  ]);
  if (state.activeIcloudMailboxId) {
    const payload = await api(`/api/icloud-mailboxes/${encodeURIComponent(state.activeIcloudMailboxId)}/aliases`);
    state.icloudAliases = asList(payload, ["aliases", "icloud_aliases"]);
    renderIcloudAliases();
  }
  showToast("子号默认链路已清除", "success");
}

async function handleInventoryAllocation(form) {
  if (!ensureMutable()) return;
  fieldError("account-allocation-error", "");
  const inventoryIdentifier = safeString(new FormData(form).get("inventory_id"));
  if (!inventoryIdentifier) {
    fieldError("account-allocation-error", "库存记录已失效，请重新搜索");
    return;
  }
  const account = await api(`/api/mailbox-inventory/${encodeURIComponent(inventoryIdentifier)}/allocate`, {method: "POST", body: {}});
  byId("account-allocation-dialog").close();
  await refreshResources(["accounts"]);
  state.inventoryDirty = true;
  if (state.inventoryQuery.trim()) scheduleInventorySearch({immediate: true});
  showToast(`已分配 ${accountEmail(account)}`, "success");
}

async function invalidateBoundAccount(id, failureType) {
  if (!ensureMutable()) return;
  const account = findAccount(id);
  const binding = account && accountBinding(account);
  if (!account || !binding?.workspace || !binding.role) {
    throw new ApiError("账号绑定已变化，请刷新后重试", {code: "binding_changed"});
  }
  const workspace = binding.workspace;
  const role = binding.role;
  const current = workspaceAccountLabel(workspace, "current");
  const next = workspaceAccountLabel(workspace, "next");
  const effect = role === "current"
    ? `${next === "未分配" ? "当前没有可提升的下一账号" : `${next} 将提升为当前账号`}，系统将尝试补充下一账号。`
    : `${current} 保持当前账号，系统将替换下一账号。`;
  const scope = failureType === "mailbox_credentials_invalid"
    ? `主邮箱 ${safeString(account.primary_email, accountEmail(account))} 将被禁用，未分配子号不再使用。`
    : `${accountEmail(account)} 将标记为不可用。`;
  if (!window.confirm(`${scope}\n\n${effect}\n\n确认继续？`)) return;
  await api(`/api/workspaces/${encodeURIComponent(workspaceId(workspace))}/replace-account`, {
    method: "POST",
    body: {
      role,
      failure_code: failureType,
      version: Number(firstValue(workspace, ["version"], 1)),
    },
  });
  state.inventoryDirty = true;
  await refreshResources(["workspaces", "accounts", "runs", "queue"]);
  if (state.accountView === "inventory" && state.inventoryQuery.trim()) scheduleInventorySearch({immediate: true});
  showToast("账号失效处理已完成", "success");
}

async function advanceWorkspace(id) {
  if (!ensureMutable()) return;
  const workspace = findWorkspace(id);
  if (!workspace) throw new ApiError("空间状态已变化，请刷新后重试", {code: "workspace_changed"});
  const current = workspaceAccountLabel(workspace, "current");
  const next = workspaceAccountLabel(workspace, "next");
  if (next === "未分配") {
    throw new ApiError("当前空间没有可提升的下一账号", {code: "next_account_missing"});
  }
  if (!window.confirm(
    `确认已将 ${next} 切换为当前账号？\n\n${current} 将归档，系统会自动分配新的下一账号。`
  )) return;
  const result = await api(`/api/workspaces/${encodeURIComponent(id)}/advance`, {
    method: "POST",
    body: {version: Number(firstValue(workspace, ["version"], 1))},
  });
  state.inventoryDirty = true;
  await refreshResources(["workspaces", "accounts", "runs", "queue"]);
  if (state.accountView === "inventory" && state.inventoryQuery.trim()) {
    scheduleInventorySearch({immediate: true});
  }
  const replacement = result?.replacement ? accountEmail(result.replacement) : "未分配";
  showToast(`轮换已确认，新的下一账号：${replacement}`, "success");
}

async function replaceIcloudWorkspaceChild(id) {
  if (!ensureMutable()) return;
  const workspace = findWorkspace(id);
  if (!workspace?.owner_alias_id) {
    throw new ApiError("空间未绑定 iCloud 归属母号", {code: "owner_missing"});
  }
  const hasPreparedNext = Boolean(workspace.next_account_id);
  const memberLimitNotice = "\n\n活跃成员硬上限为 2；旧子号退出成功后才允许新子号登录。";
  const message = hasPreparedNext
    ? `下一子号 ${workspaceAccountLabel(workspace, "next")} 已准备好，立即由当前子号开始接力？${memberLimitNotice}`
    : `将通过 HME 资源池为 ${safeString(workspace.owner_email)} 名下新建一个隐藏邮箱，并由当前子号启动接力。母号不会登录或操作。确认继续？${memberLimitNotice}`;
  if (!window.confirm(message)) return;
  const result = await api(
    `/api/workspaces/${encodeURIComponent(id)}/replace-icloud-child`,
    {
      method: "POST",
      body: {version: Number(firstValue(workspace, ["version"], 1))},
    },
  );
  await refreshResources(["workspaces", "accounts", "runs", "queue"]);
  state.icloudMailboxesLoaded = false;
  await loadIcloudMailboxes({force: true});
  showToast(
    result.created ? `已创建 ${safeString(result.alias?.email)}，接力已入队` : "接力已入队",
    "success",
  );
}

async function rescueIcloudWorkspaceChild(id) {
  if (!ensureMutable()) return;
  const workspace = findWorkspace(id);
  if (!workspace?.owner_alias_id) {
    throw new ApiError("Team 未绑定 iCloud 母号", {code: "owner_missing"});
  }
  const prepared = Boolean(workspace.next_account_id);
  const nextText = prepared
    ? `将复用已生成的新子号 ${workspaceAccountLabel(workspace, "next")}。`
    : "将先现场新建一个 iCloud 隐藏邮箱作为新子号。";
  const confirmed = window.confirm(
    `提拉仅用于当前子号故障。${nextText}\n\n`
    + "母号会登录 Team，清退除母号外的所有成员；远端确认只剩母号 1 人后，才邀请并登录新子号。最终必须恰好为母号 + 新子号 2 人。\n\n确认执行提拉？",
  );
  if (!confirmed) return;
  const result = await api(
    `/api/workspaces/${encodeURIComponent(id)}/rescue-icloud-child`,
    {
      method: "POST",
      body: {version: Number(firstValue(workspace, ["version"], 1))},
    },
  );
  await refreshResources(["workspaces", "accounts", "runs", "queue"]);
  state.icloudMailboxesLoaded = false;
  await loadIcloudMailboxes({force: true});
  const message = result.resumed
    ? "提拉已从原断点继续"
    : result.created
      ? `已创建 ${safeString(result.alias?.email)}，提拉已入队`
      : "提拉已入队";
  showToast(message, "success");
}

function settingsPayload(form) {
  const data = new FormData(form);
  const values = {
    output_dir: safeString(data.get("output_dir")).trim(),
    pat_name: safeString(data.get("pat_name")).trim(),
    openbrowser_base_url: safeString(data.get("openbrowser_base_url")).trim(),
    openbrowser_profile_ids: safeString(data.get("openbrowser_profile_ids")).trim(),
    management_base_url: safeString(data.get("management_url")).trim(),
    management_remote_name: safeString(data.get("management_filename")).trim(),
    management_push: data.get("management_push") === "on",
    management_replace: data.get("management_overwrite") === "on",
    sub2api_base_url: safeString(data.get("sub2api_url")).trim(),
    sub2api_email: safeString(data.get("sub2api_email")).trim(),
    sub2api_all_groups: data.get("sub2api_all_groups") === "on",
    sub2api_push: data.get("sub2api_push") === "on",
  };
  for (const name of ["pat_ttl", "invite_settle_seconds", "openbrowser_manual_timeout_seconds", "sub2api_concurrency", "sub2api_load_factor", "sub2api_priority"]) {
    const raw = safeString(data.get(name)).trim();
    if (raw) values[name] = Number(raw);
  }
  const sub2apiGroupId = safeString(data.get("sub2api_group_id")).trim();
  values.sub2api_group_id = sub2apiGroupId ? Number(sub2apiGroupId) : "";
  const secrets = {};
  for (const secretName of ["proxy", "openbrowser_api_key", "management_api_key", "sub2api_password", "sub2api_api_key", "sub2api_totp_secret"]) {
    const value = safeString(data.get(secretName));
    if (value && !state.clearSecrets.has(secretName)) secrets[secretName] = value;
  }
  return {values, secrets, clear_secrets: [...state.clearSecrets]};
}

async function handleSettingsSubmit(form) {
  if (!ensureMutable()) return;
  const invalid = form.querySelector(":invalid");
  if (invalid) {
    invalid.focus();
    throw new ApiError("请修正格式或范围不正确的设置项", {code: "invalid_settings"});
  }
  const payload = settingsPayload(form);
  if (payload.values.pat_ttl && payload.values.pat_ttl < 60) {
    const field = form.elements.namedItem("pat_ttl");
    field.focus();
    throw new ApiError("PAT TTL 不能小于 60 秒", {code: "invalid_pat_ttl"});
  }
  const response = await api("/api/settings", {method: "PUT", body: payload});
  state.settings = safeSettings(response || {values: payload.values, secrets: state.settings});
  state.settingsDirty = false;
  state.clearSecrets.clear();
  await loadResource("openbrowserStatus", "/api/openbrowser/status");
  renderSettings({force: true});
  byId("settings-save-state").textContent = `已保存 · ${formatDate(new Date().toISOString())}`;
  showToast("设置已保存", "success");
  void loadResource("sub2apiGroups", "/api/sub2api/groups").then(() => {
    renderSettings();
  });
}

async function testOpenBrowserConnection() {
  const payload = await api("/api/openbrowser/test", {method: "POST"});
  state.openbrowserStatus = safeOpenBrowserStatus(payload);
  renderOpenBrowserStatus();
  if (state.openbrowserStatus.connected) {
    showToast("OpenBrowser 连接正常", "success");
  } else {
    showToast(
      state.openbrowserStatus.state === "not_configured"
        ? "请先保存 OpenBrowser 设置"
        : "OpenBrowser Local API 无法连接",
      "error",
    );
  }
}

document.addEventListener("click", (event) => {
  const button = event.target.closest("[data-action]");
  if (!event.target.closest(".account-combobox")) {
    for (const [role, combo] of comboboxes) {
      if (combo.open) {
        combo.open = false;
        combo.activeIndex = -1;
        renderCombobox(role);
      }
    }
  }
  if (!button) return;
  const action = button.dataset.action;
  const run = async () => {
    if (action === "toggle-queue") {
      state.queueExpanded = !state.queueExpanded;
      renderQueue();
      return;
    }
    if (action === "close-dialog") return closeDialog(button);
    if (action === "open-workspace-dialog") return openWorkspaceDialog();
    if (action === "open-icloud-team-import") {
      return openIcloudTeamImport(button.dataset.ownerId);
    }
    if (action === "load-icloud-team-aliases") {
      return loadIcloudTeamImportAliases({
        preferredOwner: safeString(icloudTeamImportForm().elements.namedItem("owner_email").value),
        preferredChild: safeString(icloudTeamImportForm().elements.namedItem("current_child_email").value),
      });
    }
    if (action === "edit-workspace") return openWorkspaceDialog(findWorkspace(button.dataset.workspaceId));
    if (action === "advance-workspace") return advanceWorkspace(button.dataset.workspaceId);
    if (action === "replace-icloud-child") return replaceIcloudWorkspaceChild(button.dataset.workspaceId);
    if (action === "rescue-icloud-child") return rescueIcloudWorkspaceChild(button.dataset.workspaceId);
    if (action === "open-account-import") {
      fieldError("account-import-error", "");
      byId("account-import-dialog").showModal();
      return;
    }
    if (action === "open-icloud-mailbox") {
      return openIcloudMailboxDialog(findIcloudMailbox(button.dataset.mailboxId));
    }
    if (action === "refresh-icloud-mailboxes") {
      return loadIcloudMailboxes({force: true});
    }
    if (action === "check-icloud-mailbox") {
      return checkIcloudMailbox(button.dataset.mailboxId);
    }
    if (action === "open-icloud-hme-capture") {
      return openIcloudHmeCapture(findIcloudMailbox(button.dataset.mailboxId));
    }
    if (action === "cancel-icloud-hme-capture") {
      return cancelIcloudHmeCapture();
    }
    if (action === "open-icloud-sync") {
      return openIcloudSync(findIcloudMailbox(button.dataset.mailboxId));
    }
    if (action === "open-icloud-generate") {
      return openIcloudGenerateDialog(findIcloudMailbox(button.dataset.mailboxId));
    }
    if (action === "open-icloud-aliases") {
      return openIcloudAliases(findIcloudMailbox(button.dataset.mailboxId));
    }
    if (action === "toggle-icloud-mailbox") {
      return toggleIcloudMailbox(button.dataset.mailboxId, button.dataset.status);
    }
    if (action === "set-icloud-alias-state") {
      return setIcloudAliasState(button.dataset.aliasId, button.dataset.state);
    }
    if (action === "open-icloud-owner-proxy") {
      return openIcloudOwnerProxyDialog(button.dataset.aliasId);
    }
    if (action === "clear-icloud-owner-proxy") {
      return clearIcloudOwnerProxy(byId("icloud-owner-proxy-form"));
    }
    if (action === "open-account-proxy") return openAccountProxyDialog(findAccount(button.dataset.accountId));
    if (action === "clear-account-proxy") return clearAccountProxy(byId("account-proxy-form"));
    if (action === "select-account-view") return selectAccountView(button.dataset.accountView);
    if (action === "open-inventory-allocation") {
      return openInventoryAllocation(state.inventoryResults.find((item) => inventoryId(item) === button.dataset.inventoryId));
    }
    if (action === "invalidate-bound-account") return invalidateBoundAccount(button.dataset.accountId, button.dataset.failureType);
    if (action === "clear-combobox") return clearCombobox(button.dataset.role);
    if (action === "select-combobox-option") return selectComboboxChoice(button.dataset.role, Number(button.dataset.index));
    if (action === "choose-account-file") {
      const input = byId("account-import-form").elements.namedItem("path");
      input.value = await chooseLocalPath("txt", input.value);
      return;
    }
    if (action === "choose-output-directory") {
      const input = byId("settings-form").elements.namedItem("output_dir");
      const selected = await chooseLocalPath("directory", input.value);
      if (selected) {
        input.value = selected;
        state.settingsDirty = true;
      }
      return;
    }
    if (action === "enqueue-selected") return enqueueSelected();
    if (action === "retry-workspace") return retryWorkspace(button.dataset.workspaceId);
    if (action === "refresh-imported-child") {
      return refreshImportedChild(button.dataset.accountId, button.dataset.refreshMode);
    }
    if (action === "open-run-detail") return openRunDetail(button.dataset.runId);
    if (action === "set-account-status") return updateAccountStatus(button.dataset.accountId, button.dataset.status);
    if (action === "account-page-prev") return changeAccountPage(-1);
    if (action === "account-page-next") return changeAccountPage(1);
    if (action === "stop-run") return stopRun(button.dataset.runId);
    if (action === "move-queue-item") return moveQueueItem(button.dataset.queueItemId, button.dataset.direction);
    if (action === "toggle-queue-pause") return toggleQueuePause();
    if (action === "retry-migration-cleanup") return retryMigrationCleanup();
    if (action === "create-backup") return createBackup();
    if (action === "restore-backup") return restoreBackup();
    if (action === "test-openbrowser") return testOpenBrowserConnection();
    if (action === "toggle-secret-clear") {
      const secret = button.dataset.secret;
      if (state.clearSecrets.has(secret)) state.clearSecrets.delete(secret);
      else state.clearSecrets.add(secret);
      state.settingsDirty = true;
      renderSecretControls();
      return;
    }
    if (action === "filter-workspaces") {
      state.filters.workspaceStatus = button.dataset.status;
      for (const candidate of byId("workspace-status-filter").querySelectorAll("button")) {
        const active = candidate === button;
        candidate.classList.toggle("is-active", active);
        candidate.setAttribute("aria-pressed", String(active));
      }
      renderWorkspaceTable();
    }
  };
  withBusy(button, run).catch(() => {});
});

document.addEventListener("input", (event) => {
  const target = event.target;
  if (target.id === "workspace-search") {
    state.filters.workspaceSearch = target.value;
    renderWorkspaceTable();
  } else if (target.id === "account-search") {
    state.filters.accountSearch = target.value;
    state.accountPage = 1;
    renderAccountTable();
  } else if (target.id === "inventory-search") {
    state.inventoryQuery = target.value;
    state.inventoryError = "";
    scheduleInventorySearch();
  } else if (target.matches("[data-icloud-owner-proxy]")) {
    const item = state.remoteIcloudAliases.find(
      (candidate) => candidate.email === target.dataset.icloudOwnerProxy,
    );
    if (item) item.ownerProxy = target.value;
  } else if (target.matches("[data-combobox-input]")) {
    const role = target.dataset.comboboxInput;
    const combo = comboboxes.get(role);
    combo.query = target.value;
    if (combo.selected && target.value !== combo.selected.label) combo.selected = null;
    combo.open = true;
    combo.activeIndex = -1;
    combo.error = "";
    scheduleComboboxSearch(role);
    renderCombobox(role);
  } else if (target.id === "run-search") {
    state.filters.runSearch = target.value;
    renderRunTable();
  } else if (target.closest("#icloud-team-import-form")) {
    updateIcloudTeamImportSubmitState();
  } else if (target.closest("#settings-form")) {
    if (["proxy", "openbrowser_api_key", "management_api_key", "sub2api_password", "sub2api_api_key", "sub2api_totp_secret"].includes(target.name) && target.value) {
      state.clearSecrets.delete(target.name);
    }
    state.settingsDirty = true;
  }
});

document.addEventListener("change", (event) => {
  const target = event.target;
  if (target.name === "mailbox_id" && target.closest("#icloud-team-import-form")) {
    resetIcloudTeamWorkspaceLookup();
    state.icloudTeamImportAliases = [];
    state.icloudTeamImportMailboxId = safeString(target.value);
    renderIcloudTeamImportSnapshot();
    renderIcloudTeamImportSelectors();
    byId("icloud-team-alias-count").textContent = "0 个";
    byId("icloud-team-import-status").textContent = "尚未读取";
  } else if (target.name === "owner_email" && target.closest("#icloud-team-import-form")) {
    resetIcloudTeamWorkspaceLookup();
    renderIcloudTeamImportSelectors({preferredOwner: target.value});
  } else if (target.name === "current_child_email" && target.closest("#icloud-team-import-form")) {
    resetIcloudTeamWorkspaceLookup();
    updateIcloudTeamImportSubmitState();
  } else if (target.matches("[data-workspace-select]")) {
    const id = target.dataset.workspaceSelect;
    if (target.checked) state.selectedWorkspaceIds.add(id);
    else state.selectedWorkspaceIds.delete(id);
    renderWorkspaceTable();
  } else if (target.id === "select-all-workspaces") {
    const readyIds = filteredWorkspaces()
      .filter((workspace) => safeString(firstValue(workspace, ["status", "state"])) === "ready")
      .map(workspaceId);
    for (const id of readyIds) {
      if (target.checked) state.selectedWorkspaceIds.add(id);
      else state.selectedWorkspaceIds.delete(id);
    }
    renderWorkspaceTable();
  } else if (target.matches("[data-icloud-import-role]")) {
    const item = state.remoteIcloudAliases.find(
      (candidate) => candidate.email === target.dataset.icloudImportRole,
    );
    if (item) {
      item.selectionRole = target.value;
      if (target.value !== "rotating_child") item.parentOwnerEmail = "";
      item.ownerProxy = "";
      item.ownerProxyMode = target.value === "team_owner"
        ? CHAIN_PROXY_MODE
        : "direct";
      item.ownerProxyBootstrap = target.value === "team_owner"
        ? state.sharedClashProxy
        : "";
      const owners = icloudSyncOwnerChoices().filter((email) => email !== item.email);
      if (target.value === "rotating_child" && !item.parentOwnerEmail && owners.length === 1) {
        item.parentOwnerEmail = owners[0];
      }
      renderIcloudSyncRows();
    }
  } else if (target.matches("[data-icloud-parent-owner]")) {
    const item = state.remoteIcloudAliases.find(
      (candidate) => candidate.email === target.dataset.icloudParentOwner,
    );
    if (item) item.parentOwnerEmail = target.value;
  } else if (target.id === "account-status-filter") {
    state.filters.accountStatus = target.value;
    state.accountPage = 1;
    renderAccountTable();
  } else if (target.id === "inventory-status-filter") {
    state.inventoryStatus = target.value;
    state.inventoryResults = [];
    state.inventoryError = "";
    scheduleInventorySearch();
  } else if (target.name === "owner_alias_id" && target.closest("#workspace-form")) {
    const ownerAliasId = safeString(target.value);
    for (const role of ["current", "next"]) {
      const combo = comboboxes.get(role);
      const account = combo.selected?.kind === "account" ? findAccount(combo.selected.id) : null;
      if (
        combo.selected
        && ownerAliasId
        && (!account || safeString(account.icloud_owner_alias_id) !== ownerAliasId)
      ) {
        clearCombobox(role);
      } else {
        combo.inventoryResults = [];
        renderCombobox(role);
      }
    }
  } else if (target.id === "run-state-filter") {
    state.filters.runState = target.value;
    renderRunTable();
  } else if (target.id === "run-date-from") {
    state.filters.runDateFrom = target.value;
    renderRunTable();
  } else if (target.closest("#settings-form")) {
    if (target.name === "sub2api_all_groups") syncSub2APIGroupMode();
    state.settingsDirty = true;
  }
});

document.addEventListener("submit", (event) => {
  const form = event.target;
  if (!(form instanceof HTMLFormElement)) return;
  event.preventDefault();
  const submitter = event.submitter;
  let task = null;
  if (form.id === "workspace-form") task = () => handleWorkspaceSubmit(form);
  if (form.id === "account-import-form") task = () => handleAccountImport(form);
  if (form.id === "account-allocation-form") task = () => handleInventoryAllocation(form);
  if (form.id === "account-proxy-form") task = () => handleAccountProxySubmit(form);
  if (form.id === "icloud-mailbox-form") task = () => handleIcloudMailboxSubmit(form);
  if (form.id === "icloud-generate-form") task = () => handleIcloudGenerate(form);
  if (form.id === "icloud-sync-form") task = () => handleIcloudSync(form);
  if (form.id === "icloud-team-import-form") task = () => handleIcloudTeamImport(form);
  if (form.id === "icloud-owner-proxy-form") task = () => handleIcloudOwnerProxySubmit(form);
  if (form.id === "settings-form") task = () => handleSettingsSubmit(form);
  if (task) withBusy(submitter, task).catch(() => {});
});

for (const dialog of document.querySelectorAll("dialog")) {
  dialog.addEventListener("click", (event) => {
    if (event.target === dialog) dialog.close();
  });
  dialog.addEventListener("close", () => {
    if (dialog.id === "workspace-dialog") resetComboboxes();
    if ([
      "account-proxy-dialog",
      "icloud-mailbox-dialog",
      "icloud-owner-proxy-dialog",
      "icloud-sync-dialog",
      "icloud-team-import-dialog",
    ].includes(dialog.id)) {
      dialog.querySelector("form")?.reset();
    }
    if (dialog.id === "icloud-sync-dialog") state.remoteIcloudAliases = [];
    if (dialog.id === "icloud-team-import-dialog") state.icloudTeamImportAliases = [];
    if (dialog.id === "icloud-hme-capture-dialog") stopIcloudHmeCapturePolling();
  });
}

document.addEventListener("focusin", (event) => {
  const input = event.target.closest?.("[data-combobox-input]");
  if (!input) return;
  const combo = comboboxes.get(input.dataset.comboboxInput);
  combo.open = true;
  renderCombobox(combo.role);
});

document.addEventListener("keydown", (event) => {
  const input = event.target.closest?.("[data-combobox-input]");
  if (input) {
    const role = input.dataset.comboboxInput;
    const combo = comboboxes.get(role);
    if (event.key === "ArrowDown" || event.key === "ArrowUp") {
      event.preventDefault();
      moveComboboxActive(role, event.key === "ArrowDown" ? 1 : -1);
    } else if (event.key === "Enter" && combo.open && combo.activeIndex >= 0) {
      event.preventDefault();
      selectComboboxChoice(role, combo.activeIndex);
    } else if (event.key === "Escape") {
      event.preventDefault();
      cancelComboboxSearch(role);
      combo.open = false;
      combo.activeIndex = -1;
      renderCombobox(role);
      input.focus();
    } else if (event.key === "Tab") {
      combo.open = false;
      combo.activeIndex = -1;
      renderCombobox(role);
    }
    return;
  }
  const tab = event.target.closest?.("[role='tab'][data-account-view]");
  if (tab && ["ArrowLeft", "ArrowRight"].includes(event.key)) {
    event.preventDefault();
    const views = ["used", "inventory", "icloud"];
    const currentIndex = Math.max(0, views.indexOf(tab.dataset.accountView));
    const direction = event.key === "ArrowRight" ? 1 : -1;
    const nextView = views[(currentIndex + direction + views.length) % views.length];
    selectAccountView(nextView);
    document.querySelector(`[data-account-view="${nextView}"]`).focus();
  }
});

window.addEventListener("hashchange", () => selectView(currentViewFromHash()));
window.addEventListener("beforeunload", (event) => {
  state.eventSource?.close();
  if (state.settingsDirty) {
    event.preventDefault();
    event.returnValue = "";
  }
});

async function bootstrap() {
  selectView(currentViewFromHash());
  if (!window.location.hash) history.replaceState(null, "", "#spaces");
  setConnection("connecting", "正在连接…");
  try {
    const response = await fetch("/api/bootstrap", {cache: "no-store", credentials: "same-origin"});
    const payload = await response.json();
    if (!response.ok) throw normalizedError(payload, response.status);
    state.requestToken = safeString(firstValue(payload, ["request_token", "csrf_token", "token"]));
    if (!state.requestToken) throw new ApiError("本地服务未返回请求令牌", {code: "missing_request_token"});
    if (payload.migration) applyMigration(payload.migration);
    if (payload.snapshot) applySnapshot(payload.snapshot);

    await Promise.all([
      loadResource("workspaces", "/api/workspaces"),
      loadResource("accounts", "/api/accounts"),
      loadResource("runs", "/api/runs"),
      loadResource("queue", "/api/queue"),
      loadResource("settings", "/api/settings"),
      loadResource("openbrowserStatus", "/api/openbrowser/status"),
      loadResource("sub2apiGroups", "/api/sub2api/groups"),
      loadResource("icloudTeamOwners", "/api/icloud-team-owners"),
      loadResource("icloudMailboxes", "/api/icloud-mailboxes"),
      loadResource("migration", "/api/migration/status", {optional: true}),
    ]);
    renderAll();
    renderSettings({force: true});
    connectEvents();
  } catch (error) {
    setConnection("disconnected", "连接失败");
    if (isMigrationError(error)) showMigrationBlocked(error.message);
    for (const name of ["workspaces", "accounts", "runs", "queue"]) state.errors[name] = error?.message || String(error);
    renderAll();
    showToast(`${error?.message || String(error)}。请确认本地服务正在运行。`, "error");
  }
}

bootstrap();
