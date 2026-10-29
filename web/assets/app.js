"use strict";
function alertTabs(selected) {
  const events = selected === "events", mutes = selected === "mutes";
  return '<div class="alert-tabs" role="group" aria-label="告警中心视图">' +
    '<button type="button" class="alert-tab' + (events ? ' active' : '') +
    '" data-action="go-alerts" aria-pressed="' + events + '">告警记录</button>' +
    (can("alerts.manage") ? '<button type="button" class="alert-tab' +
    (mutes ? ' active' : '') + '" data-action="go-mutes" aria-pressed="' +
    mutes + '">暂时屏蔽</button>' : '') +
    '</div>';
}
async function mutesPanel() {
  const [rows, expired] = await Promise.all([
    api("/api/v1/alert-mutes?status=active"),
    api("/api/v1/alert-mutes?status=expired"),
  ]);
  return alertTabs("mutes") + intro("管理当前平台的飞书告警屏蔽，支持按到期时间自动恢复通知。", btn("refresh", "刷新列表")) +
    panel(
    "当前生效的飞书告警屏蔽（" + rows.length + " 条）",
    `<form id="mute-form"><div class="form-grid">${field("host_id", "Zabbix Host ID")}${field("trigger_id", "触发器 ID")}${field(
      "hours",
      "屏蔽时长",
      "1",
      "text",
      "",
      [
        ["1", "1 小时"],
        ["4", "4 小时"],
        ["24", "24 小时"],
        ["72", "3 天"],
        ["168", "7 天"],
      ],
    )}</div><div class="form-actions">${btn("validate-mute", "验证屏蔽规则")}<button class="button" type="submit">设置屏蔽</button></div><p role="status" data-verify-result></p></form>` +
      table(
        ["主机 ID", "触发器 ID", "设置时间", "到期时间（北京时间）", "操作"],
        rows
          .map(
            (r) =>
              `<tr><td>${E(r.host_id)}</td><td>${E(r.trigger_id)}</td><td>${E(r.created_at)}</td><td>${date(new Date(r.expires_at * 1000).toISOString())}</td><td>${btn("unmute", "提前解除", r.host_id + ":" + r.trigger_id, "small")}</td></tr>`,
          )
          .join(""),
      ),
    "仅影响本平台的问题通知；不修改 Zabbix，也不会屏蔽恢复通知。下方可查看最近到期的规则。",
    "mutes-active",
  ) + panel(
    "最近已过期的屏蔽记录",
    table(
      ["主机 ID", "触发器 ID", "设置时间", "到期时间（北京时间）", "状态"],
      expired.map(r =>
        `<tr><td>${E(r.host_id)}</td><td>${E(r.trigger_id)}</td><td>${E(r.created_at)}</td><td>${date(new Date(r.expires_at * 1000).toISOString())}</td><td>已过期</td></tr>`
      ).join(""),
    ),
    "只展示最近 100 条已到期的规则；不会继续屏蔽任何告警。",
  );
}
const $ = (s) => document.querySelector(s),
  E = OpsUI.escape;
const state = {
  user: null,
  csrf: "",
  auditPage: 1,
  taskPage: 1,
  taskStatus: "all",
  taskQuery: "",
  alertPage: 1,
  alertStatus: "all",
  alertSeverity: "",
  alertQuery: "",
  configTab: "general",
  lastHash: "",
  editor: null,
  includeLogs: false,
  hostRows: [],
};
const P = "/api/v1/platform";
const labels = {
  success: "已完成",
  partial: "部分完成",
  failed: "失败",
  running: "执行中",
  queued: "等待执行",
  cancelled: "已取消",
  active: "未收到恢复",
  recovered: "已恢复",
  sent: "已通知",
  muted: "暂时屏蔽",
  disabled: "未开启",
  pending: "等待分析",
  not_required: "未触发分析",
  reused: "复用近期分析",
  skipped_budget: "超出每日额度",
  suppressed_unpaired: "未发送问题通知",
  linux: "Linux",
  windows: "Windows",
  vmware: "VMware",
  network: "网络设备",
  unknown: "待确认",
  other: "其他",
  standard: "标准分析",
  quick: "快速分析",
  deep: "深度分析",
  super_admin: "超级管理员",
  ops_admin: "运维管理员",
  operator: "运维人员",
  auditor: "只读审计",
};
const nav = [
  ["overview", "总览", "▦", "overview.read"],
  ["alerts", "告警中心", "◴", "reports.read"],
  ["diagnostics", "AI 诊断", "✧", "diagnostics.run"],
  ["connections", "连接管理", "⇄", "tools.read"],
  ["skills", "Skill 管理", "◇", "tools.read"],
  ["history", "分析历史", "◷", "reports.read"],
  ["settings", "系统配置", "⚙", "settings.manage"],
  ["audit", "审计日志", "≡", "audit.read"],
];
const can = (p) =>
  (state.user?.permissions || []).includes("*") ||
  (state.user?.permissions || []).includes(p) ||
  state.user?.open_id === "legacy-admin";
const fmt = (n) => (n == null ? "—" : Number(n).toLocaleString("zh-CN"));
const date = (v) =>
  v
    ? new Date(
        String(v).includes("T") ? v : String(v).replace(" ", "T") + "Z",
      ).toLocaleString("zh-CN", { timeZone: "Asia/Shanghai", hour12: false })
    : "—";
const badge = (s) =>
  `<span class="tag ${E(s)}">${E(labels[s] || s || "—")}</span>`;
const sourceLabel = value => ({web: "Web 诊断", alert: "告警分析", qa: "监控问答", feishu: "飞书", ui_test: "界面测试"}[value] || value);
function stageLabel(value) {
  if (String(value).startsWith("ssh_mcp:")) return "SSH 采集中 · " + ({resolve: "核验主机", cpu: "CPU", memory: "内存", processes: "进程", memory_processes: "内存进程", disk: "磁盘", directory: "目录占用", io: "磁盘 IO", network: "网络", sockets: "连接", system: "系统", service: "服务", logs: "日志", kernel: "内核"}[value.split(":")[1]] || "补充证据");
  return labels[value] || ({collecting: "收集证据", zabbix_history: "查询监控历史", ai_reasoning: "AI 分析中", skill_analysis: "按 Skill 分析查询步骤", skill_prefetch: "按 Skill 预采集证据",skill_ssh_mcp: "正在查询后台 MCP 服务并进行分析", skill_zabbix_mcp: "正在查询后台 MCP 服务并进行分析", retired: "旧任务已停用"}[value]) || value || "等待执行";
}
const btn = (action, text, id = "", kind = "", disabled = false) =>
  `<button type="button" class="button ${kind}" data-action="${action}" data-id="${E(id)}" ${disabled ? "disabled" : ""}>${text}</button>`;
async function paged(path, key, pageSize = 25, filters = {}) {
  const query = new URLSearchParams({
    ...filters, page: state[key], page_size: pageSize,
  });
  const data = await api(path + "?" + query);
  const pages = Math.max(1, Math.ceil(data.total / pageSize));
  if (state[key] > pages) {
    state[key] = pages;
    return paged(path, key, pageSize, filters);
  }
  state[key + "Count"] = pages;
  return data;
}
function pagination(prefix, key) {
  const page = state[key], pages = state[key + "Count"];
  return `<div class="pagination">${btn(prefix + "-prev", "上一页", "", "small", page <= 1)}<span>第 ${page} 页 / ${pages} 页</span>${btn(prefix + "-next", "下一页", "", "small", page >= pages)}</div>`;
}
const intro = (text, actions = "") =>
  `<div class="page-intro"><p class="muted small">${text}</p><div class="actions">${actions}</div></div>`;
const panel = (title, body, note = "", id = "") =>
  `<section class="panel" ${id ? `id="${E(id)}"` : ""}><div class="section-heading"><div><h2>${title}</h2>${note ? `<p class="muted small">${note}</p>` : ""}</div></div>${body}</section>`;
const table = (heads, rows) =>
  `<div class="table-wrap"><table><thead><tr>${heads.map((x) => `<th>${x}</th>`).join("")}</tr></thead><tbody>${rows || `<tr><td colspan="${heads.length}" class="empty">暂无记录</td></tr>`}</tbody></table></div>`;
function toast(message) {
  // Modal dialogs are in the top layer: a page-level toast would sit behind
  // their backdrop, so show the message inside the active editor instead.
  if ($("#editor").open) {
    const feedback = $("#editor-feedback");
    feedback.textContent = message;
    feedback.hidden = false;
    feedback.scrollIntoView({ block: "nearest" });
    return;
  }
  $("#toast").textContent = message;
  $("#toast").hidden = false;
  clearTimeout(state.toastTimer);
  state.toastTimer = setTimeout(() => ($("#toast").hidden = true), 6000);
}
async function api(path, method = "GET", body) {
  const response = await fetch(path, {
    method,
    headers: {
      ...(body ? { "Content-Type": "application/json" } : {}),
      ...(state.csrf ? { "X-CSRF-Token": state.csrf } : {}),
    },
    body: body ? JSON.stringify(body) : undefined,
  });
  let result;
  try {
    result = await response.json();
  } catch {
    result = { detail: "服务器未返回有效响应" };
  }
  if (!response.ok) {
    if (response.status === 401) {
      $("#app").hidden = true;
      $("#login").hidden = false;
    }
    const error = new Error(
      typeof result.detail === "string"
        ? result.detail
        : Array.isArray(result.detail)
          ? result.detail.map((error) => error.msg || "输入无效").join("；")
          : result.detail?.message || "请求失败，请稍后重试",
    );
    error.status = response.status;
    error.detail = result.detail;
    throw error;
  }
  return result;
}
function field(
  name,
  label,
  value = "",
  type = "text",
  help = "",
  options = null,
  wide = false,
) {
  let control;
  if (type === "checkbox")
    control = `<label class="check-field"><input name="${name}" type="checkbox" ${value ? "checked" : ""}>${label}</label>`;
  else if (options)
    control = `<select aria-label="${E(label)}" name="${name}">${options.map((x) => `<option value="${E(Array.isArray(x) ? x[0] : x)}" ${String(value) === String(Array.isArray(x) ? x[0] : x) ? "selected" : ""}>${E(Array.isArray(x) ? x[1] : x)}</option>`).join("")}</select>`;
  else if (type === "textarea")
    control = `<textarea aria-label="${E(label)}" name="${name}" >${E(value)}</textarea>`;
  else
    control = `<input aria-label="${E(label)}" name="${name}" type="${type}" value="${E(value)}" ${type === "password" ? 'autocomplete="new-password"' : ""}>`;
  return `<div class="field ${wide ? "wide" : ""}">${type === "checkbox" ? "" : `<span>${label}</span>`}${type === "password" ? `<div class="secret-control">${control}${btn("toggle-secret", "显示", "", "quiet small")}</div>` : control}${help ? `<small>${E(help)}</small>` : ""}</div>`;
}
function taskRows(rows) {
  return rows
    .map(
      (r) =>
        `<tr><td><button class="link-button mono" data-action="report" data-id="${E(r.task_id)}">${E(r.task_id.slice(0, 12))}</button><small>${date(r.created_at)}</small></td><td>${E(PLAY[r.diagnostic_type] || r.diagnostic_type)}<small>${E(sourceLabel(r.source))} · ${E(labels[r.profile] || r.profile)}</small></td><td>${badge(r.status)}<small>${E(stageLabel(r.stage))}</small></td><td>${fmt(r.tools)}</td><td>${r.duration_ms == null ? "—" : (r.duration_ms / 1000).toFixed(1) + " s"}</td><td>${fmt(r.token_total)}<small>${r.token_total == null ? "未返回用量" : "模型实际用量"}</small></td><td>${btn("report", "查看", r.task_id, "small")}</td></tr>`,
    )
    .join("");
}
const PLAY = {
  cpu: "CPU 异常",
  memory: "内存不足",
  disk: "磁盘容量",
  io: "IO 性能",
  service: "服务异常",
  network: "网络异常",
  system: "系统异常",
  unreachable: "主机不可达",
  bottleneck: "资源瓶颈",
  logs: "日志异常",
};
async function overview() {
  const [o, t] = await Promise.all([api(P + "/overview"), api(P + "/tasks?page_size=6")]);
  const stat = (label, value, hint, tone = "") => `<div class="stat ${tone}"><div class="label">${label}</div><div class="value">${value}</div><div class="hint">${hint}</div></div>`;
  const readiness = [["model", "AI 模型", "settings/ai"], ["zabbix_mcp", "Zabbix MCP", "connections"], ["ssh_mcp", "SSH MCP", "connections"], ["feishu", "飞书应用", "settings/feishu"], ["webhook", "告警接入", "settings/general"]];
  const health = (provider, title, configured) => {
    const record = o.health.find(row => row.provider === provider);
    return `<div class="health-row"><div><strong>${title}</strong><p>${record ? "最近检测：" + date(record.checked_at) : "配置完成后，请主动验证连接"}</p></div><span class="tag ${record?.status || ""}">${record ? (record.status === "success" ? "最近检测通过" : "最近检测失败") : configured ? "待验证" : "未配置 / 未启用"}</span></div>`;
  };
  return intro("最近 24 小时 · 仅统计本平台收到的事件和执行的分析", btn("refresh", "刷新数据")) +
    `<div class="hero"><div><span class="eyebrow">运维工作台</span><h2>监控异常，循证诊断。</h2><p class="muted small">从告警定位问题，关联 Zabbix 历史与 Linux 实时证据。</p></div><div class="actions">${btn("go-alerts", "查看告警")}${can("diagnostics.run") ? btn("go-page", "新建诊断 →", "diagnostics", "primary") : ""}</div></div>` +
    `<div class="stats">${stat("未收到恢复的事件", fmt(o.unrecovered_received_events), "平台累计接收，非 Zabbix 全量", o.unrecovered_received_events ? "attention" : "")}${stat("AI 分析次数", fmt(o.ai_runs_24h), "最近 24 小时创建")}${stat("AI 分析成功率", o.ai_success_rate_24h == null ? "—" : o.ai_success_rate_24h + "%", "成功 / 已结束的分析")}${stat("实际 Token", fmt(o.token_total_24h), `${fmt(o.usage_available_runs_24h)} 次返回用量`)}</div>` +
    (can("settings.manage") ? `<div class="readiness-strip"><div><strong>配置检查</strong><small>仅检查是否填写，连接请主动验证</small></div>${readiness.map(([key, label, target]) => `<button class="readiness-item ${o.readiness[key] ? "ready" : ""}" data-action="go-page" data-id="${target}"><span>${o.readiness[key] ? "✓" : "○"}</span>${label}<small>${o.readiness[key] ? "已配置" : "待配置"}</small></button>`).join("")}</div>` : "") +
    `<div class="grid-two">${panel("MCP 连接状态", health("zabbix_mcp", "Zabbix MCP · 历史监控", o.mcp_configured) + health("ssh_mcp", "SSH MCP · 实时诊断", o.ssh_mcp_configured) + `<p class="muted small footnote">状态代表最近一次主动检测结果；主机通过 Zabbix Host ID 关联。</p>`)}${panel("诊断处理情况", `<div class="health-row"><span>已完成 / 部分完成</span><strong>${fmt(o.completed_24h)} / ${fmt(o.partial_24h)}</strong></div><div class="health-row"><span>执行中 / 等待执行</span><strong>${fmt(o.running)} / ${fmt(o.queued)}</strong></div><div class="health-row"><span>失败任务</span><strong>${fmt(o.failed_24h)}</strong></div><div class="health-row"><span>平均分析耗时</span><strong>${o.average_duration_ms_24h == null ? "—" : (o.average_duration_ms_24h / 1000).toFixed(1) + " 秒"}</strong></div>`)}</div>` +
    `<div class="panel"><div class="section-heading"><div><h2>最近诊断</h2><p class="muted small">告警分析、问答与手动诊断的统一记录</p></div>${btn("go-history", "全部记录 →", "", "quiet")}</div>${table(["任务 / 时间", "诊断类型 / 来源", "状态", "工具", "耗时", "Token", "操作"], taskRows(t.items))}</div>`;
}
async function alerts() {
  const data = await paged(P + "/alerts", "alertPage", 25, {
    status: state.alertStatus, q: state.alertQuery,
    ...(state.alertSeverity !== "" ? {severity: state.alertSeverity} : {}),
  });
  state.alertRows = data.items;
  const severities = ["未分类", "信息", "警告", "一般严重", "严重", "灾难"];
  return alertTabs("events") + intro("平台已接收的告警与恢复记录。恢复状态以收到的 Zabbix 通知为准。", btn("refresh", "刷新")) +
    panel("告警事件",
      `<form id="alert-filter" class="filter-bar"><input name="q" aria-label="搜索告警" maxlength="160" placeholder="搜索主机、告警名称或事件 ID" value="${E(state.alertQuery)}"><select name="status" aria-label="告警状态">${[["all", "全部状态"], ["active", "未收到恢复"], ["recovered", "已恢复"]].map(([key, label]) => `<option value="${key}" ${key === state.alertStatus ? "selected" : ""}>${label}</option>`).join("")}</select><select name="severity" aria-label="告警级别"><option value="">全部级别</option>${severities.map((label, i) => `<option value="${i}" ${String(i) === state.alertSeverity ? "selected" : ""}>${label}</option>`).join("")}</select><button class="button primary" type="submit">查询</button>${btn("reset-alert-filter", "重置", "", "quiet")}</form><p class="muted small">共 ${fmt(data.total)} 条符合条件的告警</p>` +
      table(["主机 / 告警", "级别", "当前状态", "通知 / 分析", "操作"], data.items.map(r => `<tr><td><span class="cell-title">${E(r.host_name || "未提供主机名")}</span><small class="event-title">${E(r.event_name)}</small><small>事件 ${E(r.event_id)} · ${date(r.received_at)}</small></td><td><span class="severity s${E(r.severity)}"></span>${severities[r.severity] || "—"}</td><td>${badge(r.status)}${r.recovered_at ? `<small>${date(r.recovered_at)}</small>` : ""}</td><td>${badge(r.notify_status)} ${badge(r.ai_status)}</td><td><div class="row-actions">${r.task_id ? btn("report", "查看分析", r.task_id, "small") : ""}${can("diagnostics.run") ? btn("analyze-event", "AI 分析", r.event_id, "small") : ""}</div></td></tr>`).join("")) + pagination("alert", "alertPage"));
}
async function diagnostics() {
  const options = await api(P + "/diagnostic-options");
  return (
    intro(
      "输入问题发起诊断。启用 Skill 后按指引选择后台服务，可直接查询已登记的 SSH 主机 IP，也可选择监控主机或关联告警。",
    ) +
    panel(
      "新建诊断",
      `<form id="diagnostic-form">${state.selectedEvent ? `<div class="notice context-banner"><div><strong>正在分析告警 ${E(state.selectedEvent)}</strong><p>${E(state.selectedEventTitle || "以告警中记录的主机为诊断目标。")}</p></div>${btn("clear-event", "取消关联", "", "small")}</div>` : ""}<div class="form-grid"><div class="field wide"><span>查询监控主机</span><div class="toolbar"><input id="host-search" aria-label="搜索 Zabbix 主机" placeholder="输入主机名称或 Zabbix Host ID">${btn("search-hosts", "查询 Zabbix 主机")}</div><small id="host-search-result" role="status">直接从 Zabbix MCP 读取主机，无需在平台登记资产。</small></div>${field("zabbix_hostid", "诊断主机", "", "text", "可选。按 Skill 查询明确 SSH IP 时可不选择；选择 Host ID 或关联告警时，以该主机为准。", [["", "未选择主机"], ...state.hostRows.map(h => [h.zabbix_hostid, h.name + " · Host ID " + h.zabbix_hostid + " · " + (labels[h.device_type] || h.device_type)])])}${field("event_id", "告警事件 ID", state.selectedEvent || "", "text", "可选，必须是平台已经接收的事件。")}${field("diagnostic_type", "诊断类型", "auto", "text", "", [["auto", "自动识别告警类型"], ...Object.entries(PLAY)])}${field(
        "profile",
        "分析模式",
        options.default_profile,
        "text",
        "选择本次轮次、次数和时间预算；启用 Skill 后，查询来源和步骤由 Skill 决定。",
        [
          ["quick", "快速分析"],
          ["standard", "标准分析"],
          ["deep", "深度分析"],
        ],
      )}${field("service", "systemd 服务名", "", "text", "服务/日志诊断时填写，如 nginx.service。")}${field("time_window", "日志窗口（分钟）", "30", "number", "范围 1–120 分钟；Skill 按此窗口及原生工具参数查询日志。")}${field("question", "诊断问题", "请根据实际证据诊断故障并给出建议", "textarea", "", null, true)}</div><div class="form-actions">${btn("validate-diagnostic", "验证诊断参数与关联")}<button class="button primary" type="submit">开始诊断 →</button></div><p role="status" data-verify-result></p></form>`,
    ) +
    panel(
      "监控问答",
      `<form id="ask-form">${field("question", "查询监控或提出问题", "", "textarea", "启用 Skill 后，可填写 SSH 服务已登记的明确 IP，按指引直接查询实时证据。", null, true)}<div class="form-actions"><button class="button" type="submit">发送问题</button></div></form><div id="ask-result" class="report-answer"></div>`,
    )
  );
}
async function diagnosticTools() {
  const data = await api(P + "/tools");
  return panel(
    "诊断工具",
    intro(
      "检测使用已保存的 MCP 连接。平台固定白名单独立生效；远端自称只读或动态发现都不能扩大授权。",
      can("settings.manage") ? btn("discover", "检测 MCP 工具") : "",
    ) +
      "<h3>工具注册表</h3>" +
      table(
        ["工具 / 提供方", "适用设备", "风险 / 超时", "状态", "说明"],
        data.tools
          .map(
            (t) =>
              `<tr><td><span class="mono">${E(t.name)}</span><small>${E(t.provider)} · ${E(t.required_scope)}</small></td><td>${E(t.device_types.map((x) => labels[x] || x).join(" / "))}</td><td>${E(t.risk)} · ${t.timeout}s<small>输出 ≤ ${fmt(t.max_output_chars)} 字符</small></td><td>${badge(t.enabled ? "已启用" : "已禁用")}</td><td>${E(t.description)}</td></tr>`,
          )
          .join(""),
      ) +
      "<h3 class=\"subsection-heading\">诊断类型</h3>" +
      table(
        ["问题类型", "相关监控数据", "诊断边界"],
        Object.entries(data.playbooks)
          .map(
            ([key, p]) =>
              `<tr><td>${E(p.label)}</td><td class="mono">${E(p.metrics.join(", "))}</td><td class="muted small">${E(p.limitation)}</td></tr>`,
          )
          .join(""),
      ),
    "诊断类型用于任务分类；查询哪些工具、按什么顺序由已启用的 Skill 决定（默认为平台基础 Skill），可在 Skill 管理验证实际目录。",
    "connection-tools",
  );
}
async function connections() {
  const tools = can("tools.read") ? await diagnosticTools() : "";
  if (!can("settings.manage"))
    return intro("当前角色可查看诊断工具和标准流程；连接参数由管理员配置。") + tools;
  const values = await api("/api/v1/settings");
  const groups = [
    ["zabbix_mcp", "Zabbix MCP", "监控指标、历史趋势和告警事实。", [["mcp_url", "Zabbix MCP 地址", "text"], ["mcp_token", "Zabbix MCP 令牌", "password"]]],
    ["ssh_mcp", "SSH MCP", "Linux 实时诊断；主机及 SSH 密钥在独立服务维护。", [["ssh_mcp_enabled", "启用 SSH MCP", "select", [["false", "关闭"], ["true", "开启"]]], ["ssh_mcp_url", "SSH MCP 地址", "text"], ["ssh_mcp_token", "SSH MCP 专用令牌", "password"], ["ssh_mcp_timeout_seconds", "单工具超时（秒）", "number"]]],
  ];
  return intro("分别配置两个 Streamable HTTP MCP。令牌加密保存且不回显原文；HTTP 地址仅用于受信任内网。验证连接检查当前表单，无需先保存。", btn("scroll-section", "查看诊断工具 ↓", "connection-tools")) + groups.map(([provider, title, note, fields]) => panel(title,
    `<form id="${provider}-form" class="connection-form" data-provider="${provider}"><div class="form-grid">${fields.map(([key, label, type, options]) => field(key, label, values[key] || "", type === "select" ? "text" : type, key.includes("url") ? "例如 http://服务所在服务器:端口/mcp；请填写容器可访问的地址。" : "", options || null)).join("")}</div><div class="form-actions">${btn("validate-connection", "验证填写内容", provider)}${btn("verify-mcp", "验证连接", provider)}<button class="button primary" type="submit">保存连接</button></div><p class="muted small" role="status" data-verify-result></p></form>`, note)).join("") + tools;
}
async function analysisHistory() {
  const [data, usage] = await Promise.all([
    paged(P + "/tasks", "taskPage", 25, { status: state.taskStatus, q: state.taskQuery }),
    api("/api/v1/ai-token-usage?days=30&limit=20"),
  ]);
  return (
    intro(
      "任务、工具调用与证据可按 trace_id 追溯。Token 仅使用模型实际返回数据。",
      btn("refresh", "刷新"),
    ) +
    `<div class="token-grid"><div class="stat"><div class="label">最近 30 天 · 输入 Token</div><div class="value">${fmt(usage.total_input)}</div></div><div class="stat"><div class="label">最近 30 天 · 输出 Token</div><div class="value">${fmt(usage.total_output)}</div></div><div class="stat"><div class="label">最近 30 天 · 总 Token</div><div class="value">${fmt(usage.total_tokens)}</div><div class="hint">未返回用量的请求不计入汇总</div></div></div><div class="panel"><form id="history-filter" class="toolbar"><input name="q" aria-label="搜索分析历史" placeholder="搜索任务、事件或 Trace ID" value="${E(state.taskQuery)}" maxlength="160"><button class="button" type="submit">搜索</button><select id="task-status" aria-label="任务状态"><option value="all">全部任务状态</option>${["queued", "running", "success", "partial", "failed", "cancelled"].map((s) => `<option value="${s}" ${s === state.taskStatus ? "selected" : ""}>${labels[s]}</option>`).join("")}</select><span class="muted small">共 ${data.total} 条</span></form>${table(["任务 / 时间", "诊断类型 / 来源", "状态", "工具", "耗时", "Token", "操作"], taskRows(data.items))}${pagination("task", "taskPage")}</div>` +
    panel(
      "逐轮用量",
      table(
        ["时间 / 模型", "来源 / 模式", "Token", "轮次 / 工具", "执行记录"],
        usage.records
          .map(
            (r) =>
              `<tr><td>${E(r.time)}<small>${E(r.model)}</small></td><td>${E(r.source)} · ${E(r.profile)}</td><td>${fmt(r.total)}</td><td>${r.rounds} / ${r.tools}</td><td><details><summary>展开</summary><pre>${E(JSON.stringify(r.details, null, 2))}</pre></details></td></tr>`,
          )
          .join(""),
      ),
    )
  );
}
function readableReportAnswer(raw) {
  const text = String(raw ?? "").trim();
  const fence = String.fromCharCode(96, 96, 96);
  let candidate = text;
  if (text.startsWith(fence)) {
    candidate = text.slice(3).replace(/^json\s*/i, "").trim();
    if (candidate.endsWith(fence)) candidate = candidate.slice(0, -3).trim();
  }
  let value;
  try { value = JSON.parse(candidate); } catch { return text; }
  if (!value || typeof value !== "object" || Array.isArray(value) ||
      !["cause", "action", "analysis"].some(k => typeof value[k] === "string")) return text;
  const fields = [
    ["故障原因（AI 推断）", "cause"],
    ["处理建议", "action"],
    ["分析与依据", "analysis"],
  ];
  const lines = fields.filter(([, k]) => typeof value[k] === "string" && value[k].trim())
    .map(([label, k]) => label + "\n" + value[k].trim());
  if (value.human_required === true) lines.push("需人工核验：是");
  return lines.join("\n\n");
}
function modelInteractionsPanel(data) {
  const items = data?.items || [];
  const introText = "按模型请求记录实际发送内容和模型返回值；脱敏、限长预览。Token 为模型返回的逐轮实际用量；MCP 证据在下方单独查看。";
  if (!items.length) return panel("与大模型交互记录", '<div class="empty">暂无交互记录。旧任务不会补录；新诊断任务执行后自动保存。</div>', introText);
  const content = items.map((entry) => {
    const payload = entry.payload || {}, request = payload.request || {}, response = payload.response || {};
    const tokenText = `输入 ${fmt(entry.token_input)} / 输出 ${fmt(entry.token_output)} / 合计 ${fmt(entry.token_total)}`;
    const preview = (title, value) => value ? `<details class="evidence"><summary>${E(title)} · ${fmt(value.original_chars)} 字符${value.truncated ? " · 已截断" : ""}</summary><pre>${E(value.text)}</pre></details>` : "";
    const details = data.content_visible
      ? preview("系统指令（脱敏预览）", request.instructions) +
        preview("发送给模型的消息（脱敏预览）", request.input) +
        preview("模型返回的正文（脱敏预览）", response.text) +
        (response.items?.length ? `<details class="evidence"><summary>模型输出类型与工具调用</summary><pre>${E(JSON.stringify(response.items, null, 2))}</pre></details>` : "") +
        (payload.error ? `<p class="muted small">错误：${E(payload.error)}（${E(payload.error_class)}）</p>` : "")
      : '<p class="muted small">请求及响应内容需要 logs.read 权限才能展开，当前仅显示调用元数据。</p>';
    return `<details class="evidence"><summary>第 ${E(entry.round_number)} 轮 · ${E(entry.model)} · ${E(entry.status === "completed" ? "完成" : "失败")} · ${(entry.duration_ms / 1000).toFixed(1)} 秒 · ${E(tokenText)}</summary><p class="muted small">请求时间：${date(entry.created_at)} · 可用工具：${E((request.tools || []).join(" / ") || "见任务授权")}</p>${details}</details>`;
  }).join("");
  return panel("与大模型交互记录", content, introText);
}
async function report(id) {
  const t = await api(
    P +
      "/tasks/" +
      encodeURIComponent(id) +
      (state.includeLogs ? "?include_logs=true" : ""),
  );
  let modelHistory = {items: []};
  try {
    modelHistory = await api(P + "/tasks/" + encodeURIComponent(id) + "/model-interactions" + (can("logs.read") ? "?include_content=true" : ""));
  } catch (err) {
    modelHistory = {items: [], note: "模型交互记录读取失败：" + (err.message || "未知错误")};
  }
  if (location.hash === "#report/" + id) state.currentTask = t;
  const target = t.report?.target || {};
  return (
    intro(
      `任务 ${E(t.task_id)} · trace_id ${E(t.trace_id)}`,
      btn("go-history", "返回历史") +
        (can("diagnostics.run")
          ? ["running", "queued"].includes(t.status)
            ? btn("cancel-task", "取消任务", id, "danger")
            : t.kind !== "legacy" && ["failed", "partial", "cancelled"].includes(t.status)
              ? btn("retry-task", "重试", id)
              : ""
          : "") +
        btn("copy-report", "复制结论") + btn("download-report", "下载报告") +
        (can("logs.read") ? btn("download-detailed-report", "下载详细报告", id) : "") + btn("refresh", "刷新"),
    ) +
    reportProgress(t) +
    `<div class="stats"><div class="stat"><div class="label">诊断状态</div><div class="value">${badge(t.status)}</div><div class="hint">${E(stageLabel(t.stage))}</div></div><div class="stat"><div class="label">主机 / 事件 ID</div><div class="value">${E(t.alert?.host_id || t.asset?.zabbix_hostid || "—")}</div><div class="hint">事件 ${E(t.event_id || "未关联")}</div></div><div class="stat"><div class="label">实际 Token / 工具调用</div><div class="value">${fmt(t.token_total)}</div><div class="hint">${fmt(t.tools)} 次采集 · 输入 ${fmt(t.token_input)} / 输出 ${fmt(t.token_output)}</div></div><div class="stat"><div class="label">执行耗时</div><div class="value">${t.duration_ms == null ? "—" : (t.duration_ms / 1000).toFixed(1) + " s"}</div><div class="hint">${date(t.created_at)}</div></div></div>` +
    reportBudget(t) +
    (t.skills?.length ? panel("本次加载的 Skill", t.skills.map(row => `<p><strong>${E(row.name)}</strong> · v${row.revision} · ${row.providers.map(E).join(" / ")}</p><p class="muted small mono">SHA256 ${E(row.digest)}</p>`).join(""), "查询步骤由任务创建时保存的 Skill 决定。") : "") +
    panel(
      "告警与主机信息",
      `<p>${E(t.alert?.event_name || "手动诊断 / 连接测试")}</p><p class="muted small">主机：${E(t.asset?.name || t.alert?.host_name || "未关联")} · Zabbix Host ID：${E(t.asset?.zabbix_hostid || t.alert?.host_id || "—")}${target.ssh_host_id ? ` · SSH 资产 ID：${E(target.ssh_host_id)} · IP：${E(target.address || "—")}` : ""} · 类型：${E(labels[t.report?.device_type || t.asset?.device_type] || "待确认")}</p>`,
    ) +
    panel(
      "AI 诊断结论 · 分析推断",
      `<div class="notice">监控和 SSH 事实在下方按来源记录。AI 总结需结合时间窗口与原始证据核验。</div><div class="report-answer">${OpsUI.answer(reportAnswer(t))}</div>`,
    ) +
    (t.report?.limitations?.length
      ? panel(
          "诊断不足与待核验",
          t.report.limitations
            .map((x) => `<p class="muted small">${E(x)}</p>`)
            .join(""),
        )
      : "") +
    panel(
      "诊断时间线",
      `<div class="timeline"><div>任务创建<small>${date(t.created_at)}</small></div>${t.started_at ? `<div>开始执行<small>${date(t.started_at)}</small></div>` : ""}${t.evidence.map((e) => `<div>${E(e.provider)} · ${E(e.tool)} ${badge(e.status)}<small>${date(e.collected_at)} · ${e.duration_ms} ms</small></div>`).join("")}${t.completed_at ? `<div>任务结束<small>${date(t.completed_at)}</small></div>` : ""}</div>`,
    ) +
    modelInteractionsPanel(modelHistory) +
    `<div class="panel"><div class="section-heading"><div><h2>证据与工具执行记录</h2><p class="muted small">Zabbix 为监控证据；SSH 为采集当时快照。日志内容需要独立权限。</p></div>${can("logs.read") ? btn("toggle-logs", state.includeLogs ? "隐藏原始日志" : "读取日志证据", id) : ""}</div>${t.evidence.length ? t.evidence.map((e) => `<details class="evidence" data-evidence="${E(e.id)}"><summary>${t.report?.evidence_ids?.[e.id] ? `<strong>${E(t.report.evidence_ids[e.id])}</strong> ` : ""}${E(e.provider)} / ${E(e.tool)} ${badge(e.status)} · ${date(e.collected_at)}</summary><pre>${E(JSON.stringify(e.payload, null, 2))}</pre></details>`).join("") : '<div class="empty">暂无采集证据</div>'}</div>`
  );
}
function reportBudget(task) {
  const budget = task.budget || task.report?.budget;
  if (!budget?.limits?.calls) return "";
  const limits = budget.limits, used = budget.used || {};
  const usage = [
    ["采集次数", `${fmt(used.calls ?? task.tools)} / ${fmt(limits.calls)}`],
    ["模型轮次", `${fmt(used.rounds)} / ${fmt(limits.rounds)}`],
    ["实际 Token / 停止阈值", `${fmt(task.token_total)} / ${fmt(limits.tokens)}`],
    ["耗时 / 时间上限", `${used.seconds ?? (task.duration_ms == null ? "—" : (task.duration_ms / 1000).toFixed(1))} / ${limits.seconds} 秒`],
  ];
  const timing = task.report?.timing;
  if (Array.isArray(timing?.rounds)) {
    const longest = timing.rounds.length ? Math.max(...timing.rounds) : 0;
    usage.push(["阶段耗时", `预采集 ${timing.prefetch} 秒 · 模型 ${timing.rounds.length} 轮 ${timing.model} 秒（最长一轮 ${longest} 秒） · 工具 ${timing.tools} 秒`]);
  }
  return panel("分析预算", `<p>${E(labels[task.profile] || task.profile)} · 使用任务创建时的配置</p>` + table(["预算项", "已使用 / 上限"], usage.map(([label, value]) => `<tr><td>${E(label)}</td><td>${E(value)}</td></tr>`).join("")) + (budget.reasons || []).map(reason => `<p class="notice">${E(reason)}</p>`).join("") + `<p class="muted small">包含 Zabbix 查询、SSH 主机解析及每个诊断动作。预算耗尽时跳过后续采集；Token 阈值用于停止后续请求。</p>` + (can("settings.manage") ? btn("go-page", "配置分析预算", "settings/ai") : ""));
}
function reportAnswer(task) {
  return readableReportAnswer(task.report?.answer || task.report?.message || (task.status === "failed" ? "任务未能完成。请结合下方状态说明排查后重试。" : ["queued", "running"].includes(task.status) ? "正在收集证据并分析，完成后将在这里显示结论。" : "未返回分析结论，请查看采集证据和诊断不足。"));
}
function reportProgress(task) {
  const active = ["queued", "running"].includes(task.status);
  const reasons = {QueueUnavailable: "诊断队列连接失败。请检查 Redis 和诊断 Worker，恢复后可重试此任务。", WorkerLost: "执行超过允许时间，Worker 可能已退出。请检查服务状态，已有证据仍可查看。", PermissionRevoked: "提交者的诊断权限已撤销，请联系管理员。", LocalSSHRemoved: "此任务使用已停用的旧版执行方式，请重新发起诊断。", ModelTimeout: "AI 模型请求超时；已保留已有证据，可调整单次请求超时后重试。", ModelRateLimited: "模型接口受到限流；请检查部署容量、配额或稍后重试。", ModelConnectionError: "模型连接失败；请检查服务连通性。", ModelServiceError: "模型服务返回 5xx；请检查供应商状态。", ModelRequestError: "模型请求被拒绝；请检查部署名及请求参数。"};
  const text = task.cancel_requested && active ? "已请求取消，正在停止后续采集。已开始的远端操作受其自身超时控制。" : active ? stageLabel(task.stage) : task.error_type ? reasons[task.error_type] || "分析未完成。请验证模型、两个 MCP 连接以及主机授权，再重试。" : task.status === "partial" ? "已保存可用证据；请查看诊断不足，补足信息后再判断。" : "分析已结束，可核验依据或下载报告。";
  return `<div class="report-progress ${active ? "is-active" : ""}"><span class="progress-mark">${active ? "◌" : task.status === "success" ? "✓" : "i"}</span><div><strong>${E(text)}</strong><p id="report-refresh-state">${active ? "每 5 秒检查进度，保留展开的证据与阅读位置。" : "历史监控与实时采集分别记录，AI 结论需要结合证据核验。"}</p></div>${task.error_type ? `<span class="mono">${E(task.error_type)}</span>` : ""}</div>`;
}
function reportText() {
  const task = state.currentTask;
  return `# AI 运维诊断报告\n\n任务：${task.task_id}\nTrace ID：${task.trace_id}\n主机：${task.alert?.host_name || "未关联"}\n事件：${task.event_id || "未关联"}\n状态：${labels[task.status] || task.status}\n生成时间：${date(task.completed_at || task.created_at)}\n\n${reportAnswer(task)}\n\n## 诊断不足\n${(task.report?.limitations || []).map(item => "- " + item).join("\n") || "未记录"}\n\n实际 Token：${task.token_total ?? "未返回"} · 工具采集：${task.tools} 次\n\nAI 内容属于分析推断，请结合平台中保存的证据核验。\n`;
}
const configHelp = {
  web_protocol: "用于生成飞书登录回调和报告链接；HTTPS 证书由外部入口配置。",
  web_public_host: "用户实际访问的平台域名/IP和端口，例如 192.0.2.11:8088。",
  zabbix_frontend_url: "用于从告警卡片和报告打开 Zabbix 网页。",
  zabbix_webhook_secret: "验证 Zabbix 推送告警的身份，需与 Zabbix 告警媒介中的密钥一致。",
  ai_request_timeout_seconds: "默认 90 秒，受任务总时限及留给总结的时间共同约束。仅影响新任务。",
  ai_alert_reuse_hours: "同一主机、同一触发器在此时间内已完成 AI 分析时，新告警不再自动分析，原告警卡片附上该次报告链接和 24 小时告警次数。手动点击“AI分析”不受影响。",
  ai_daily_token_limit: "只统计自动告警分析（北京时间自然日）。达到上限后新告警只发送通知并在卡片注明，手动分析不受限制。",
  ai_quick_severity_max: "达到自动分析门槛、但级别不高于所选值的告警，使用快速分析模式的预算。",
  ai_quick_host_groups: "告警所属主机组包含任一关键字（如 测试环境）时，自动分析使用快速分析模式。",
  data_retention_days: "超过天数的已结束任务，删除 MCP 证据和逐轮模型交互明细；任务结论、状态与 Token 统计永久保留。0 为永久保留，建议 180。每天最多清理一次，操作记入审计。",
};
const configGroups = {
  ai: [
    ["openai_base_url", "模型 Base URL"],
    ["openai_model", "模型部署名称"],
    ["openai_api_key", "API Key", "password"],
    ["ai_request_timeout_seconds", "AI 单次请求超时（秒，15–180）", "number"],
    [
      "ai_analysis_profile",
      "默认分析模式",
      "select",
      [
        ["quick", "快速分析"],
        ["standard", "标准分析"],
        ["deep", "深度分析"],
      ],
    ],
    ["data_retention_days", "诊断明细保留天数（0 为永久）", "number"],
  ],
  feishu: [
    ["lark_app_id", "飞书应用 App ID"],
    ["lark_app_secret", "飞书应用 App Secret", "password"],
    [
      "feishu_enabled",
      "发送飞书告警",
      "select",
      [
        ["true", "开启"],
        ["false", "关闭"],
      ],
    ],
    ["feishu_alert_chat_ids", "告警群 Chat ID（英文逗号分隔）"],
    ["allowed_chat_ids", "允许问答的群 Chat ID（英文逗号分隔）"],
    [
      "ai_min_severity",
      "自动 AI 分析最低级别",
      "select",
      [
        ["0", "未分类"],
        ["1", "信息"],
        ["2", "警告"],
        ["3", "一般严重"],
        ["4", "严重"],
        ["5", "灾难"],
      ],
    ],
    ["ai_alert_reuse_hours", "复用同一触发器近期分析（小时，0 为关闭）", "number"],
    ["ai_daily_token_limit", "自动分析每日 Token 上限（0 为不限）", "number"],
    ["ai_quick_severity_max", "按告警级别使用快速分析", "select", [["", "不按级别降档"], ["2", "警告及以下"], ["3", "一般严重及以下"]]],
    ["ai_quick_host_groups", "使用快速分析的主机组关键字（英文逗号分隔）"],
    ["feishu_admin_open_ids", "超级管理员 Open ID（英文逗号分隔）"],
  ],
  settings: [
    [
      "web_protocol",
      "Web 访问协议",
      "select",
      [
        ["http", "HTTP · 内网受限访问"],
        ["https", "HTTPS"],
      ],
    ],
    ["web_public_host", "Web 外部主机（含端口）"],
    ["zabbix_frontend_url", "Zabbix 前端 URL"],
    ["zabbix_webhook_secret", "Zabbix Webhook Bearer Secret", "password"],
  ],
};
function budgetFields(values, options) {
  let custom = {};
  try { custom = JSON.parse(values.ai_profile_budgets || "{}"); } catch {}
  const names = {rounds: "最大轮次", calls: "采集次数", per_round: "每轮调用", result_chars: "每次结果字符", seconds: "总时间（秒）", tokens: "Token 阈值"};
  return `<h3>分析预算</h3><p class="muted small">各项预算无固定数值上限，仍保留整数和最小值校验。任务按保存的预算执行；修改后用于新任务或重试任务。SSH 主机解析也计入采集次数。</p>` + table(["分析模式", ...Object.values(names)], Object.entries(options.profiles).map(([profile, limits]) => `<tr><td>${labels[profile]}</td>${Object.keys(names).map(key => `<td><input class="budget-input" type="number" name="budget_${profile}_${key}" aria-label="${labels[profile]} ${names[key]}" min="${options.ranges[key][0]}" ${options.ranges[key][1] == null ? "" : `max="${options.ranges[key][1]}"`} step="1" required value="${E(custom[profile]?.[key] ?? limits[key])}"></td>`).join("")}</tr>`).join(""));
}
function toolFields(values, options) {
  let disabled = [];
  try { disabled = JSON.parse(values.disabled_tools || "[]"); } catch {}
  return `<fieldset class="group-picker"><legend>允许 AI 使用的 Zabbix 只读工具</legend><div class="group-options">${options.tools.map(name => `<label class="check-field"><input type="checkbox" name="enabled_tool" value="${E(name)}" ${disabled.includes(name) ? "" : "checked"}>${E(name)}</label>`).join("")}</div><p class="muted small">取消勾选可禁用；任何远端写入工具始终不获授权。</p></fieldset>`;
}
function formValues(form) {
  const data = Object.fromEntries(new FormData(form));
  if (form.id === "editor-form") {
    if (state.editor.type === "member") data.enabled = form.elements.enabled.checked;
  }
  if (form.id === "diagnostic-form") {
    data.zabbix_hostid = data.zabbix_hostid || null;
    data.event_id = data.event_id || null; data.service = data.service || null;
    data.time_window = Number(data.time_window);
    if (!data.zabbix_hostid && !data.event_id) throw Error("请选择监控主机或填写告警事件 ID；不指定主机的问题请使用下方监控问答。");
  }
  if (form.classList.contains("settings-form")) {
    if (form.dataset.group === "ai") {
      const budgets = {};
      for (const [key, value] of Object.entries(data)) if (key.startsWith("budget_")) {
        const [, profile, ...parts] = key.split("_");
        (budgets[profile] ||= {})[parts.join("_")] = Number(value); delete data[key];
      }
      data.ai_profile_budgets = JSON.stringify(budgets);
    }
    if (form.dataset.group === "settings" && can("*")) {
      const enabled = new FormData(form).getAll("enabled_tool");
      data.disabled_tools = JSON.stringify(state.options.tools.filter(n => !enabled.includes(n)));
      delete data.enabled_tool;
    }
  }
  return data;
}
async function verifyAction(action, id, button) {
  const form = button.closest("form");
  const result = form?.querySelector("[data-verify-result]");
  const show = (message, kind = "pending") => { if (result) { result.textContent = message; result.dataset.result = kind; } else toast(message); };
  const request = async (path, body) => {
    const checked = form ? OpsUI.fingerprint(form) : "";
    show("正在验证…");
    try {
      const r = await api(path, "POST", body);
      if (form && checked !== OpsUI.fingerprint(form)) show("验证期间内容已修改，请重新验证当前配置。");
      else show(r.message || r.reply || (r.ok ? `连接成功，${r.authorized_tools?.length || 0} 个授权工具` : "验证失败：" + r.detail), r.ok === false ? "error" : "success");
    }
    catch (err) {show("验证未通过：" + err.message, "error");}
  };
  if (["validate-settings", "validate-connection"].includes(action)) await request("/api/v1/settings/validate", {values: formValues(form)});
  else if (action === "verify-mcp") await request(P + "/tools/discover?provider=" + id, {values: formValues(form)});
  else if (action === "test-model") await request("/api/v1/test/ai", form ? {values: formValues(form)} : undefined);
  else if (action === "verify-feishu" || action === "verify-feishu-groups") await request("/api/v1/test/feishu" + (action === "verify-feishu-groups" ? "?check_groups=true" : ""), {values: formValues(form)});
  else if (action === "validate-diagnostic") await request(P + "/tasks/validate", formValues(form));
  else if (action === "validate-editor") {
    await request(P + "/members/validate", formValues(form));
  } else if (action === "validate-mute") {
    const values = formValues(form); values.hours = Number(values.hours);
    await request("/api/v1/alert-mutes/validate", values);
  } else return false;
  return true;
}

function configSection(group, values, options) {
  const titles = { settings: "基础设置", feishu: "飞书应用与告警策略", ai: "AI 模型与分析策略" };
  const hints = {
    settings: "配置访问地址、告警认证和 Zabbix 只读工具权限。敏感字段保留掩码表示不修改。",
    feishu: "告警与问答沿用同一飞书应用。更换应用或访问地址后，请同时核对飞书回调地址和机器人权限。更换应用凭据后需重启飞书接收器。",
    ai: "仅配置模型、执行超时与预算。诊断规则统一在 Skill 管理中维护；已保存的旧提示词不再参与新分析。",
  };
  const actions = group === "ai"
    ? btn("test-model", "验证模型连接") + '<a class="button" href="#skills">管理诊断 Skill</a>'
    : group === "feishu"
      ? btn("verify-feishu", "验证飞书应用") + btn("verify-feishu-groups", "验证群访问权限")
      : "";
  const fields = configGroups[group].filter(x => can("*") || x[0] !== "feishu_admin_open_ids");
  return panel(
    titles[group],
    `<form id="${group}-settings-form" class="settings-form" data-group="${group}"><div class="form-grid">${fields.map(([key, label, type, choices]) => field(key, label, values[key] || "", type === "select" ? "text" : type || "text", configHelp[key] || "", choices || null, type === "textarea")).join("")}</div>${group === "ai" ? budgetFields(values, options) : ""}${group === "settings" && can("*") ? toolFields(values, options) : ""}<div class="form-actions">${btn("validate-settings", "验证填写内容")}${actions}<button class="button primary" type="submit">保存${group === "settings" ? "基础" : group === "feishu" ? "飞书" : "AI"}配置</button></div><p class="muted small" role="status" data-verify-result></p></form>`,
    hints[group],
    "settings-" + (group === "settings" ? "general" : group),
  );
}
async function systemSettings() {
  const [values, options] = await Promise.all([api("/api/v1/settings"), api("/api/v1/settings/options")]);
  state.options = options;
  let feishuExtra = "";
  if (can("*")) {
    const members = await api(P + "/members");
    state.members = members;
    feishuExtra = `<div class="panel"><div class="section-heading"><div><h2>授权成员</h2><p class="muted small">超级管理员通过上方名单管理；其他角色由后端授权。</p></div>${btn("new-member", "添加成员")}</div>${table(["Open ID", "角色", "状态", "操作"], members.map((m) => `<tr><td class="mono">${E(m.open_id)}</td><td>${E(labels[m.role])}</td><td>${badge(m.enabled ? "已启用" : "已停用")}</td><td>${btn("edit-member", "编辑", m.open_id, "small")}</td></tr>`).join(""))}</div>`;
  }
  return (
    intro("在同一处管理平台、飞书与 AI。各分区独立保存；切换分区保留填写内容。") +
    `<div class="section-tabs" role="tablist" aria-label="系统配置分区">${[["general", "基础设置"], ["feishu", "飞书配置"], ["ai", "AI 配置"], ["maintenance", "服务与维护"]].map(([key, label]) => `<button type="button" role="tab" id="tab-${key}" aria-controls="region-${key}" aria-selected="${state.configTab === key}" data-action="settings-tab" data-id="${key}" class="section-tab ${state.configTab === key ? "active" : ""}">${label}</button>`).join("")}</div>` +
    configRegion("general", configSection("settings", values, options)) +
    configRegion("feishu", configSection("feishu", values, options) + feishuExtra) +
    configRegion("ai", configSection("ai", values, options)) +
    configRegion("maintenance",
    panel(
      "服务状态与备份",
      `<p class="muted small">检查队列连接、排队任务与 Worker 注册状态。升级前备份数据库与配对主密钥，操作步骤见仓库 docs/UPGRADING.md。</p>${btn("runtime-status", "查看服务与队列状态")}<div id="runtime-result" role="status"></div>`,
      "",
      "settings-maintenance",
    ))
  );
}
function configRegion(key, html) {
  return `<div id="region-${key}" role="tabpanel" aria-labelledby="tab-${key}" data-config-section="${key}" ${state.configTab === key ? "" : "hidden"}>${html}</div>`;
}
function selectConfigTab(key) {
  state.configTab = key;
  document.querySelectorAll("[data-config-section]").forEach(region => region.hidden = region.dataset.configSection !== key);
  document.querySelectorAll('[data-action="settings-tab"]').forEach(button => {
    const selected = button.dataset.id === key;
    button.setAttribute("aria-selected", selected); button.classList.toggle("active", selected);
  });
  window.history.replaceState(null, "", "#settings/" + key);
  state.lastHash = location.hash;
  window.scrollTo(0, 0);
}
async function auditPage() {
  const data = await paged(P + "/audit", "auditPage", 50);
  return (
    intro(
      "登录、配置变更、报告访问和诊断操作",
      btn("refresh", "刷新"),
    ) +
    panel(
      "操作记录",
      table(
        ["时间", "操作", "对象", "操作人", "Trace ID"],
        data.items
          .map(
            (r) =>
              `<tr><td>${date(r.created_at)}</td><td>${E(r.action)}</td><td class="mono">${E(r.key)}</td><td class="mono">${E(r.actor || "旧版记录")}</td><td class="mono">${E(r.trace_id || "—")}</td></tr>`,
          )
          .join(""),
      ) + pagination("audit", "auditPage"),
    )
  );
}
let generation = 0,
  poll;
async function navigate(options = {}) {
  clearTimeout(poll);
  if (!options.quiet && !options.preserveDrafts && OpsUI.dirty() && !window.confirm("有配置尚未保存。离开此页将丢弃修改，是否继续？")) {
    window.history.replaceState(null, "", state.lastHash || "#overview");
    return;
  }
  const drafts = options.preserveDrafts ? OpsUI.drafts() : [];
  const openEvidence = options.quiet ? [...document.querySelectorAll("details.evidence[open]")].map(el => el.dataset.evidence) : [];
  const scrollY = window.scrollY;
  const current = ++generation;
  const parts = (location.hash.slice(1) || "overview").split("/");
  // Keep existing bookmarks useful after consolidating the navigation.
  if (parts[0] === "mutes") {
    parts.splice(0, parts.length, "alerts", "mutes");
    window.history.replaceState(null, "", "#alerts/mutes");
  }
  if (["ai", "feishu", "tools"].includes(parts[0])) {
    const oldPage = parts[0];
    parts.splice(0, parts.length, oldPage === "tools" ? "connections" : "settings", oldPage);
    window.history.replaceState(null, "", "#" + parts.join("/"));
  }
  const page = parts[0];
  if (page === "settings" && ["general", "feishu", "ai", "maintenance"].includes(parts[1])) state.configTab = parts[1];
  if (page !== "report" || state.currentTask?.task_id !== parts[1]) state.includeLogs = false;
  state.lastHash = location.hash || "#overview";
  const item = nav.find((x) => x[0] === page);
  $("#page-title").textContent =
    page === "report" ? "诊断详情" : item?.[1] || "总览";
  document
    .querySelectorAll("nav button")
    .forEach((b) =>
      b.classList.toggle(
        "active",
        b.dataset.page === page ||
          (page === "report" && b.dataset.page === "history"),
      ),
    );
  if (!options.quiet) $("#content").innerHTML = '<div class="loading-state" role="status"><span class="loading-dot"></span>正在加载…</div>';
  try {
    let html;
    if (page === "overview") html = await overview();
    else if (page === "alerts") {
      html = parts[1] === "mutes" && can("alerts.manage")
        ? await mutesPanel()
        : await alerts();
    }
    else if (page === "diagnostics") html = await diagnostics();
    else if (page === "connections") html = await connections();
    else if (page === "skills") html = await skillsPage(parts[1]);
    else if (page === "history") html = await analysisHistory();
    else if (page === "report") html = await report(parts[1] || "");
    else if (page === "settings") html = await systemSettings();
    else if (page === "audit") html = await auditPage();
    else html = await overview();
    if (current !== generation) return;
    $("#content").innerHTML = html;
    OpsUI.track(); OpsUI.restore(drafts);
    const section = page === "connections" && parts[1] === "tools" ? "connection-tools" : "";
    if (section) document.getElementById(section)?.scrollIntoView({ block: "start" });
    else if (options.quiet) {
      document.querySelectorAll("details.evidence").forEach(el => { el.open = openEvidence.includes(el.dataset.evidence); });
      window.scrollTo(0, scrollY);
    } else window.scrollTo(0, 0);
    if (
      (page === "report" && ["running", "queued"].includes(state.currentTask?.status))
    )
      scheduleReportPoll(parts[1], current);
  } catch (err) {
    if (current === generation && !options.quiet)
      $("#content").innerHTML =
        `<div class="notice error" role="alert">${E(err.message)}</div>`;
    else if (current === generation) {
      toast("报告刷新失败，已保留当前内容。");
      scheduleReportPoll(parts[1], current);
    }
  }
}
function scheduleReportPoll(id, current) {
  poll = setTimeout(async () => {
    if (current !== generation || !location.hash.startsWith("#report/")) return;
    if (document.hidden) { scheduleReportPoll(id, current); return; }
    try {
      const latest = await api(P + "/tasks/" + encodeURIComponent(id) + "/status");
      if (current !== generation) return;
      if (["status", "stage", "tools", "cancel_requested", "error_type", "completed_at"].some(key => latest[key] !== state.currentTask[key])) await navigate({quiet: true});
      else scheduleReportPoll(id, current);
    } catch {
      if (current === generation && !$("#app").hidden) {
        const hint = $("#report-refresh-state");
        if (hint) hint.textContent = "暂时无法刷新，稍后重试。当前内容已保留。";
        scheduleReportPoll(id, current);
      }
    }
  }, 5000);
}
function go(page) {
  if (location.hash === "#" + page) navigate();
  else location.hash = page;
}
async function openEditor(type, id) {
  state.editor = { type, id };
  let title,
    fields,
    note = "";
  if (type === "member") {
    const member = (state.members || []).find((m) => m.open_id === id);
    title = id ? "编辑成员" : "授权成员";
    fields =
      field("open_id", "飞书 Open ID", member?.open_id || "") +
      field("role", "角色", member?.role || "operator", "text", "", [
        ["ops_admin", "运维管理员"],
        ["operator", "运维人员"],
        ["auditor", "只读审计"],
      ]) +
      field("enabled", "启用该成员", member ? !!member.enabled : true, "checkbox");
  }
  $("#editor-title").textContent = title;
  $("#editor-fields").innerHTML = fields;
  $("#editor-note").textContent = note;
  $("#editor-feedback").textContent = "";
  $("#editor-feedback").hidden = true;
  if (type === "member" && id) $("#editor-form").elements.open_id.readOnly = true;
  $("#editor").showModal();
}
document.addEventListener("click", async (event) => {
  const b = event.target.closest("[data-action]");
  if (!b || b.disabled) return;
  const { action, id } = b.dataset;
  b.disabled = true;
  try {
    if (await verifyAction(action, id, b)) return;
    if (action === "refresh") await navigate();
    else if (action === "settings-tab") selectConfigTab(id);
    else if (action === "go-page") go(id);
    else if (action === "toggle-secret") {
      const input = b.closest(".secret-control").querySelector("input");
      input.type = input.type === "password" ? "text" : "password";
      b.textContent = input.type === "password" ? "显示" : "隐藏";
    }
    else if (action === "copy-report") { await OpsUI.copy(reportText()); toast("报告已复制"); }
    else if (action === "download-report") {
      const url = URL.createObjectURL(new Blob([reportText()], {type: "text/markdown;charset=utf-8"}));
      const link = document.createElement("a"); link.href = url;
      link.download = "诊断报告-" + state.currentTask.task_id.slice(0, 12) + ".md";
      link.click(); setTimeout(() => URL.revokeObjectURL(url), 1000);
    }
    else if (action === "download-detailed-report") {
      const taskId = id || state.currentTask?.task_id;
      if (!taskId || !can("logs.read")) throw new Error("无权下载详细报告");
      const response = await fetch(P + "/tasks/" + encodeURIComponent(taskId) + "/detailed-report", {
        method: "GET", credentials: "same-origin", cache: "no-store"
      });
      if (!response.ok) {
        let message = "下载详细报告失败（HTTP " + response.status + "）";
        try { const err = await response.json(); message = err.detail || message; } catch {}
        throw new Error(message);
      }
      const url = URL.createObjectURL(await response.blob());
      const link = document.createElement("a"); link.href = url;
      link.download = "诊断详细报告-" + taskId.slice(0, 12) + ".md";
      link.click(); setTimeout(() => URL.revokeObjectURL(url), 1000);
      toast("已生成详细报告，请妥善保管内部日志和诊断证据");
    }
    else if (action === "reset-alert-filter") {
      state.alertQuery = ""; state.alertSeverity = ""; state.alertStatus = "all"; state.alertPage = 1; await navigate();
    }
    else if (action === "clear-event") { state.selectedEvent = ""; state.selectedEventTitle = ""; await navigate(); }
    else if (action === "scroll-section") document.getElementById(id)?.scrollIntoView({ block: "start" });
    else if (action === "go-history") go("history");
    else if (action === "go-alerts") go("alerts");
    else if (action === "go-mutes" && can("alerts.manage")) go("alerts/mutes");
    else if (action === "report") go("report/" + id);
    else if (action === "unmute") {
      const [host, trigger] = id.split(":");
      await api("/api/v1/alert-mutes/" + host + "/" + trigger, "DELETE");
      toast("屏蔽已解除");
      await navigate();
    } else if (action === "new-member" || action === "edit-member")
      await openEditor("member", id);
    else if (action === "search-hosts") {
      const form = b.closest("form"), output = form.querySelector("#host-search-result");
      output.textContent = "正在从 Zabbix MCP 查询…";
      try {
        const response = await api(P + "/hosts?q=" + encodeURIComponent(form.querySelector("#host-search").value.trim()));
        if (!output.isConnected) return;
        state.hostRows = response.items;
        form.elements.zabbix_hostid.innerHTML = '<option value="">请选择监控主机</option>' + state.hostRows.map(h => `<option value="${E(h.zabbix_hostid)}">${E(h.name)} · Host ID ${E(h.zabbix_hostid)} · ${E(labels[h.device_type] || h.device_type)}</option>`).join("");
        output.textContent = `已查询 ${response.items.length} 台主机。${response.at_limit ? "达到100台上限，请输入更精确名称或Host ID。" : "主机信息不在平台落库。"}`;
      } catch (err) { if (output.isConnected) output.textContent = "查询失败：" + err.message; }
    } else if (action === "analyze-event") {
      state.selectedEvent = id;
      const row = state.alertRows?.find(row => row.event_id === id);
      state.selectedEventTitle = row ? row.host_name + " · " + row.event_name : "";
      go("diagnostics");
    } else if (action === "discover") {
      const results = await Promise.all(["zabbix_mcp", "ssh_mcp"].map(provider => api(P + "/tools/discover?provider=" + provider, "POST")));
      toast(results.map(r => `${r.provider}：${r.ok ? "连接成功，" + r.authorized_tools.length + " 个工具" : "失败，" + r.detail}`).join("；"));
    } else if (action === "runtime-status") {
      const output = $("#runtime-result"); output.textContent = "正在检查服务…";
      const result = await api("/api/v1/status");
      if (output.isConnected) output.innerHTML = OpsUI.runtime(result);
    }
    else if (action === "alert-prev" || action === "alert-next") {
      state.alertPage = Math.max(1, Math.min(state.alertPageCount, state.alertPage + (action === "alert-next" ? 1 : -1)));
      await navigate();
    }
    else if (action === "task-prev" || action === "task-next") {
      state.taskPage = Math.max(1, Math.min(
        state.taskPageCount,
        state.taskPage + (action === "task-next" ? 1 : -1),
      ));
      await navigate();
    } else if (action === "audit-prev" || action === "audit-next") {
      state.auditPage = Math.max(1, Math.min(
        state.auditPageCount,
        state.auditPage + (action === "audit-next" ? 1 : -1),
      ));
      await navigate();
    } else if (action === "toggle-logs") {
      state.includeLogs = !state.includeLogs;
      await navigate();
    } else if (action === "cancel-task") {
      await api(P + `/tasks/${id}/cancel`, "POST");
      toast("已请求取消；平台停止后续调用，远端已开始的 SSH 受其自身超时限制。");
      await navigate();
    } else if (action === "retry-task") {
      const t = await api(P + `/tasks/${id}/retry`, "POST");
      go("report/" + t.task_id);
    }
  } catch (err) {
    if (err.status === 503 && err.detail?.task_id) go("report/" + err.detail.task_id);
    toast(err.message);
  } finally {
    b.disabled = false;
  }
});
document.addEventListener("change", (e) => {
  OpsUI.mark(e.target.closest("form"));
  if (e.target.id === "task-status") {
    state.taskStatus = e.target.value;
    state.taskPage = 1;
    navigate();
  }
});
document.addEventListener("input", event => {
  const form = event.target.closest("form");
  OpsUI.mark(form);
  const verification = form?.querySelector("[data-verify-result]");
  if (verification?.textContent && !form.querySelector('[data-action]:disabled')) {
    verification.textContent = "填写内容已修改，请重新验证。"; verification.dataset.result = "pending";
  }
});
window.addEventListener("beforeunload", event => { if (OpsUI.dirty()) { event.preventDefault(); event.returnValue = ""; } });
document.addEventListener("keydown", event => {
  if (!event.target.matches('[role="tab"]') || !["ArrowLeft", "ArrowRight", "Home", "End"].includes(event.key)) return;
  event.preventDefault();
  const tabs = [...document.querySelectorAll('[role="tab"]')];
  const index = tabs.indexOf(event.target);
  const next = event.key === "Home" ? 0 : event.key === "End" ? tabs.length - 1 : (index + (event.key === "ArrowRight" ? 1 : -1) + tabs.length) % tabs.length;
  selectConfigTab(tabs[next].dataset.id); tabs[next].focus();
});
document.addEventListener("submit", async (event) => {
  const form = event.target;
  if (["alert-filter", "history-filter"].includes(form.id)) {
    event.preventDefault(); const data = Object.fromEntries(new FormData(form));
    if (form.id === "alert-filter") {
      state.alertQuery = data.q.trim(); state.alertStatus = data.status; state.alertSeverity = data.severity; state.alertPage = 1;
    } else { state.taskQuery = data.q.trim(); state.taskPage = 1; }
    await navigate(); return;
  }
  if (
    ![
      "editor-form",
      "diagnostic-form",
      "ask-form",
      "mute-form",
      "zabbix_mcp-form",
      "ssh_mcp-form",
    ].includes(form.id) && !form.classList.contains("settings-form")
  )
    return;
  event.preventDefault();
  if (form.id === "editor-form") {
    $("#editor-feedback").textContent = "";
    $("#editor-feedback").hidden = true;
  }
  const b = form.querySelector("[type=submit]");
  b.disabled = true;
  try {
    const data = formValues(form);
    if (form.id === "mute-form") {
      data.hours = Number(data.hours);
      await api("/api/v1/alert-mutes", "POST", data);
      toast("已设置本平台飞书告警屏蔽");
      await navigate();
    } else if (form.classList.contains("settings-form") || form.classList.contains("connection-form")) {
      const unlock = OpsUI.lock(form);
      try {
        await api("/api/v1/settings", "PUT", { values: data });
        form.querySelectorAll('.secret-control input').forEach(input => { if (input.value) input.value = "********"; input.type = "password"; });
        form.querySelectorAll('[data-action="toggle-secret"]').forEach(button => button.textContent = "显示");
      } finally { unlock(); }
      OpsUI.saved(form);
      const result = form.querySelector("[data-verify-result]");
      result.dataset.result = "success";
      result.textContent = "配置已保存。连接参数有修改时，请重新验证连接。";
      toast("配置已保存");
    } else if (form.id === "ask-form") {
      if (!data.question.trim()) throw Error("请输入问题");
      const output = $("#ask-result");
      output.textContent = "正在查询后台MCP服务并进行分析……";
      const r = await api("/api/v1/ask", "POST", data);
      if (output.isConnected) output.innerHTML = OpsUI.answer(readableReportAnswer(r.answer));
    } else if (form.id === "diagnostic-form") {
      const t = await api(P + "/tasks", "POST", data);
      go("report/" + t.task_id);
    } else {
      const { type, id } = state.editor;
      let path,
        method = id ? "PUT" : "POST",
        payload = data;
      if (type === "member") {
        path = "/members";
        method = "PUT";
        data.enabled = form.elements.enabled.checked;
      }
      await api(P + path, method, payload);
      $("#editor").close();
      toast("已保存");
      await navigate({preserveDrafts: true});
    }
  } catch (err) {
    if (err.status === 503 && err.detail?.task_id) go("report/" + err.detail.task_id);
    toast(err.message || "操作失败，请检查网络后重试");
  } finally {
    b.disabled = false;
  }
});
$("#close-editor").addEventListener("click", () => $("#editor").close());
$("#theme-toggle").addEventListener("click", () => {
  const theme =
    document.documentElement.dataset.theme === "dark" ? "light" : "dark";
  document.documentElement.dataset.theme = theme;
  localStorage.setItem("aiops-theme", theme);
});
$("#logout").addEventListener("click", async () => {
  try {
    if (OpsUI.dirty() && !window.confirm("有配置尚未保存，仍然退出登录？")) return;
    await api("/api/v1/auth/logout", "POST");
    location.reload();
  } catch (e) {
    toast(e.message);
  }
});
window.addEventListener("hashchange", navigate);
(async () => {
  const theme = localStorage.getItem("aiops-theme");
  if (theme) document.documentElement.dataset.theme = theme;
  try {
    state.user = await api("/api/v1/auth/me");
    state.csrf = state.user.csrf || "";
    const nextReport = sessionStorage.getItem("aiops-next-report");
    if (
      !location.hash &&
      nextReport &&
      /^#report\/[a-f0-9]{32}$/.test(nextReport)
    ) {
      location.hash = nextReport;
      sessionStorage.removeItem("aiops-next-report");
    }
    $("#login").hidden = true;
    $("#app").hidden = false;
    $("#username").textContent = state.user.name;
    $("#role-label").textContent = labels[state.user.role] || "管理员";
    $("#navigation").innerHTML = nav
      .filter((x) => can(x[3]))
      .map(
        ([page, title, icon]) =>
          `<button data-page="${page}"><span class="nav-icon" aria-hidden="true">${icon}</span>${title}</button>`,
      )
      .join("");
    $("#navigation").addEventListener("click", (e) => {
      const b = e.target.closest("[data-page]");
      if (b) go(b.dataset.page);
    });
    const h = await api("/healthz");
    $("#version").textContent = "v" + h.version;
    await navigate();
  } catch (err) {
    $("#login-error").textContent = err.message;
    try {
      if ((await api("/api/v1/setup/status")).setup_required)
        $("#login-error").textContent = "首次部署，请点击下方「首次初始化」。";
    } catch {}
  }
})();

$('#login a[href="/api/v1/auth/login"]').addEventListener("click", () => {
  if (/^#report\/[a-f0-9]{32}$/.test(location.hash))
    sessionStorage.setItem("aiops-next-report", location.hash);
});
