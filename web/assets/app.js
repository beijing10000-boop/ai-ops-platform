"use strict";
async function mutesPanel() {
  const rows = await api("/api/v1/alert-mutes");
  return panel(
    "飞书告警屏蔽",
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
        ["主机 ID", "触发器 ID", "到期时间", "操作"],
        rows
          .map(
            (r) =>
              `<tr><td>${E(r.host_id)}</td><td>${E(r.trigger_id)}</td><td>${date(new Date(r.expires_at * 1000).toISOString())}</td><td>${btn("unmute", "提前解除", r.host_id + ":" + r.trigger_id, "small")}</td></tr>`,
          )
          .join(""),
      ),
    "仅影响本平台的问题通知；不修改 Zabbix，也不屏蔽已经发送的告警对应的恢复。",
  );
}
const $ = (s) => document.querySelector(s),
  E = (v) =>
    String(v ?? "").replace(
      /[&<>"']/g,
      (c) =>
        ({
          "&": "&amp;",
          "<": "&lt;",
          ">": "&gt;",
          '"': "&quot;",
          "'": "&#39;",
        })[c],
    );
const state = {
  user: null,
  csrf: "",
  auditPage: 1,
  taskPage: 1,
  taskStatus: "all",
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
    throw new Error(
      typeof result.detail === "string"
        ? result.detail
        : Array.isArray(result.detail)
          ? result.detail.map((error) => error.msg || "输入无效").join("；")
          : "请求失败，请稍后重试",
    );
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
  return `<div class="field ${wide ? "wide" : ""}">${type === "checkbox" ? "" : `<span>${label}</span>`}${control}${help ? `<small>${E(help)}</small>` : ""}</div>`;
}
function taskRows(rows) {
  return rows
    .map(
      (r) =>
        `<tr><td><button class="link-button mono" data-action="report" data-id="${E(r.task_id)}">${E(r.task_id.slice(0, 12))}</button><small>${date(r.created_at)}</small></td><td>${E(PLAY[r.diagnostic_type] || r.diagnostic_type)}<small>${E(r.source)} · ${E(labels[r.profile] || r.profile)}</small></td><td>${badge(r.status)}<small>${E(r.stage)}</small></td><td>${fmt(r.tools)}</td><td>${r.duration_ms == null ? "—" : (r.duration_ms / 1000).toFixed(1) + " s"}</td><td>${fmt(r.token_total)}<small>${r.token_total == null ? "未返回用量" : "模型实际用量"}</small></td><td>${btn("report", "查看", r.task_id, "small")}</td></tr>`,
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
  const [o, t] = await Promise.all([
    api(P + "/overview"),
    api(P + "/tasks?page_size=6"),
  ]);
  const stat = (label, value, hint) =>
    `<div class="stat"><div class="label">${label}</div><div class="value">${value}</div><div class="hint">${hint}</div></div>`;
  return (
    intro(
      "最近 24 小时 · 统计截止当前 · 北京时间",
      btn("refresh", "刷新数据"),
    ) +
    `<div class="hero"><div><span class="eyebrow">EVIDENCE BEFORE ACTION</span><h2>让每一次诊断，都有据可循。</h2><p class="muted small">告警历史、Linux 实时检查与 AI 分析，汇聚到同一条诊断记录。</p></div><div class="hero-mark">✧</div></div><div class="stats">${stat("未收到恢复的事件", fmt(o.unrecovered_received_events), "限平台已接收事件，非全量 Zabbix 告警")}${stat("AI 分析次数", fmt(o.ai_runs_24h), "最近 24 小时创建")}${stat("AI 分析成功率", o.ai_success_rate_24h == null ? "—" : o.ai_success_rate_24h + "%", "已完成 / AI 已结束任务")}${stat("Token 消耗", fmt(o.token_total_24h), `最近 24 小时 · ${fmt(o.usage_available_runs_24h)} 次返回实际用量`)}</div><div class="grid-two">${panel("连接与诊断能力", `<div class="health-row"><div>Zabbix MCP<p>以最近一次主动连接检测为准</p></div>${badge(o.health.find((x) => x.provider === "zabbix_mcp")?.status || (o.mcp_configured ? "未检测" : "未配置"))}</div><div class="health-row"><div>SSH MCP<p>独立服务，按 Host ID 补充实时证据</p></div>${badge(o.health.find((x) => x.provider === "ssh_mcp")?.status || (o.ssh_mcp_configured ? "未检测" : "未配置"))}</div><p class="muted small">主机由 Zabbix MCP 与 SSH MCP 管理，通过 Zabbix Host ID 关联。</p>`)}${panel("诊断概况", `<div class="health-row"><span>已完成 / 部分完成</span><strong>${fmt(o.completed_24h)} / ${fmt(o.partial_24h)}</strong></div><div class="health-row"><span>失败任务</span><strong>${fmt(o.failed_24h)}</strong></div><div class="health-row"><span>平均分析耗时</span><strong>${o.average_duration_ms_24h == null ? "—" : (o.average_duration_ms_24h / 1000).toFixed(1) + " s"}</strong></div><div class="notice small">缺失数据会明确标记。AI 结论属于分析推断，监控与 SSH 证据可在任务详情核验。</div>`)}</div><div class="panel"><div class="section-heading"><div><h2>最近诊断</h2><p class="muted small">告警分析、问答与手动诊断</p></div>${btn("go-history", "全部记录 →", "", "quiet")}</div>${table(["任务 / 时间", "诊断类型 / 来源", "状态", "工具", "耗时", "Token", "操作"], taskRows(t.items))}</div>`
  );
}
async function alerts() {
  const rows = await api("/api/v1/alert-events?kind=problems&limit=100");
  return (
    intro(
      "最近 100 条已接收的问题事件 · 恢复与通知状态保留在事件记录中",
      btn("refresh", "刷新"),
    ) +
    panel(
      "告警事件",
      table(
        ["事件 ID", "主机 / 事件", "级别", "接收时间", "通知 / AI", "操作"],
        rows
          .map(
            (r) =>
              `<tr><td class="mono">${E(r.event_id)}</td><td><span class="cell-title">${E(r.host_name)}</span><small>${E(r.event_name)}</small></td><td><span class="severity s${E(r.severity)}"></span>${["未分类", "信息", "警告", "一般严重", "严重", "灾难"][r.severity] || "—"}</td><td>${E(r.received_at)}</td><td>${badge(r.notify_status)} ${badge(r.ai_status)}</td><td>${can("diagnostics.run") ? btn("analyze-event", "AI 分析", r.event_id, "small") : ""}</td></tr>`,
          )
          .join(""),
      ),
    )
  );
}
async function diagnostics() {
  return (
    intro(
      "选择 Zabbix 监控主机或已接收的告警发起诊断。执行前查询监控，必要时补充 Linux 实时证据。",
    ) +
    panel(
      "新建诊断",
      `<form id="diagnostic-form"><div class="form-grid"><div class="field wide"><span>查询监控主机</span><div class="toolbar"><input id="host-search" aria-label="搜索 Zabbix 主机" placeholder="输入主机名称或 Zabbix Host ID">${btn("search-hosts", "查询 Zabbix 主机")}</div><small id="host-search-result" role="status">直接从 Zabbix MCP 读取主机，无需在平台登记资产。</small></div>${field("zabbix_hostid", "诊断主机", "", "text", "选择监控主机后，平台通过相同 Host ID 关联独立 SSH MCP；填写告警事件 ID 时以事件主机为准。", [["", "未选择主机"], ...state.hostRows.map(h => [h.zabbix_hostid, h.name + " · Host ID " + h.zabbix_hostid + " · " + (labels[h.device_type] || h.device_type)])])}${field("event_id", "告警事件 ID", state.selectedEvent || "", "text", "可选，必须是平台已经接收的事件。")}${field("diagnostic_type", "诊断类型", "auto", "text", "", [["auto", "自动识别告警类型"], ...Object.entries(PLAY)])}${field(
        "profile",
        "分析模式",
        "standard",
        "text",
        "快速仅监控；标准按需 SSH；深度允许更多补查。",
        [
          ["quick", "快速分析"],
          ["standard", "标准分析"],
          ["deep", "深度分析"],
        ],
      )}${field("service", "systemd 服务名", "", "text", "服务/日志诊断时填写，如 nginx.service。")}${field("time_window", "日志窗口（分钟）", "30", "number", "范围 1–120 分钟；监控历史默认围绕告警前 30 分钟。")}${field("question", "诊断问题", "请根据实际证据诊断故障并给出建议", "textarea", "", null, true)}</div><div class="form-actions">${btn("validate-diagnostic", "验证诊断参数与关联")}<button class="button primary" type="submit">开始诊断 →</button></div><p role="status" data-verify-result></p></form>`,
    ) +
    panel(
      "监控问答",
      `<form id="ask-form">${field("question", "查询监控或提出问题", "", "textarea", "问答中的地址文字不会自动成为 SSH 连接目标。", null, true)}<div class="form-actions"><button class="button" type="submit">发送问题</button></div></form><div id="ask-result" class="report-answer"></div>`,
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
      "<h3 class=\"subsection-heading\">标准诊断流程</h3>" +
      table(
        ["问题类型", "监控数据", "固定动作", "诊断边界"],
        Object.entries(data.playbooks)
          .map(
            ([key, p]) =>
              `<tr><td>${E(p.label)}</td><td class="mono">${E(p.metrics.join(", "))}</td><td>${E(p.actions.join(", "))}</td><td class="muted small">${E(p.limitation)}</td></tr>`,
          )
          .join(""),
      ),
    "查看两个 MCP 的授权工具与各类问题的诊断边界。",
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
    paged(P + "/tasks", "taskPage", 25, { status: state.taskStatus }),
    api("/api/v1/ai-token-usage?days=30&limit=20"),
  ]);
  return (
    intro(
      "任务、工具调用与证据可按 trace_id 追溯。Token 仅使用模型实际返回数据。",
      btn("refresh", "刷新"),
    ) +
    `<div class="token-grid"><div class="stat"><div class="label">最近 30 天 · 输入 Token</div><div class="value">${fmt(usage.total_input)}</div></div><div class="stat"><div class="label">最近 30 天 · 输出 Token</div><div class="value">${fmt(usage.total_output)}</div></div><div class="stat"><div class="label">最近 30 天 · 总 Token</div><div class="value">${fmt(usage.total_tokens)}</div><div class="hint">未返回用量的请求不计入汇总</div></div></div><div class="panel"><div class="toolbar"><select id="task-status" aria-label="任务状态"><option value="all">全部任务状态</option>${["queued", "running", "success", "partial", "failed", "cancelled"].map((s) => `<option value="${s}" ${s === state.taskStatus ? "selected" : ""}>${labels[s]}</option>`).join("")}</select><span class="muted small">共 ${data.total} 条</span></div>${table(["任务 / 时间", "诊断类型 / 来源", "状态", "工具", "耗时", "Token", "操作"], taskRows(data.items))}${pagination("task", "taskPage")}</div>` +
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
async function report(id) {
  const t = await api(
    P +
      "/tasks/" +
      encodeURIComponent(id) +
      (state.includeLogs ? "?include_logs=true" : ""),
  );
  state.currentTask = t;
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
        btn("refresh", "刷新"),
    ) +
    `<div class="stats"><div class="stat"><div class="label">诊断状态</div><div class="value">${badge(t.status)}</div><div class="hint">${E(t.stage)}</div></div><div class="stat"><div class="label">主机 / 事件 ID</div><div class="value">${E(t.alert?.host_id || t.asset?.zabbix_hostid || "—")}</div><div class="hint">事件 ${E(t.event_id || "未关联")}</div></div><div class="stat"><div class="label">实际 Token / 工具调用</div><div class="value">${fmt(t.token_total)}</div><div class="hint">${fmt(t.tools)} 次采集 · 输入 ${fmt(t.token_input)} / 输出 ${fmt(t.token_output)}</div></div><div class="stat"><div class="label">执行耗时</div><div class="value">${t.duration_ms == null ? "—" : (t.duration_ms / 1000).toFixed(1) + " s"}</div><div class="hint">${date(t.created_at)}</div></div></div>` +
    panel(
      "告警与资产信息",
      `<p>${E(t.alert?.event_name || "手动诊断 / 连接测试")}</p><p class="muted small">主机：${E(t.asset?.name || t.alert?.host_name || "未关联")} · Host ID：${E(t.asset?.zabbix_hostid || t.alert?.host_id || "—")} · 类型：${E(labels[t.report?.device_type || t.asset?.device_type] || "待确认")}</p>`,
    ) +
    panel(
      "AI 诊断结论 · 分析推断",
      `<div class="notice">监控和 SSH 事实在下方按来源记录。AI 总结需结合时间窗口与原始证据核验。</div><div class="report-answer">${E(t.report?.answer || t.report?.message || (["queued", "running"].includes(t.status) ? "任务正在进行，页面会自动更新。" : JSON.stringify(t.report || {})))}</div>`,
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
    `<div class="panel"><div class="section-heading"><div><h2>证据与工具执行记录</h2><p class="muted small">Zabbix 为监控证据；SSH 为采集当时快照。日志内容需要独立权限。</p></div>${can("logs.read") ? btn("toggle-logs", state.includeLogs ? "隐藏原始日志" : "读取日志证据", id) : ""}</div>${t.evidence.length ? t.evidence.map((e) => `<details class="evidence"><summary>${E(e.provider)} / ${E(e.tool)} ${badge(e.status)} · ${date(e.collected_at)}</summary><pre>${E(JSON.stringify(e.payload, null, 2))}</pre></details>`).join("") : '<div class="empty">暂无采集证据</div>'}</div>`
  );
}
const configHelp = {
  web_protocol: "用于生成飞书登录回调和报告链接；HTTPS 证书由外部入口配置。",
  web_public_host: "用户实际访问的平台域名/IP和端口，例如 172.20.200.94:8088。",
  zabbix_frontend_url: "用于从告警卡片和报告打开 Zabbix 网页。",
  zabbix_webhook_secret: "验证 Zabbix 推送告警的身份，需与 Zabbix 告警媒介中的密钥一致。",
};
const configGroups = {
  ai: [
    ["openai_base_url", "模型 Base URL"],
    ["openai_model", "模型部署名称"],
    ["openai_api_key", "API Key", "password"],
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
    ["ai_alert_prompt", "告警分析提示词", "textarea"],
    ["ai_qa_prompt", "问答提示词", "textarea"],
    ["ai_tool_loading", "监控工具加载方式", "select", [["dynamic", "按需加载（推荐）"], ["full", "加载全部授权工具"]]],
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
  return `<h3>分析预算</h3><p class="muted small">SSH MCP 的主机解析也计入采集次数；实际调用受任务剩余时间限制。</p>` + table(["分析模式", ...Object.values(names)], Object.entries(options.profiles).map(([profile, limits]) => `<tr><td>${labels[profile]}</td>${Object.keys(names).map(key => `<td><input class="budget-input" type="number" name="budget_${profile}_${key}" aria-label="${labels[profile]} ${names[key]}" min="${options.ranges[key][0]}" max="${options.ranges[key][1]}" required value="${E(custom[profile]?.[key] ?? limits[key])}"></td>`).join("")}</tr>`).join(""));
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
  const show = message => { if (result) result.textContent = message; else toast(message); };
  const request = async (path, body) => {
    show("正在验证…");
    try { const r = await api(path, "POST", body); show(r.message || r.reply || (r.ok ? `连接成功，${r.authorized_tools?.length || 0} 个授权工具` : "验证失败：" + r.detail)); }
    catch (err) {show("验证未通过：" + err.message);}
  };
  if (["validate-settings", "validate-connection"].includes(action)) await request("/api/v1/settings/validate", {values: formValues(form)});
  else if (action === "verify-mcp") await request(P + "/tools/discover?provider=" + id, {values: formValues(form)});
  else if (action === "test-model") await request("/api/v1/test/ai", form ? {values: formValues(form)} : undefined);
  else if (action === "verify-feishu" || action === "verify-feishu-groups") await request("/api/v1/test/feishu" + (action === "verify-feishu-groups" ? "?check_groups=true" : ""), {values: formValues(form)});
  else if (action === "validate-diagnostic") await request(P + "/tasks/validate", formValues(form));
  else if (action === "validate-editor") {
    await request(P + "/members/validate", formValues(form));
  } else if (action === "reset-prompts") {
    for (const [key, value] of Object.entries(state.options.prompts)) form.elements[key].value = value;
    show("已恢复项目默认提示词，保存后生效。");
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
    ai: "配置模型、默认提示词与分析预算。单次请求的实际 Token 用量在上游响应后才可确认。验证模型连接会产生少量实际用量。",
  };
  const actions = group === "ai"
    ? btn("test-model", "验证模型连接") + btn("reset-prompts", "恢复默认提示词")
    : group === "feishu"
      ? btn("verify-feishu", "验证飞书应用") + btn("verify-feishu-groups", "验证群访问权限")
      : "";
  const fields = configGroups[group].filter(x => can("*") || x[0] !== "feishu_admin_open_ids");
  return panel(
    titles[group],
    `<form id="${group}-settings-form" class="settings-form" data-group="${group}"><div class="form-grid">${fields.map(([key, label, type, choices]) => field(key, label, values[key] || "", type === "select" ? "text" : type || "text", key.includes("prompt") ? "已提供项目默认提示词；可编辑。留空后使用默认值。平台只读与证据规则始终生效。" : (configHelp[key] || ""), choices || null, type === "textarea")).join("")}</div>${group === "ai" ? budgetFields(values, options) : ""}${group === "settings" && can("*") ? toolFields(values, options) : ""}<div class="form-actions">${btn("validate-settings", "验证填写内容")}${actions}<button class="button primary" type="submit">保存${group === "settings" ? "基础" : group === "feishu" ? "飞书" : "AI"}配置</button></div><p class="muted small" role="status" data-verify-result></p></form>`,
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
  if (can("alerts.manage")) feishuExtra += await mutesPanel();
  return (
    intro("基础设置、飞书与 AI 配置集中管理。每个区域独立验证和保存；区域跳转会保留当前填写内容。") +
    `<div class="toolbar" aria-label="系统配置分区">${btn("scroll-section", "基础设置", "settings-general")}${btn("scroll-section", "飞书配置", "settings-feishu")}${btn("scroll-section", "AI 配置", "settings-ai")}${btn("scroll-section", "备份与升级", "settings-maintenance")}</div>` +
    configSection("settings", values, options) +
    configSection("feishu", values, options) + feishuExtra +
    configSection("ai", values, options) +
    panel(
      "备份与升级",
      `<p class="muted small">凭据保存在加密数据库中。升级前停止本项目 Worker，备份 SQLite 和持久化主密钥。数据库与配对主密钥需一起备份；升级步骤见仓库 docs/UPGRADING.md。</p>${btn("runtime-status", "查看服务与队列状态")}<pre id="runtime-result"></pre>`,
      "",
      "settings-maintenance",
    )
  );
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
async function navigate() {
  clearTimeout(poll);
  const current = ++generation;
  const parts = (location.hash.slice(1) || "overview").split("/");
  // Keep existing bookmarks useful after consolidating the navigation.
  if (["ai", "feishu", "tools"].includes(parts[0])) {
    const oldPage = parts[0];
    parts.splice(0, parts.length, oldPage === "tools" ? "connections" : "settings", oldPage);
    window.history.replaceState(null, "", "#" + parts.join("/"));
  }
  const page = parts[0];
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
  $("#content").innerHTML = '<div class="empty" role="status">正在加载…</div>';
  try {
    let html;
    if (page === "overview") html = await overview();
    else if (page === "alerts") html = await alerts();
    else if (page === "diagnostics") html = await diagnostics();
    else if (page === "connections") html = await connections();
    else if (page === "history") html = await analysisHistory();
    else if (page === "report") html = await report(parts[1] || "");
    else if (page === "settings") html = await systemSettings();
    else if (page === "audit") html = await auditPage();
    else html = await overview();
    if (current !== generation) return;
    $("#content").innerHTML = html;
    const section = page === "settings" ? "settings-" + parts[1] : page === "connections" && parts[1] === "tools" ? "connection-tools" : "";
    if (section) document.getElementById(section)?.scrollIntoView({ block: "start" });
    if (
      (page === "report" && ["running", "queued"].includes(state.currentTask?.status))
    )
      poll = setTimeout(navigate, 3000);
  } catch (err) {
    if (current === generation)
      $("#content").innerHTML =
        `<div class="notice error" role="alert">${E(err.message)}</div>`;
  }
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
    else if (action === "scroll-section") document.getElementById(id)?.scrollIntoView({ block: "start" });
    else if (action === "go-history") go("history");
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
      go("diagnostics");
    } else if (action === "discover") {
      const results = await Promise.all(["zabbix_mcp", "ssh_mcp"].map(provider => api(P + "/tools/discover?provider=" + provider, "POST")));
      toast(results.map(r => `${r.provider}：${r.ok ? "连接成功，" + r.authorized_tools.length + " 个工具" : "失败，" + r.detail}`).join("；"));
    } else if (action === "runtime-status")
      $("#runtime-result").textContent = JSON.stringify(
        await api("/api/v1/status"),
        null,
        2,
      );
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
    toast(err.message);
  } finally {
    b.disabled = false;
  }
});
document.addEventListener("change", (e) => {
  if (e.target.id === "task-status") {
    state.taskStatus = e.target.value;
    state.taskPage = 1;
    navigate();
  }
});
document.addEventListener("submit", async (event) => {
  const form = event.target;
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
      await api("/api/v1/settings", "PUT", { values: data });
      toast("配置已保存");
    } else if (form.id === "ask-form") {
      if (!data.question.trim()) throw Error("请输入问题");
      const output = $("#ask-result");
      output.textContent = "正在查询监控并分析…";
      const r = await api("/api/v1/ask", "POST", data);
      if (output.isConnected) output.textContent = r.answer;
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
      await navigate();
    }
  } catch (err) {
    toast(err.message);
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
