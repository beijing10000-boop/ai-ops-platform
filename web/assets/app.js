"use strict";
async function groupsPanel(rows) {
  state.groupRows = rows;
  return panel(
    "主机组",
    table(
      ["ID", "名称", "来源", "操作"],
      rows
        .map(
          (g) =>
            `<tr><td>${g.id}</td><td>${E(g.name)}</td><td>${g.zabbix_groupid ? "Zabbix · " + E(g.zabbix_groupid) : "本地手工组"}</td><td>${can("inventory.manage") && !g.zabbix_groupid ? btn("edit-group", "编辑", g.id, "small") + btn("delete-group", "删除", g.id, "small danger") : ""}</td></tr>`,
        )
        .join(""),
    ),
    "同步组在 Zabbix 维护；本地组可以创建、编辑及分配给多个资产。",
  );
}
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
  assetPage: 1,
  assetQuery: "",
  assetType: "all",
  assetGroup: "",
  auditPage: 1,
  taskPage: 1,
  taskStatus: "all",
  editor: null,
  assetRows: [],
  includeLogs: false,
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
  ["assets", "主机资产", "▤", "inventory.read"],
  ["tools", "诊断工具", "⌘", "tools.read"],
  ["connections", "连接管理", "⇄", "settings.manage"],
  ["history", "分析历史", "◷", "reports.read"],
  ["feishu", "飞书管理", "◇", "settings.manage"],
  ["ai", "AI 配置", "◎", "settings.manage"],
  ["settings", "系统设置", "⚙", "settings.manage"],
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
const panel = (title, body, note = "") =>
  `<section class="panel"><div class="section-heading"><div><h2>${title}</h2>${note ? `<p class="muted small">${note}</p>` : ""}</div></div>${body}</section>`;
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
    `<div class="hero"><div><span class="eyebrow">EVIDENCE BEFORE ACTION</span><h2>让每一次诊断，都有据可循。</h2><p class="muted small">告警历史、Linux 实时检查与 AI 分析，汇聚到同一条诊断记录。</p></div><div class="hero-mark">✧</div></div><div class="stats">${stat("未收到恢复的事件", fmt(o.unrecovered_received_events), "限平台已接收事件，非全量 Zabbix 告警")}${stat("AI 分析次数", fmt(o.ai_runs_24h), "最近 24 小时创建")}${stat("AI 分析成功率", o.ai_success_rate_24h == null ? "—" : o.ai_success_rate_24h + "%", "已完成 / AI 已结束任务")}${stat("Token 消耗", fmt(o.token_total_24h), `最近 24 小时 · ${fmt(o.usage_available_runs_24h)} 次返回实际用量`)}</div><div class="grid-two">${panel("连接与诊断能力", `<div class="health-row"><div>Zabbix MCP<p>以最近一次主动连接检测为准</p></div>${badge(o.health.find((x) => x.provider === "zabbix_mcp")?.status || (o.mcp_configured ? "未检测" : "未配置"))}</div><div class="health-row"><div>SSH MCP<p>独立服务，按 Host ID 补充实时证据</p></div>${badge(o.health.find((x) => x.provider === "ssh_mcp")?.status || (o.ssh_mcp_configured ? "未检测" : "未配置"))}</div><div class="health-row"><div>已关联 Linux 主机<p>以 Zabbix Host ID 绑定</p></div><strong>${fmt(o.linked_linux_hosts)}</strong></div>`)}${panel("诊断概况", `<div class="health-row"><span>已完成 / 部分完成</span><strong>${fmt(o.completed_24h)} / ${fmt(o.partial_24h)}</strong></div><div class="health-row"><span>失败任务</span><strong>${fmt(o.failed_24h)}</strong></div><div class="health-row"><span>平均分析耗时</span><strong>${o.average_duration_ms_24h == null ? "—" : (o.average_duration_ms_24h / 1000).toFixed(1) + " s"}</strong></div><div class="notice small">缺失数据会明确标记。AI 结论属于分析推断，监控与 SSH 证据可在任务详情核验。</div>`)}</div><div class="panel"><div class="section-heading"><div><h2>最近诊断</h2><p class="muted small">告警分析、问答与手动诊断</p></div>${btn("go-history", "全部记录 →", "", "quiet")}</div>${table(["任务 / 时间", "诊断类型 / 来源", "状态", "工具", "耗时", "Token", "操作"], taskRows(t.items))}</div>`
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
      "按注册资产或已接收的告警发起诊断。执行前查询监控，必要时补充 Linux 实时证据。",
    ) +
    panel(
      "新建诊断",
      `<form id="diagnostic-form"><div class="form-grid">${field("asset_id", "资产 ID", state.selectedAsset || "", "number", "在主机资产页点击「诊断」可自动带入；不接受任意网络地址。")}${field("event_id", "告警事件 ID", state.selectedEvent || "", "text", "可选，必须是平台已经接收的事件。")}${field("diagnostic_type", "诊断类型", "auto", "text", "", [["auto", "自动识别告警类型"], ...Object.entries(PLAY)])}${field(
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
async function assets() {
  const [data, groups] = await Promise.all([
    paged(P + "/assets", "assetPage", 25, {
      q: state.assetQuery, device_type: state.assetType,
      ...(state.assetGroup ? {group_id: state.assetGroup} : {}),
    }), api(P + "/groups"),
  ]);
  state.assetRows = data.items;
  return intro("监控资产用于告警关联。SSH 主机、私钥、跳板及公钥在独立 SSH MCP 管理；两边登记相同 Zabbix Host ID 即可关联。",
    can("inventory.manage") ? btn("sync-assets", "同步 Zabbix") + btn("import-assets", "批量导入") + btn("new-group", "新增主机组") + btn("new-asset", "登记资产", "", "primary") : "") +
    `<section class="panel"><div class="toolbar"><input id="asset-search" aria-label="搜索主机资产" placeholder="搜索名称、展示地址或 Host ID" value="${E(state.assetQuery)}"><select id="asset-type" aria-label="设备类型"><option value="all">全部设备类型</option>${["linux", "windows", "vmware", "network", "other", "unknown"].map(x => `<option value="${x}" ${state.assetType === x ? "selected" : ""}>${labels[x]}</option>`).join("")}</select><select id="asset-group" aria-label="主机组"><option value="">全部主机组</option>${groups.map(g => `<option value="${g.id}" ${state.assetGroup === String(g.id) ? "selected" : ""}>${E(g.name)}</option>`).join("")}</select>${btn("search-assets", "搜索")}<span class="muted small">共 ${fmt(data.total)} 台</span></div>${table(["资产 / Host ID", "设备类型", "展示地址", "诊断来源", "状态", "操作"], data.items.map(r => `<tr><td><span class="cell-title">${E(r.name)}</span><small>资产 ${r.id} · Host ID ${E(r.zabbix_hostid || "未关联")}</small></td><td>${badge(r.device_type)}</td><td class="mono">${E(r.address || "—")}</td><td>${r.device_type === "linux" ? "Zabbix + SSH MCP" : "仅监控分析"}</td><td>${badge(r.enabled ? "已启用" : "已禁用")}</td><td><div class="actions">${can("diagnostics.run") && r.enabled ? btn("diagnose-asset", "诊断", r.id, "small") + (r.device_type === "linux" ? btn("verify-binding", "验证关联", r.id, "small") : "") : ""}${can("inventory.manage") ? btn("edit-asset", "编辑", r.id, "small") : ""}</div></td></tr>`).join(""))}${pagination("asset", "assetPage")}</section>` + await groupsPanel(groups);
}

async function tools() {
  const data = await api(P + "/tools");
  state.toolData = data;
  return (
    intro(
      "平台固定白名单独立生效；远端自称只读或动态发现都不能扩大授权。",
      can("settings.manage") ? btn("discover", "检测 MCP 工具") : "",
    ) +
    panel(
      "工具注册表",
      table(
        ["工具 / 提供方", "适用设备", "风险 / 超时", "状态", "说明"],
        data.tools
          .map(
            (t) =>
              `<tr><td><span class="mono">${E(t.name)}</span><small>${E(t.provider)} · ${E(t.required_scope)}</small></td><td>${E(t.device_types.map((x) => labels[x] || x).join(" / "))}</td><td>${E(t.risk)} · ${t.timeout}s<small>输出 ≤ ${fmt(t.max_output_chars)} 字符</small></td><td>${badge(t.enabled ? "已启用" : "已禁用")}</td><td>${E(t.description)}</td></tr>`,
          )
          .join(""),
      ),
    ) +
    panel(
      "标准诊断流程",
      table(
        ["问题类型", "监控数据", "固定动作", "诊断边界"],
        Object.entries(data.playbooks)
          .map(
            ([key, p]) =>
              `<tr><td>${E(p.label)}</td><td class="mono">${E(p.metrics.join(", "))}</td><td>${E(p.actions.join(", "))}</td><td class="muted small">${E(p.limitation)}</td></tr>`,
          )
          .join(""),
      ),
    )
  );
}
async function connections() {
  const values = await api("/api/v1/settings");
  const groups = [
    ["zabbix_mcp", "Zabbix MCP", "监控指标、历史趋势和告警事实。", [["mcp_url", "Zabbix MCP 地址", "text"], ["mcp_token", "Zabbix MCP 令牌", "password"]]],
    ["ssh_mcp", "SSH MCP", "Linux 实时诊断；主机及 SSH 密钥在独立服务维护。", [["ssh_mcp_enabled", "启用 SSH MCP", "select", [["false", "关闭"], ["true", "开启"]]], ["ssh_mcp_url", "SSH MCP 地址", "text"], ["ssh_mcp_token", "SSH MCP 专用令牌", "password"], ["ssh_mcp_timeout_seconds", "单工具超时（秒）", "number"]]],
  ];
  return intro("分别配置两个 Streamable HTTP MCP。令牌加密保存且不回显原文；HTTP 地址仅用于受信任内网。验证连接检查当前表单，无需先保存。") + groups.map(([provider, title, note, fields]) => panel(title,
    `<form id="${provider}-form" class="connection-form" data-provider="${provider}"><div class="form-grid">${fields.map(([key, label, type, options]) => field(key, label, values[key] || "", type === "select" ? "text" : type, key.includes("url") ? "例如 http://服务所在服务器:端口/mcp；请填写容器可访问的地址。" : "", options || null)).join("")}</div><div class="form-actions">${btn("validate-connection", "验证填写内容", provider)}${btn("verify-mcp", "验证连接", provider)}<button class="button primary" type="submit">保存连接</button></div><p class="muted small" role="status" data-verify-result></p></form>`, note)).join("");
}
async function history() {
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
    `<div class="stats"><div class="stat"><div class="label">诊断状态</div><div class="value">${badge(t.status)}</div><div class="hint">${E(t.stage)}</div></div><div class="stat"><div class="label">资产 / 事件 ID</div><div class="value">${E(t.asset_id || "—")}</div><div class="hint">事件 ${E(t.event_id || "未关联")}</div></div><div class="stat"><div class="label">实际 Token / 工具调用</div><div class="value">${fmt(t.token_total)}</div><div class="hint">${fmt(t.tools)} 次采集 · 输入 ${fmt(t.token_input)} / 输出 ${fmt(t.token_output)}</div></div><div class="stat"><div class="label">执行耗时</div><div class="value">${t.duration_ms == null ? "—" : (t.duration_ms / 1000).toFixed(1) + " s"}</div><div class="hint">${date(t.created_at)}</div></div></div>` +
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
function parseAssetList(text) {
  // CSV and Excel TSV, including quoted fields. Never ask users to write JSON.
  const rows = [], row = []; let cell = "", quoted = false;
  const input = String(text || "").replace(/^\uFEFF/, "");
  const separator = input.includes("\t") ? "\t" : ",";
  for (let i = 0; i <= input.length; i++) {
    const c = input[i];
    if (quoted) {
      if (c === '"' && input[i + 1] === '"') {cell += '"'; i++;}
      else if (c === '"') quoted = false;
      else if (c === undefined) throw Error("清单引号未闭合");
      else cell += c;
    } else if (c === '"' && !cell) quoted = true;
    else if (c === separator) {row.push(cell); cell = "";}
    else if (c === "\n" || c === undefined) {
      row.push(cell.replace(/\r$/, "")); cell = "";
      if (row.some(v => v.trim())) rows.push([...row]); row.length = 0;
    } else cell += c;
  }
  if (rows[0]?.[0] === "资产名称") rows.shift();
  if (!rows.length || rows.length > 1000) throw Error("请填写 1–1000 行资产");
  return rows.map((r, index) => {
    if (r.length < 3 || r.length > 4) throw Error(`第 ${index + 1} 行需填写 3–4 列`);
    return {name: r[0].trim(), zabbix_hostid: r[1].trim() || null, device_type: r[2].trim(), address: (r[3] || "").trim()};
  });
}
function formValues(form) {
  const data = Object.fromEntries(new FormData(form));
  if (form.id === "editor-form") {
    if (state.editor.type === "asset") {
      data.enabled = form.elements.enabled.checked;
      data.zabbix_hostid = data.zabbix_hostid || null;
      data.group_ids = new FormData(form).getAll("group_ids").map(Number);
    } else if (state.editor.type === "member") data.enabled = form.elements.enabled.checked;
  }
  if (form.id === "diagnostic-form") {
    data.asset_id = data.asset_id ? Number(data.asset_id) : null;
    data.event_id = data.event_id || null; data.service = data.service || null;
    data.time_window = Number(data.time_window);
  }
  if (form.id === "settings-form") {
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
  const form = button.closest("form") || $("#settings-form");
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
  else if (action === "verify-binding") await request(P + "/assets/" + id + "/validate");
  else if (action === "validate-diagnostic") await request(P + "/tasks/validate", formValues(form));
  else if (action === "validate-editor") {
    const kind = state.editor.type, values = formValues(form);
    await request(P + "/validate", {kind, values: kind === "import" ? {assets: parseAssetList(values.csv)} : values});
  } else if (action === "reset-prompts") {
    for (const [key, value] of Object.entries(state.options.prompts)) form.elements[key].value = value;
    show("已恢复项目默认提示词，保存后生效。");
  } else if (action === "import-template") {
    const url = URL.createObjectURL(new Blob(["\uFEFF资产名称,Zabbix Host ID,设备类型,内网 IP\n测试Linux,10001,linux,172.20.1.10\n"], {type: "text/csv;charset=utf-8"}));
    const link = document.createElement("a"); link.href = url; link.download = "assets-template.csv"; link.click(); URL.revokeObjectURL(url);
  } else if (action === "validate-mute") {
    const values = formValues(form); values.hours = Number(values.hours);
    await request("/api/v1/alert-mutes/validate", values);
  } else return false;
  return true;
}

async function configPage(page) {
  const [values, options] = await Promise.all([api("/api/v1/settings"), api("/api/v1/settings/options")]);
  state.options = options;
  let fields = configGroups[page].filter(
    (x) =>
      can("*") || !["feishu_admin_open_ids", "disabled_tools"].includes(x[0]),
  );
  const hints = {
    ai: "预算可配置轮次、实际采集调用数、每轮调用数、输出字符、总时间和 Token 阈值。单次请求的实际 Token 用量在上游响应后才可确认。",
    feishu:
      "告警与问答沿用同一飞书应用。更换应用或访问地址后，请同时核对飞书回调地址和机器人权限。",
    settings:
      "敏感字段保留掩码表示不修改；凭据保存在同一加密数据库。主密钥和数据库必须一起备份。",
  };
  let extra = "";
  if (page === "feishu" && can("*")) {
    const members = await api(P + "/members");
    state.members = members;
    extra = `<div class="panel"><div class="section-heading"><div><h2>授权成员</h2><p class="muted small">超级管理员通过上方名单管理；其他角色由后端授权。</p></div>${btn("new-member", "添加成员")}</div>${table(["Open ID", "角色", "状态", "操作"], members.map((m) => `<tr><td class="mono">${E(m.open_id)}</td><td>${E(labels[m.role])}</td><td>${badge(m.enabled ? "已启用" : "已停用")}</td><td>${btn("edit-member", "编辑", m.open_id, "small")}</td></tr>`).join(""))}</div>`;
  }
  if (page === "feishu" && can("alerts.manage")) extra += await mutesPanel();
  if (page === "settings")
    extra += panel(
      "备份与升级",
      `<p class="muted small">升级前停止本项目 Worker，使用离线迁移工具备份 SQLite 和持久化主密钥。升级会删除旧 SSH 配置并保留历史报告，具体步骤见仓库 docs/UPGRADING.md。</p>${btn("runtime-status", "查看服务与队列状态")}<pre id="runtime-result"></pre>`,
    );
  return (
    intro(hints[page], page === "ai" ? btn("test-model", "验证模型连接") + btn("reset-prompts", "恢复默认提示词") : page === "feishu" ? btn("verify-feishu", "验证飞书应用") + btn("verify-feishu-groups", "验证群访问权限") : "") +
    panel(
      page === "ai"
        ? "AI 模型与分析策略"
        : page === "feishu"
          ? "飞书应用与告警策略"
          : "系统设置",
      `<form id="settings-form" data-group="${page}"><div class="form-grid">${fields.map(([key, label, type, options]) => field(key, label, values[key] || "", type === "select" ? "text" : type || "text", key.includes("prompt") ? "已提供项目默认提示词；可编辑。留空后使用默认值。平台只读与证据规则始终生效。" : "", options || null, type === "textarea")).join("")}</div>${page === "ai" ? budgetFields(values, options) : ""}${page === "settings" && can("*") ? toolFields(values, options) : ""}<div class="form-actions">${btn("validate-settings", "验证填写内容")}<button class="button primary" type="submit">保存配置</button></div><p class="muted small" role="status" data-verify-result></p></form>`,
    ) +
    extra
  );
}
async function auditPage() {
  const data = await paged(P + "/audit", "auditPage", 50);
  return (
    intro(
      "登录、配置变更、资产操作、报告访问和诊断操作",
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
    else if (page === "assets") html = await assets();
    else if (page === "tools") html = await tools();
    else if (page === "connections") html = await connections();
    else if (page === "history") html = await history();
    else if (page === "report") html = await report(parts[1] || "");
    else if (configGroups[page]) html = await configPage(page);
    else if (page === "audit") html = await auditPage();
    else html = await overview();
    if (current !== generation) return;
    $("#content").innerHTML = html;
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
  if (type === "asset") {
    const r = state.assetRows.find((x) => x.id === Number(id)) || {};
    const groups = await api(P + "/groups");
    title = id ? "编辑资产" : "登记资产";
    fields =
      field("name", "资产名称", r.name || "") +
      field("zabbix_hostid", "Zabbix Host ID", r.zabbix_hostid || "") +
      field(
        "device_type",
        "设备类型",
        r.device_type || "linux",
        "text",
        "",
        Array.from(
          ["linux", "windows", "vmware", "network", "other", "unknown"],
          (x) => [x, labels[x] || x],
        ),
      ) +
      `<fieldset class="field wide group-picker"><legend>主机组（可多选）</legend><div class="group-options">${groups.length ? groups.map((g) => `<label class="check-field"><input type="checkbox" name="group_ids" value="${g.id}" ${(r.group_ids || []).includes(g.id) ? "checked" : ""}><span>${E(g.name)}</span></label>`).join("") : '<span class="muted small">暂无主机组，可在资产页新增。</span>'}</div></fieldset>` +
      field("address", "展示用内网 IP（可选）", r.address || "", "text", "仅作资产展示；SSH MCP 通过 Host ID 确定实际连接地址。") +
      field(
        "enabled",
        "启用资产",
        r.enabled === undefined || !!r.enabled,
        "checkbox",
      );
    note = "SSH 连接信息在独立 SSH MCP 维护；平台无需上传私钥或公钥。";
  } else if (type === "group") {
    title = id ? "编辑主机组" : "新增主机组";
    fields = field(
      "name",
      "主机组名称",
      (state.groupRows || []).find((g) => g.id === Number(id))?.name || "",
    );
  } else if (type === "member") {
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
  } else if (type === "import") {
    title = "批量导入资产";
    fields = field(
      "csv",
      "粘贴 Excel 表格或 CSV 清单",
      "",
      "textarea",
      "四列依次为：资产名称、Zabbix Host ID、设备类型、内网 IP（可空）。设备类型填写 linux/windows/network/vmware/other/unknown；最多 1000 台。",
      null,
      true,
    ) + btn("import-template", "下载导入模板");
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
    else if (action === "go-history") go("history");
    else if (action === "report") go("report/" + id);
    else if (action === "new-asset" || action === "edit-asset")
      await openEditor("asset", id);
    else if (action === "new-group") await openEditor("group");
    else if (action === "edit-group") await openEditor("group", id);
    else if (action === "delete-group") {
      await api(P + "/groups/" + id, "DELETE");
      toast("本地主机组已删除，资产保留。");
      await navigate();
    } else if (action === "unmute") {
      const [host, trigger] = id.split(":");
      await api("/api/v1/alert-mutes/" + host + "/" + trigger, "DELETE");
      toast("屏蔽已解除");
      await navigate();
    } else if (action === "new-member" || action === "edit-member")
      await openEditor("member", id);
    else if (action === "import-assets") await openEditor("import");
    else if (action === "diagnose-asset") {
      state.selectedAsset = id;
      state.selectedEvent = "";
      go("diagnostics");
    } else if (action === "analyze-event") {
      state.selectedEvent = id;
      state.selectedAsset = "";
      go("diagnostics");
    } else if (action === "sync-assets") {
      const r = await api(P + "/assets-sync", "POST");
      toast(`已同步 ${r.count} 台。${r.note}`);
      await navigate();
    } else if (action === "discover") {
      const results = await Promise.all(["zabbix_mcp", "ssh_mcp"].map(provider => api(P + "/tools/discover?provider=" + provider, "POST")));
      toast(results.map(r => `${r.provider}：${r.ok ? "连接成功，" + r.authorized_tools.length + " 个工具" : "失败，" + r.detail}`).join("；"));
    } else if (action === "runtime-status")
      $("#runtime-result").textContent = JSON.stringify(
        await api("/api/v1/status"),
        null,
        2,
      );
    else if (action === "asset-prev" || action === "asset-next") {
      state.assetPage = Math.max(1, Math.min(
        state.assetPageCount,
        state.assetPage + (action === "asset-next" ? 1 : -1),
      ));
      await navigate();
    } else if (action === "search-assets") {
      state.assetQuery = $("#asset-search").value;
      state.assetType = $("#asset-type").value;
      state.assetGroup = $("#asset-group").value;
      state.assetPage = 1;
      await navigate();
    } else if (action === "task-prev" || action === "task-next") {
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
      "settings-form",
      "diagnostic-form",
      "ask-form",
      "mute-form",
      "zabbix_mcp-form",
      "ssh_mcp-form",
    ].includes(form.id)
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
    } else if (form.id === "settings-form" || form.classList.contains("connection-form")) {
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
      if (type === "asset") {
        path = "/assets" + (id ? "/" + id : "");
      } else if (type === "group") path = "/groups" + (id ? "/" + id : "");
      else if (type === "member") {
        path = "/members";
        method = "PUT";
        data.enabled = form.elements.enabled.checked;
      } else if (type === "import") {
        path = "/assets-import";
        payload = { assets: parseAssetList(data.csv) };
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
