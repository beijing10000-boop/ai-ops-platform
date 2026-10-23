"use strict";
async function groupsPanel() {
  const rows = await api(P + "/groups");
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
    )}</div><div class="form-actions"><button class="button" type="submit">设置屏蔽</button></div></form>` +
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
const btn = (action, text, id = "", kind = "") =>
  `<button type="button" class="button ${kind}" data-action="${action}" data-id="${E(id)}">${text}</button>`;
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
        : JSON.stringify(result.detail || result),
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
    control = `<textarea aria-label="${E(label)}" name="${name}" ${name === "private_key" ? 'autocomplete="off"' : ""}>${E(value)}</textarea>`;
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
  connection: "SSH 连接测试",
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
    `<div class="hero"><div><span class="eyebrow">EVIDENCE BEFORE ACTION</span><h2>让每一次诊断，都有据可循。</h2><p class="muted small">告警历史、Linux 实时检查与 AI 分析，汇聚到同一条诊断记录。</p></div><div class="hero-mark">✧</div></div><div class="stats">${stat("未收到恢复的事件", fmt(o.unrecovered_received_events), "限平台已接收事件，非全量 Zabbix 告警")}${stat("AI 分析次数", fmt(o.ai_runs_24h), "最近 24 小时创建")}${stat("AI 分析成功率", o.ai_success_rate_24h == null ? "—" : o.ai_success_rate_24h + "%", "已完成 / AI 已结束任务")}${stat("Token 消耗", fmt(o.token_total_24h), `最近 24 小时 · ${fmt(o.usage_available_runs_24h)} 次返回实际用量`)}</div><div class="grid-two">${panel("连接与诊断能力", `<div class="health-row"><div>Zabbix MCP<p>以最近一次主动连接检测为准</p></div>${badge(o.health.find((x) => x.provider === "zabbix_mcp")?.status || (o.mcp_configured ? "未检测" : "未配置"))}</div><div class="health-row"><div>Linux 诊断适配器<p>内置固定诊断动作，按登记权限执行</p></div>${badge("已加载")}</div><div class="health-row"><div>已关联 Linux 主机<p>以 Zabbix Host ID 绑定</p></div><strong>${fmt(o.linked_linux_hosts)}</strong></div><div class="health-row"><div>SSH 连接验证<p>${fmt(o.configured_ssh_hosts)} 台配置完整；变更后需重新测试</p></div><strong>${fmt(o.tested_ssh_hosts)} 台通过</strong></div>`)}${panel("诊断概况", `<div class="health-row"><span>已完成 / 部分完成</span><strong>${fmt(o.completed_24h)} / ${fmt(o.partial_24h)}</strong></div><div class="health-row"><span>失败任务</span><strong>${fmt(o.failed_24h)}</strong></div><div class="health-row"><span>平均分析及连接耗时</span><strong>${o.average_duration_ms_24h == null ? "—" : (o.average_duration_ms_24h / 1000).toFixed(1) + " s"}</strong></div><div class="notice small">缺失数据会明确标记。AI 结论属于分析推断，监控与 SSH 证据可在任务详情核验。</div>`)}</div><div class="panel"><div class="section-heading"><div><h2>最近诊断</h2><p class="muted small">告警分析、问答、手动诊断与连接测试</p></div>${btn("go-history", "全部记录 →", "", "quiet")}</div>${table(["任务 / 时间", "诊断类型 / 来源", "状态", "工具", "耗时", "Token", "操作"], taskRows(t.items))}</div>`
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
      `<form id="diagnostic-form"><div class="form-grid">${field("asset_id", "资产 ID", state.selectedAsset || "", "number", "在主机资产页点击「诊断」可自动带入；不接受任意网络地址。")}${field("event_id", "告警事件 ID", state.selectedEvent || "", "text", "可选，必须是平台已经接收的事件。")}${field("diagnostic_type", "诊断类型", "auto", "text", "", [["auto", "自动识别告警类型"], ...Object.entries(PLAY).filter((x) => x[0] !== "connection")])}${field(
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
      )}${field("service", "systemd 服务名", "", "text", "服务/日志诊断时填写，如 nginx.service。")}${field("time_window", "日志窗口（分钟）", "30", "number", "范围 1–120 分钟；监控历史默认围绕告警前 30 分钟。")}${field("question", "诊断问题", "请根据实际证据诊断故障并给出建议", "textarea", "", null, true)}</div><div class="form-actions"><button class="button primary" type="submit">开始诊断 →</button></div></form>`,
    ) +
    panel(
      "监控问答",
      `<form id="ask-form">${field("question", "查询监控或提出问题", "", "textarea", "问答中的地址文字不会自动成为 SSH 连接目标。", null, true)}<div class="form-actions"><button class="button" type="submit">发送问题</button></div></form><div id="ask-result" class="report-answer"></div>`,
    )
  );
}
async function assets() {
  const q = new URLSearchParams({
    page: state.assetPage,
    page_size: 25,
    q: state.assetQuery,
    device_type: state.assetType,
  });
  const data = await api(P + "/assets?" + q);
  state.assetRows = data.items;
  const html =
    intro(
      "Zabbix Host ID 为唯一监控关联依据。重名、重复 IP 与跳板连接需按资产显式配置。",
      can("inventory.manage")
        ? btn("sync-assets", "同步 Zabbix") +
            btn("import-assets", "批量导入") +
            btn("new-group", "新增主机组") +
            btn("new-asset", "登记资产", "", "primary")
        : "",
    ) +
    `<section class="panel"><div class="toolbar"><input id="asset-search" aria-label="搜索主机资产" placeholder="搜索名称、地址或 Host ID" value="${E(state.assetQuery)}"><select id="asset-type" aria-label="设备类型"><option value="all">全部设备类型</option>${["linux", "windows", "vmware", "network", "unknown"].map((x) => `<option value="${x}" ${state.assetType === x ? "selected" : ""}>${labels[x]}</option>`).join("")}</select>${btn("search-assets", "搜索")}<span class="muted small">共 ${fmt(data.total)} 台</span></div>${table(["资产 / Host ID", "设备类型", "SSH 路由", "权限模式", "状态 / 验证", "操作"], data.items.map((r) => `<tr><td><span class="cell-title">${E(r.name)}</span><small>资产 ${r.id} · Host ID ${E(r.zabbix_hostid || "未关联")}</small></td><td>${badge(r.device_type)}</td><td class="mono">${E(r.address || "未配置")}<small>${r.address ? E(r.username) + " · " + r.ssh_port + (r.proxy_id ? " · 跳板 " + r.proxy_id : " · 直连") : ""}</small></td><td>${E(r.diagnostic_mode === "privileged" ? "B · 受限特权" : "A · 低权限免 Agent")}</td><td>${badge(r.enabled ? "已启用" : "已禁用")}<small>${r.last_test_status ? E(labels[r.last_test_status] || r.last_test_status) : "尚未验证"}</small></td><td><div class="actions">${can("diagnostics.run") ? btn("diagnose-asset", "诊断", r.id, "small") + (r.device_type === "linux" ? btn("test-asset", "测试", r.id, "small") : "") : ""}${can("inventory.manage") ? btn("edit-asset", "编辑", r.id, "small") : ""}</div></td></tr>`).join(""))}<div class="pagination">${btn("asset-prev", "上一页", "", "small")}<span>第 ${state.assetPage} 页 / ${Math.max(1, Math.ceil(data.total / 25))} 页</span>${btn("asset-next", "下一页", "", "small")}</div></section>`;
  return html + (await groupsPanel());
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
        ["工具 / 提供方", "适用设备", "风险 / 超时", "状态", "Schema"],
        data.tools
          .map(
            (t) =>
              `<tr><td><span class="mono">${E(t.name)}</span><small>${E(t.provider)} · ${E(t.required_scope)}</small></td><td>${E(t.device_types.map((x) => labels[x] || x).join(" / "))}</td><td>${E(t.risk)} · ${t.timeout}s<small>输出 ≤ ${fmt(t.max_output_chars)} 字符</small></td><td>${badge(t.enabled ? "已启用" : "已禁用")}</td><td><details><summary>参数与结果</summary><pre>${E(JSON.stringify({ input: t.input_schema, output: t.output_schema }, null, 2))}</pre></details></td></tr>`,
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
  const [creds, proxies] = await Promise.all([
    api(P + "/credentials"),
    api(P + "/proxies"),
  ]);
  state.credentials = creds;
  state.proxies = proxies;
  return (
    intro(
      "凭据加密保存。主机和跳板均须核验 SSH 主机公钥；密钥不会传入模型。",
      btn("discover", "检测 Zabbix MCP") + btn("test-model", "测试 AI 模型"),
    ) +
    `<div class="panel"><div class="section-heading"><div><h2>SSH 凭据</h2><p class="muted small">轮换后，关联主机的原连接测试结果失效。</p></div>${btn("new-credential", "新增凭据", "", "primary")}</div>${table(["名称", "版本", "更新时间", "操作"], creds.map((c) => `<tr><td>${E(c.name)}<small>ID ${c.id}</small></td><td>v${c.revision}</td><td>${date(c.updated_at)}</td><td>${btn("rotate-credential", "轮换密钥", c.id, "small")}</td></tr>`).join(""))}</div><div class="panel"><div class="section-heading"><div><h2>SSH 跳板</h2><p class="muted small">诊断目标仍须单独登记并验证主机身份。</p></div>${btn("new-proxy", "新增跳板")}</div>${table(["名称", "地址", "账号", "凭据", "操作"], proxies.map((p) => `<tr><td>${E(p.name)}</td><td class="mono">${E(p.address)}:${p.port}</td><td>${E(p.username)}</td><td>${p.credential_id}</td><td>${btn("edit-proxy", "编辑", p.id, "small")}</td></tr>`).join(""))}</div><div id="connection-result" class="notice" hidden></div>`
  );
}
async function history() {
  const [data, usage] = await Promise.all([
    api(
      P +
        `/tasks?page=${state.taskPage}&page_size=25&status=${encodeURIComponent(state.taskStatus)}`,
    ),
    api("/api/v1/ai-token-usage?days=30&limit=20"),
  ]);
  return (
    intro(
      "任务、工具调用与证据可按 trace_id 追溯。Token 仅使用模型实际返回数据。",
      btn("refresh", "刷新"),
    ) +
    `<div class="token-grid"><div class="stat"><div class="label">最近 30 天 · 输入 Token</div><div class="value">${fmt(usage.total_input)}</div></div><div class="stat"><div class="label">最近 30 天 · 输出 Token</div><div class="value">${fmt(usage.total_output)}</div></div><div class="stat"><div class="label">最近 30 天 · 总 Token</div><div class="value">${fmt(usage.total_tokens)}</div><div class="hint">未返回用量的请求不计入汇总</div></div></div><div class="panel"><div class="toolbar"><select id="task-status" aria-label="任务状态"><option value="all">全部任务状态</option>${["queued", "running", "success", "partial", "failed", "cancelled"].map((s) => `<option value="${s}" ${s === state.taskStatus ? "selected" : ""}>${labels[s]}</option>`).join("")}</select><span class="muted small">共 ${data.total} 条</span></div>${table(["任务 / 时间", "诊断类型 / 来源", "状态", "工具", "耗时", "Token", "操作"], taskRows(data.items))}<div class="pagination">${btn("task-prev", "上一页", "", "small")}<span>第 ${state.taskPage} 页</span>${btn("task-next", "下一页", "", "small")}</div></div>` +
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
            : ["failed", "partial", "cancelled"].includes(t.status)
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
    ["ai_alert_prompt", "告警分析补充提示词", "textarea"],
    ["ai_qa_prompt", "问答补充提示词", "textarea"],
    ["ai_profile_budgets", "三种模式预算（JSON）", "textarea"],
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
    ["mcp_url", "Zabbix MCP URL"],
    ["mcp_token", "Zabbix MCP Token", "password"],
    ["ssh_concurrency", "全局 SSH 最大并发"],
    ["ssh_timeout", "单动作超时（秒）"],
    ["disabled_tools", "禁用的 Zabbix 工具名称（JSON 数组）", "textarea"],
  ],
};
async function configPage(page) {
  const values = await api("/api/v1/settings");
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
    extra = `<div class="panel"><div class="section-heading"><div><h2>授权成员</h2><p class="muted small">超级管理员通过上方名单管理；其他角色由后端授权。</p></div>${btn("new-member", "添加 / 调整成员")}</div>${table(["Open ID", "角色", "状态"], members.map((m) => `<tr><td class="mono">${E(m.open_id)}</td><td>${E(labels[m.role])}</td><td>${badge(m.enabled ? "已启用" : "已停用")}</td></tr>`).join(""))}</div>`;
  }
  if (page === "feishu" && can("alerts.manage")) extra += await mutesPanel();
  if (page === "settings")
    extra += panel(
      "备份与升级",
      `<p class="muted small">升级前停止本项目 Worker，使用离线迁移工具备份 SQLite 和持久化主密钥。旧数据库导入具备事务回滚和重复执行保护，具体步骤见仓库 docs/UPGRADING.md。</p>${btn("runtime-status", "查看服务与队列状态")}<pre id="runtime-result"></pre>`,
    );
  return (
    intro(hints[page], page === "ai" ? btn("test-model", "测试 AI 模型") : "") +
    panel(
      page === "ai"
        ? "AI 模型与分析策略"
        : page === "feishu"
          ? "飞书应用与告警策略"
          : "系统与监控连接",
      `<form id="settings-form" data-group="${page}"><div class="form-grid">${fields.map(([key, label, type, options]) => field(key, label, values[key] || "", type === "select" ? "text" : type || "text", "", options || null, type === "textarea")).join("")}</div><div class="form-actions"><button class="button primary" type="submit">保存配置</button></div></form>`,
    ) +
    extra
  );
}
async function auditPage() {
  const data = await api(P + "/audit?page_size=100");
  return (
    intro(
      "最近 100 条 · 登录、配置变更、资产操作、报告访问和诊断操作",
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
      ),
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
      page === "report" &&
      ["running", "queued"].includes(state.currentTask?.status)
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
    const [creds, proxies, groups] = await Promise.all([
      api(P + "/credentials"),
      api(P + "/proxies"),
      api(P + "/groups"),
    ]);
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
      field(
        "group_ids",
        "主机组 ID（英文逗号分隔）",
        (r.group_ids || []).join(","),
        "text",
        groups.map((g) => `${g.id}: ${g.name}`).join(" · "),
      ) +
      field("address", "已核验的 SSH 内网 IP", r.address || "") +
      field("ssh_port", "SSH 端口", r.ssh_port || 22, "number") +
      field("username", "SSH 账号", r.username || "ai-diagnostic") +
      field("credential_id", "凭据", r.credential_id || "", "text", "", [
        ["", "未配置"],
        ...creds.map((c) => [c.id, c.name]),
      ]) +
      field("proxy_id", "SSH 跳板", r.proxy_id || "", "text", "", [
        ["", "直连"],
        ...proxies.map((p) => [p.id, p.name]),
      ]) +
      field(
        "diagnostic_mode",
        "诊断模式",
        r.diagnostic_mode || "standard",
        "text",
        "A 无目标端脚本；B 需要强制命令网关。",
        [
          ["standard", "A · 标准免 Agent"],
          ["privileged", "B · 受限特权"],
        ],
      ) +
      field(
        "diagnostic_paths",
        "允许检查占用的数据目录（英文逗号分隔）",
        (r.diagnostic_paths || []).join(","),
        "text",
        "可选，最多 5 个路径，仅 /data、/var/log、/var/lib、/opt 及子目录；每个目录最多 3 秒。",
        null,
        true,
      ) +
      field(
        "host_key",
        "目标 SSH 主机公钥",
        r.host_key || "",
        "textarea",
        "必须从独立可信渠道核对，平台不自动信任未知公钥。",
        null,
        true,
      ) +
      field(
        "privileged_approved",
        "已核验 B 模式强制命令、来源限制与禁用转发",
        !!r.privileged_approved,
        "checkbox",
      ) +
      field(
        "enabled",
        "启用资产",
        r.enabled === undefined || !!r.enabled,
        "checkbox",
      );
    note = "低权限账号仍可能具有写权限；root 仅允许用于明确授权的 B 模式。";
  } else if (type === "credential") {
    title = id ? "轮换 SSH 密钥" : "新增 SSH 凭据";
    const c = (state.credentials || []).find((x) => x.id === Number(id));
    fields =
      field("name", "凭据名称", c?.name || "") +
      field("passphrase", "私钥口令", "", "password") +
      field(
        "private_key",
        "SSH 私钥",
        "",
        "textarea",
        "保存后不明文回显。",
        null,
        true,
      );
  } else if (type === "proxy") {
    const p = (state.proxies || []).find((x) => x.id === Number(id)) || {};
    title = id ? "编辑跳板" : "新增 SSH 跳板";
    fields =
      field("name", "跳板名称", p.name || "") +
      field("address", "内网 IP", p.address || "") +
      field("port", "端口", p.port || 22, "number") +
      field("username", "SSH 账号", p.username || "diag-proxy") +
      field("credential_id", "凭据 ID", p.credential_id || "", "number") +
      field(
        "host_key",
        "跳板 SSH 主机公钥",
        p.host_key || "",
        "textarea",
        "",
        null,
        true,
      );
  } else if (type === "group") {
    title = id ? "编辑主机组" : "新增主机组";
    fields = field(
      "name",
      "主机组名称",
      (state.groupRows || []).find((g) => g.id === Number(id))?.name || "",
    );
  } else if (type === "member") {
    title = "授权成员";
    fields =
      field("open_id", "飞书 Open ID") +
      field("role", "角色", "operator", "text", "", [
        ["ops_admin", "运维管理员"],
        ["operator", "运维人员"],
        ["auditor", "只读审计"],
      ]) +
      field("enabled", "启用该成员", true, "checkbox");
  } else if (type === "import") {
    title = "批量导入资产";
    fields = field(
      "json",
      "资产 JSON 数组",
      "[]",
      "textarea",
      "最多 1000 台，全部校验通过后一次写入。字段与资产 API 相同。",
      null,
      true,
    );
  }
  $("#editor-title").textContent = title;
  $("#editor-fields").innerHTML = fields;
  $("#editor-note").textContent = note;
  $("#editor-feedback").textContent = "";
  $("#editor-feedback").hidden = true;
  $("#editor").showModal();
}
document.addEventListener("click", async (event) => {
  const b = event.target.closest("[data-action]");
  if (!b) return;
  const { action, id } = b.dataset;
  b.disabled = true;
  try {
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
    } else if (action === "new-member") await openEditor("member");
    else if (action === "new-credential" || action === "rotate-credential")
      await openEditor("credential", id);
    else if (action === "new-proxy" || action === "edit-proxy")
      await openEditor("proxy", id);
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
    } else if (action === "test-asset") {
      const t = await api(P + `/assets/${id}/test`, "POST");
      go("report/" + t.task_id);
    } else if (action === "discover") {
      const r = await api(P + "/tools/discover", "POST");
      toast(
        r.ok
          ? `MCP 连接成功，${r.authorized_tools.length} 个工具获授权`
          : "MCP 连接失败：" + r.detail,
      );
    } else if (action === "test-model") {
      const r = await api("/api/v1/test/ai", "POST");
      toast(`${r.reply} · ${r.elapsed_seconds}s`);
    } else if (action === "runtime-status")
      $("#runtime-result").textContent = JSON.stringify(
        await api("/api/v1/status"),
        null,
        2,
      );
    else if (action === "asset-prev" || action === "asset-next") {
      state.assetPage = Math.max(
        1,
        state.assetPage + (action === "asset-next" ? 1 : -1),
      );
      await navigate();
    } else if (action === "search-assets") {
      state.assetQuery = $("#asset-search").value;
      state.assetType = $("#asset-type").value;
      state.assetPage = 1;
      await navigate();
    } else if (action === "task-prev" || action === "task-next") {
      state.taskPage = Math.max(
        1,
        state.taskPage + (action === "task-next" ? 1 : -1),
      );
      await navigate();
    } else if (action === "toggle-logs") {
      state.includeLogs = !state.includeLogs;
      await navigate();
    } else if (action === "cancel-task") {
      await api(P + `/tasks/${id}/cancel`, "POST");
      toast("已请求取消，正在执行的 SSH 将在有界超时内结束。");
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
    const data = Object.fromEntries(new FormData(form));
    if (form.id === "mute-form") {
      data.hours = Number(data.hours);
      await api("/api/v1/alert-mutes", "POST", data);
      toast("已设置本平台飞书告警屏蔽");
      await navigate();
    } else if (form.id === "settings-form") {
      await api("/api/v1/settings", "PUT", { values: data });
      toast("配置已保存");
    } else if (form.id === "ask-form") {
      if (!data.question.trim()) throw Error("请输入问题");
      $("#ask-result").textContent = "正在查询监控并分析…";
      const r = await api("/api/v1/ask", "POST", data);
      $("#ask-result").textContent = r.answer;
    } else if (form.id === "diagnostic-form") {
      data.asset_id = data.asset_id ? Number(data.asset_id) : null;
      data.event_id = data.event_id || null;
      data.service = data.service || null;
      data.time_window = Number(data.time_window);
      const t = await api(P + "/tasks", "POST", data);
      go("report/" + t.task_id);
    } else {
      const { type, id } = state.editor;
      let path,
        method = id ? "PUT" : "POST",
        payload = data;
      if (type === "asset") {
        for (const k of ["credential_id", "proxy_id"])
          data[k] = data[k] ? Number(data[k]) : null;
        data.ssh_port = Number(data.ssh_port);
        data.diagnostic_paths = data.diagnostic_paths
          ? data.diagnostic_paths
              .split(",")
              .map((x) => x.trim())
              .filter(Boolean)
          : [];
        data.enabled = form.elements.enabled.checked;
        data.privileged_approved = form.elements.privileged_approved.checked;
        data.zabbix_hostid = data.zabbix_hostid || null;
        data.group_ids = data.group_ids
          ? data.group_ids.split(",").map((x) => Number(x.trim()))
          : [];
        path = "/assets" + (id ? "/" + id : "");
      } else if (type === "credential")
        path = "/credentials" + (id ? "/" + id : "");
      else if (type === "proxy") {
        data.port = Number(data.port);
        data.credential_id = Number(data.credential_id);
        path = "/proxies" + (id ? "/" + id : "");
      } else if (type === "group") path = "/groups" + (id ? "/" + id : "");
      else if (type === "member") {
        path = "/members";
        method = "PUT";
        data.enabled = form.elements.enabled.checked;
      } else if (type === "import") {
        path = "/assets-import";
        payload = { assets: JSON.parse(data.json) };
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
