"use strict";

function skillChoices(values = {}) {
  const scopes = values.scopes || ["qa", "web", "alert"], providers = values.providers || ["ssh_mcp", "zabbix_mcp"];
  return `<fieldset class="skill-choices"><legend>适用场景</legend>${[["qa", "飞书问答"], ["web", "Web 诊断"], ["alert", "告警分析"]].map(([key, label]) => `<label><input type="checkbox" name="scopes" value="${key}" ${scopes.includes(key) ? "checked" : ""}>${label}</label>`).join("")}</fieldset>` +
    `<fieldset class="skill-choices"><legend>允许使用的后台服务</legend>${[["ssh_mcp", "SSH MCP"], ["zabbix_mcp", "Zabbix MCP"]].map(([key, label]) => `<label><input type="checkbox" name="providers" value="${key}" ${providers.includes(key) ? "checked" : ""}>${label}</label>`).join("")}</fieldset>` +
    `<div class="form-grid">${field("priority", "优先级（数值越大越优先）", values.priority ?? 100, "number")}${field("enabled", "启用状态", String(values.enabled ?? false), "text", "", [["false", "停用"], ["true", "启用"]])}</div>`;
}

async function skillsPage(id) {
  const data = await api(P + "/skills"), manage = can("settings.manage");
  let html = intro("按 Skill 选择查询来源、工具与步骤。实时诊断可直接查询 SSH；每个新任务保存所用 Skill 版本。", `<a class="button" href="${P}/skills/template">下载运维模板 ZIP</a>` + btn("refresh", "刷新"));
  html += panel("已加载的 Skill", table(["名称与说明", "状态 / 版本", "适用场景", "操作"], data.items.map(row => `<tr><td><strong>${E(row.name)}</strong><p class="muted small">${E(row.description)}</p><span class="muted small">优先级 ${row.priority} · ${row.providers.map(E).join(" / ")}</span></td><td>${row.enabled ? '<span class="badge success">已启用</span>' : '<span class="badge disabled">已停用</span>'}<p class="small">v${row.revision}</p></td><td>${row.scopes.map(scope => ({qa: "飞书问答", web: "Web 诊断", alert: "告警分析"})[scope]).join(" / ")}</td><td><div class="actions">${btn("skill-open", manage ? "查看 / 编辑" : "查看", row.id, "small")}<a class="button small" href="${P}/skills/${row.id}/export">导出</a>${manage ? btn("skill-verify", "验证工具", row.id, "small") + btn("skill-toggle", row.enabled ? "停用" : "启用", row.id, "small") : ""}</div></td></tr>`).join("")), "同一场景可启用多个 Skill，按优先级向模型加载；工具权限仍由后台服务与平台校验。未启用 Skill 的场景沿用兼容流程。") + '<p id="skill-status" role="status" class="notice" hidden></p>';
  if (id) {
    const row = await api(P + "/skills/" + encodeURIComponent(id));
    html += panel(E(row.name) + " · v" + row.revision, manage ? `<form id="skill-edit" data-id="${E(row.id)}">${field("description", "适用说明", row.description, "textarea")}${field("instructions", "查询指引（Markdown）", row.instructions, "textarea")}<p class="muted small">参考资料：${row.resources.map(E).join("、") || "无"}。修改参考资料可重新导入 ZIP，并选择更新同名 Skill。</p>${skillChoices(row)}<p class="muted small mono">SHA256 ${E(row.digest)}</p><div class="form-actions">${btn("skill-check-edit", "验证格式")}<button class="button primary" type="submit">保存 Skill</button>${btn("skill-delete", "删除", row.id, "danger")}</div><p data-verify-result role="status"></p></form>` : `<p>${E(row.description)}</p><pre class="skill-preview">${E(row.instructions)}</pre>`);
  }
  if (manage) html += panel("导入 Skill", `<form id="skill-import"><label class="field">Skill 文件<input name="package" type="file" accept=".md,.zip" required><span class="muted small">上传 SKILL.md 或包含 SKILL.md、references 文本资料的 ZIP，最大 1 MB。</span></label>${skillChoices()}<label class="skill-check"><input type="checkbox" name="replace_existing">更新同名 Skill（保留记录 ID，生成新版本）</label><div class="form-actions">${btn("skill-check-import", "验证并预览")}<button class="button primary" type="submit">导入 Skill</button></div><p data-verify-result role="status"></p><details id="skill-preview" hidden><summary>预览查询指引</summary><pre class="skill-preview"></pre></details></form>`, "导入后选择启用才会参与新任务；正在运行的任务继续使用创建时的版本。可先下载模板，按环境修改后上传。");
  return html;
}

function skillValues(form) {
  const data = new FormData(form);
  return {scopes: data.getAll("scopes"), providers: data.getAll("providers"), enabled: data.get("enabled") === "true", priority: Number(data.get("priority"))};
}

async function skillPackage(form) {
  const file = form.elements.package.files[0];
  if (!file || !file.size || file.size > 1024 * 1024) throw new Error("请选择不超过 1 MB 的 Skill Markdown 或 ZIP 文件");
  const data = await new Promise((resolve, reject) => { const reader = new FileReader(); reader.onload = () => resolve(reader.result.split(",")[1]); reader.onerror = () => reject(new Error("读取文件失败")); reader.readAsDataURL(file); });
  return {...skillValues(form), filename: file.name, data, replace_existing: form.elements.replace_existing.checked};
}

function skillEditValues(form) {
  return {...skillValues(form), description: form.elements.description.value, instructions: form.elements.instructions.value};
}

document.addEventListener("click", async event => {
  const button = event.target.closest('[data-action^="skill-"]');
  if (!button || button.disabled) return;
  const {action, id} = button.dataset;
  button.disabled = true;
  const form = button.closest("form");
  const feedback = form?.querySelector("[data-verify-result]") || $("#skill-status");
  try {
    if (action === "skill-open") { go("skills/" + id); return; }
    if (action === "skill-check-import" || action === "skill-check-edit") {
      let body;
      if (action === "skill-check-import") body = await skillPackage(form);
      else {
        const row = await api(P + "/skills/" + form.dataset.id), values = skillEditValues(form);
        const text = "---\nname: " + row.name + "\ndescription: " + JSON.stringify(values.description) + "\n---\n\n" + values.instructions;
        const bytes = new TextEncoder().encode(text);
        body = {...values, filename: "SKILL.md", data: btoa(Array.from(bytes, value => String.fromCharCode(value)).join(""))};
        delete body.instructions; delete body.description;
      }
      const result = await api(P + "/skills/validate", "POST", body);
      feedback.textContent = result.message + " 名称：" + result.name + "；参考资料 " + result.resources.length + " 份。";
      feedback.dataset.result = "ok";
      if (action === "skill-check-import") { $("#skill-preview").hidden = false; $("#skill-preview").open = true; $("#skill-preview pre").textContent = result.instructions; }
    } else if (action === "skill-verify") {
      feedback.hidden = false; feedback.textContent = "正在验证后台 MCP 服务的工具目录…";
      const result = await api(P + "/skills/" + id + "/verify", "POST", {});
      feedback.textContent = (result.ok ? "工具验证通过。" : "工具验证未通过。") + result.results.map(row => `${row.provider}：${row.error || (row.missing.length ? "缺少 " + row.missing.join("、") : row.tools + " 个只读工具可用")}`).join("；");
    } else if (action === "skill-toggle") {
      const row = await api(P + "/skills/" + id);
      await api(P + "/skills/" + id, "PUT", {enabled: !row.enabled});
      await navigate(); toast(row.enabled ? "Skill 已停用，新任务将使用当前配置" : "Skill 已启用，新任务将按查询指引执行");
    } else if (action === "skill-delete") {
      if (!window.confirm("删除此 Skill？历史任务保留已加载的版本。")) return;
      await api(P + "/skills/" + id, "DELETE"); OpsUI.saved(form); go("skills");
    }
    if (feedback) feedback.hidden = false;
  } catch (error) {
    if (feedback) { feedback.hidden = false; feedback.textContent = error.message; feedback.dataset.result = "error"; }
    else toast(error.message);
  } finally { button.disabled = false; }
});

document.addEventListener("submit", async event => {
  const form = event.target;
  if (!["skill-import", "skill-edit"].includes(form.id)) return;
  event.preventDefault();
  const button = form.querySelector('[type="submit"]'), feedback = form.querySelector("[data-verify-result]");
  button.disabled = true;
  try {
    if (!form.reportValidity()) return;
    if (form.id === "skill-import") await api(P + "/skills", "POST", await skillPackage(form));
    else await api(P + "/skills/" + form.dataset.id, "PUT", skillEditValues(form));
    OpsUI.saved(form); await navigate(); toast("Skill 已保存，后续新任务使用当前启用配置");
  } catch (error) { feedback.textContent = error.message; feedback.dataset.result = "error"; }
  finally { button.disabled = false; }
});
