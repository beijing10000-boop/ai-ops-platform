"use strict";
// Presentation helpers. External text is always escaped; no remote HTML or scripts.
const OpsUI = (() => {
  const escape = value => String(value ?? "").replace(/[&<>"']/g, c => ({"&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"})[c]);
  const inline = value => escape(value).replace(/`([^`\n]+)`/g, "<code>$1</code>").replace(/\*\*([^*\n]+)\*\*/g, "<strong>$1</strong>");
  function answer(raw) {
    let html = "", code = null, paragraph = [], list = [];
    const flush = () => {
      if (paragraph.length) html += "<p>" + paragraph.map(inline).join("<br>") + "</p>";
      if (list.length) html += "<ul>" + list.map(x => "<li>" + inline(x) + "</li>").join("") + "</ul>";
      paragraph = []; list = [];
    };
    for (const line of String(raw ?? "").split("\n")) {
      if (/^\s*```/.test(line)) {
        flush();
        if (code === null) code = [];
        else { html += "<pre><code>" + escape(code.join("\n")) + "</code></pre>"; code = null; }
      } else if (code !== null) code.push(line);
      else if (!line.trim()) flush();
      else if (/^\s*#{1,6}\s+/.test(line) || /^(结论|建议|依据|故障原因（AI 推断）|处理建议|分析与依据)[：:]?$/.test(line.trim())) {
        flush(); html += "<h3>" + inline(line.replace(/^\s*#{1,6}\s+/, "")) + "</h3>";
      } else if (/^\s*(?:[-*]|\d+[.、])\s+/.test(line)) {
        if (paragraph.length) flush();
        list.push(line.replace(/^\s*(?:[-*]|\d+[.、])\s+/, ""));
      } else {
        if (list.length) flush();
        paragraph.push(line);
      }
    }
    flush();
    if (code !== null) html += "<pre><code>" + escape(code.join("\n")) + "</code></pre>";
    return html;
  }
  const baselines = new WeakMap();
  const forms = () => [...document.querySelectorAll("form.settings-form, form.connection-form, #skill-edit")];
  const fingerprint = form => JSON.stringify([...new FormData(form)]);
  function changed(form) {
    return baselines.has(form) && baselines.get(form) !== fingerprint(form);
  }
  function mark(form) {
    if (!form || !baselines.has(form)) return;
    const dirty = changed(form), output = form.querySelector("[data-save-state]");
    form.classList.toggle("has-changes", dirty);
    if (output) output.textContent = dirty ? "有未保存的修改" : "已保存";
  }
  function track() {
    for (const form of forms()) {
      baselines.set(form, fingerprint(form));
      if (!form.querySelector("[data-save-state]")) {
        const indicator = document.createElement("span");
        indicator.className = "save-state"; indicator.dataset.saveState = "";
        indicator.setAttribute("role", "status");
        form.querySelector(".form-actions")?.prepend(indicator);
      }
      mark(form);
    }
  }
  function saved(form) { baselines.set(form, fingerprint(form)); mark(form); }
  function drafts() { return forms().filter(changed).map(form => ({id: form.id, entries: [...new FormData(form)]})); }
  function restore(items) {
    for (const {id, entries} of items) {
      const form = document.getElementById(id);
      if (!form) continue;
      for (const input of form.querySelectorAll("input,select,textarea")) {
        const values = entries.filter(([name]) => name === input.name).map(([, value]) => value);
        if (input.type === "checkbox") input.checked = values.includes(input.value);
        else if (values.length) input.value = values[0];
      }
      mark(form);
    }
  }
  function lock(form) {
    const controls = [...form.querySelectorAll("input,textarea,select,button")].map(el => [el, el.disabled]);
    controls.forEach(([el]) => { el.disabled = true; });
    return () => controls.forEach(([el, wasDisabled]) => { el.disabled = wasDisabled; });
  }
  async function copy(text) {
    try {
      if (navigator.clipboard) { await navigator.clipboard.writeText(text); return; }
    } catch {}
    // Clipboard API is unavailable on plain HTTP intranets.
    const area = document.createElement("textarea");
    area.value = text; area.className = "clipboard-helper";
    document.body.append(area); area.select();
    const copied = document.execCommand("copy"); area.remove();
    if (!copied) throw Error("复制未成功，请使用下载报告按钮");
  }
  function runtime(data) {
    const names = {"ai-alerts": "告警通知", "ai-alert-manual": "手动告警分析", "ai-alert-analysis": "自动告警分析", "ai-questions": "飞书问答", "ai-diagnostics": "Web 诊断"};
    const ok = data.redis === "ok";
    return `<div class="runtime-summary"><span class="status success">数据库可访问</span><span class="status ${ok ? "success" : "failed"}">Redis ${ok ? "可访问" : "不可用"}</span><span class="muted small">版本 ${escape(data.version)}</span></div>` +
      (ok ? `<div class="runtime-grid">${Object.entries(names).map(([key, name]) => `<div class="runtime-cell"><strong>${name}</strong><p>${escape(data.queues[key] ?? "—")} 个排队任务</p><span class="status ${data.workers?.[key] ? "success" : "failed"}">${escape(data.workers?.[key] ?? 0)} 个已注册 Worker</span></div>`).join("")}</div><p class="muted small">Worker 数量来自 Redis 注册记录；飞书长连接接收器需结合实际消息联调。</p>` : '<p class="notice error">队列连接失败。请检查 Redis 服务；已有失败任务可在服务恢复后重试。</p>');
  }
  return {escape, answer, track, changed, mark, saved, drafts, restore, lock, copy, runtime, fingerprint, dirty: () => forms().some(changed)};
})();
