"use strict";
const status = document.getElementById("status"),
  form = document.getElementById("setup");
function show(text, tone = "") {
  status.textContent = text;
  status.className = "notice " + tone;
  status.hidden = !text;
}
fetch("/api/v1/setup/status", { cache: "no-store" })
  .then((r) => r.json())
  .then((v) => {
    if (!v.setup_required) {
      form.hidden = true;
      show("初始化已完成，请返回首页登录。", "success");
    }
  })
  .catch(() => show("无法获取初始化状态，请检查服务。", "error"));
form.addEventListener("submit", async (e) => {
  e.preventDefault();
  show("正在验证并保存…");
  const payload = Object.fromEntries(new FormData(form).entries());
  try {
    const resp = await fetch("/api/v1/setup", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    const data = await resp.json();
    if (!resp.ok)
      throw Error(typeof data.detail === "string" ? data.detail : "初始化失败");
    form.hidden = true;
    show(
      "初始化成功。请确认飞书开放平台的回调地址为 " +
        payload.web_protocol +
        "://" +
        payload.web_public_host +
        "/api/v1/auth/callback ，再返回首页使用飞书登录。",
      "success",
    );
  } catch (err) {
    show(err.message, "error");
  }
});

document.getElementById("validate-setup").addEventListener("click", async (event) => {
  const button = event.currentTarget;
  if (!form.reportValidity()) return;
  button.disabled = true;
  show("正在校验…");
  try {
    const response = await fetch("/api/v1/setup/validate", {method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify(Object.fromEntries(new FormData(form)))});
    const result = await response.json();
    if (!response.ok) throw Error(typeof result.detail === "string" ? result.detail : "初始化信息无效");
    show(result.message + " 回调地址：" + result.callback_url, "success");
  } catch (err) {show(err.message, "error");}
  finally {button.disabled = false;}
});
