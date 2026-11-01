# AI Ops Platform 工作约定

给 AI 编程助手和贡献者。跨项目约定见 `docs/ENGINEERING.md`（职责边界、MCP 契约、主机身份、降级）与 `docs/UI-GUIDELINES.md`（控制台 UI 与交互）。

## 结构

- `app/skill_runtime.py`：一次诊断的全过程（目标解析、阶段 A/B/C 预采集、模型轮次、引用核对、报告）。预算与覆盖率只在这里记账。
- `app/skill_mcp.py`：三个 MCP 的会话、工具发现与授权过滤、参数校验、调用；`app/integrations/` 是各服务的连接细节。
- `app/skill_context.py`：证据 → 模型视图（裁剪、摘要、派生信号）；`app/evidence_check.py`：答案解析、引用核对、可信度、诊断范围。
- `app/skill_templates/platform-*`：托管 Skill（诊断策略与预采集声明）；`app/skill_store.py` 负责安装、刷新、快照与适用判断。
- `app/worker.py`、`app/qa_worker.py`：告警与问答的队列任务、飞书卡片；`app/main.py`、`app/platform_api.py`：Web API。

## 规则

1. **诊断规则只写一处。** 诊断策略写在 Skill；平台代码只放安全、预算、校验、证据、渲染。新增“遇到 X 告警先查 Y”之类的逻辑，先考虑 Skill 的 prefetch 与正文，而不是 Python 分支。
2. **预算统一记账。** 预采集作业经 `take()`/`collect()` 记入采集次数；被预算挡下的作业写入 `coverage.skipped` 并在 `limits_hit` 说明，不能静默丢弃。
3. **能力发现，不比版本。** 依赖某个 MCP 参数或字段前，看工具的 `inputSchema` 或目录（`ssh_list_tool_catalog` / `log_list_tool_catalog`）；旧服务没有时走原有路径。
4. **缺口要分类。** 只有“应取得而未取得的证据”进入诊断不足；主机不具备的能力进“能力说明”；模型自己的无效调用（`RequestRejected`）不算缺口。
5. **飞书输出规则**：告警卡片 = 诊断结论（一段 ≤200 字）+ 处理建议（≤4 条，具体可执行）；任何飞书输出都不出现证据编号（E1…）；容量单位用 GiB；不提 Swap；未完成的分析给出具体下一步。Web 报告保持完整。
6. **托管 Skill 改动**会改变其 digest 与 revision；它们在第一次读取 Skill（`skill_store.rows()`）时刷新，不是在容器启动时。
7. 改动 MCP 调用或 Skill 引用的工具后，运行联合测试 `tests/joint/`（见该目录 conftest 的环境变量说明）。

## 提交前

- `python -m ruff format app tests`、`python -m ruff check --select F401,F811,F821,F841 app tests`
- `python -m pytest -q --ignore=tests/browser_smoke.py`（Windows 上 `tests/test_migrations.py` 有两个文件权限用例会失败，属环境限制）
- 改了 `web/assets/*.js` 或 `*.css`：`node --check`，并更新 `web/index.html`、`web/setup.html` 中的 `?v=`
- 共享 ui-kit 只能经 `scripts/sync_ui_kit.py` 同步修改
- 一个 PR 一类变更；CHANGELOG 写在“未发布”；仓库公开，不写真实内网地址与令牌
