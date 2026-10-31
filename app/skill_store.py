"""Validated, encrypted Markdown Skills. Packages are read as data, never extracted or executed."""

import base64
from functools import cache
import hashlib
import io
import json
import logging
from pathlib import Path, PurePosixPath
import re
import sqlite3
import stat
import uuid
import zipfile

import yaml
from fastapi import HTTPException

log = logging.getLogger(__name__)
MAX_PACKAGE = 1024 * 1024
MAX_DOCUMENT = 64000
SCOPES = {"alert", "qa", "web"}
PROVIDERS = {"ssh_mcp", "zabbix_mcp", "logs"}
# A custom Skill either replaces the platform base Skill or is loaded with it.
MODES = {"standalone", "supplement"}
BASE_NAME = "platform-base"
# Platform-maintained Skills, refreshed on upgrade. Device and alert-type
# Skills declare `devices` / `types`; the runtime gives the model only those
# that apply to the task, so a CPU alert does not carry the Nginx playbook.
MANAGED = {
    "platform-base": 50,
    "platform-logs": 52,
    "platform-linux": 55,
    "platform-windows": 55,
    "platform-network": 55,
    "platform-service": 60,
    "platform-syslog": 60,
    "platform-nginx": 65,
    "platform-java": 65,
}
# MCP services a platform Skill may use when first installed (admins can change
# them later). Only the log Skill opens the log MCP, so disabling it turns log
# evidence off, on upgraded and new installations alike.
MANAGED_PROVIDERS = {"platform-logs": ["logs"]}
DEFAULT_PROVIDERS = ["ssh_mcp", "zabbix_mcp"]
DEVICES = {"linux", "windows", "network", "vmware", "other", "unknown"}
TEMPLATES = Path(__file__).parent / "skill_templates"


class SkillLoader(yaml.SafeLoader):
    def compose_node(self, parent, index):
        if self.check_event(yaml.AliasEvent):
            raise ValueError("Skill 元数据不支持 YAML 引用")
        return super().compose_node(parent, index)

    def construct_mapping(self, node, deep=False):
        result = {}
        for key_node, value_node in node.value:
            key = self.construct_object(key_node, deep=deep)
            if not isinstance(key, str) or key in result:
                raise ValueError("Skill 元数据含重复或无效字段")
            result[key] = self.construct_object(value_node, deep=deep)
        return result


def parse_document(text):
    if (
        not isinstance(text, str)
        or len(text.encode("utf-8")) > MAX_DOCUMENT
        or "\x00" in text
    ):
        raise ValueError("SKILL.md 须为不超过 64 KB 的 UTF-8 文本")
    match = re.match(r"\A\ufeff?---\r?\n(.*?)\r?\n---(?:\r?\n|$)(.*)\Z", text, re.S)
    if not match:
        raise ValueError("SKILL.md 须以 YAML name、description 元数据开头")
    try:
        meta = yaml.load(match[1], Loader=SkillLoader)
    except (yaml.YAMLError, ValueError) as exc:
        raise ValueError("Skill 元数据格式无效") from exc
    if not isinstance(meta, dict) or not (
        {"name", "description"}
        <= set(meta)
        <= {"name", "description", "prefetch", "types", "devices"}
    ):
        raise ValueError(
            "Skill 元数据只支持 name、description 和可选的 prefetch、types、devices"
        )
    name, description = meta["name"], meta["description"]
    if (
        not isinstance(name, str)
        or not re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", name)
        or len(name) > 64
    ):
        raise ValueError("Skill 名称须为 1–64 位小写字母、数字或连字符")
    if not isinstance(description, str) or not 1 <= len(description.strip()) <= 1024:
        raise ValueError("Skill 描述须为 1–1024 字")
    if not match[2].strip():
        raise ValueError("Skill 指引正文不能为空")
    return {
        "name": name,
        "description": description.strip(),
        "instructions": match[2].strip(),
        "prefetch": validate_prefetch(meta.get("prefetch", [])),
        **applicability(meta),
    }


def applicability(meta):
    """Optional `types` (diagnostic types) and `devices` a Skill is limited to."""
    from .diagnostics.playbooks import PLAYBOOKS

    result = {}
    for key, allowed, label in (
        ("types", set(PLAYBOOKS), "诊断类型"),
        ("devices", DEVICES, "设备类型"),
    ):
        if key not in meta:
            continue
        value = meta[key]
        if (
            not isinstance(value, list)
            or not 1 <= len(value) <= 12
            or any(not isinstance(item, str) for item in value)
            or set(value) - allowed - {"*"}
        ):
            raise ValueError(f"Skill {key} 须为{label}列表或 *")
        result[key] = list(dict.fromkeys(value))
    return result


def applies(skill, diagnostic_type=None, device=None):
    """Whether a loaded Skill's guidance belongs to this task.

    Skills without `types` / `devices` (every custom Skill so far) apply to
    every task; a value of None means "not known yet" and matches.
    """
    types = skill.get("types") or ["*"]
    devices = skill.get("devices") or ["*"]
    return (diagnostic_type is None or "*" in types or diagnostic_type in types) and (
        device is None or "*" in devices or device in devices
    )


# SSH tools whose required argument the platform cannot derive from a task
# (a directory root or a JVM pid) cannot be pre-collected. `service` tools can:
# the Web form or the alert's trigger items may name the unit.
PARAMETRIZED_SSH = {
    "ssh_diagnose_directory_usage",
    "ssh_diagnose_jvm",
}
SSH_TOOL = re.compile(r"ssh_diagnose_[a-z_]{1,40}|ssh_collect")
LOG_TOOL = re.compile(r"log_[a-z_]{1,40}")
# Log tools the platform runs itself (target lookup) or cannot fill: a trace
# id, an anchor time and line counts.
PARAMETRIZED_LOGS = {
    "log_list_tool_catalog",
    "log_list_sources",
    "log_resolve_target",
    "log_context",
    "log_trace",
}
# Item key fragments or `*` patterns; Windows performance counters need spaces,
# backslashes, quotes, % and parentheses (perf_counter_en["\System\..."]).
ITEM_KEY = re.compile(r'[A-Za-z0-9_.,\[\]*/ \\"%():#-]{1,120}')
RULE_KEYS = (
    "scopes",
    "types",
    "devices",
    "ssh",
    "zabbix_items",
    "history",
    "logs",
    "schemas",
)


def validate_prefetch(rules):
    """Skill-declared evidence the platform collects before the first model round.

    Each rule: scopes, types (diagnostic types or "*"), optional devices (device
    types the rule is limited to), and any of ssh (fixed read-only SSH
    diagnostics), zabbix_items (item key search terms for the task host),
    history (exact item keys or `*` patterns among the found items whose
    alert-window history and 7-day trend are collected), logs (log tools run on
    the target's log source around the alert) and schemas (tool schemas handed
    to the model up front).
    """
    from .diagnostics.playbooks import PLAYBOOKS
    from .integrations.zabbix import READ_TOOLS

    if not isinstance(rules, list) or len(rules) > 20:
        raise ValueError("prefetch 须为最多 20 条规则的列表")
    result = []
    for rule in rules:
        if not isinstance(rule, dict) or not {"scopes", "types"} <= set(rule) <= set(
            RULE_KEYS
        ):
            raise ValueError(
                "prefetch 规则须包含 scopes、types，可选 devices、ssh、zabbix_items、history、logs、schemas"
            )
        lists = {key: rule.get(key, []) for key in RULE_KEYS}
        if any(
            not isinstance(value, list)
            or len(value) > 8
            or any(not isinstance(item, str) for item in value)
            for value in lists.values()
        ):
            raise ValueError("prefetch 各字段须为最多 8 项的字符串列表")
        if not lists["scopes"] or set(lists["scopes"]) - SCOPES:
            raise ValueError("prefetch scopes 须为 alert、qa、web")
        if not lists["types"] or set(lists["types"]) - set(PLAYBOOKS) - {"*"}:
            raise ValueError("prefetch types 须为诊断类型或 *")
        if set(lists["devices"]) - DEVICES - {"*"}:
            raise ValueError("prefetch devices 须为设备类型或 *")
        if len(lists["logs"]) > 6 or any(
            not LOG_TOOL.fullmatch(tool) or tool in PARAMETRIZED_LOGS
            for tool in lists["logs"]
        ):
            raise ValueError(
                "prefetch logs 只能是平台能按日志来源和告警时间填参的 log_* 工具（最多 6 个）"
            )
        if len(lists["ssh"]) > 6 or any(
            not SSH_TOOL.fullmatch(tool) or tool in PARAMETRIZED_SSH
            for tool in lists["ssh"]
        ):
            raise ValueError(
                "prefetch ssh 只能是平台能自行填参的 ssh_diagnose_* 工具（最多 6 个）"
            )
        if any(
            not ITEM_KEY.fullmatch(key)
            for key in lists["zabbix_items"] + lists["history"]
        ):
            raise ValueError("prefetch zabbix_items、history 须为监控项 key 片段或模式")
        if len(lists["schemas"]) > 4 or any(
            tool not in READ_TOOLS
            and not SSH_TOOL.fullmatch(tool)
            and not LOG_TOOL.fullmatch(tool)
            for tool in lists["schemas"]
        ):
            raise ValueError("prefetch schemas 须为已开放的工具名（最多 4 个）")
        result.append(lists)
    return result


def document(name, description, instructions, prefetch=None):
    meta = {"name": name, "description": description}
    if prefetch:
        meta["prefetch"] = prefetch
    return (
        "---\n"
        + yaml.safe_dump(meta, allow_unicode=True, sort_keys=False).strip()
        + "\n---\n\n"
        + instructions.strip()
        + "\n"
    )


def scope_of(request, source):
    """alert: the trusted alert itself; qa: chat questions, including follow-ups
    in an alert thread; web: the diagnosis form."""
    event = request.get("event") or {}
    if event.get("event_id") and not request.get("follow_up"):
        return "alert"
    return "qa" if source in {"qa", "feishu"} else "web"


def prefetch_plan(skills, scope, diagnostic_type, device=None):
    """Merge the loaded Skills' matching rules, higher priority first, no repeats.

    A rule with `devices` applies only to those device types; None means the
    device is not known yet and matches, as in applies().
    """
    plan = {"ssh": [], "zabbix_items": [], "history": [], "logs": [], "schemas": []}
    for skill in skills:
        if not applies(skill, diagnostic_type, device):
            continue
        for rule in skill.get("prefetch") or []:
            devices = rule.get("devices") or ["*"]
            if (
                scope in rule["scopes"]
                and (diagnostic_type in rule["types"] or "*" in rule["types"])
                and (device is None or "*" in devices or device in devices)
            ):
                for key in plan:
                    # Snapshots taken before `history` / `logs` existed lack them.
                    plan[key].extend(x for x in rule.get(key, []) if x not in plan[key])
    plan["ssh"] = plan["ssh"][:6]
    plan["schemas"] = plan["schemas"][:4]
    plan["zabbix_items"] = plan["zabbix_items"][:8]
    plan["history"] = plan["history"][:8]
    plan["logs"] = plan["logs"][:6]
    return plan


def parse_package(filename, encoded):
    try:
        raw = base64.b64decode(encoded, validate=True)
    except (ValueError, TypeError):
        raise ValueError("上传文件编码无效") from None
    if not raw or len(raw) > MAX_PACKAGE:
        raise ValueError("Skill 文件须大于 0 且不超过 1 MB")
    files = {}
    if filename.lower().endswith(".md"):
        files["SKILL.md"] = raw.decode("utf-8-sig")
    elif filename.lower().endswith(".zip"):
        try:
            with zipfile.ZipFile(io.BytesIO(raw)) as archive:
                entries = [entry for entry in archive.infolist() if not entry.is_dir()]
                if (
                    not 1 <= len(entries) <= 32
                    or sum(entry.file_size for entry in entries) > MAX_PACKAGE
                ):
                    raise ValueError("Skill 包最多 32 个文件，解压总大小不超过 1 MB")
                roots = [
                    entry.filename
                    for entry in entries
                    if PurePosixPath(entry.filename).name == "SKILL.md"
                ]
                if len(roots) != 1:
                    raise ValueError("Skill 包须包含唯一 SKILL.md")
                prefix = roots[0][: -len("SKILL.md")]
                for entry in entries:
                    path = PurePosixPath(entry.filename)
                    if (
                        path.is_absolute()
                        or ".." in path.parts
                        or "\\" in entry.filename
                        or stat.S_ISLNK(entry.external_attr >> 16)
                        or entry.flag_bits & 1
                    ):
                        raise ValueError("Skill 包含无效路径、链接或加密文件")
                    if not entry.filename.startswith(prefix):
                        raise ValueError("所有 Skill 文件须在同一个目录中")
                    relative = entry.filename[len(prefix) :]
                    if relative != "SKILL.md" and not (
                        relative.startswith("references/")
                        and path.suffix.lower() in {".md", ".txt"}
                    ):
                        raise ValueError(
                            "仅支持 SKILL.md 与 references 下的 Markdown/文本资料，不执行脚本"
                        )
                    if relative in files or entry.file_size > MAX_DOCUMENT:
                        raise ValueError("Skill 文件重复或单文件超过 64 KB")
                    files[relative] = archive.read(entry).decode("utf-8-sig")
        except (zipfile.BadZipFile, UnicodeError, RuntimeError):
            raise ValueError("Skill ZIP 内容无效或不是 UTF-8 文本") from None
    else:
        raise ValueError("请上传 .md 或 .zip 文件")
    return {**parse_document(files["SKILL.md"]), "files": files}


def digest(files):
    return hashlib.sha256(
        json.dumps(files, sort_keys=True, ensure_ascii=False).encode()
    ).hexdigest()


def template_files(name):
    root = TEMPLATES / name
    return {
        path.relative_to(root).as_posix(): path.read_text(encoding="utf-8")
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }


@cache
def managed_package(name):
    files = template_files(name)
    return {**parse_document(files["SKILL.md"]), "files": files}


def base_package():
    return managed_package(BASE_NAME)


def ensure_base(db):
    """Install the platform-maintained Skills, or refresh those whose bundled
    copy changed. Admin choices (enabled, scopes, providers, priority) survive
    refreshes; a Skill the admin disabled stays disabled.
    """
    for name, priority in MANAGED.items():
        package = managed_package(name)
        wanted = digest(package["files"])
        row = db.execute(
            "SELECT id,digest,managed FROM platform_skills WHERE name=?", (name,)
        ).fetchone()
        if row and not row[2]:
            # A custom Skill already uses the name; never overwrite it.
            log.info("PLATFORM_SKILL_NOT_INSTALLED name_taken name=%s", name)
            continue
        if row and row[1] == wanted:
            continue
        if row:
            db.execute(
                "UPDATE platform_skills SET description=?,digest=?,bundle=?,revision=revision+1,"
                "updated_by='platform',updated_at=CURRENT_TIMESTAMP WHERE id=? AND digest!=?",
                (
                    package["description"],
                    wanted,
                    encode(package["files"]),
                    row[0],
                    wanted,
                ),
            )
            continue
        try:
            db.execute(
                "INSERT INTO platform_skills(id,name,description,enabled,priority,scopes,"
                "providers,digest,bundle,updated_by,managed,mode) "
                "VALUES (?,?,?,1,?,?,?,?,?,'platform',1,'base')",
                (
                    uuid.uuid4().hex,
                    name,
                    package["description"],
                    priority,
                    json.dumps(sorted(SCOPES)),
                    json.dumps(MANAGED_PROVIDERS.get(name, DEFAULT_PROVIDERS)),
                    wanted,
                    encode(package["files"]),
                ),
            )
        except sqlite3.IntegrityError:
            # Another worker installed it first.
            log.info("PLATFORM_SKILL_NOT_INSTALLED race name=%s", name)


def encode(files):
    from .main import cipher

    return cipher().encrypt(json.dumps(files, ensure_ascii=False).encode()).decode()


def decode(raw):
    from .main import cipher

    return json.loads(cipher().decrypt(raw.encode()))


def rows(include_content=False):
    from .main import connection

    with connection() as db:
        ensure_base(db)
        cursor = db.execute("SELECT * FROM platform_skills ORDER BY priority DESC,name")
        values = [
            dict(zip([col[0] for col in cursor.description], row))
            for row in cursor.fetchall()
        ]
    for row in values:
        row["enabled"] = bool(row["enabled"])
        row["managed"] = bool(row["managed"])
        row["scopes"], row["providers"] = (
            json.loads(row["scopes"]),
            json.loads(row["providers"]),
        )
        files = decode(row.pop("bundle"))
        row["resources"] = sorted(path for path in files if path != "SKILL.md")
        if include_content:
            row.update(parse_document(files["SKILL.md"]))
            row["files"] = files
        else:
            row.update(_applicability_of(files["SKILL.md"]))
    return values


@cache
def _applicability_of(text):
    try:
        parsed = parse_document(text)
    except ValueError:
        return {}
    return {key: parsed[key] for key in ("types", "devices") if key in parsed}


def get(ident):
    row = next((row for row in rows(True) if row["id"] == ident), None)
    if not row:
        raise HTTPException(404, "Skill 不存在")
    return row


def validate_choices(scopes, providers):
    if (
        not scopes
        or set(scopes) - SCOPES
        or not providers
        or set(providers) - PROVIDERS
    ):
        raise ValueError("请选择有效的适用场景与 MCP 服务")


def save(
    package,
    *,
    scopes,
    providers,
    enabled,
    priority,
    actor,
    replace=False,
    mode="standalone",
):
    from .main import connection

    validate_choices(scopes, providers)
    if mode not in MODES:
        raise ValueError("Skill 与基础 Skill 的关系须为替代或补充")
    ident = uuid.uuid4().hex
    with connection() as db:
        old = db.execute(
            "SELECT id,managed FROM platform_skills WHERE name=?", (package["name"],)
        ).fetchone()
        if (old and old[1]) or (not old and package["name"] in MANAGED):
            raise HTTPException(
                409,
                package["name"] + " 由平台维护，请用其他名称导入自定义 Skill",
            )
        if old and not replace:
            raise HTTPException(409, "同名 Skill 已存在，请明确选择更新")
        if old:
            ident = old[0]
            db.execute(
                "UPDATE platform_skills SET description=?,enabled=?,priority=?,scopes=?,providers=?,mode=?,revision=revision+1,digest=?,bundle=?,updated_by=?,updated_at=CURRENT_TIMESTAMP WHERE id=?",
                (
                    package["description"],
                    int(enabled),
                    priority,
                    json.dumps(scopes),
                    json.dumps(providers),
                    mode,
                    digest(package["files"]),
                    encode(package["files"]),
                    actor,
                    ident,
                ),
            )
        else:
            db.execute(
                "INSERT INTO platform_skills(id,name,description,enabled,priority,scopes,providers,mode,digest,bundle,updated_by) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                (
                    ident,
                    package["name"],
                    package["description"],
                    int(enabled),
                    priority,
                    json.dumps(scopes),
                    json.dumps(providers),
                    mode,
                    digest(package["files"]),
                    encode(package["files"]),
                    actor,
                ),
            )
    return get(ident)


def configure_base(ident, *, scopes, providers, enabled, priority, actor):
    """The base Skill's text is platform-owned; admins choose only where it runs."""
    from .main import connection

    validate_choices(scopes, providers)
    with connection() as db:
        db.execute(
            "UPDATE platform_skills SET enabled=?,priority=?,scopes=?,providers=?,revision=revision+1,updated_by=?,updated_at=CURRENT_TIMESTAMP WHERE id=? AND managed=1",
            (
                int(enabled),
                priority,
                json.dumps(scopes),
                json.dumps(providers),
                actor,
                ident,
            ),
        )
    return get(ident)


def snapshot(request, source):
    scope = scope_of(request, source)
    selected = [row for row in rows(True) if row["enabled"] and scope in row["scopes"]]
    # A custom Skill in "standalone" mode replaces the base Skill for this scope;
    # "supplement" Skills load alongside it (higher priority first).
    if any(not row["managed"] and row["mode"] == "standalone" for row in selected):
        selected = [row for row in selected if not row["managed"]]
    elif not any(row["managed"] and row["name"] == BASE_NAME for row in selected):
        # Device and alert-type Skills extend the base Skill's procedure; with
        # the base disabled (or not serving this scope) they are not loaded.
        selected = [row for row in selected if not row["managed"]]
    if sum(len(row["files"]["SKILL.md"].encode()) for row in selected) > 128000:
        raise HTTPException(
            422, "本场景启用的 Skill 正文合计超过 128 KB，请停用无关 Skill"
        )
    return selected


def summary(snapshot, applied=None):
    """Report rows for the Skills a task loaded; `applied` marks which of them
    the model actually received (device/type Skills may not apply)."""
    return [
        {
            **{
                key: row.get(key)
                for key in (
                    "id",
                    "name",
                    "description",
                    "revision",
                    "digest",
                    "providers",
                    "managed",
                    "mode",
                    "types",
                    "devices",
                )
            },
            **({"applied": row.get("name") in applied} if applied is not None else {}),
        }
        for row in snapshot
    ]


def applied_names(report):
    """Names of the Skills the model received, read from a finished task's
    report; None when the task never reached the model (queued, running).

    Reports before v1.2.0 carry no `applied` flag: every Skill was sent then.
    """
    rows = [row for row in (report or {}).get("skills") or [] if isinstance(row, dict)]
    if not rows:
        return None
    return {row.get("name") for row in rows if row.get("applied", True)}


def export(files):
    target = io.BytesIO()
    with zipfile.ZipFile(target, "w", zipfile.ZIP_DEFLATED) as archive:
        for path, text in sorted(files.items()):
            archive.writestr(path, text)
    return target.getvalue()
