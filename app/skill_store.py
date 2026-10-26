"""Validated, encrypted Markdown Skills. Packages are read as data, never extracted or executed."""

import base64
import hashlib
import io
import json
from pathlib import PurePosixPath
import re
import stat
import uuid
import zipfile

import yaml
from fastapi import HTTPException

MAX_PACKAGE = 1024 * 1024
MAX_DOCUMENT = 64000
SCOPES = {"alert", "qa", "web"}
PROVIDERS = {"ssh_mcp", "zabbix_mcp"}


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
    if not isinstance(meta, dict) or set(meta) != {"name", "description"}:
        raise ValueError("Skill 元数据只需 name 和 description")
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
    }


def document(name, description, instructions):
    return (
        "---\n"
        + yaml.safe_dump(
            {"name": name, "description": description},
            allow_unicode=True,
            sort_keys=False,
        ).strip()
        + "\n---\n\n"
        + instructions.strip()
        + "\n"
    )


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


def encode(files):
    from .main import cipher

    return cipher().encrypt(json.dumps(files, ensure_ascii=False).encode()).decode()


def decode(raw):
    from .main import cipher

    return json.loads(cipher().decrypt(raw.encode()))


def rows(include_content=False):
    from .main import connection

    with connection() as db:
        cursor = db.execute("SELECT * FROM platform_skills ORDER BY priority DESC,name")
        values = [
            dict(zip([col[0] for col in cursor.description], row))
            for row in cursor.fetchall()
        ]
    for row in values:
        row["enabled"] = bool(row["enabled"])
        row["scopes"], row["providers"] = (
            json.loads(row["scopes"]),
            json.loads(row["providers"]),
        )
        files = decode(row.pop("bundle"))
        row["resources"] = sorted(path for path in files if path != "SKILL.md")
        if include_content:
            row.update(parse_document(files["SKILL.md"]))
            row["files"] = files
    return values


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


def save(package, *, scopes, providers, enabled, priority, actor, replace=False):
    from .main import connection

    validate_choices(scopes, providers)
    ident = uuid.uuid4().hex
    with connection() as db:
        old = db.execute(
            "SELECT id FROM platform_skills WHERE name=?", (package["name"],)
        ).fetchone()
        if old and not replace:
            raise HTTPException(409, "同名 Skill 已存在，请明确选择更新")
        if old:
            ident = old[0]
            db.execute(
                "UPDATE platform_skills SET description=?,enabled=?,priority=?,scopes=?,providers=?,revision=revision+1,digest=?,bundle=?,updated_by=?,updated_at=CURRENT_TIMESTAMP WHERE id=?",
                (
                    package["description"],
                    int(enabled),
                    priority,
                    json.dumps(scopes),
                    json.dumps(providers),
                    digest(package["files"]),
                    encode(package["files"]),
                    actor,
                    ident,
                ),
            )
        else:
            db.execute(
                "INSERT INTO platform_skills(id,name,description,enabled,priority,scopes,providers,digest,bundle,updated_by) VALUES (?,?,?,?,?,?,?,?,?,?)",
                (
                    ident,
                    package["name"],
                    package["description"],
                    int(enabled),
                    priority,
                    json.dumps(scopes),
                    json.dumps(providers),
                    digest(package["files"]),
                    encode(package["files"]),
                    actor,
                ),
            )
    return get(ident)


def snapshot(request, source):
    scope = (
        "alert"
        if (request.get("event") or {}).get("event_id")
        else "qa"
        if source in {"qa", "feishu"}
        else "web"
    )
    selected = [row for row in rows(True) if row["enabled"] and scope in row["scopes"]]
    if sum(len(row["files"]["SKILL.md"].encode()) for row in selected) > 128000:
        raise HTTPException(422, "本场景启用的 Skill 正文合计超过 128 KB，请停用无关 Skill")
    return selected


def summary(snapshot):
    return [
        {
            key: row[key]
            for key in ("id", "name", "description", "revision", "digest", "providers")
        }
        for row in snapshot
    ]


def export(files):
    target = io.BytesIO()
    with zipfile.ZipFile(target, "w", zipfile.ZIP_DEFLATED) as archive:
        for path, text in sorted(files.items()):
            archive.writestr(path, text)
    return target.getvalue()
