"""Web-managed Skills: preview, import, edit, enable, export and readiness checks."""

from pathlib import Path
import re

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import Response
from pydantic import BaseModel, ConfigDict, Field, StrictBool

from . import skill_store as skills
from .main import connection
from .security.rbac import require, audit

router = APIRouter(prefix="/api/v1/platform/skills")


class ImportSkill(BaseModel):
    model_config = ConfigDict(extra="forbid")
    filename: str = Field(max_length=200)
    data: str = Field(max_length=1500000)
    enabled: StrictBool = False
    replace_existing: StrictBool = False
    scopes: list[str] = Field(
        default_factory=lambda: ["qa", "alert", "web"], max_length=3
    )
    providers: list[str] = Field(
        default_factory=lambda: ["ssh_mcp", "zabbix_mcp"], max_length=2
    )
    priority: int = Field(default=100, ge=0, le=2147483647)


class UpdateSkill(BaseModel):
    model_config = ConfigDict(extra="forbid")
    description: str | None = Field(default=None, min_length=1, max_length=1024)
    instructions: str | None = Field(default=None, min_length=1, max_length=64000)
    enabled: StrictBool | None = None
    scopes: list[str] | None = Field(default=None, max_length=3)
    providers: list[str] | None = Field(default=None, max_length=2)
    priority: int | None = Field(default=None, ge=0, le=2147483647)


def checked(call):
    try:
        return call()
    except (ValueError, UnicodeError) as exc:
        raise HTTPException(422, str(exc)) from None


def public(row):
    return {key: value for key, value in row.items() if key != "files"}


@router.get("")
def list_skills(who=Depends(require("tools.read"))):
    return {"items": skills.rows()}


@router.get("/template")
def template(who=Depends(require("tools.read"))):
    root = Path(__file__).parent / "skill_templates" / "ops-readonly"
    files = {
        str(path.relative_to(root)): path.read_text()
        for path in root.rglob("*")
        if path.is_file()
    }
    return Response(
        skills.export(files),
        media_type="application/zip",
        headers={
            "Content-Disposition": 'attachment; filename="ai-ops-skill-template.zip"'
        },
    )


@router.post("/validate")
def validate(body: ImportSkill, who=Depends(require("settings.manage"))):
    package = checked(lambda: skills.parse_package(body.filename, body.data))
    checked(lambda: skills.validate_choices(body.scopes, body.providers))
    old = next((row for row in skills.rows() if row["name"] == package["name"]), None)
    return {
        "ok": True,
        "message": "Skill 格式验证通过；尚未保存、未调用 MCP 或模型。",
        **{key: package[key] for key in ("name", "description", "instructions")},
        "resources": sorted(set(package["files"]) - {"SKILL.md"}),
        "existing_id": old["id"] if old else None,
        "digest": skills.digest(package["files"]),
    }


@router.post("", status_code=201)
def import_skill(body: ImportSkill, who=Depends(require("settings.manage"))):
    package = checked(lambda: skills.parse_package(body.filename, body.data))
    row = checked(
        lambda: skills.save(
            package,
            scopes=body.scopes,
            providers=body.providers,
            enabled=body.enabled,
            priority=body.priority,
            actor=who["open_id"],
            replace=body.replace_existing,
        )
    )
    audit(who["open_id"], "skill_imported", row["name"])
    return public(row)


@router.get("/{ident}/export")
def export_skill(ident: str, who=Depends(require("tools.read"))):
    row = skills.get(ident)
    return Response(
        skills.export(row["files"]),
        media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="{row["name"]}.zip"'},
    )


@router.get("/{ident}")
def detail(ident: str, who=Depends(require("tools.read"))):
    return public(skills.get(ident))


@router.put("/{ident}")
def update(ident: str, body: UpdateSkill, who=Depends(require("settings.manage"))):
    row = skills.get(ident)
    values = {**row, **body.model_dump(exclude_none=True)}
    files = dict(row["files"])
    files["SKILL.md"] = skills.document(
        row["name"], values["description"], values["instructions"]
    )
    package = {
        **checked(lambda: skills.parse_document(files["SKILL.md"])),
        "files": files,
    }
    saved = checked(
        lambda: skills.save(
            package,
            scopes=values["scopes"],
            providers=values["providers"],
            enabled=values["enabled"],
            priority=values["priority"],
            actor=who["open_id"],
            replace=True,
        )
    )
    audit(who["open_id"], "skill_updated", row["name"])
    return public(saved)


@router.delete("/{ident}")
def delete(ident: str, who=Depends(require("settings.manage"))):
    row = skills.get(ident)
    with connection() as db:
        db.execute("DELETE FROM platform_skills WHERE id=?", (ident,))
    audit(who["open_id"], "skill_deleted", row["name"])
    return {"ok": True}


@router.post("/{ident}/verify")
async def verify(ident: str, who=Depends(require("settings.manage"))):
    import time
    from .skill_mcp import SkillMCP
    from .main import read_setting

    row = skills.get(ident)
    referenced = set(
        re.findall(r"`((?:ssh_[a-z_]+|[a-z]+_get))`", "\n".join(row["files"].values()))
    )
    results = []
    async with SkillMCP(
        read_setting, row["providers"], deadline=time.monotonic() + 35
    ) as bridge:
        for provider in row["providers"]:
            try:
                tools = await bridge.catalog(provider)
                required = {
                    name
                    for name in referenced
                    if (name.startswith("ssh_")) == (provider == "ssh_mcp")
                }
                missing = sorted(required - tools.keys())
                results.append(
                    {
                        "provider": provider,
                        "ok": not missing,
                        "tools": len(tools),
                        "missing": missing,
                    }
                )
            except Exception as exc:
                results.append(
                    {
                        "provider": provider,
                        "ok": False,
                        "error": str(exc)
                        if isinstance(exc, ValueError)
                        else type(exc).__name__,
                    }
                )
    return {
        "ok": all(item["ok"] for item in results),
        "results": results,
        "message": "仅检测已保存的 MCP 连接和只读工具目录；未登录目标主机、未调用模型。",
    }
