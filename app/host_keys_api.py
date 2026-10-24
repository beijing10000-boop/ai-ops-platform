"""Authenticated APIs for batch discovery; fetched keys are never trusted automatically."""

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, ConfigDict, Field, StrictBool, StrictInt

from .inventory import host_keys
from .security.rbac import require

router = APIRouter(prefix="/api/v1/platform/host-keys")


class Selection(BaseModel):
    model_config = ConfigDict(extra="forbid")
    asset_ids: list[StrictInt] = Field(min_length=1, max_length=1000)


class Confirmation(Selection):
    verified: StrictBool
    replace_changed: StrictBool = False


@router.get("/targets")
def targets(
    q: str = Query("", max_length=160),
    device_type: str = "all",
    group_id: int | None = Query(None, ge=1),
    who=Depends(require("credentials.manage")),
):
    ids = host_keys.targets(q, device_type, group_id)
    return {"asset_ids": ids, "total": len(ids)}


@router.get("")
def recent(who=Depends(require("credentials.manage"))):
    return host_keys.recent()


@router.post("", status_code=202)
def create(body: Selection, who=Depends(require("credentials.manage"))):
    return host_keys.create(body.asset_ids, who["open_id"])


@router.get("/{scan_id}")
def detail(
    scan_id: str,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=100),
    who=Depends(require("credentials.manage")),
):
    return host_keys.detail(scan_id, page, page_size)


@router.post("/{scan_id}/confirm")
def confirm(
    scan_id: str, body: Confirmation, who=Depends(require("credentials.manage"))
):
    return host_keys.confirm(
        scan_id,
        body.asset_ids,
        who["open_id"],
        body.verified,
        body.replace_changed,
    )


@router.post("/{scan_id}/retry", status_code=202)
def retry(scan_id: str, who=Depends(require("credentials.manage"))):
    return host_keys.retry(scan_id, who["open_id"])
