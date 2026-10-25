"""Monitoring inventory and exact Zabbix Host ID bindings. No SSH material."""

import ipaddress
from pydantic import BaseModel, ConfigDict, Field

DEVICE_TYPES = {"linux", "windows", "vmware", "network", "other", "unknown"}
NETWORKS = tuple(
    ipaddress.ip_network(x)
    for x in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7")
)


def address(value):
    try:
        ip = ipaddress.ip_address(value.strip())
    except ValueError:
        raise ValueError("资产地址格式无效，请填写内网 IP") from None
    if getattr(ip, "scope_id", None) or not any(
        ip.version == n.version and ip in n for n in NETWORKS
    ):
        raise ValueError("资产地址仅接受 RFC1918/ULA 内网 IP（仅展示，不作为诊断目标）")
    return str(ip)


class AssetInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=1, max_length=160)
    zabbix_hostid: str | None = Field(default=None, pattern=r"^[0-9]{1,32}$")
    device_type: str = "unknown"
    address: str = Field(default="", max_length=64)
    enabled: bool = True
    group_ids: list[int] = Field(default_factory=list, max_length=50)

    def checked(self):
        if not self.name.strip() or self.device_type not in DEVICE_TYPES:
            raise ValueError("资产名称或设备类型无效")
        if self.address:
            self.address = address(self.address)
        return self


def row_dict(row, cur):
    result = dict(zip((x[0] for x in cur.description), row)) if row else None
    return result


def asset_values(body):
    values = body.model_dump(exclude={"group_ids"})
    return values


def get_asset(asset_id=None, *, zabbix_hostid=None):
    from ..main import connection

    with connection() as db:
        cur = db.execute(
            "SELECT * FROM assets WHERE "
            + ("id=?" if asset_id is not None else "zabbix_hostid=?"),
            (asset_id if asset_id is not None else zabbix_hostid,),
        )
        return row_dict(cur.fetchone(), cur)


def save_asset(body, actor, asset_id=None):
    from ..main import connection
    from ..security.rbac import audit

    body = body.checked()
    values = asset_values(body)
    with connection() as db:
        if asset_id is None:
            asset_id = db.execute(
                "INSERT INTO assets("
                + ",".join(values)
                + ") VALUES ("
                + ",".join("?" for _ in values)
                + ")",
                tuple(values.values()),
            ).lastrowid
        else:
            cur = db.execute(
                "UPDATE assets SET "
                + ",".join(k + "=?" for k in values)
                + ",revision=revision+1,updated_at=CURRENT_TIMESTAMP WHERE id=?",
                (*values.values(), asset_id),
            )
            if not cur.rowcount:
                raise ValueError("资产不存在")
        db.execute("DELETE FROM asset_group_members WHERE asset_id=?", (asset_id,))
        db.executemany(
            "INSERT INTO asset_group_members VALUES (?,?)",
            ((asset_id, gid) for gid in set(body.group_ids)),
        )
    audit(actor, "asset_saved", asset_id)
    return get_asset(asset_id)


def asset_page(page=1, page_size=25, query="", device_type="all", group_id=None):
    from ..main import connection

    clauses, values = ["1=1"], []
    if query:
        clauses.append(
            "(instr(lower(name),lower(?))>0 OR instr(address,?)>0 OR zabbix_hostid=?)"
        )
        values.extend((query, query, query))
    if device_type != "all":
        clauses.append("device_type=?")
        values.append(device_type)
    if group_id:
        clauses.append(
            "id IN (SELECT asset_id FROM asset_group_members WHERE group_id=?)"
        )
        values.append(group_id)
    where = " WHERE " + " AND ".join(clauses)
    with connection() as db:
        total = db.execute("SELECT COUNT(*) FROM assets" + where, values).fetchone()[0]
        cur = db.execute(
            "SELECT * FROM assets" + where + " ORDER BY id DESC LIMIT ? OFFSET ?",
            (*values, page_size, (page - 1) * page_size),
        )
        rows = [row_dict(row, cur) for row in cur.fetchall()]
        for row in rows:
            row["group_ids"] = [
                r[0]
                for r in db.execute(
                    "SELECT group_id FROM asset_group_members WHERE asset_id=?",
                    (row["id"],),
                )
            ]
    return {"items": rows, "total": total, "page": page, "page_size": page_size}


def infer_device(host):
    tags = {
        t.get("tag"): str(t.get("value", "")).lower()
        for t in host.get("tags", [])
        if isinstance(t, dict)
    }
    if tags.get("aiops.device_type") in DEVICE_TYPES:
        return tags["aiops.device_type"]
    os_name = str((host.get("inventory") or {}).get("os", "")).lower()
    for kind, words in [
        ("windows", ("windows",)),
        ("vmware", ("vmware", "esxi", "vcenter")),
        ("network", ("huawei", "vrp", "cisco", "comware")),
        ("linux", ("linux",)),
    ]:
        if any(w in os_name for w in words):
            return kind
    return "unknown"
