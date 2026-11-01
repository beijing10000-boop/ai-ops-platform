"""Bounded, read-only queries for the operations workspace."""

from .main import connection
from .platform_db import row_dict


def literal_search(value):
    return (
        "%" + value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
    )


def alert_page(page=1, page_size=25, status="all", severity=None, query=""):
    clauses = ["a.event_value='1'"]
    args = []
    if status != "all":
        clauses.append("r.id IS " + ("NULL" if status == "active" else "NOT NULL"))
    if severity is not None:
        clauses.append("a.severity=?")
        args.append(severity)
    if query.strip():
        clauses.append(
            "(a.event_id LIKE ? ESCAPE '\\' OR a.host_name LIKE ? ESCAPE '\\' OR a.event_name LIKE ? ESCAPE '\\')"
        )
        args.extend([literal_search(query.strip())] * 3)
    source = " FROM alert_events a LEFT JOIN alert_events r ON r.event_id=a.event_id AND r.event_value='0'"
    where = " WHERE " + " AND ".join(clauses)
    columns = [
        "a.event_id,a.event_name,a.host_name,a.severity,a.received_at,a.notify_status,a.ai_status",
        "r.received_at AS recovered_at,CASE WHEN r.id IS NULL THEN 'active' ELSE 'recovered' END AS status",
        "(SELECT t.task_id FROM diagnostic_tasks t WHERE t.event_id=a.event_id AND t.kind='analysis' ORDER BY t.created_at DESC,t.rowid DESC LIMIT 1) AS task_id",
    ]
    # The Zabbix Host ID and trigger ID name the alert's mute rule (its 屏蔽
    # button); the rest of the stored event stays out of the list.
    columns += [
        f"CASE WHEN json_valid(a.event_json) THEN CAST(json_extract(a.event_json,'$.{key}') AS TEXT) END AS {key}"
        for key in ("host_id", "trigger_id")
    ]
    with connection() as db:
        total = db.execute("SELECT COUNT(*)" + source + where, args).fetchone()[0]
        cur = db.execute(
            "SELECT "
            + ",".join(columns)
            + source
            + where
            + " ORDER BY a.id DESC LIMIT ? OFFSET ?",
            (*args, page_size, (page - 1) * page_size),
        )
        rows = [row_dict(row, cur) for row in cur.fetchall()]
    return {"items": rows, "total": total, "page": page, "page_size": page_size}
