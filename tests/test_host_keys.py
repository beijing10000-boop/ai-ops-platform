"""Batch discovery never trusts keys until explicit, atomic confirmation."""

import secrets
import time

import paramiko
import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from app import feishu_auth, inventory, main
from app.inventory import host_keys

API = "/api/v1/platform/host-keys"


@pytest.fixture(autouse=True)
def isolated(monkeypatch, tmp_path):
    monkeypatch.setattr(main, "DATA_DIR", tmp_path)
    monkeypatch.setattr(main, "DB", tmp_path / "app.sqlite3")
    monkeypatch.setattr(host_keys, "enqueue", lambda *_: None)
    with main.connection() as db:
        db.execute(
            "INSERT OR REPLACE INTO settings VALUES ('feishu_admin_open_ids','ou_keys',0)"
        )


@pytest.fixture(scope="module")
def keys():
    values = [paramiko.RSAKey.generate(2048) for _ in range(2)]
    return [key.get_name() + " " + key.get_base64() for key in values]


def client_for(role="super_admin"):
    actor = "ou_keys" if role == "super_admin" else "ou_" + role
    raw, csrf = secrets.token_hex(24), secrets.token_hex(24)
    with main.connection() as db:
        feishu_auth._tables(db)
        if role != "super_admin":
            db.execute("INSERT OR REPLACE INTO members VALUES (?,?,1)", (actor, role))
        db.execute(
            "INSERT INTO admin_sessions VALUES (?,?,?,?,?)",
            (feishu_auth._hash(raw), actor, role, csrf, int(time.time()) + 3600),
        )
    return TestClient(
        main.app, headers={"x-csrf-token": csrf}, cookies={feishu_auth.COOKIE: raw}
    )


def asset(name="node", **kwargs):
    return inventory.save_asset(
        inventory.AssetInput(
            **{"name": name, "device_type": "linux", "address": "10.10.0.10", **kwargs}
        ),
        "ou_keys",
    )


def collect(ids, monkeypatch, key):
    monkeypatch.setattr(host_keys, "fetch_key", lambda _: key)
    scan_id = host_keys.create(ids, "ou_keys")["scan_id"]
    host_keys.collect(scan_id)
    return scan_id


@pytest.mark.parametrize("role", ["operator", "auditor"])
def test_read_and_write_require_credential_permission(role):
    client = client_for(role)
    for path in (API, API + "/targets", API + "/missing"):
        assert client.get(path).status_code == 403
    for path, body in (
        (API, {"asset_ids": [1]}),
        (API + "/missing/confirm", {"asset_ids": [1], "verified": True}),
        (API + "/missing/retry", None),
    ):
        assert client.post(path, json=body).status_code == 403
    assert TestClient(main.app).get(API).status_code == 401


def test_csrf_and_payload_validation():
    client = client_for()
    for body in (
        {"asset_ids": []},
        {"asset_ids": [0]},
        {"asset_ids": [True]},
        {"asset_ids": ["1"]},
        {"asset_ids": list(range(1, 1002))},
        {"asset_ids": [1], "address": "10.0.0.1"},
    ):
        assert client.post(API, json=body).status_code == 422
    client.headers.pop("x-csrf-token")
    assert client.post(API, json={"asset_ids": [1]}).status_code == 403


def test_invalid_selection_rolls_back_and_never_enqueues(monkeypatch):
    good = asset()
    bad = asset("windows", device_type="windows")
    calls = []
    monkeypatch.setattr(host_keys, "enqueue", lambda *args: calls.append(args))
    client = client_for()
    for ident in (
        bad["id"],
        9999,
        asset("off", enabled=False)["id"],
        asset("no IP", address="")["id"],
    ):
        assert (
            client.post(API, json={"asset_ids": [good["id"], ident]}).status_code == 422
        )
    # Validate again at use time, including a corrupt legacy address.
    with main.connection() as db:
        db.execute("UPDATE assets SET address='8.8.8.8' WHERE id=?", (good["id"],))
    assert client.post(API, json={"asset_ids": [good["id"]]}).status_code == 422
    with main.connection() as db:
        assert db.execute("SELECT COUNT(*) FROM host_key_scans").fetchone()[0] == 0
    assert calls == []


def test_filter_selects_all_1000_targets_across_pages_and_respects_group():
    with main.connection() as db:
        db.execute("INSERT INTO asset_groups(id,name) VALUES (1,'fleet')")
        db.executemany(
            "INSERT INTO assets(name,device_type,address) VALUES (?,'linux','10.0.0.10')",
            [("fleet-" + str(i),) for i in range(1000)],
        )
        db.executemany(
            "INSERT INTO asset_group_members VALUES (?,1)",
            [(i,) for i in range(1, 501)],
        )
    client = client_for()
    result = client.get(API + "/targets").json()
    assert result["total"] == 1000 and len(set(result["asset_ids"])) == 1000
    assert client.get(API + "/targets?group_id=1").json()["total"] == 500
    assert client.get(API + "/targets?q=fleet-999").json()["asset_ids"] == [1000]
    assert client.get(API + "/targets?device_type=windows").json()["total"] == 0
    scan = client.post(API, json={"asset_ids": result["asset_ids"]}).json()
    last = client.get(API + "/" + scan["scan_id"] + "?page=20").json()
    assert last["total"] == 1000 and len(last["items"]) == 50
    assert last["items"][-1]["asset_id"] == 1000
    asset("over limit")
    assert client.get(API + "/targets").status_code == 422
    assert client.get(API + "/" + scan["scan_id"] + "?page=0").status_code == 422


def test_discovery_classifies_without_trusting_and_confirmation_is_explicit(
    monkeypatch, keys
):
    fresh = asset("fresh")
    changed = asset("changed", host_key=keys[0])
    unchanged = asset("unchanged", host_key=keys[1])
    failed = asset("unreachable")

    def probe(row):
        if row["id"] == failed["id"]:
            raise ValueError("SSH handshake unavailable")
        return keys[1]

    monkeypatch.setattr(host_keys, "fetch_key", probe)
    client = client_for("ops_admin")
    ids = [row["id"] for row in (fresh, changed, unchanged, failed)]
    response = client.post(API, json={"asset_ids": ids})
    assert response.status_code == 202
    scan_id = response.json()["scan_id"]
    host_keys.collect(scan_id)
    result = client.get(API + "/" + scan_id).json()
    assert result["status"] == "completed"
    assert result["counts"] == {"new": 1, "changed": 1, "unchanged": 1, "failed": 1}
    assert result["new_ids"] == [fresh["id"]]
    assert result["changed_ids"] == [changed["id"]]
    assert result["items"][0]["fingerprint"] == inventory.fingerprint(keys[1])
    assert result["items"][1]["previous_fingerprint"] == inventory.fingerprint(keys[0])
    assert inventory.get_asset(fresh["id"])["host_key"] == ""
    assert inventory.get_asset(changed["id"])["host_key"] == keys[0]
    endpoint = API + "/" + scan_id + "/confirm"
    assert (
        client.post(
            endpoint, json={"asset_ids": ids[:2], "verified": False}
        ).status_code
        == 422
    )
    assert (
        client.post(
            endpoint, json={"asset_ids": ids[:2], "verified": "true"}
        ).status_code
        == 422
    )
    assert (
        client.post(endpoint, json={"asset_ids": ids[:2], "verified": True}).status_code
        == 409
    )
    assert inventory.get_asset(fresh["id"])["host_key"] == ""
    with main.connection() as db:
        db.execute(
            "UPDATE assets SET last_test_status='success',last_test_at=CURRENT_TIMESTAMP"
        )
    result = client.post(
        endpoint, json={"asset_ids": ids[:2], "verified": True, "replace_changed": True}
    )
    assert result.status_code == 200 and result.json()["saved"] == 2
    for row in (fresh, changed):
        stored = inventory.get_asset(row["id"])
        assert (
            stored["host_key"] == keys[1] and stored["revision"] == row["revision"] + 1
        )
        assert stored["last_test_status"] is None and stored["last_test_at"] is None
    assert (
        client.post(endpoint, json={"asset_ids": ids[:2], "verified": True}).json()[
            "already_saved"
        ]
        == 2
    )
    with main.connection() as db:
        rows = db.execute(
            "SELECT actor,trace_id FROM audit WHERE action='host_key_confirmed'"
        ).fetchall()
    assert rows == [("ou_ops_admin", scan_id)] * 2


def test_stale_confirmation_rolls_back_all_selected_keys(monkeypatch, keys):
    first, second = asset("first"), asset("second")
    ids = [first["id"], second["id"]]
    scan_id = collect(ids, monkeypatch, keys[0])
    inventory.save_asset(
        inventory.AssetInput(name="edited", device_type="linux", address="10.0.0.11"),
        "ou_keys",
        second["id"],
    )
    with pytest.raises(HTTPException) as error:
        host_keys.confirm(scan_id, ids, "ou_keys", True)
    assert error.value.status_code == 409
    assert inventory.get_asset(first["id"])["host_key"] == ""
    assert host_keys.detail(scan_id)["counts"] == {"new": 2}
    with main.connection() as db:
        assert (
            db.execute(
                "SELECT COUNT(*) FROM audit WHERE action='host_key_confirmed'"
            ).fetchone()[0]
            == 0
        )


def test_configuration_change_during_probe_discards_candidate(monkeypatch, keys):
    row = asset()

    def probe(_):
        inventory.save_asset(
            inventory.AssetInput(
                name="edited", device_type="linux", address="10.0.0.12"
            ),
            "ou_keys",
            row["id"],
        )
        return keys[0]

    monkeypatch.setattr(host_keys, "fetch_key", probe)
    scan_id = host_keys.create([row["id"]], "ou_keys")["scan_id"]
    host_keys.collect(scan_id)
    item = host_keys.detail(scan_id)["items"][0]
    assert item["status"] == "failed" and not item["host_key"]
    assert "变更" in item["error"]


def test_permission_revoked_before_worker_prevents_network(monkeypatch):
    row = asset()
    scan_id = host_keys.create([row["id"]], "ou_keys")["scan_id"]
    calls = []
    monkeypatch.setattr(host_keys, "fetch_key", lambda r: calls.append(r))
    with main.connection() as db:
        db.execute("UPDATE settings SET value='' WHERE key='feishu_admin_open_ids'")
    host_keys.collect(scan_id)
    assert calls == []
    assert "撤销" in host_keys.detail(scan_id)["items"][0]["error"]


def test_queue_failure_is_visible_and_retry_only_selects_failed(monkeypatch, keys):
    first, second = asset("first"), asset("second")

    def broken(*_):
        raise ConnectionError("Redis unavailable")

    monkeypatch.setattr(host_keys, "enqueue", broken)
    scan_id = host_keys.create([first["id"], second["id"]], "ou_keys")["scan_id"]
    result = host_keys.detail(scan_id)
    assert result["status"] == "failed" and result["counts"] == {"failed": 2}
    assert "host-key-worker" in result["error"]
    monkeypatch.setattr(host_keys, "enqueue", lambda *_: None)
    retry = host_keys.retry(scan_id, "ou_keys")["scan_id"]

    def probe(row):
        if row["id"] == second["id"]:
            raise ValueError("unreachable")
        return keys[0]

    monkeypatch.setattr(host_keys, "fetch_key", probe)
    host_keys.collect(retry)
    final = host_keys.retry(retry, "ou_keys")["scan_id"]
    assert [r["asset_id"] for r in host_keys.detail(final)["items"]] == [second["id"]]
    assert inventory.get_asset(first["id"])["host_key"] == ""


def test_stale_worker_can_recover_without_overwriting_completed_candidates(
    monkeypatch, keys
):
    first, second = asset("first"), asset("second")
    scan_id = host_keys.create([first["id"], second["id"]], "ou_keys")["scan_id"]
    with main.connection() as db:
        db.execute("UPDATE host_key_scans SET status='running'")
        db.execute(
            "UPDATE host_key_scan_items SET status='new',host_key=?,fingerprint=? WHERE asset_id=?",
            (keys[0], inventory.fingerprint(keys[0]), first["id"]),
        )
        db.execute("UPDATE host_key_scans SET updated_at=datetime('now','-3 minutes')")
    result = host_keys.detail(scan_id)
    assert result["status"] == "failed" and result["counts"] == {"new": 1, "failed": 1}
    assert host_keys.confirm(scan_id, [first["id"]], "ou_keys", True)["saved"] == 1
    assert (
        host_keys.detail(host_keys.retry(scan_id, "ou_keys")["scan_id"])["total"] == 1
    )


def test_duplicate_worker_does_not_repeat_network(monkeypatch, keys):
    row = asset()
    calls = []

    def probe(r):
        calls.append(r["id"])
        return keys[0]

    monkeypatch.setattr(host_keys, "fetch_key", probe)
    scan_id = host_keys.create([row["id"], row["id"]], "ou_keys")["scan_id"]
    host_keys.collect(scan_id)
    host_keys.collect(scan_id)
    assert calls == [row["id"]]
    assert host_keys.detail(scan_id)["total"] == 1


def test_migration_from_v2_preserves_assets_and_is_idempotent():
    row = asset("existing root", username="root")
    with main.connection() as db:
        db.execute("DROP TABLE host_key_scan_items")
        db.execute("DROP TABLE host_key_scans")
        db.execute("DELETE FROM platform_migrations WHERE version=3")
    for _ in range(2):
        with main.connection() as db:
            assert (
                db.execute("SELECT MAX(version) FROM platform_migrations").fetchone()[0]
                == 3
            )
            assert db.execute("SELECT COUNT(*) FROM host_key_scans").fetchone()[0] == 0
    assert inventory.get_asset(row["id"])["username"] == "root"
