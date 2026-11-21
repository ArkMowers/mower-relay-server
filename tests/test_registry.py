import asyncio
import hashlib
import json
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
from aiohttp import WSServerHandshakeError
from aiohttp.test_utils import TestClient, TestServer

from mower_relay_server.registry import Registry, RegistryConflict
from mower_relay_server.server import create_app


def record(secret, enabled=True, subject="qq:fixture"):
    return {
        "credential_sha256": hashlib.sha256(secret.encode()).hexdigest(),
        "enabled": enabled,
        "subject": subject,
    }


def test_old_gateway_and_cli_paths_share_the_migrated_registry(tmp_path):
    old = tmp_path / "members.json"
    records = {"live": record("original"), "revoked": record("revoked", False)}
    old.write_text(json.dumps(records))
    snapshot = old.read_bytes()
    store = Registry(old)
    headers = {"Host": "free.mower.work:58000"}

    async def scenario():
        app = create_app(old, tmp_path, "s" * 48, "a" * 48)
        async with TestClient(TestServer(app)) as bot:
            async with bot.ws_connect(
                "/__mower/connect",
                headers={**headers, "Authorization": "Bearer original"},
            ) as peer:
                await peer.send_json(
                    {"op": "hello", "version": 1, "ui_build": "a" * 64}
                )
                assert (await peer.receive_json())["subdomain"] == "live"
            with pytest.raises(WSServerHandshakeError) as denied:
                await bot.ws_connect(
                    "/__mower/connect",
                    headers={**headers, "Authorization": "Bearer revoked"},
                )
            assert denied.value.status == 403
            auth = {**headers, "Authorization": "Bearer " + "a" * 48}
            dispatch = await bot.post("/admin/users/live/revoke", headers=auth)
            assert (await dispatch.json())["enabled"] is False
            store.path.unlink()
            assert (await bot.get("/admin/users", headers=auth)).status == 503
            assert not store.path.exists()

    asyncio.run(scenario())
    assert (
        not old.exists() and old.with_suffix(".json.migrated").read_bytes() == snapshot
    )
    with pytest.raises(ValueError):
        Registry(store.path).initialize()


@pytest.mark.parametrize(
    "invalid", ["duplicate_digest", "duplicate_subject", "bad_digest", "bad_json"]
)
def test_failed_import_rolls_back_and_can_be_retried(tmp_path, invalid):
    store = Registry(tmp_path / "users.sqlite3")
    data = {"alice": record("a"), "bob": record("b", subject="qq:other")}
    if invalid == "duplicate_digest":
        data["bob"]["credential_sha256"] = data["alice"]["credential_sha256"]
    elif invalid == "duplicate_subject":
        data["bob"]["subject"] = "qq:fixture"
    elif invalid == "bad_digest":
        data["bob"]["credential_sha256"] = "invalid"
    source = "{" if invalid == "bad_json" else json.dumps(data)
    store.legacy.write_text(source)
    with pytest.raises((ValueError, sqlite3.IntegrityError)):
        store.initialize()
    assert store.legacy.read_text() == source
    assert not list(tmp_path.glob("*.migrated"))
    with store.transaction() as db:
        assert db.execute("SELECT name FROM sqlite_master").fetchall() == []
    del data["bob"]
    store.legacy.write_text(json.dumps(data))
    store.initialize()
    assert store.get("alice")["credential_sha256"] == record("a")["credential_sha256"]


def test_resume_interrupted_archive_without_reimport(tmp_path, monkeypatch):
    store = Registry(tmp_path / "users.json")
    store.legacy.write_text(json.dumps({"alice": record("a")}))
    with monkeypatch.context() as patch:

        def interrupted(*args):
            raise OSError("fixture")

        patch.setattr(Path, "rename", interrupted)
        with pytest.raises(OSError):
            store.initialize()
    store.initialize()
    store.update("alice", "qq:fixture", "renamed")
    store.initialize()
    assert store.identify(record("a")["credential_sha256"]) == "renamed"


def test_concurrent_issue_by_subject_and_reuse_revoked_name(tmp_path):
    store = Registry(tmp_path / "users.sqlite3")
    store.initialize()

    def claim(i):
        try:
            return store.issue(f"bot-{i}", "qq:same")
        except RegistryConflict:
            return None

    with ThreadPoolExecutor(max_workers=5) as executor:
        issued = [v for v in executor.map(claim, range(8)) if v]
    assert len(issued) == 1
    old = record(issued[0])["credential_sha256"]
    name = store.identify(old)
    store.update(name, "qq:same")
    store.issue(name, "qq:other")
    assert store.identify(old) is None
    assert store.page("qq:same", 0, 1) == (0, [])
    assert store.get(name)["subject"] == "qq:other"
