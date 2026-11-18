import asyncio
import hashlib
import json
from unittest.mock import Mock
from zipfile import ZipFile

import pytest
from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer

from mower_relay_server import ui_cache
from mower_relay_server.admin import issue
from mower_relay_server.server import COOKIE, GATEWAY, Peer, create_app

A, B = "a" * 64, "b" * 64


def write_zip(path, build):
    with ZipFile(path, "w") as z:
        z.writestr("relay-ui.json", json.dumps({"build": build}))
        z.writestr("frontend-routes.json", '["/", "/new-page"]')
        z.writestr("index.html", build)
        z.writestr("assets/main.js", "alert")


def test_initialization_and_build_isolation(tmp_path, monkeypatch):
    async def scenario():
        ui = tmp_path / "ui"
        ui.mkdir()
        (ui / "frontend-routes.json").write_text('["/"]')
        (ui / "index.html").write_text("legacy-ui")
        registry = tmp_path / "users.json"
        issue(registry, "alice")
        issue(registry, "bob")
        app = create_app(registry, ui, "s" * 48, "k" * 48)
        gateway = app[GATEWAY]
        release = asyncio.Event()
        calls = []

        async def download(build, archive):
            calls.append(build)
            await release.wait()
            write_zip(archive, build)

        monkeypatch.setattr(gateway.cache, "download", download)
        async with TestClient(TestServer(app)) as browser:

            def headers(name, build):
                peer = gateway.peers[name] = Peer(Mock(closed=False))
                peer.ui_build = build
                cookie = gateway.signer.dumps(
                    {"tenant": name, "connection": peer.generation}
                )
                return {
                    "Host": f"{name}.free.mower.work:58000",
                    "Accept": "text/html",
                    "Cookie": f"{COOKIE}={cookie}",
                }

            alice, bob = headers("alice", A), headers("bob", B)
            try:
                assert (
                    await browser.get("/", headers={"Host": alice["Host"]})
                ).status == 401
                assert not calls
                for h in (alice, alice, bob):
                    assert (
                        "正在准备" in await (await browser.get("/", headers=h)).text()
                    )
                state = await (
                    await browser.get("/__mower/ui-state", headers=alice)
                ).json()
                assert state["phase"] == "waiting"
                release.set()
                await asyncio.gather(*list(gateway.cache.jobs.values()))
                for h, build in ((alice, A), (bob, B)):
                    assert (
                        await (await browser.get("/new-page", headers=h)).text()
                        == build
                    )
                    assert (
                        await (await browser.get("/__mower/ui-state", headers=h)).json()
                    )["phase"] == "ready"
                stale = await browser.get(
                    "/status", headers={**alice, "X-Mower-UI-Build": B}
                )
                assert stale.status == 409 and stale.headers["X-Mower-UI-Reload"] == "1"
                for _ in range(45):
                    assert (
                        await browser.get("/assets/main.js", headers=alice)
                    ).status == 200
                assert (
                    await browser.get("/__mower/ui-state", headers=alice)
                ).status == 200
                assert calls == [A, B]
            finally:
                gateway.peers.clear()

    asyncio.run(scenario())


def test_capacity_protects_connected_and_evicts_idle(tmp_path, monkeypatch):
    cache = ui_cache.UiCache(tmp_path, lambda: {A})
    monkeypatch.setattr(ui_cache, "ARCHIVE_LIMIT", 4)
    monkeypatch.setattr(ui_cache, "BUILD_LIMIT", 4)
    cache.capacity = 12
    for build in (A, B):
        directory = cache.directory(build)
        directory.mkdir()
        (directory / "index.html").write_bytes(b"1234")
    cache.reserve()
    assert cache.directory(A).is_dir() and not cache.directory(B).exists()
    cache.capacity -= 1
    with pytest.raises(ValueError, match="在线"):
        cache.reserve()


def test_mismatch_keeps_cache_clean_and_explicit_retry(tmp_path, monkeypatch):
    cache = ui_cache.UiCache(tmp_path, lambda: {A})
    calls = []

    async def download(build, archive):
        calls.append(build)
        write_zip(archive, B if len(calls) == 1 else A)

    monkeypatch.setattr(cache, "download", download)

    async def scenario():
        assert cache.state(A)["phase"] == "waiting"
        await cache.jobs[A]
        assert cache.state(A)["phase"] == "error"
        assert not list(tmp_path.iterdir())
        cache.state(A, retry=True)
        await cache.jobs[A]
        assert cache.state(A)["phase"] == "ready"

    asyncio.run(scenario())


def test_download_verifies_official_digest(tmp_path, monkeypatch):
    async def scenario():
        payload = b"official-ui"
        digest = hashlib.sha256(payload).hexdigest()
        routes = web.Application()

        async def missing(request):
            raise web.HTTPNotFound()

        async def metadata(request):
            return web.json_response(
                {
                    "assets": [
                        {
                            "name": f"ui-{A}.zip",
                            "id": 7,
                            "size": len(payload),
                            "digest": "sha256:" + digest,
                        }
                    ]
                }
            )

        async def download(request):
            assert request.headers["Accept"] == "application/octet-stream"
            return web.Response(body=payload)

        routes.router.add_get(
            "/ArkMowers/arknights-mower/releases/tags/relay-ui", missing
        )
        routes.router.add_get(
            "/ArkMowers/mower-relay-server/releases/tags/relay-ui", metadata
        )
        routes.router.add_get(
            "/ArkMowers/mower-relay-server/releases/assets/7", download
        )
        async with TestServer(routes) as upstream:
            monkeypatch.setattr(
                ui_cache, "RELEASE_API", str(upstream.make_url("/")).rstrip("/")
            )
            cache = ui_cache.UiCache(tmp_path, lambda: {A})
            await cache.download(A, tmp_path / "good.zip")
            assert (tmp_path / "good.zip").read_bytes() == payload
            assert cache.states[A]["received"] == len(payload)
            digest = "0" * 64
            with pytest.raises(ValueError, match="校验值"):
                await cache.download(A, tmp_path / "bad.zip")

    asyncio.run(scenario())


def test_release_timeout_allows_slow_progress_but_bounds_stalls():
    size = 14_249_842
    timeout = ui_cache.asset_download_timeout(size)
    assert size / (16 * 1024) < timeout.total < 3600
    assert 0 < timeout.sock_connect < timeout.sock_read <= 60
    assert ui_cache.asset_download_timeout(1).total < timeout.total
    for invalid in (None, True, -1, 0, ui_cache.ARCHIVE_LIMIT + 1):
        with pytest.raises(ValueError):
            ui_cache.asset_download_timeout(invalid)


def test_release_timeout_cleans_stage_and_allows_retry(tmp_path, monkeypatch):
    cache = ui_cache.UiCache(tmp_path, lambda: {A})

    async def stalled(build, archive):
        archive.write_bytes(b"partial")
        raise TimeoutError

    async def success(build, archive):
        write_zip(archive, build)

    async def scenario():
        monkeypatch.setattr(cache, "download", stalled)
        cache.state(A)
        await cache.jobs[A]
        assert "超时" in cache.state(A)["message"]
        assert not list(tmp_path.iterdir())
        monkeypatch.setattr(cache, "download", success)
        cache.state(A, retry=True)
        await cache.jobs[A]
        assert cache.state(A)["phase"] == "ready"

    asyncio.run(scenario())
