import json
from http.client import HTTPConnection
from http.server import ThreadingHTTPServer
from threading import Thread

import pytest

from mower_relay_server import admin_ui


@pytest.fixture
def local():
    with ThreadingHTTPServer(("127.0.0.1", 0), admin_ui.AdminPage) as server:
        thread = Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            yield server.server_port
        finally:
            server.shutdown()
            thread.join()


def post(port, payload, **headers):
    conn = HTTPConnection("127.0.0.1", port, timeout=3)
    try:
        conn.request(
            "POST",
            "/api",
            json.dumps(payload),
            {
                "Content-Type": "application/json",
                "Authorization": "Bearer fixture",
                "Origin": f"http://127.0.0.1:{port}",
                **headers,
            },
        )
        response = conn.getresponse()
        return response.status, json.loads(response.read())
    finally:
        conn.close()


def test_only_local_page_can_submit(local, monkeypatch):
    def unexpected(*args):
        pytest.fail("unexpected gateway request")

    monkeypatch.setattr(admin_ui, "gateway_request", unexpected)
    for headers, expected in [
        ({"Origin": "https://elsewhere.invalid"}, 403),
        ({"Host": "elsewhere.invalid"}, 404),
        ({"Authorization": ""}, 403),
    ]:
        assert post(local, {"action": "list"}, **headers)[0] == expected
    assert (
        post(local, {"action": "issue", "subdomain": "../other", "subject": "test"})[0]
        == 400
    )


@pytest.mark.parametrize(
    ("payload", "method", "suffix", "fields"),
    [
        ({"action": "list", "offset": 25}, "GET", "/users?offset=25&limit=25", None),
        (
            {"action": "issue", "subdomain": "demo", "subject": "test"},
            "POST",
            "/users",
            {"subdomain": "demo", "subject": "test"},
        ),
        (
            {
                "action": "rename",
                "subdomain": "demo",
                "new_name": "renamed",
                "subject": "test",
            },
            "POST",
            "/users/demo/rename",
            {"subject": "test", "subdomain": "renamed"},
        ),
        (
            {"action": "revoke", "subdomain": "demo", "subject": "test"},
            "POST",
            "/users/demo/revoke",
            {"subject": "test"},
        ),
    ],
)
def test_local_requests_use_fixed_management_routes(
    local, monkeypatch, payload, method, suffix, fields
):
    def upstream(*args):
        assert args == (method, suffix, fields, "Bearer fixture")
        return 200, {"ok": True}

    monkeypatch.setattr(admin_ui, "gateway_request", upstream)
    assert post(local, payload) == (200, {"ok": True})


def test_hosted_entry_moves_atomically_and_survives_restart(tmp_path):
    import asyncio

    from aiohttp.test_utils import TestClient, TestServer

    from mower_relay_server.server import create_app

    def app():
        return create_app(tmp_path / "users.json", tmp_path, "s" * 48, "a" * 48)

    async def scenario():
        host = {"Host": "free.mower.work:58000"}
        auth = {**host, "Authorization": "Bearer " + "a" * 48}
        change = {"original": "/admin/", "path": "/ops/mower/"}
        async with TestClient(TestServer(app())) as client:
            before = await client.get("/admin/", headers=host)
            assert before.status == 200 and "中转凭据管理" in await before.text()
            assert "frame-ancestors 'none'" in before.headers["Content-Security-Policy"]
            assert (
                await client.put("/admin/entry", headers=host, json=change)
            ).status == 403
            for invalid in (
                "//example.com/",
                "/admin/users",
                "/__mower/connect",
                "/ops/../admin",
                "/ops?token=x",
            ):
                assert (
                    await client.put(
                        "/admin/entry", headers=auth, json={**change, "path": invalid}
                    )
                ).status == 400
            assert (
                await client.put("/admin/entry", headers=auth, json=change)
            ).status == 200
            assert (
                await client.put("/admin/entry", headers=auth, json=change)
            ).status == 409
            for old in ("/admin", "/admin/", "/admin/admin_ui.js"):
                assert (await client.get(old, headers=host)).status == 404
            for new in ("/ops/mower/", "/ops/mower/admin_ui.js"):
                assert (await client.get(new, headers=host)).status == 200
                assert (
                    await client.get(
                        new, headers={"Host": "alice.free.mower.work:58000"}
                    )
                ).status != 200
            assert (await client.get("/admin/users", headers=auth)).status == 200
        async with TestClient(TestServer(app())) as client:
            assert (await client.get("/ops/mower/", headers=host)).status == 200
            saved = await client.get("/admin/entry", headers=auth)
            assert await saved.json() == {"path": "/ops/mower/"}

    asyncio.run(scenario())
