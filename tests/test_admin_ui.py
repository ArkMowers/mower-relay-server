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
    for path in ["//example.org", "https://example.org/", "/ops/../x"]:
        assert post(local, {"action": "list", "entry": path})[0] == 400
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
@pytest.mark.parametrize("entry", [None, "/ops/mower"])
def test_local_requests_use_configured_management_routes(
    local, monkeypatch, payload, method, suffix, fields, entry
):
    if entry:
        payload = {**payload, "entry": entry}

    def upstream(*args):
        assert args == (method, (entry or "/admin") + suffix, fields, "Bearer fixture")
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
            issued = await client.post(
                "/admin/users",
                headers=auth,
                json={"subdomain": "trial", "subject": "test"},
            )
            assert issued.status == 201
            credential = (await issued.json())["credential"]
            assert (
                await client.put("/admin/entry", headers=auth, json=change)
            ).status == 200
            assert (
                await client.put("/ops/mower/entry", headers=auth, json=change)
            ).status == 409
            overlap = {"original": change["path"], "path": change["path"] + "users/"}
            assert (
                await client.put("/ops/mower/entry", headers=auth, json=overlap)
            ).status == 400
            for old in (
                "/admin",
                "/admin/",
                "/admin/admin_ui.js",
                "/admin/users",
                "/admin/entry",
                "/admin/users/trial",
            ):
                assert (
                    await client.get(old, headers=auth, allow_redirects=False)
                ).status == 404
            for method, suffix in (
                ("put", "entry"),
                ("post", "users"),
                ("post", "users/trial/rename"),
                ("post", "users/trial/revoke"),
            ):
                assert (
                    await client.request(method, "/admin/" + suffix, headers=auth)
                ).status == 404
            for new in ("/ops/mower/", "/ops/mower/admin_ui.js"):
                assert (await client.get(new, headers=host)).status == 200
            for token in ("", "Bearer wrong", "Bearer " + credential):
                assert (
                    await client.get(
                        "/ops/mower/users", headers={**host, "Authorization": token}
                    )
                ).status == 403
            assert (
                await client.get(
                    "/ops/mower/users",
                    headers={**auth, "Host": "trial.free.mower.work:58000"},
                )
            ).status == 404
        async with TestClient(TestServer(app())) as client:
            assert (await client.get("/ops/mower/", headers=host)).status == 200
            assert (await client.get("/admin/users", headers=auth)).status == 404
            saved = await client.get("/ops/mower/entry", headers=auth)
            assert await saved.json() == {"path": "/ops/mower/"}
            async with client.ws_connect(
                "/__mower/connect",
                headers={**host, "Authorization": "Bearer " + credential},
            ) as peer:
                await peer.send_json(
                    {"op": "hello", "version": 1, "ui_build": "a" * 64}
                )
                assert (await peer.receive_json(timeout=2))["subdomain"] == "trial"
                online = await client.get("/ops/mower/users/trial", headers=auth)
                assert (await online.json())["connected"] is True
            users = "/ops/mower/users"
            status = await client.get(users + "/trial", headers=auth)
            assert (await status.json())["enabled"] is True
            assert (
                await client.post(
                    users,
                    headers=auth,
                    json={"subdomain": "users", "subject": "second"},
                )
            ).status == 201
            assert (await client.get(users + "/users", headers=auth)).status == 200
            renamed = await client.post(
                users + "/trial/rename", headers=auth, json={"subdomain": "entry"}
            )
            assert renamed.status == 200
            revoked = await client.post(users + "/entry/revoke", headers=auth)
            assert (await revoked.json())["enabled"] is False

    asyncio.run(scenario())
