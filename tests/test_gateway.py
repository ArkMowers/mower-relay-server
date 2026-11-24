"""Offline admission, local authentication and Mower-only transport checks."""

import asyncio
import base64
import hashlib
import json
import sqlite3
import ssl
from datetime import datetime, timedelta, timezone
from ipaddress import ip_address
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from aiohttp import ClientSession, TCPConnector, WSMsgType, WSServerHandshakeError
from aiohttp.test_utils import TestClient, TestServer
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from mower_relay_server.admin import issue, revoke
from mower_relay_server.protocol import (
    MAX_BODY,
    allowed_request,
    public_origin,
    validate_response,
)
from mower_relay_server.registry import Registry
from mower_relay_server.server import COOKIE, GATEWAY, create_app, create_tls_context


@pytest.mark.parametrize(
    "method,path",
    [
        ("CONNECT", "/status"),
        ("GET", "http://127.0.0.1/status"),
        ("GET", "//evil.test/status"),
        ("GET", "/status#fragment"),
        ("GET", "/relay/settings"),
        ("GET", "/assets/evil.js"),
        ("GET", "/screenshots/../secret.png"),
        ("GET", "/screenshots/%2e%2e/secret.png"),
        ("POST", "/__mower/connect"),
    ],
)
def test_generic_proxy_and_local_management_paths_are_absent(method, path):
    assert not allowed_request(method, path)


def test_conversation_routes_match_only_the_supported_operations():
    item = "/ai/conversations/" + "a" * 32
    routes = {
        "/ai/conversations": {"GET", "DELETE"},
        item: {"GET", "DELETE"},
        item + "/summary": {"POST"},
        item + "/turns/12/control": {"POST"},
        item + "/turns/x/control": set(),
        item + "/turns/12": set(),
        item + "/settings": set(),
        "/ai/conversations/unknown": set(),
        "/ai/attachments": set(),
    }
    for path, allowed in routes.items():
        assert {
            m
            for m in ("GET", "POST", "DELETE", "PUT", "PATCH")
            if allowed_request(m, path)
        } == allowed


def test_relay_rejects_remote_web_content_and_oversized_responses():
    for mime, content in (
        ("text/html", b"<html>other site</html>"),
        ("application/javascript", b"alert(1)"),
        ("image/svg+xml", b"<svg/>"),
    ):
        with pytest.raises(ValueError):
            validate_response("/status", 200, mime, content)
    with pytest.raises(ValueError):
        validate_response("/latest-screenshot", 200, "image/jpeg", b"not an image")
    with pytest.raises(ValueError):
        validate_response("/status", 200, "text/plain", b"a" * (MAX_BODY + 1))


def fixture_gateway(tmp_path):
    ui = tmp_path / "ui"
    ui.mkdir()
    (ui / "index.html").write_text("<h1>Official Mower</h1>")
    (ui / "frontend-routes.json").write_text('["/settings"]')
    registry = tmp_path / "users.sqlite3"
    credential = issue(registry, "alice", subject="qq:alice")
    app = create_app(registry, ui, "s" * 48, "a" * 48)
    return app, registry, credential


@pytest.fixture
def tls_files(tmp_path):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "free.mower.work")])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(
            x509.SubjectAlternativeName(
                [
                    x509.DNSName("free.mower.work"),
                    x509.DNSName("*.free.mower.work"),
                    x509.IPAddress(ip_address("127.0.0.1")),
                ]
            ),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    cert_file = tmp_path / "certificate.pem"
    key_file = tmp_path / "private-key.pem"
    cert_file.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_file.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return cert_file, key_file


@pytest.mark.parametrize("failure", [None, "missing", "invalid", "mismatched"])
def test_entry_loads_certificate_before_starting_one_https_listener(
    tmp_path, tls_files, monkeypatch, failure
):
    from mower_relay_server import server

    cert_file, key_file = tls_files
    if failure == "missing":
        cert_file.unlink()
    elif failure == "invalid":
        cert_file.write_text("invalid certificate")
    elif failure == "mismatched":
        key_file.write_bytes(
            rsa.generate_private_key(
                public_exponent=65537, key_size=2048
            ).private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
    ui = tmp_path / "ui"
    ui.mkdir()
    (ui / "frontend-routes.json").write_text("[]")
    session_file, admin_file = tmp_path / "session.txt", tmp_path / "admin.txt"
    session_file.write_text("s" * 48)
    admin_file.write_text("a" * 48)
    registry = tmp_path / "users.sqlite3"
    monkeypatch.setattr(
        "sys.argv",
        [
            "mower-relay",
            "--registry",
            str(registry),
            "--ui",
            str(ui),
            "--session-key-file",
            str(session_file),
            "--admin-token-file",
            str(admin_file),
            "--cert-file",
            str(cert_file),
            "--key-file",
            str(key_file),
        ],
    )
    run = Mock()
    monkeypatch.setattr(server.web, "run_app", run)
    if failure:
        with pytest.raises((OSError, ssl.SSLError)):
            server.main()
        run.assert_not_called()
        assert not registry.exists()
    else:
        server.main()
        run.assert_called_once()
        options = run.call_args.kwargs
        assert options["host"] == "0.0.0.0" and options["port"] == 58000
        assert options["ssl_context"].minimum_version == ssl.TLSVersion.TLSv1_2
        assert options["access_log"] is None


def test_work_directory_initializes_separate_secrets_and_preserves_them(
    tmp_path, tls_files, monkeypatch
):
    from mower_relay_server import server

    cert_file, key_file = tls_files
    certificates = tmp_path / "certificates"
    certificates.mkdir()
    (certificates / "free.mower.work.crt").write_bytes(cert_file.read_bytes())
    (certificates / "free.mower.work.key").write_bytes(key_file.read_bytes())
    ui = tmp_path / "ui-dist"
    ui.mkdir()
    (ui / "frontend-routes.json").write_text("[]")
    monkeypatch.setattr("sys.argv", ["mower-relay-server", "--work-dir", str(tmp_path)])
    run = Mock()
    monkeypatch.setattr(server.web, "run_app", run)
    server.main()
    data = tmp_path / "data"
    session = (data / "session-key.txt").read_bytes()
    admin = (data / "admin-token.txt").read_bytes()
    assert len(session) >= 48 and len(admin) >= 48 and session != admin
    server.main()
    assert run.call_count == 2
    assert (data / "session-key.txt").read_bytes() == session
    assert (data / "admin-token.txt").read_bytes() == admin
    gateway = run.call_args.args[0][GATEWAY]
    assert gateway.registry.path == (data / "users.sqlite3").resolve()
    assert gateway.ui_origin == "https://mower.231240092.xyz"


def test_https_bot_and_wss_agent_share_one_tls_listener(tmp_path, tls_files):
    async def scenario():
        app, _, credential = fixture_gateway(tmp_path)
        cert_file, key_file = tls_files
        listener = TestServer(app)
        await listener.start_server(ssl=create_tls_context(cert_file, key_file))
        trusted = ssl.create_default_context(cafile=str(cert_file))
        async with TestClient(listener, connector=TCPConnector(ssl=trusted)) as bot:
            assert bot.make_url("/").scheme == "https"
            headers = {
                "Host": "free.mower.work:58000",
                "Authorization": f"Bearer {'a' * 48}",
            }
            async with bot.ws_connect(
                "/__mower/connect",
                headers={
                    "Host": headers["Host"],
                    "Authorization": f"Bearer {credential}",
                },
            ) as agent:
                await agent.send_json(
                    {"op": "hello", "version": 1, "ui_build": "a" * 64}
                )
                assert await agent.receive_json(timeout=2) == {
                    "op": "ready",
                    "subdomain": "alice",
                    "ui_build": "a" * 64,
                    "version": 1,
                }
                status = await bot.get("/admin/users/alice", headers=headers)
                assert status.status == 200 and (await status.json())["connected"]
                revoked = await bot.post("/admin/users/alice/revoke", headers=headers)
                assert revoked.status == 200
                assert (await agent.receive(timeout=2)).type in {
                    WSMsgType.CLOSE,
                    WSMsgType.CLOSED,
                }

    asyncio.run(scenario())


def test_missing_build_and_ambiguous_credential_are_rejected(tmp_path):
    async def scenario():
        app, registry, credential = fixture_gateway(tmp_path)
        headers = {
            "Host": "free.mower.work:58000",
            "Authorization": f"Bearer {credential}",
        }
        async with TestClient(TestServer(app)) as browser:
            async with browser.ws_connect("/__mower/connect", headers=headers) as agent:
                await agent.send_json({"op": "hello", "version": 1})
                assert (await agent.receive(timeout=2)).type == WSMsgType.CLOSE
            with (
                pytest.raises(sqlite3.IntegrityError),
                Registry(registry).transaction(write=True) as db,
            ):
                db.execute(
                    "INSERT INTO users SELECT 'bob', '', 1, credential_sha256 FROM users WHERE subdomain='alice'"
                )
            assert not app[GATEWAY].peers

    asyncio.run(scenario())


def test_direct_entry_limits_requests_and_admin_body_before_writes(
    tmp_path, monkeypatch
):
    from mower_relay_server import server

    async def scenario():
        app, registry, _ = fixture_gateway(tmp_path)
        headers = {
            "Host": "free.mower.work:58000",
            "Authorization": f"Bearer {'a' * 48}",
        }
        now = [100.0]
        monkeypatch.setattr(server, "time", SimpleNamespace(monotonic=lambda: now[0]))
        async with TestClient(TestServer(app)) as browser:
            before = registry.read_bytes()
            assert (
                await browser.post("/admin/users", headers=headers, data="a" * 4097)
            ).status == 413

            async def chunks():
                yield b"a" * 2048
                yield b"a" * 2049

            assert (
                await browser.post("/admin/users", headers=headers, data=chunks())
            ).status == 413
            assert registry.read_bytes() == before
            for _ in range(38):
                assert (
                    await browser.get("/admin/users", headers=headers)
                ).status == 200
            assert (await browser.get("/admin/users", headers=headers)).status == 429
            now[0] += 1
            for _ in range(20):
                assert (
                    await browser.get("/admin/users", headers=headers)
                ).status == 200
            assert (await browser.get("/admin/users", headers=headers)).status == 429

    asyncio.run(scenario())


def test_gateway_requires_individual_admission_and_local_login_before_http(tmp_path):
    async def scenario():
        app, registry, credential = fixture_gateway(tmp_path)
        gateway = app[GATEWAY]
        async with TestClient(TestServer(app)) as browser, ClientSession() as transport:
            connect_url = str(browser.make_url("/__mower/connect")).replace(
                "http:", "ws:"
            )
            for secret in ("", "wrong"):
                with pytest.raises(WSServerHandshakeError) as caught:
                    await transport.ws_connect(
                        connect_url,
                        headers={
                            "Host": "free.mower.work:58000",
                            "Authorization": f"Bearer {secret}",
                        },
                    )
                assert caught.value.status == 403
            async with transport.ws_connect(
                connect_url,
                headers={
                    "Host": "free.mower.work:58000",
                    "Authorization": f"Bearer {credential}",
                },
            ) as agent:
                build = "a" * 64
                await agent.send_json({"op": "hello", "version": 1, "ui_build": build})
                assert await agent.receive_json(timeout=2) == {
                    "op": "ready",
                    "version": 1,
                    "subdomain": "alice",
                    "ui_build": build,
                }
                with pytest.raises(WSServerHandshakeError) as duplicate:
                    await transport.ws_connect(
                        connect_url,
                        headers={
                            "Host": "free.mower.work:58000",
                            "Authorization": f"Bearer {credential}",
                        },
                    )
                assert duplicate.value.status == 409
                host = {"Host": "alice.free.mower.work:58000"}
                challenge = await browser.get(
                    "/", headers={**host, "Accept": "text/html"}
                )
                assert challenge.status == 401
                assert (
                    await browser.get(
                        "/",
                        headers={
                            **host,
                            "Accept": "text/html",
                            "Sec-Fetch-Site": "cross-site",
                        },
                    )
                ).status == 401
                assert (
                    await browser.get(
                        "/", headers={**host, "Authorization": "Basic !!!"}
                    )
                ).status == 401
                assert (
                    challenge.headers["WWW-Authenticate"]
                    == 'Basic realm="Mower", charset="UTF-8"'
                )
                password = "短:" + "长" * 300
                basic = base64.b64encode(f"Alice:{password}".encode()).decode()
                login_task = asyncio.create_task(
                    browser.get(
                        "/", headers={**host, "Authorization": f"Basic {basic}"}
                    )
                )
                auth = await agent.receive_json(timeout=2)
                assert auth["op"] == "authenticate"
                assert auth["username"] == "Alice" and auth["password"] == password
                await agent.send_json(
                    {"op": "authenticated", "id": auth["id"], "ok": True}
                )
                response = await login_task
                assert response.status == 200
                cookie = response.cookies[COOKIE]
                assert (
                    cookie["secure"]
                    and cookie["httponly"]
                    and cookie["samesite"] == "Strict"
                )
                headers = {**host, "Cookie": f"{COOKIE}={cookie.value}"}
                home = await browser.get("/", headers=headers)
                shell = await home.text()
                assert "https://mower.231240092.xyz" in shell and build in shell
                assert (
                    await browser.get("/assets/demo.js", headers=headers)
                ).status == 404
                assert (
                    await browser.get(
                        "/settings", headers={**headers, "Accept": "text/html"}
                    )
                ).status == 200
                assert (
                    await browser.get("/not-a-mower-operation", headers=headers)
                ).status == 404
                request_task = asyncio.create_task(
                    browser.get(
                        "/status", headers={**headers, "token": "local-instance-token"}
                    )
                )
                operation = await agent.receive_json(timeout=2)
                assert operation["op"] == "request" and operation["path"] == "/status"
                assert operation["headers"]["token"] == "local-instance-token"
                await agent.send_json(
                    {
                        "op": "response",
                        "id": operation["id"],
                        "status": 200,
                        "mime": "application/json",
                        "body": base64.b64encode(b'{"status":"stopped"}').decode(),
                    }
                )
                result = await request_task
                assert (
                    result.status == 200
                    and (await result.json())["status"] == "stopped"
                )
                # A response cannot manufacture a session: only the pending login id accepts an auth result.
                await agent.send_json(
                    {"op": "authenticated", "id": "unsolicited", "ok": True}
                )
                assert (await browser.get("/", headers=host)).status == 401
                revoke(registry, "alice")
                assert (await browser.get("/status", headers=headers)).status == 403
        assert not gateway.peers

    asyncio.run(scenario())


def test_admin_api_authentication_subject_queries_and_revocation(tmp_path, monkeypatch):
    async def scenario():
        app, registry, credential = fixture_gateway(tmp_path)
        headers = {
            "Host": "free.mower.work:58000",
            "Authorization": f"Bearer {'a' * 48}",
        }
        async with TestClient(TestServer(app)) as bot:
            before = registry.read_bytes()
            with monkeypatch.context() as scoped:
                users = Mock(side_effect=AssertionError("未鉴权时不能读取注册文件"))
                scoped.setattr(app[GATEWAY].registry, "transaction", users)
                for host in (
                    "alice.free.mower.work:58000",
                    "free.mower.work:58002",
                    "other.example:58000",
                ):
                    assert (
                        await bot.post(
                            "/admin/users", headers={**headers, "Host": host}, data="{"
                        )
                    ).status == 404
                for secret in (None, "Bearer wrong", f"Bearer {credential}"):
                    unauthenticated = {"Host": headers["Host"]}
                    if secret is not None:
                        unauthenticated["Authorization"] = secret
                    for method, path in (
                        ("get", "/admin/users"),
                        ("get", "/admin/users/alice"),
                        ("post", "/admin/users"),
                        ("post", "/admin/users/alice/revoke"),
                        ("post", "/admin/users/alice/rename"),
                    ):
                        assert (
                            await getattr(bot, method)(
                                path, headers=unauthenticated, data="{"
                            )
                        ).status == 403
                users.assert_not_called()
            assert registry.read_bytes() == before
            result = await bot.post(
                "/admin/users",
                headers=headers,
                json={"subdomain": "bob", "subject": "qq:bob"},
            )
            assert result.status == 201
            issued = await result.json()
            assert len(issued["credential"]) >= 48
            record = Registry(registry).get("bob")
            assert (
                record["credential_sha256"]
                == hashlib.sha256(issued["credential"].encode()).hexdigest()
            )
            assert issued["credential"].encode() not in registry.read_bytes()
            assert (
                await bot.post(
                    "/admin/users",
                    headers=headers,
                    json={"subdomain": "other", "subject": "qq:bob"},
                )
            ).status == 409
            query = await (
                await bot.get("/admin/users?subject=qq:bob", headers=headers)
            ).json()
            assert query["total"] == 1 and query["users"][0]["subdomain"] == "bob"
            assert "credential" not in json.dumps(query)
            detail = await (await bot.get("/admin/users/bob", headers=headers)).json()
            assert detail == query["users"][0]
            assert (
                await bot.post("/admin/users/bob/revoke", headers=headers)
            ).status == 200
            assert not Registry(registry).get("bob")["enabled"]

    asyncio.run(scenario())


def test_sessions_are_bound_to_tenant_and_connection_and_login_is_limited(tmp_path):
    from mower_relay_server.server import Peer

    async def scenario():
        app, registry, _ = fixture_gateway(tmp_path)
        issue(registry, "bob", subject="qq:bob")
        gateway = app[GATEWAY]
        alice = Peer(Mock(closed=False), await gateway.admitted("alice"))
        alice.ui_build = "a" * 64
        bob = Peer(Mock(closed=False), await gateway.admitted("bob"))
        bob.ui_build = "b" * 64
        gateway.peers.update(alice=alice, bob=bob)
        signed = gateway.signer.dumps(
            {"tenant": "alice", "connection": alice.generation}
        )
        headers = {
            "Host": "alice.free.mower.work:58000",
            "Cookie": f"{COOKIE}={signed}",
        }
        try:
            async with TestClient(TestServer(app)) as browser:
                assert (await browser.get("/", headers=headers)).status == 200
                assert (
                    await browser.get(
                        "/", headers={**headers, "Host": "bob.free.mower.work:58000"}
                    )
                ).status == 401
                gateway.peers["alice"] = Peer(
                    Mock(closed=False), await gateway.admitted("alice")
                )
                gateway.peers["alice"].ui_build = "a" * 64
                assert (await browser.get("/", headers=headers)).status == 401
                gateway.failures["alice"] = [asyncio.get_running_loop().time()] * 5
                limited = await browser.get(
                    "/",
                    headers={"Host": headers["Host"], "Authorization": "Basic YTpi"},
                )
                assert limited.status == 429
                assert not gateway.peers["alice"].pending
                # Test peers have no real transport to close during app cleanup.
                gateway.peers.clear()
        finally:
            gateway.peers.clear()

    asyncio.run(scenario())


def test_gateway_does_not_serve_html_supplied_by_an_admitted_client(tmp_path):
    async def scenario():
        app, registry, credential = fixture_gateway(tmp_path)
        async with TestClient(TestServer(app)) as browser, ClientSession() as transport:
            url = str(browser.make_url("/__mower/connect")).replace("http:", "ws:")
            async with transport.ws_connect(
                url,
                headers={
                    "Host": "free.mower.work:58000",
                    "Authorization": f"Bearer {credential}",
                },
            ) as agent:
                await agent.send_json(
                    {"op": "hello", "version": 1, "ui_build": "a" * 64}
                )
                await agent.receive_json(timeout=2)
                peer = app[GATEWAY].peers["alice"]
                signed = app[GATEWAY].signer.dumps(
                    {"tenant": "alice", "connection": peer.generation}
                )
                headers = {
                    "Host": "alice.free.mower.work:58000",
                    "Cookie": f"{COOKIE}={signed}",
                }
                pending = asyncio.create_task(browser.get("/status", headers=headers))
                operation = await agent.receive_json(timeout=2)
                await agent.send_json(
                    {
                        "op": "response",
                        "id": operation["id"],
                        "status": 200,
                        "mime": "text/html",
                        "body": base64.b64encode(b"<html>free hosting</html>").decode(),
                    }
                )
                result = await asyncio.wait_for(pending, 2)
                assert result.status == 504
                assert "free hosting" not in await result.text()

    asyncio.run(scenario())


def test_gateway_rejects_concurrency_and_traffic_excess_before_dispatch(tmp_path):
    from mower_relay_server.server import Peer

    async def scenario():
        app, _, _ = fixture_gateway(tmp_path)
        gateway = app[GATEWAY]
        peer = Peer(Mock(closed=False), await gateway.admitted("alice"))
        peer.ui_build = "a" * 64
        gateway.peers["alice"] = peer
        signed = gateway.signer.dumps(
            {"tenant": "alice", "connection": peer.generation}
        )
        headers = {
            "Host": "alice.free.mower.work:58000",
            "Origin": public_origin("alice"),
            "Cookie": f"{COOKIE}={signed}",
        }
        async with TestClient(TestServer(app)) as browser:
            peer.inflight = 8
            assert (
                await browser.post("/plan", headers=headers, data=b"x")
            ).status == 429
            peer.inflight = 0
            peer.bytes = 64 * 1024 * 1024
            assert (
                await browser.post("/plan", headers=headers, data=b"x")
            ).status == 429
            assert not peer.pending and peer.inflight == 0
            peer.ws.send_json.assert_not_called()
            gateway.peers.clear()

    asyncio.run(scenario())


def test_concurrent_admin_processes_issue_a_subdomain_once(tmp_path):
    import subprocess
    import sys

    registry = tmp_path / "users.sqlite3"
    command = [
        sys.executable,
        "-m",
        "mower_relay_server.admin",
        "--registry",
        str(registry),
        "issue",
        "trial",
    ]
    processes = [
        subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        for _ in range(8)
    ]
    results = [process.communicate(timeout=30) for process in processes]
    issued = [
        out.strip()
        for process, (out, _) in zip(processes, results)
        if process.returncode == 0
    ]
    assert len(issued) == 1
    for process, (_, err) in zip(processes, results):
        if process.returncode:
            assert b"RegistryConflict" in err
    record = Registry(registry).get("trial")
    assert record["credential_sha256"] == hashlib.sha256(issued[0]).hexdigest()


def test_rename_keeps_credentials_and_moves_a_connected_agent(tmp_path):
    async def scenario():
        app, registry, credential = fixture_gateway(tmp_path)
        issue(registry, "taken", subject="qq:other")
        admin = {"Host": "free.mower.work:58000", "Authorization": "Bearer " + "a" * 48}
        auth = {**admin, "Authorization": f"Bearer {credential}"}
        hello = {"op": "hello", "version": 1, "ui_build": "a" * 64}
        async with TestClient(TestServer(app)) as api:

            async def change(name):
                return await api.post(
                    "/admin/users/alice/rename", headers=admin, json={"subdomain": name}
                )

            async with api.ws_connect("/__mower/connect", headers=auth) as old:
                await old.send_json(hello)
                assert (await old.receive_json())["subdomain"] == "alice"
                previous = dict(Registry(registry).get("alice"))
                before = registry.read_bytes()
                for action, payload in (
                    ("rename", {"subdomain": "new-name", "subject": "qq:other"}),
                    ("revoke", {"subject": "qq:other"}),
                ):
                    response = await api.post(
                        f"/admin/users/alice/{action}", headers=admin, json=payload
                    )
                    assert response.status == 409
                assert (await change("admin")).status == 400
                assert (await change("taken")).status == 409
                assert (await (await change("alice")).json())["connected"]
                assert registry.read_bytes() == before
                gateway = app[GATEWAY]
                cookie = gateway.signer.dumps(
                    {"tenant": "alice", "connection": gateway.peers["alice"].generation}
                )
                task = asyncio.create_task(change("new-name"))
                assert (await old.receive(timeout=3)).type == WSMsgType.CLOSE
                response = await task
                assert response.status == 200
                assert await response.json() == {
                    "subdomain": "new-name",
                    "subject": "qq:alice",
                    "enabled": True,
                    "connected": False,
                    "url": public_origin("new-name"),
                }
            assert dict(Registry(registry).get("new-name")) == {
                **previous,
                "subdomain": "new-name",
            }
            assert Registry(registry).get("alice") is None
            headers = {
                "Host": "alice.free.mower.work:58000",
                "Cookie": f"{COOKIE}={cookie}",
            }
            assert (await api.get("/", headers=headers)).status == 403
            async with api.ws_connect("/__mower/connect", headers=auth) as new:
                await new.send_json(hello)
                assert (await new.receive_json())["subdomain"] == "new-name"
                assert (
                    await api.get(
                        "/",
                        headers={**headers, "Host": "new-name.free.mower.work:58000"},
                    )
                ).status == 401
            assert (await change("another")).status == 404

    asyncio.run(scenario())


def test_relay_confirmed_device_start_methods():
    routes = {
        "/device/avd/start": {"POST"},
        "/device/redroid/start": {"POST"},
        "/device/genymotion/start": {"POST"},
        "/device/other/start": set(),
        "/device/avd/stop": set(),
    }
    for path, expected in routes.items():
        assert {
            method
            for method in ("HEAD", "GET", "POST", "PUT", "PATCH", "DELETE")
            if allowed_request(method, path)
        } == expected


def test_relay_maa_update_operation_methods():
    routes = {
        "/maa-update/info": {"GET"},
        "/maa-update/status": {"GET"},
        "/maa-update/check": set(),
        "/maa-update/start": set(),
        "/maa-resource-update/info": {"GET"},
        "/maa-resource-update/status": {"GET"},
        "/maa-resource-update/check": set(),
        "/maa-resource-update/start": set(),
        "/maa-other-update/info": set(),
        "/maa-update/mirrorchyan-status": set(),
    }
    for path, expected in routes.items():
        assert {
            method
            for method in ("HEAD", "GET", "POST", "PUT", "PATCH", "DELETE")
            if allowed_request(method, path)
        } == expected


def test_relay_copilot_library_methods():
    routes = {
        "/sss-copilot": {"GET", "POST"},
        "/maa-copilot": set(),
        "/maa-paradox": set(),
        "/other-copilot": set(),
        "/sss-copilot/" + "a" * 64: set(),
        "/maa-copilot/" + "a" * 64: set(),
        "/maa-paradox/" + "a" * 64: set(),
    }
    for path, expected in routes.items():
        assert {
            method
            for method in ("HEAD", "GET", "POST", "PUT", "PATCH", "DELETE")
            if allowed_request(method, path)
        } == expected
