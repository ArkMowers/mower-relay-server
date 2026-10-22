"""Offline admission, local authentication and Mower-only transport checks."""

import asyncio
import base64
import hashlib
import json
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
    registry = tmp_path / "users.json"
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
    registry = tmp_path / "users.json"
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
    assert gateway.registry == (data / "users.json").resolve()
    assert gateway.ui == ui.resolve()


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
                    "X-Mower-Subdomain": "alice",
                },
            ) as agent:
                await agent.send_json({"op": "hello", "version": 1})
                assert await agent.receive_json(timeout=2) == {
                    "op": "ready",
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
            for name, secret in (("alice", "wrong"), ("bob", credential)):
                with pytest.raises(WSServerHandshakeError) as caught:
                    await transport.ws_connect(
                        connect_url,
                        headers={
                            "Host": "free.mower.work:58000",
                            "X-Mower-Subdomain": name,
                            "Authorization": f"Bearer {secret}",
                        },
                    )
                assert caught.value.status == 403
            async with transport.ws_connect(
                connect_url,
                headers={
                    "Host": "free.mower.work:58000",
                    "X-Mower-Subdomain": "alice",
                    "Authorization": f"Bearer {credential}",
                },
            ) as agent:
                await agent.send_json({"op": "hello", "version": 1})
                assert await agent.receive_json(timeout=2) == {
                    "op": "ready",
                    "version": 1,
                }
                with pytest.raises(WSServerHandshakeError) as duplicate:
                    await transport.ws_connect(
                        connect_url,
                        headers={
                            "Host": "free.mower.work:58000",
                            "X-Mower-Subdomain": "alice",
                            "Authorization": f"Bearer {credential}",
                        },
                    )
                assert duplicate.value.status == 409
                host = {"Host": "alice.free.mower.work:58000"}
                assert (await browser.get("/status", headers=host)).status == 401
                assert (
                    await browser.post("/__mower/login", headers=host, data={})
                ).status == 403
                login_task = asyncio.create_task(
                    browser.post(
                        "/__mower/login",
                        headers={**host, "Origin": public_origin("alice")},
                        data={"username": "Alice", "password": "a-local-password"},
                        allow_redirects=False,
                    )
                )
                auth = await agent.receive_json(timeout=2)
                assert auth["op"] == "authenticate"
                assert (
                    auth["username"] == "Alice"
                    and auth["password"] == "a-local-password"
                )
                await agent.send_json(
                    {"op": "authenticated", "id": auth["id"], "ok": True}
                )
                response = await login_task
                assert response.status == 303
                cookie = response.cookies[COOKIE]
                assert (
                    cookie["secure"]
                    and cookie["httponly"]
                    and cookie["samesite"] == "Strict"
                )
                headers = {**host, "Cookie": f"{COOKIE}={cookie.value}"}
                home = await browser.get("/", headers=headers)
                assert await home.text() == "<h1>Official Mower</h1>"
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
                scoped.setattr(app[GATEWAY], "users", users)
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
            record = json.loads(registry.read_text())["bob"]
            assert (
                record["credential_sha256"]
                == hashlib.sha256(issued["credential"].encode()).hexdigest()
            )
            assert issued["credential"] not in registry.read_text()
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
            assert json.loads(registry.read_text())["bob"]["enabled"] is False

    asyncio.run(scenario())


def test_sessions_are_bound_to_tenant_and_connection_and_login_is_limited(tmp_path):
    from mower_relay_server.server import Peer

    async def scenario():
        app, registry, _ = fixture_gateway(tmp_path)
        issue(registry, "bob", subject="qq:bob")
        gateway = app[GATEWAY]
        alice = Peer(Mock(closed=False))
        bob = Peer(Mock(closed=False))
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
                gateway.peers["alice"] = Peer(Mock(closed=False))
                assert (await browser.get("/", headers=headers)).status == 401
                gateway.failures["alice"] = [asyncio.get_running_loop().time()] * 5
                limited = await browser.post(
                    "/__mower/login",
                    headers={"Host": headers["Host"], "Origin": public_origin("alice")},
                    data={"username": "guess", "password": "guess"},
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
                    "X-Mower-Subdomain": "alice",
                    "Authorization": f"Bearer {credential}",
                },
            ) as agent:
                await agent.send_json({"op": "hello", "version": 1})
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
        peer = Peer(Mock(closed=False))
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
