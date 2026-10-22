"""跨平台 Mower 专用 HTTPS/WSS 中转服务。"""

import argparse
import asyncio
import base64
import hashlib
import hmac
import json
import os
import secrets
import ssl
import time
from collections import OrderedDict
from pathlib import Path
from uuid import uuid4

from aiohttp import WSMsgType, web
from itsdangerous import BadSignature, URLSafeTimedSerializer

from mower_relay_server.admin_api import create_admin_app
from mower_relay_server.protocol import (
    DOMAIN,
    MAX_BODY,
    MAX_FRAME,
    MAX_PENDING,
    MAX_SOCKETS,
    PORT,
    SOCKETS,
    VERSION,
    allowed_request,
    decode_body,
    public_origin,
    response_kind,
    valid_subdomain,
    validate_response,
)

LOGIN = """<!doctype html><html lang="zh-CN"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>Mower 登录</title><body><main style="max-width:360px;margin:15vh auto;font-family:sans-serif"><h1>Mower 远程访问</h1><form method="post" action="/__mower/login"><p><input name="username" autocomplete="username" placeholder="本地设置的用户名" required maxlength="64"></p><p><input name="password" type="password" autocomplete="current-password" placeholder="本地设置的密码" required maxlength="256"></p><button>登录</button></form><p>登录信息由你的 Mower 实例验证。登录后仍需实例 token。</p></main></body></html>"""
COOKIE = "__Host-mower_relay"
GATEWAY = web.AppKey("gateway", object)


def html_navigation(request):
    if request.headers.get("Sec-Fetch-Dest", "") not in {"", "document", "iframe"}:
        return False
    for entry in request.headers.get("Accept", "").split(","):
        fields = [part.strip().lower() for part in entry.split(";")]
        if fields[0] != "text/html":
            continue
        quality = next((part[2:] for part in fields[1:] if part.startswith("q=")), "1")
        try:
            if 0 < float(quality) <= 1:
                return True
        except ValueError:
            pass
    return False


class Peer:
    def __init__(self, ws):
        self.ws = ws
        self.generation = secrets.token_hex(16)
        self.pending = {}
        self.sockets = {}
        self.window = time.monotonic()
        self.bytes = 0
        self.request_window = time.monotonic()
        self.requests = 0
        self.inflight = 0

    def charge(self, size):
        now = time.monotonic()
        if now - self.window >= 60:
            self.window, self.bytes = now, 0
        self.bytes += size
        if self.bytes > 64 * 1024 * 1024:
            raise web.HTTPTooManyRequests(text="每分钟流量超过限制")

    async def request(self, message, kind, timeout=30):
        if len(self.pending) >= MAX_PENDING:
            raise web.HTTPTooManyRequests()
        now = time.monotonic()
        if now - self.request_window >= 60:
            self.request_window, self.requests = now, 0
        self.requests += 1
        if self.requests > 600:
            raise web.HTTPTooManyRequests()
        key = uuid4().hex
        future = asyncio.get_running_loop().create_future()
        self.pending[key] = (kind, message, future)
        try:
            await asyncio.wait_for(self.ws.send_json({**message, "id": key}), 5)
            return await asyncio.wait_for(future, timeout)
        except (TimeoutError, ConnectionError):
            raise web.HTTPGatewayTimeout() from None
        finally:
            self.pending.pop(key, None)


class Gateway:
    def __init__(self, registry, ui, session_key):
        self.registry = Path(registry)
        self.ui = Path(ui).resolve()
        if len(session_key) < 32:
            raise ValueError("网关会话密钥至少需要 32 个字符")
        self.signer = URLSafeTimedSerializer(session_key, salt="mower-relay-v1")
        self.peers = {}
        self.failures = OrderedDict()
        manifest = self.ui / "frontend-routes.json"
        self.pages = {
            path.rstrip("/").lower() or "/"
            for path in json.loads(manifest.read_text("utf-8"))
        }

    def users(self):
        try:
            data = json.loads(self.registry.read_text("utf-8"))
        except (OSError, ValueError):
            raise web.HTTPServiceUnavailable(text="审核名单不可用") from None
        if not isinstance(data, dict):
            raise web.HTTPServiceUnavailable()
        return data

    def admitted(self, name, credential=None):
        record = self.users().get(name)
        if not isinstance(record, dict) or record.get("enabled") is not True:
            raise web.HTTPForbidden()
        expected = record.get("credential_sha256", "")
        if credential is not None and not hmac.compare_digest(
            hashlib.sha256(credential.encode()).hexdigest(), expected
        ):
            raise web.HTTPForbidden()
        return expected

    def tenant(self, request):
        host = request.host.lower()
        suffix = f".{DOMAIN}:{PORT}"
        if not host.endswith(suffix):
            raise web.HTTPNotFound()
        name = host[: -len(suffix)]
        if not valid_subdomain(name):
            raise web.HTTPNotFound()
        self.admitted(name)
        return name

    def peer(self, name):
        peer = self.peers.get(name)
        if peer is None or peer.ws.closed:
            raise web.HTTPServiceUnavailable(text="Mower 实例未连接")
        return peer

    def same_origin(self, request, name):
        if request.headers.get("Origin") != public_origin(name):
            raise web.HTTPForbidden()

    def authenticated(self, request, name, peer):
        try:
            value = self.signer.loads(request.cookies.get(COOKIE, ""), max_age=8 * 3600)
        except BadSignature:
            return False
        return value == {"tenant": name, "connection": peer.generation}

    async def connect(self, request):
        if request.host.lower() != f"{DOMAIN}:{PORT}":
            raise web.HTTPNotFound()
        name = request.headers.get("X-Mower-Subdomain", "")
        if not valid_subdomain(name):
            raise web.HTTPForbidden()
        header = request.headers.get("Authorization", "")
        if not header.startswith("Bearer ") or len(header) > 512:
            raise web.HTTPForbidden()
        digest = self.admitted(name, header[7:])
        if name in self.peers:
            raise web.HTTPConflict(text="实例已经连接")
        # Reserve the domain before the first await to prevent duplicate admission.
        ws = web.WebSocketResponse(heartbeat=20, max_msg_size=MAX_FRAME, compress=False)
        peer = Peer(ws)
        self.peers[name] = peer
        try:
            await ws.prepare(request)
            hello = await ws.receive_json(timeout=10)
            if hello != {"op": "hello", "version": VERSION}:
                raise ValueError("协议版本无效")
            await ws.send_json({"op": "ready", "version": VERSION})
            async for frame in ws:
                if frame.type != WSMsgType.TEXT:
                    break
                if self.admitted(name) != digest:
                    break
                peer.charge(len(frame.data.encode()))
                message = json.loads(frame.data)
                key, op = message.get("id"), message.get("op")
                if op in {"response", "authenticated", "error"} and key in peer.pending:
                    kind, original, future = peer.pending[key]
                    if future.done():
                        continue
                    if op == "error":
                        future.set_exception(ConnectionError())
                    elif (
                        kind == "login"
                        and op == "authenticated"
                        and type(message.get("ok")) is bool
                    ):
                        future.set_result(message["ok"])
                    elif kind == "http" and op == "response":
                        body = decode_body(message.get("body"))
                        validate_response(
                            original["path"],
                            message.get("status"),
                            message.get("mime"),
                            body,
                        )
                        future.set_result((message["status"], message["mime"], body))
                    else:
                        raise ValueError("响应类型无效")
                elif op in {"ws_data", "ws_close"} and key in peer.sockets:
                    socket = peer.sockets[key]
                    if op == "ws_close":
                        await socket.close()
                    elif (
                        isinstance(message.get("data"), str)
                        and len(message["data"].encode()) <= 65536
                    ):
                        await asyncio.wait_for(socket.send_str(message["data"]), 5)
                    else:
                        raise ValueError("消息大小无效")
                elif op not in {
                    "response",
                    "authenticated",
                    "error",
                    "ws_data",
                    "ws_close",
                }:
                    raise ValueError("非预期消息")
        except (
            ValueError,
            TypeError,
            TimeoutError,
            ConnectionError,
            web.HTTPException,
        ):
            pass
        finally:
            if self.peers.get(name) is peer:
                self.peers.pop(name, None)
            for _, _, future in peer.pending.values():
                if not future.done():
                    future.set_exception(ConnectionError())
            for socket in list(peer.sockets.values()):
                await socket.close()
            await ws.close()
        return ws

    async def login(self, request, name, peer):
        self.same_origin(request, name)
        now = time.monotonic()
        attempts = [value for value in self.failures.get(name, []) if now - value < 60]
        if len(attempts) >= 5:
            raise web.HTTPTooManyRequests(text="登录尝试过多，请一分钟后重试")
        attempts.append(now)
        self.failures[name] = attempts
        self.failures.move_to_end(name)
        while len(self.failures) > 2048:
            self.failures.popitem(last=False)
        data = await request.post()
        username, password = data.get("username"), data.get("password")
        if (
            not isinstance(username, str)
            or not isinstance(password, str)
            or len(username) > 64
            or len(password) > 256
        ):
            raise web.HTTPBadRequest()
        ok = await peer.request(
            {"op": "authenticate", "username": username, "password": password},
            "login",
            timeout=15,
        )
        if not ok:
            return web.Response(text="用户名或密码错误", status=401)
        response = web.Response(status=303, headers={"Location": "/"})
        response.set_cookie(
            COOKIE,
            self.signer.dumps({"tenant": name, "connection": peer.generation}),
            secure=True,
            httponly=True,
            samesite="Strict",
            max_age=8 * 3600,
            path="/",
        )
        return response

    async def handle(self, request):
        name = self.tenant(request)
        peer = self.peer(name)
        if request.path == "/__mower/login" and request.method == "POST":
            return await self.login(request, name, peer)
        if not self.authenticated(request, name, peer):
            if request.method == "GET" and html_navigation(request):
                return web.Response(text=LOGIN, content_type="text/html")
            raise web.HTTPUnauthorized()
        if (
            request.method not in {"GET", "HEAD"}
            or request.headers.get("Upgrade", "").lower() == "websocket"
        ):
            self.same_origin(request, name)
        if request.path == "/__mower/logout" and request.method == "POST":
            response = web.Response(status=303, headers={"Location": "/"})
            response.del_cookie(
                COOKIE, path="/", secure=True, httponly=True, samesite="Strict"
            )
            return response
        if (
            request.path in SOCKETS
            and request.headers.get("Upgrade", "").lower() == "websocket"
        ):
            if len(peer.sockets) >= MAX_SOCKETS:
                raise web.HTTPTooManyRequests()
            socket = web.WebSocketResponse(
                heartbeat=20, max_msg_size=65536, compress=False
            )
            key = uuid4().hex
            peer.sockets[key] = socket
            try:
                await socket.prepare(request)
                await peer.ws.send_json(
                    {"op": "ws_open", "id": key, "path": request.path}
                )
                async for frame in socket:
                    self.admitted(name)
                    if frame.type != WSMsgType.TEXT:
                        break
                    peer.charge(len(frame.data.encode()))
                    await peer.ws.send_json(
                        {"op": "ws_data", "id": key, "data": frame.data}
                    )
            finally:
                peer.sockets.pop(key, None)
                if not peer.ws.closed:
                    await peer.ws.send_json({"op": "ws_close", "id": key})
            return socket
        if request.method in {"GET", "HEAD"}:
            if (
                request.path == "/"
                or request.path.rstrip("/").lower() in self.pages
                and html_navigation(request)
            ):
                return web.FileResponse(self.ui / "index.html")
            if not allowed_request(request.method, request.path):
                path = (self.ui / request.path.lstrip("/")).resolve()
                if path.is_relative_to(self.ui) and path.is_file():
                    return web.FileResponse(path)
                raise web.HTTPNotFound()
        if not allowed_request(request.method, request.path_qs):
            raise web.HTTPNotFound()
        if peer.inflight >= MAX_PENDING:
            raise web.HTTPTooManyRequests()
        peer.inflight += 1
        try:
            body = await request.read()
            peer.charge(len(body))
            status, mime, result = await peer.request(
                {
                    "op": "request",
                    "method": request.method,
                    "path": request.path_qs,
                    "headers": {
                        key: request.headers[key]
                        for key in ("token", "content-type")
                        if key in request.headers
                    },
                    "body": base64.b64encode(body).decode(),
                },
                "http",
            )
        finally:
            peer.inflight -= 1
        response = web.Response(body=result, status=status, content_type=mime)
        if response_kind(request.path) == "attachment":
            response.headers["Content-Type"] = "application/octet-stream"
            response.headers["Content-Disposition"] = (
                'attachment; filename="mower-export.bin"'
            )
        return response


def create_app(registry, ui, session_key, admin_token):
    gateway = Gateway(registry, ui, session_key)
    traffic = OrderedDict()

    @web.middleware
    async def entry_limit(request, handler):
        now = time.monotonic()
        address = request.remote
        tokens, previous = traffic.get(address, (40, now))
        tokens = min(40, tokens + (now - previous) * 20)
        allowed = tokens >= 1
        traffic[address] = (tokens - 1 if allowed else tokens, now)
        traffic.move_to_end(address)
        while len(traffic) > 4096:
            traffic.popitem(last=False)
        if not allowed:
            raise web.HTTPTooManyRequests()
        return await handler(request)

    @web.middleware
    async def headers(request, handler):
        try:
            response = await handler(request)
        except web.HTTPException as exc:
            response = web.Response(
                status=exc.status, text=exc.text, headers=exc.headers
            )
        if not response.prepared:
            if request.path.rstrip("/").lower() in gateway.pages:
                response.headers["Vary"] = "Accept, Sec-Fetch-Dest"
            response.headers.update(
                {
                    "Cache-Control": "no-store",
                    "X-Content-Type-Options": "nosniff",
                    "Referrer-Policy": "same-origin",
                    "X-Frame-Options": "DENY",
                }
            )
        return response

    app = web.Application(client_max_size=MAX_BODY, middlewares=[headers, entry_limit])
    app[GATEWAY] = gateway
    app.add_subapp("/admin", create_admin_app(gateway, admin_token))
    app.router.add_get("/__mower/connect", gateway.connect)
    app.router.add_route("*", "/{path:.*}", gateway.handle)

    async def shutdown(app):
        await asyncio.gather(
            *(peer.ws.close() for peer in list(gateway.peers.values()))
        )

    app.on_shutdown.append(shutdown)
    return app


def create_tls_context(cert_file, key_file):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(cert_file, key_file, password="")
    return context


def read_or_create_secret(path):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        with open(
            path,
            "x",
            encoding="utf-8",
            opener=lambda name, flags: os.open(name, flags, 0o600),
        ) as stream:
            stream.write(secrets.token_urlsafe(48))
    except FileExistsError:
        pass
    return path.read_text("utf-8").strip()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--work-dir", type=Path, default=Path.cwd())
    parser.add_argument("--registry", type=Path)
    parser.add_argument("--ui", type=Path)
    parser.add_argument("--session-key-file", type=Path)
    parser.add_argument("--admin-token-file", type=Path)
    parser.add_argument("--cert-file", type=Path)
    parser.add_argument("--key-file", type=Path)
    parser.add_argument("--bind", default="0.0.0.0")
    args = parser.parse_args()
    work_dir = args.work_dir.resolve()

    def location(value, default):
        return (work_dir / (value if value is not None else default)).resolve()

    tls_context = create_tls_context(
        location(args.cert_file, "certificates/free.mower.work.crt"),
        location(args.key_file, "certificates/free.mower.work.key"),
    )
    app = create_app(
        location(args.registry, "data/users.json"),
        location(args.ui, "ui-dist"),
        read_or_create_secret(location(args.session_key_file, "data/session-key.txt")),
        read_or_create_secret(location(args.admin_token_file, "data/admin-token.txt")),
    )
    # 页面查询参数可能含实例 token，关闭访问日志。
    web.run_app(
        app,
        host=args.bind,
        port=PORT,
        ssl_context=tls_context,
        access_log=None,
        print=None,
    )


if __name__ == "__main__":
    main()
