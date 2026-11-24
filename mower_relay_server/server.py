"""跨平台 Mower 专用 HTTPS/WSS 中转服务。"""

import argparse
import asyncio
import base64
import hashlib
import json
import logging
import os
import re
import secrets
import sqlite3
import ssl
import time
from collections import OrderedDict
from pathlib import Path
from urllib.parse import urlsplit
from uuid import uuid4

from aiohttp import WSMsgType, web
from itsdangerous import BadSignature, URLSafeTimedSerializer

from mower_relay_server.admin_api import install_admin_routes
from mower_relay_server.admin_entry import AdminEntry
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
from mower_relay_server.registry import (
    Registry,
    RegistryConflict,
    daily_usage,
    quota_day,
)

BUILD = re.compile(r"[a-f0-9]{64}")
DEFAULT_UI_ORIGIN = "https://mower.231240092.xyz"

DEFAULT_DAILY_QUOTA_MIB = 1024
logger = logging.getLogger(__name__)


class DailyQuotaExceeded(web.HTTPTooManyRequests):
    def __init__(self):
        super().__init__(text="当日中转流量已达上限，请在北京时间零点后重试")


BASIC_CHALLENGE = 'Basic realm="Mower", charset="UTF-8"'

INITIALIZING = Path(__file__).with_name("initializing.html")
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
    def __init__(self, ws, credential_digest, name, gateway):
        self.name = name
        self.gateway = gateway
        self.credential_digest = credential_digest
        self.ws = ws
        self.generation = secrets.token_hex(16)
        self.pending = {}
        self.sockets = {}
        self.window = time.monotonic()
        self.bytes = 0
        self.request_window = time.monotonic()
        self.requests = 0
        self.inflight = 0
        self.ui_build = None

    def charge(self, size):
        now = time.monotonic()
        if now - self.window >= 60:
            self.window, self.bytes = now, 0
        self.bytes += size
        if self.bytes > 64 * 1024 * 1024:
            raise web.HTTPTooManyRequests(text="每分钟流量超过限制")

    async def account(self, size):
        limit = self.gateway.daily_limit
        try:
            allowed, transition, used, day = await asyncio.to_thread(
                self.gateway.registry.charge_traffic,
                self.name,
                self.credential_digest,
                size,
                limit,
            )
        except RegistryConflict:
            raise web.HTTPForbidden() from None
        if transition:
            logger.warning(
                "中转日配额 %s | subdomain=%s day=%s used_bytes=%d limit_bytes=%d",
                transition,
                self.name,
                day,
                used,
                limit,
            )
        if not allowed:
            raise DailyQuotaExceeded()

    async def send(self, message):
        text = json.dumps(message, ensure_ascii=False, separators=(",", ":"))
        await self.account(len(text.encode("utf-8")))
        await self.ws.send_str(text)

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
            await asyncio.wait_for(self.send({**message, "id": key}), 5)
            return await asyncio.wait_for(future, timeout)
        except (TimeoutError, ConnectionError):
            raise web.HTTPGatewayTimeout() from None
        finally:
            self.pending.pop(key, None)


class Gateway:
    def __init__(self, registry, session_key, ui_origin, daily_quota_mib):
        if type(daily_quota_mib) is not int or not 1 <= daily_quota_mib < 2**43:
            raise ValueError("日配额须为正整数 MiB，且小于 2^43 MiB")
        self.daily_limit = daily_quota_mib * 1024**2
        self.registry = Registry(registry)
        if len(session_key) < 32:
            raise ValueError("网关会话密钥至少需要 32 个字符")
        self.signer = URLSafeTimedSerializer(session_key, salt="mower-relay-v1")
        self.peers = {}
        origin = urlsplit(ui_origin)
        if (
            origin.scheme != "https"
            or not origin.hostname
            or origin.username is not None
            or origin.path not in {"", "/"}
            or origin.query
            or origin.fragment
            or not re.fullmatch(r"[a-zA-Z0-9.-]+(?::[0-9]+)?", origin.netloc)
        ):
            raise ValueError("前端地址须为 HTTPS 域名")
        self.ui_origin = f"https://{origin.netloc}"
        self.shell = INITIALIZING.read_text("utf-8")
        self.failures = OrderedDict()

    async def admitted(self, name):
        record = await asyncio.to_thread(self.registry.get, name)
        if record is None or not record["enabled"]:
            raise web.HTTPForbidden()
        if daily_usage(record, quota_day())[1] == "limited":
            raise DailyQuotaExceeded()
        return record["credential_sha256"]

    def tenant(self, request):
        host = request.host.lower()
        suffix = f".{DOMAIN}:{PORT}"
        if not host.endswith(suffix):
            raise web.HTTPNotFound()
        name = host[: -len(suffix)]
        if not valid_subdomain(name):
            raise web.HTTPNotFound()
        return name

    async def peer(self, name):
        digest = await self.admitted(name)
        peer = self.peers.get(name)
        if (
            peer is None
            or peer.credential_digest != digest
            or peer.ws.closed
            or not peer.ui_build
        ):
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
        header = request.headers.get("Authorization", "")
        if not header.startswith("Bearer ") or not 7 < len(header) <= 512:
            raise web.HTTPForbidden()
        digest = hashlib.sha256(header[7:].encode()).hexdigest()
        name = await asyncio.to_thread(self.registry.identify, digest)
        if name is None:
            raise web.HTTPForbidden()
        if await self.admitted(name) != digest:
            raise web.HTTPForbidden()
        if name in self.peers:
            raise web.HTTPConflict(text="实例已经连接")
        # Reserve the domain before the first await to prevent duplicate admission.
        ws = web.WebSocketResponse(heartbeat=20, max_msg_size=MAX_FRAME, compress=False)
        peer = Peer(ws, digest, name, self)
        self.peers[name] = peer
        try:
            await ws.prepare(request)
            first = await ws.receive(timeout=10)
            if first.type == WSMsgType.BINARY:
                await peer.account(len(first.data))
            if first.type != WSMsgType.TEXT:
                raise ValueError("握手需要文本帧")
            await peer.account(len(first.data.encode("utf-8")))
            hello = json.loads(first.data)
            if (
                not isinstance(hello, dict)
                or hello.get("op") != "hello"
                or hello.get("version") != VERSION
            ):
                raise ValueError("协议版本无效")
            build = hello.get("ui_build")
            if not isinstance(build, str) or not BUILD.fullmatch(build):
                raise ValueError("前端构建标识无效")
            peer.ui_build = build
            await peer.send(
                {
                    "op": "ready",
                    "version": VERSION,
                    "subdomain": name,
                    "ui_build": build,
                }
            )
            async for frame in ws:
                if frame.type == WSMsgType.BINARY:
                    await peer.account(len(frame.data))
                if frame.type != WSMsgType.TEXT:
                    break
                size = len(frame.data.encode("utf-8"))
                peer.charge(size)
                await peer.account(size)
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
        except DailyQuotaExceeded:
            for _, _, future in peer.pending.values():
                if not future.done():
                    future.set_exception(DailyQuotaExceeded())
            await ws.close(code=1008, message=b"daily quota exceeded")
        except (
            ValueError,
            TypeError,
            TimeoutError,
            ConnectionError,
            sqlite3.Error,
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

    async def basic_login(self, request, name, peer):
        challenge = {"WWW-Authenticate": BASIC_CHALLENGE}
        scheme, _, encoded = request.headers.get("Authorization", "").partition(" ")
        if scheme.lower() != "basic":
            raise web.HTTPUnauthorized(headers=challenge)
        try:
            decoded = base64.b64decode(encoded, validate=True).decode("utf-8")
        except (ValueError, UnicodeError):
            raise web.HTTPUnauthorized(headers=challenge) from None
        username, separator, password = decoded.partition(":")
        if not separator or not username or len(username) > 64 or not password:
            raise web.HTTPUnauthorized(headers=challenge)
        now = time.monotonic()
        attempts = [value for value in self.failures.get(name, []) if now - value < 60]
        if len(attempts) >= 5:
            raise web.HTTPTooManyRequests(text="登录尝试过多，请一分钟后重试")
        attempts.append(now)
        self.failures[name] = attempts
        self.failures.move_to_end(name)
        while len(self.failures) > 2048:
            self.failures.popitem(last=False)
        ok = await peer.request(
            {"op": "authenticate", "username": username, "password": password},
            "login",
            timeout=15,
        )
        if not ok:
            raise web.HTTPUnauthorized(headers=challenge)

    async def handle(self, request):
        name = self.tenant(request)
        peer = await self.peer(name)
        if self.authenticated(request, name, peer):
            return await self.serve(request, name, peer)
        if request.headers.get("Sec-Fetch-Site") == "cross-site" and not (
            request.method == "GET" and html_navigation(request)
        ):
            raise web.HTTPForbidden()
        origin = request.headers.get("Origin")
        if origin and origin != public_origin(name):
            raise web.HTTPForbidden()
        await self.basic_login(request, name, peer)
        response = await self.serve(request, name, peer)
        if response.prepared or request.path == "/__mower/logout":
            return response
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

    async def serve(self, request, name, peer):
        page_build = request.headers.get("X-Mower-UI-Build")
        if request.headers.get("Upgrade", "").lower() == "websocket":
            page_build = request.query.get("relay_build")
        if page_build and page_build != peer.ui_build:
            raise web.HTTPConflict(
                text="实例版本已更新，请刷新页面", headers={"X-Mower-UI-Reload": "1"}
            )

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
                await peer.send({"op": "ws_open", "id": key, "path": request.path})
                async for frame in socket:
                    if await self.peer(name) is not peer:
                        break
                    if frame.type != WSMsgType.TEXT:
                        break
                    peer.charge(len(frame.data.encode()))
                    await peer.send({"op": "ws_data", "id": key, "data": frame.data})
            except DailyQuotaExceeded:
                await socket.close(code=1008, message=b"daily quota exceeded")
                await peer.ws.close(code=1008, message=b"daily quota exceeded")
            finally:
                peer.sockets.pop(key, None)
                if not peer.ws.closed:
                    # Closing a subscription carries no application data and must work at quota.
                    await peer.ws.send_json({"op": "ws_close", "id": key})
            return socket
        if request.method in {"GET", "HEAD"} and (
            request.path == "/" or html_navigation(request)
        ):
            html = self.shell.replace("__BUILD__", peer.ui_build).replace(
                "__UI_ORIGIN__", self.ui_origin
            )
            return web.Response(
                text=html,
                content_type="text/html",
                headers={"Vary": "Accept, Sec-Fetch-Dest"},
            )

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
                        for key in (
                            "token",
                            "content-type",
                            "x-mower-config-generation",
                            "x-mower-settings",
                        )
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


def create_app(
    registry,
    ui,
    session_key,
    admin_token,
    *,
    ui_origin=DEFAULT_UI_ORIGIN,
    daily_quota_mib=DEFAULT_DAILY_QUOTA_MIB,
):
    gateway = Gateway(registry, session_key, ui_origin, daily_quota_mib)
    traffic = OrderedDict()

    @web.middleware
    async def entry_limit(request, handler):
        now = time.monotonic()
        address = request.remote
        static = request.method in {"GET", "HEAD"} and request.path.startswith(
            (
                "/assets/",
                "/avatar/",
                "/depot/",
                "/building_skill/",
                "/product/",
                "/shop/",
            )
        )
        bucket = (address, static)
        burst = 256 if static else 40
        tokens, previous = traffic.get(bucket, (burst, now))
        tokens = min(burst, tokens + (now - previous) * 20)
        allowed = tokens >= 1
        traffic[bucket] = (tokens - 1 if allowed else tokens, now)
        traffic.move_to_end(bucket)
        while len(traffic) > 4096:
            traffic.popitem(last=False)
        if not allowed:
            raise web.HTTPTooManyRequests()
        return await handler(request)

    @web.middleware
    async def headers(request, handler):
        try:
            response = await handler(request)
        except sqlite3.Error:
            response = web.Response(status=503, text="凭据数据库不可用")
        except web.HTTPException as exc:
            response = web.Response(
                status=exc.status, text=exc.text, headers=exc.headers
            )
        if not response.prepared:
            response.headers.update(
                {
                    "Cache-Control": "no-store",
                    "X-Content-Type-Options": "nosniff",
                    "Referrer-Policy": "same-origin",
                    "X-Frame-Options": "DENY",
                }
            )
        return response

    entry = AdminEntry(gateway.registry.path)
    app = web.Application(
        client_max_size=MAX_BODY, middlewares=[headers, entry_limit, entry.serve]
    )
    app[GATEWAY] = gateway
    app.router.add_get("/__mower/connect", gateway.connect)
    install_admin_routes(app, gateway, admin_token, entry)

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
    parser.add_argument("--ui", type=Path, help=argparse.SUPPRESS)
    parser.add_argument("--ui-origin")
    parser.add_argument(
        "--daily-quota-mib",
        type=int,
        default=DEFAULT_DAILY_QUOTA_MIB,
        help="每个凭据每天可转发的 MiB 数（北京时间零点重置）",
    )
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
        location(args.registry, "data/users.sqlite3"),
        location(args.ui, "ui-dist"),
        read_or_create_secret(location(args.session_key_file, "data/session-key.txt")),
        read_or_create_secret(location(args.admin_token_file, "data/admin-token.txt")),
        daily_quota_mib=args.daily_quota_mib,
        ui_origin=args.ui_origin
        or (
            (work_dir / "ui-origin.txt").read_text("utf-8-sig").strip()
            if (work_dir / "ui-origin.txt").is_file()
            else DEFAULT_UI_ORIGIN
        ),
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
