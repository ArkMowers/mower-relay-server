"""通过主域名 HTTPS 入口供异机 bot 调用的独立鉴权管理 API。"""

import asyncio
import hmac

from aiohttp import web

from mower_relay_server.protocol import (
    DOMAIN,
    PORT,
    public_origin,
    valid_subdomain,
)
from mower_relay_server.registry import RegistryConflict


def install_admin_routes(app, gateway, token, entry):
    if not isinstance(token, str) or len(token) < 32:
        raise ValueError("管理 API 密钥至少需要 32 个字符")

    def summary(name, record):
        peer = gateway.peers.get(name)
        return {
            "subdomain": name,
            "subject": record["subject"],
            "enabled": bool(record["enabled"]),
            "connected": bool(peer and peer.ui_build and not peer.ws.closed),
            "url": public_origin(name),
        }

    async def get_user(request, name):
        record = await asyncio.to_thread(gateway.registry.get, name)
        if record is None:
            raise web.HTTPNotFound()
        return web.json_response(summary(name, record))

    async def list_users(request):
        subject = request.query.get("subject")
        try:
            offset = max(0, int(request.query.get("offset", "0")))
            limit = max(1, min(100, int(request.query.get("limit", "50"))))
        except ValueError:
            raise web.HTTPBadRequest() from None
        total, users = await asyncio.to_thread(
            gateway.registry.page, subject, offset, limit
        )
        return web.json_response(
            {"users": [summary(row["subdomain"], row) for row in users], "total": total}
        )

    async def issue_user(request):
        try:
            data = await request.json()
        except ValueError:
            raise web.HTTPBadRequest() from None
        if not isinstance(data, dict) or set(data) != {"subdomain", "subject"}:
            raise web.HTTPBadRequest(text="需要 subdomain 和 subject")
        name, subject = data["subdomain"], data["subject"]
        if (
            not valid_subdomain(name)
            or not isinstance(subject, str)
            or not 1 <= len(subject) <= 128
        ):
            raise web.HTTPBadRequest()
        try:
            credential = await asyncio.to_thread(gateway.registry.issue, name, subject)
        except RegistryConflict as exc:
            raise web.HTTPConflict(text=str(exc)) from None
        return web.json_response(
            {
                **summary(name, {"subject": subject, "enabled": True}),
                "credential": credential,
            },
            status=201,
        )

    async def update_user(request, name, *, rename_to_new):
        if not valid_subdomain(name):
            raise web.HTTPNotFound()
        body = {}
        if request.can_read_body:
            try:
                body = await request.json()
            except ValueError:
                raise web.HTTPBadRequest() from None
        fields = {"subject", "subdomain"} if rename_to_new else {"subject"}
        if not isinstance(body, dict) or set(body) - fields:
            raise web.HTTPBadRequest(text="管理请求字段无效")
        subject = body.get("subject")
        if "subject" in body and (not isinstance(subject, str) or len(subject) > 128):
            raise web.HTTPBadRequest(text="subject 无效")
        target = body.get("subdomain") if rename_to_new else name
        if not valid_subdomain(target):
            raise web.HTTPBadRequest(text="需要有效的新子域名 subdomain")
        try:
            record = await asyncio.to_thread(
                gateway.registry.update,
                name,
                subject,
                target if rename_to_new else None,
            )
        except KeyError:
            raise web.HTTPNotFound(text="子域名不存在") from None
        except RegistryConflict as exc:
            raise web.HTTPConflict(text=str(exc)) from None
        if target != name or not rename_to_new:
            peer = gateway.peers.get(name)
            if peer and peer.credential_digest == record["credential_sha256"]:
                await peer.ws.close()
        return web.json_response(summary(target, record))

    async def rename_user(request, name):
        return await update_user(request, name, rename_to_new=True)

    async def revoke_user(request, name):
        return await update_user(request, name, rename_to_new=False)

    async def manage_entry(request):
        if request.method == "PUT":
            try:
                data = await request.json()
                if not isinstance(data, dict) or set(data) != {"original", "path"}:
                    raise ValueError("需要 original 和 path")
                await entry.change(data["original"], data["path"])
            except ValueError as exc:
                raise web.HTTPBadRequest(text=str(exc)) from None
        return web.json_response({"path": entry.path})

    async def initialize(app):
        await asyncio.to_thread(gateway.registry.initialize)

    app.on_startup.append(initialize)
    routes = web.UrlDispatcher()
    routes.add_get("/entry", manage_entry)
    routes.add_put("/entry", manage_entry)
    routes.add_get("/users", list_users)
    routes.add_post("/users", issue_user)
    routes.add_get("/users/{name}", get_user)
    routes.add_post("/users/{name}/rename", rename_user)
    routes.add_post("/users/{name}/revoke", revoke_user)
    routes.freeze()

    async def dispatch(request):
        if not request.path.startswith(entry.path):
            return await gateway.handle(request)
        suffix = request.path[len(entry.path) - 1 :]
        url = request.rel_url.with_path(suffix).with_query(request.rel_url.query)
        api_request = request.clone(rel_url=url, client_max_size=4096)
        match = await routes.resolve(api_request)
        if request.host.lower() != f"{DOMAIN}:{PORT}":
            if match.http_exception is not None:
                return await gateway.handle(request)
            raise web.HTTPNotFound()
        if match.http_exception is not None:
            raise match.http_exception
        supplied = request.headers.get("Authorization", "")
        if not hmac.compare_digest(supplied.encode(), f"Bearer {token}".encode()):
            raise web.HTTPForbidden()
        return await match.handler(api_request, **match)

    app.router.add_route("*", "/{path:.*}", dispatch)
