"""通过主域名 HTTPS 入口供异机 bot 调用的独立鉴权管理 API。"""

import hmac

from aiohttp import web

from mower_relay_server.admin import issue, revoke, write_json
from mower_relay_server.protocol import (
    DOMAIN,
    PORT,
    public_origin,
    valid_subdomain,
)


def create_admin_app(gateway, token):
    if not isinstance(token, str) or len(token) < 32:
        raise ValueError("管理 API 密钥至少需要 32 个字符")

    @web.middleware
    async def authorize(request, handler):
        if request.host.lower() != f"{DOMAIN}:{PORT}":
            raise web.HTTPNotFound()
        supplied = request.headers.get("Authorization", "")
        if not hmac.compare_digest(supplied.encode(), f"Bearer {token}".encode()):
            raise web.HTTPForbidden()
        response = await handler(request.clone(client_max_size=4096))
        response.headers["Cache-Control"] = "no-store"
        return response

    app = web.Application(client_max_size=4096, middlewares=[authorize])

    def summary(name, record):
        peer = gateway.peers.get(name)
        return {
            "subdomain": name,
            "subject": record.get("subject", ""),
            "enabled": record.get("enabled") is True,
            "connected": bool(peer and not peer.ws.closed),
            "url": public_origin(name),
        }

    async def get_user(request):
        name = request.match_info["name"]
        record = gateway.users().get(name)
        if not isinstance(record, dict) or not valid_subdomain(name):
            raise web.HTTPNotFound()
        return web.json_response(summary(name, record))

    async def list_users(request):
        subject = request.query.get("subject")
        try:
            offset = max(0, int(request.query.get("offset", "0")))
            limit = max(1, min(100, int(request.query.get("limit", "50"))))
        except ValueError:
            raise web.HTTPBadRequest() from None
        users = [
            (name, record)
            for name, record in sorted(gateway.users().items())
            if isinstance(record, dict)
            and valid_subdomain(name)
            and (subject is None or record.get("subject") == subject)
        ]
        return web.json_response(
            {
                "users": [
                    summary(name, record)
                    for name, record in users[offset : offset + limit]
                ],
                "total": len(users),
            }
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
        users = gateway.users()
        if any(
            record.get("subject") == subject and record.get("enabled")
            for record in users.values()
            if isinstance(record, dict)
        ):
            raise web.HTTPConflict(text="该用户已有启用的子域名")
        try:
            credential = issue(gateway.registry, name, subject=subject)
        except ValueError:
            raise web.HTTPConflict(text="子域名已经启用") from None
        return web.json_response(
            {**summary(name, gateway.users()[name]), "credential": credential},
            status=201,
        )

    async def revoke_user(request):
        name = request.match_info["name"]
        if name not in gateway.users() or not valid_subdomain(name):
            raise web.HTTPNotFound()
        revoke(gateway.registry, name)
        peer = gateway.peers.get(name)
        if peer:
            await peer.ws.close()
        return web.json_response(summary(name, gateway.users()[name]))

    async def initialize(app):
        if not gateway.registry.exists():
            write_json(gateway.registry, {})

    app.on_startup.append(initialize)
    app.router.add_get("/users", list_users)
    app.router.add_get("/users/{name}", get_user)
    app.router.add_post("/users", issue_user)
    app.router.add_post("/users/{name}/revoke", revoke_user)
    return app
