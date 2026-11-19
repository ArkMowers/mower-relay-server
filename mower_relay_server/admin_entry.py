"""Gateway-hosted management page and its persisted URL path."""

import asyncio
import json
import re
from importlib.resources import files

from aiohttp import web

from mower_relay_server.admin import write_json
from mower_relay_server.protocol import DOMAIN, PORT

DEFAULT_ENTRY = "/admin/"


def entry_path(value):
    if not isinstance(value, str) or not 1 <= len(value.removesuffix("/")) < 128:
        raise ValueError("入口必须是本站的路径，例如 /ops-mower/")
    path = value.removesuffix("/")
    if not re.fullmatch(r"(?:/[A-Za-z0-9][A-Za-z0-9_-]*)+", path):
        raise ValueError("路径各段须以字母或数字开头，可使用连字符和下划线")
    if path.startswith("/admin/"):
        raise ValueError("该路径已保留给管理 API")
    return path + "/"


class AdminEntry:
    def __init__(self, registry):
        self.file = registry.with_name("admin-entry.json")
        try:
            self.path = entry_path(json.loads(self.file.read_text("utf-8")))
        except FileNotFoundError:
            self.path = DEFAULT_ENTRY
        self.lock = asyncio.Lock()

    async def change(self, original, target):
        target = entry_path(target)
        async with self.lock:
            if self.path != original:
                raise web.HTTPConflict(text="入口已变更，请重新打开设置")
            if target != self.path:
                try:
                    await asyncio.to_thread(write_json, self.file, target)
                except OSError:
                    raise web.HTTPServiceUnavailable(
                        text="入口保存失败，请检查网关数据目录权限"
                    ) from None
                self.path = target
        return target

    @web.middleware
    async def serve(self, request, handler):
        if request.host.lower() == f"{DOMAIN}:{PORT}" and request.method in {
            "GET",
            "HEAD",
        }:
            path = request.path
            if path == self.path[:-1]:
                raise web.HTTPTemporaryRedirect(location=self.path)
            if path == self.path or path == self.path + "admin_ui.js":
                is_page = path == self.path
                asset = "admin_ui.html" if is_page else "admin_ui.js"
                return web.Response(
                    body=files("mower_relay_server").joinpath(asset).read_bytes(),
                    content_type="text/html" if is_page else "text/javascript",
                    charset="utf-8",
                    headers={
                        "Content-Security-Policy": "default-src 'none'; script-src 'self'; style-src 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
                    },
                )
            if path in {"/admin", "/admin/", "/admin/admin_ui.js"}:
                raise web.HTTPNotFound()
        return await handler(request)
