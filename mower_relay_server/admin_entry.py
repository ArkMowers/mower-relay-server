"""Gateway-hosted management page and its persisted URL path."""

import asyncio
import json
from importlib.resources import files

from aiohttp import web

from mower_relay_server.admin import write_json
from mower_relay_server.protocol import DEFAULT_ENTRY, DOMAIN, PORT, entry_path


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
                parent, child = sorted((self.path, target), key=len)
                if child.startswith(parent) and child[len(parent) :].split("/", 1)[
                    0
                ] in {"users", "entry"}:
                    raise ValueError("新旧入口的管理路径重叠，请选择其他路径")
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
        return await handler(request)
