"""Local browser client for the Mower relay credential API."""

import argparse
import json
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib.resources import files
from urllib.error import HTTPError
from urllib.request import HTTPRedirectHandler, Request, build_opener

from mower_relay_server.protocol import DOMAIN, PORT, valid_subdomain

API = f"https://{DOMAIN}:{PORT}/admin"
PAGE_SIZE = 25
ASSETS = {
    "/": ("admin_ui.html", "text/html; charset=utf-8"),
    "/admin_ui.js": ("admin_ui.js", "text/javascript; charset=utf-8"),
}


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def operation(data):
    if not isinstance(data, dict):
        raise ValueError("请求格式无效")
    action = data.get("action")
    if action == "list":
        offset = data.get("offset", 0)
        if type(offset) is not int or offset < 0:
            raise ValueError("分页位置无效")
        return "GET", f"/users?offset={offset}&limit={PAGE_SIZE}", None
    if action == "get_entry":
        return "GET", "/entry", None
    if action == "set_entry":
        return (
            "PUT",
            "/entry",
            {"original": data.get("original"), "path": data.get("path")},
        )
    name = data.get("subdomain")
    subject = data.get("subject")
    if not valid_subdomain(name):
        raise ValueError("请输入可用的子域名，使用 1–32 位小写字母、数字和中间的连字符")
    if not isinstance(subject, str) or len(subject) > 128:
        raise ValueError("用户标识最长为 128 个字符")
    if action == "issue" and subject.strip():
        return "POST", "/users", {"subject": subject, "subdomain": name}
    if action == "rename" and valid_subdomain(data.get("new_name")):
        return (
            "POST",
            f"/users/{name}/rename",
            {"subject": subject, "subdomain": data["new_name"]},
        )
    if action == "revoke":
        return "POST", f"/users/{name}/revoke", {"subject": subject}
    raise ValueError("请检查用户标识和子域名")


def gateway_request(method, suffix, body, auth):
    request = Request(
        API + suffix,
        method=method,
        data=None if body is None else json.dumps(body).encode(),
        headers={"Authorization": auth, "Content-Type": "application/json"},
    )
    try:
        with build_opener(NoRedirect()).open(request, timeout=12) as response:
            return response.status, json.loads(response.read(256 * 1024))
    except HTTPError as exc:
        with exc:
            details = exc.read(512).decode("utf-8", "replace").strip()
        messages = {
            400: "网关拒绝了输入，请检查子域名和用户标识",
            403: "管理密钥无效，请重新输入",
            404: "未找到该凭据或管理接口，请刷新列表",
            409: "名称或用户归属发生冲突，请刷新列表",
            429: "请求过于频繁，请稍后重试",
        }
        message = messages.get(exc.code, "网关暂时不可用")
        if exc.code in (400, 409) and details and "<" not in details:
            message = details
        return exc.code if 400 <= exc.code < 600 else 502, {"error": message}
    except (OSError, ValueError):
        return 502, {
            "error": "未收到网关的有效响应。若刚提交了操作，请先刷新列表核对结果。"
        }


class AdminPage(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def respond(self, status, content, mime="application/json; charset=utf-8"):
        if isinstance(content, dict):
            content = json.dumps(content, ensure_ascii=False).encode()
        self.send_response(status)
        self.send_header("Content-Type", mime)
        self.send_header("Content-Length", str(len(content)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'none'; script-src 'self'; "
            "style-src 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'; "
            "base-uri 'none'; form-action 'none'",
        )
        self.end_headers()
        self.wfile.write(content)

    @property
    def authority(self):
        return f"127.0.0.1:{self.server.server_port}"

    def do_GET(self):
        if self.headers.get("Host") != self.authority or self.path not in ASSETS:
            self.respond(404, {"error": "未找到页面"})
            return
        filename, mime = ASSETS[self.path]
        self.respond(
            200, files("mower_relay_server").joinpath(filename).read_bytes(), mime
        )

    def do_POST(self):
        if self.path != "/api" or self.headers.get("Host") != self.authority:
            self.respond(404, {"error": "未找到接口"})
            return
        if self.headers.get("Origin") != f"http://{self.authority}":
            self.respond(403, {"error": "请从本机管理页面操作"})
            return
        auth = self.headers.get("Authorization", "")
        if (
            not auth.startswith("Bearer ")
            or not auth[7:]
            or not auth.isascii()
            or not auth.isprintable()
        ):
            self.respond(403, {"error": "请输入管理密钥"})
            return
        try:
            size = int(self.headers.get("Content-Length", "0"))
            if (
                not 0 < size <= 4096
                or self.headers.get_content_type() != "application/json"
            ):
                raise ValueError("请求格式无效")
            method, suffix, body = operation(json.loads(self.rfile.read(size)))
        except (ValueError, UnicodeError) as exc:
            self.respond(400, {"error": str(exc)})
            return
        self.respond(*gateway_request(method, suffix, body, auth))


def main():
    parser = argparse.ArgumentParser(description="在本机管理 Mower 中转凭据")
    parser.add_argument("--port", type=int, default=0)
    parser.add_argument("--no-browser", action="store_true")
    args = parser.parse_args()
    with ThreadingHTTPServer(("127.0.0.1", args.port), AdminPage) as server:
        url = f"http://127.0.0.1:{server.server_port}/"
        print(url, flush=True)
        if not args.no_browser:
            webbrowser.open(url)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass


if __name__ == "__main__":
    main()
