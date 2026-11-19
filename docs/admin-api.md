# bot 管理 API

管理 API 与用户 HTTPS/WSS 共用 TCP 58000，入口为 `https://free.mower.work:58000/admin/`。所有请求携带 `Authorization: Bearer <管理密钥>`，密钥来自工作目录的 `data/admin-token.txt`，通过可信渠道配置到异机 bot 的环境变量或秘密存储。它与用户准入凭据、实例 token、浏览器 Cookie 不同。

服务先检查主域名及固定端口的 Host 和独立管理密钥，再解析输入或读写注册文件。请求体最多 4 KiB。QQ 用户身份验证和是否通过审核由 bot 判断，持有管理密钥的程序可以签发凭据、修改子域名及吊销凭据。

| 方法及路径 | 输入 | 结果 |
| --- | --- | --- |
| `POST /admin/users` | JSON：`subdomain`、`subject` | 签发独立凭据，返回 201 |
| `GET /admin/users` | 可选 `subject`、`offset`、`limit` | 查询状态，最多 100 项 |
| `GET /admin/users/<名称>` | 无 | 查询单个用户状态 |
| `POST /admin/users/<原名称>/rename` | JSON：`subdomain`，可选 `subject` | 保留凭据，返回新地址 |
| `POST /admin/users/<名称>/revoke` | 可选 JSON：`subject` | 保存吊销状态并断开当前连接 |

签发只接受两个输入字段，例如 `{"subdomain":"alice","subject":"qq:123456789"}`。名称为 1 至 32 位小写字母、数字及中间的连字符，保留名称不能签发。一个 subject 同时只能有一个启用名称。

改名和吊销请求可附带预期的 `subject`。网关在写入前核对归属；归属已变更时返回 409，保留现有记录。

例如，要将 `trial` 改为 `my-mower`，向 `/admin/users/trial/rename` 提交 `{"subdomain":"my-mower"}`。新名称已启用时返回 409，原连接继续使用。改名成功后网关关闭原连接，桌面客户端用原凭据重连并显示新地址。用户从客户端打开新链接并重新登录。原地址不跳转；如请求超时，可按 subject 查询当前名称。

返回状态包括 `subdomain`、`subject`、`enabled`、`connected`、`url`；签发时另返回 `credential`，其原值只返回一次。查询不返回原值或摘要。bot 将凭据私下交付给已审核用户。超时后先查询状态，不能假定签发失败；需要重新领取时先明确吊销再签发，不能覆盖仍启用的名称。

403 表示鉴权失败，400 表示输入无效，404 表示 Host 或用户不存在，409 表示名称占用、归属冲突或凭据已吊销，413 表示请求体超限，429 表示入口限流。注册文件不可读返回 503，不使用默认名单继续授权。

## Python bot 调用示例

bot 后端可用 `requests` 调用同一组接口。把工作目录 `data/admin-token.txt` 中的管理密钥配置为 bot 的环境变量 `MOWER_RELAY_ADMIN_TOKEN`。本例处理用户自助改名。bot 从平台已认证的事件取得 `qq_id`，从命令参数取得原名称和新名称。网关会核对原名称的归属。bot 也可以通过 `GET /admin/users?subject=qq:123456789` 分页查询用户的名称和连接状态。

```python
import os
from urllib.parse import quote

import requests


def rename_for_qq(qq_id, old_name, new_name):
    base = "https://free.mower.work:58000/admin/users"
    subject = f"qq:{qq_id}"
    headers = {"Authorization": "Bearer " + os.environ["MOWER_RELAY_ADMIN_TOKEN"]}
    response = requests.post(
        f"{base}/{quote(old_name, safe='')}/rename",
        headers=headers,
        json={"subdomain": new_name, "subject": subject},
        timeout=10,
    )
    response.raise_for_status()
    return response.json()["url"]
```

管理接口返回普通访问地址。带实例 Token 的直达链接由桌面客户端生成。bot 私聊交付签发结果时只发送该用户的中转凭据。

Windows PowerShell 的完整调用示例见[部署指南](windows.md#3-qqbot-管理-api)。Linux/macOS 可使用支持 HTTPS 的任意 bot HTTP 客户端，始终校验证书。管理服务不记录请求体或 Authorization，bot 也应避免把密钥和准入凭据写入日志。

本地 CLI 仅在停止服务时维护注册文件：`mower-relay-admin --registry <工作目录>/data/users.json issue alice` 或 `revoke alice`。服务运行时使用管理 API，以免多个进程同时替换注册文件。
