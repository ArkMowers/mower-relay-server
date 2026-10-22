# bot 管理 API

管理 API 与用户 HTTPS/WSS 共用 TCP 58000，入口为 `https://free.mower.work:58000/admin/`。所有请求携带 `Authorization: Bearer <管理密钥>`，密钥来自工作目录的 `data/admin-token.txt`，通过可信渠道配置到异机 bot 的环境变量或秘密存储。它与用户准入凭据、实例 token、浏览器 Cookie 不同。

服务先检查主域名及固定端口的 Host 和独立管理密钥，再解析输入或读写注册文件。请求体最多 4 KiB。QQ 用户身份验证和是否通过审核由 bot 判断，持有管理密钥的程序拥有签发及吊销权限。

| 方法及路径 | 输入 | 结果 |
| --- | --- | --- |
| `POST /admin/users` | JSON：`subdomain`、`subject` | 签发独立凭据，返回 201 |
| `GET /admin/users` | 可选 `subject`、`offset`、`limit` | 查询状态，最多 100 项 |
| `GET /admin/users/<名称>` | 无 | 查询单个用户状态 |
| `POST /admin/users/<名称>/revoke` | 无 | 保存吊销状态并断开当前连接 |

签发只接受两个输入字段，例如 `{"subdomain":"alice","subject":"qq:123456789"}`。名称为 1 至 32 位小写字母、数字及中间的连字符，保留名称不能签发。一个 subject 同时只能有一个启用名称。

返回状态包括 `subdomain`、`subject`、`enabled`、`connected`、`url`；签发时另返回 `credential`，其原值只返回一次。查询不返回原值或摘要。bot 将凭据私下交付给已审核用户。超时后先查询状态，不能假定签发失败；需要重新领取时先明确吊销再签发，不能覆盖仍启用的名称。

403 表示鉴权失败，400 表示输入无效，404 表示 Host 或用户不存在，409 表示名称或 subject 已启用，413 表示请求体超限，429 表示入口限流。注册文件不可读返回 503，不使用默认名单继续授权。

Windows PowerShell 的完整调用示例见[部署指南](windows.md#3-qqbot-管理-api)。Linux/macOS 可使用支持 HTTPS 的任意 bot HTTP 客户端，始终校验证书。管理服务不记录请求体或 Authorization，bot 也应避免把密钥和准入凭据写入日志。

本地 CLI 仅在停止服务时维护注册文件：`mower-relay-admin --registry <工作目录>/data/users.json issue alice` 或 `revoke alice`。服务运行时使用管理 API，以免多个进程同时替换注册文件。
