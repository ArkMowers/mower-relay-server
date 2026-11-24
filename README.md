# Mower Relay Server

Mower 专用的 HTTPS/WSS 中转服务，独立于 [Arknights Mower](https://github.com/ArkMowers/arknights-mower) 安装和发布。支持 Windows、Linux、macOS，要求 Python 3.12 或更新版本。公网仅开放 TCP **58000**，服务直接加载证书，无须 Nginx 或 frps。

- 用户入口：`https://<名称>.free.mower.work:58000`。
- 内置客户端连接：`wss://free.mower.work:58000/__mower/connect`。
- 异机 bot 管理 API 默认入口：`https://free.mower.work:58000/admin/`，使用独立 Bearer 管理密钥。
- 管理员审核后发放独立凭据。Mower 用户名、密码校验值和实例 token 由本地 Mower 保存及验证。
- 服务端将业务请求转给当前连接的 Mower 实例，本机管理操作由网关和实例共同拦截。协议不接受转发目的地址或端口。前端静态文件由浏览器从 R2 直接读取。

本项目实现协议 v1，需配合具有内置中转客户端的 Mower 版本使用；该客户端接入目前尚未发布。开源客户端不能证明其运行的代码未经修改，合法凭据持有人仍可模拟协议。服务通过准入、操作限制、限额及吊销控制用途，不承诺阻止所有伪装或滥用。

## 安装与启动

克隆本仓库，在项目目录创建虚拟环境并安装：

```sh
python3.12 -m venv .relay-venv
.relay-venv/bin/python -m pip install .
.relay-venv/bin/python -m mower_relay_server --work-dir .
```

Windows 使用 `py -3.12 -m venv .relay-venv` 及 `.relay-venv\Scripts\python.exe`。本仓库还提供 Windows 的 [start.ps1](start.ps1) 和 Linux/macOS 的 [start.sh](start.sh)。

工作目录的结构为：

```text
<工作目录>/
  certificates/free.mower.work.crt   # PEM 格式完整证书链
  certificates/free.mower.work.key   # 匹配的私钥
  data/                             # 管理密钥、会话密钥及凭据数据库
```

### 已有网关升级到 SQLite

1. 停止旧网关，在服务停止期间备份整个工作目录的 `data` 文件夹。升级程序后，以原工作目录启动。
2. 首次启动自动将 `data/users.json` 导入同目录的 `users.sqlite3`，保留子域名、用户标识、启用状态和凭据摘要。导入提交后，旧文件改名为 `users.json.migrated`。原有 `--registry …/users.json` 启动命令仍可使用。新安装直接创建数据库。
3. 用原管理密钥查询用户，核对启用和吊销记录，并用已有凭据重连。原管理入口、管理密钥和会话密钥沿用原文件。若旧数据损坏、启用记录的凭据摘要或非空用户标识重复，网关会在监听前报告错误，保留原文件供核查。

备份时停止网关并复制整个 `data` 目录。迁移后尚未变更记录时，可停机恢复升级前备份和旧程序。迁移后的签发、改名和吊销只写入 SQLite。此后回退旧程序前，必须把数据库的最新记录同步到旧格式，否则旧备份可能重新启用已吊销的凭据。

前端发布和域名设置见 [R2 配置](docs/r2.md)。网关证书须同时覆盖 `free.mower.work` 和 `*.free.mower.work`。

服务默认监听 `0.0.0.0:58000`，支持 `--bind` 选择监听地址。`--ui-origin`、`--registry`、`--cert-file`、`--key-file`、`--session-key-file` 和 `--admin-token-file` 可覆盖对应路径。证书更新后需要重启服务，客户端会重新连接，用户需重新登录。

网关默认在主域名的 `/admin/` 提供[管理页面](docs/admin-api.md#网关管理页面)，登录后可一并更改网页和管理 API 的入口路径。管理员也可从本机运行 `python -m mower_relay_server.admin_ui`，在浏览器中签发、查看、改名和吊销凭据。参见[本机凭据管理页面](docs/admin-api.md#本机凭据管理页面)。

完整步骤见 [Windows 部署](docs/windows.md)、[Linux/macOS 部署](docs/posix.md)、[bot 管理 API](docs/admin-api.md) 和[服务端行为说明](docs/architecture.md)。

## 开发验证

```sh
python -m pip install -e ".[dev]"
python -m pytest -q
python -m ruff check .
python -m ruff format --check .
python -m build
```

测试只访问回环地址和临时文件，不需要 Mower 主仓、设备或线上服务。GitHub Actions 在 Windows、Linux、macOS 上执行这些检查；实际公网 DNS、生产证书及服务管理配置需在部署环境验收。

网关和 Mower 实例独立实现[中转协议](mower_relay_server/protocol.py)。普通 HTTP 接口随实例版本提供。新增本机管理限制、调整传输格式或 WebSocket 订阅时，需要同步核对两端实现。

本项目从 Arknights Mower 的中转实现拆分，保留原项目的 [MIT 许可证](LICENSE)。
