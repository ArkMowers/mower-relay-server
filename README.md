# Mower Relay Server

Mower 专用的 HTTPS/WSS 中转服务，独立于 [Arknights Mower](https://github.com/ArkMowers/arknights-mower) 安装和发布。支持 Windows、Linux、macOS，要求 Python 3.12 或更新版本。公网仅开放 TCP **58000**，服务直接加载证书，无须 Nginx 或 frps。

- 用户入口：`https://<名称>.free.mower.work:58000`。
- 内置客户端连接：`wss://free.mower.work:58000/__mower/connect`。
- 异机 bot 管理 API：`https://free.mower.work:58000/admin/`，使用独立 Bearer 管理密钥。
- 管理员审核后发放独立凭据。Mower 用户名、密码校验值和实例 token 由本地 Mower 保存及验证。
- 服务端只分派明确允许的 Mower 操作，不接受目标地址、端口或通用 TCP 流。前端静态文件由管理员部署。

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
  ui-dist/                          # 对应 Mower 版本的前端和资源
  data/                             # 自动生成的管理密钥、会话密钥及注册文件
```

`ui-dist` 须包含 `index.html`、`frontend-routes.json` 和前端资源。前端在构建机准备后复制到服务器，不需要把 Mower 源码或 Python 包部署到服务器。证书须同时覆盖 `free.mower.work` 和 `*.free.mower.work`。

服务默认监听 `0.0.0.0:58000`，支持 `--bind` 选择监听地址。`--ui`、`--registry`、`--cert-file`、`--key-file`、`--session-key-file` 和 `--admin-token-file` 可覆盖对应路径。证书更新后需要重启服务，客户端会重新连接，用户需重新登录。

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

协议与允许的操作由本项目的 [protocol.py](mower_relay_server/protocol.py) 独立实现；Mower 主仓维护客户端协议实现和可选跨项目联调测试，不通过 Python 导入共享运行时。协议变更须同时核对两端版本、操作范围和联调结果。

本项目从 Arknights Mower 的中转实现拆分，保留原项目的 [MIT 许可证](LICENSE)。
