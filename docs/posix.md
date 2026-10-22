# Linux 与 macOS 部署

[服务端行为说明](architecture.md)规定 HTTPS、认证、用途和资源限制。[管理 API](admin-api.md)供异机 bot 签发、查询和吊销。

在支持 Python 3.12 的 Linux 或 macOS 上，将本仓库克隆到自行选择且有权限访问的目录。以下命令从克隆目录运行，不指定固定部署位置，所有路径均可通过 CLI 参数覆盖。

```sh
git clone https://github.com/ArkMowers/mower-relay-server.git
cd mower-relay-server
python3.12 -m venv .relay-venv
.relay-venv/bin/python -m pip install .
```

将对应 Mower 版本的前端及图片资源复制到 `ui-dist`，包括 `index.html` 和 `frontend-routes.json`。完整资源准备要求见 [Windows 指南的文件准备](windows.md#1-准备文件与证书)，仅需将 Windows 路径换为实际工作目录。服务端不需要 Mower Python 包或源码。

证书完整链及私钥分别放在 `certificates/free.mower.work.crt`、`certificates/free.mower.work.key`，证书同时覆盖 `free.mower.work` 和 `*.free.mower.work`。证书须为 PEM 格式；如果完整链位于 `.pem` 文件，使用 `--cert-file` 指定。启动：

```sh
sh ./start.sh
# 或使用已安装的跨平台入口：
.relay-venv/bin/mower-relay-server --work-dir .
```

首次启动自动创建 `data/session-key.txt`、`data/admin-token.txt` 和 `data/users.json`。密钥文件在 POSIX 系统上以仅属主可读写的权限创建；证书、私钥及工作目录的权限由管理员维护。保留 `data` 可保留已有用户和管理密钥。仅放行入站 TCP 58000，服务不提供明文 HTTP 入口，也不需要其他代理监听端口。

## Linux systemd

使用独立服务账号运行，确保其能读取证书和前端、写入 `data`。以下是单元模板，须将 `<工作目录绝对路径>` 替换为管理员选择的实际目录，并调整服务账号：

```ini
[Unit]
Description=Mower Relay Server
After=network.target

[Service]
Type=simple
User=mower-relay
WorkingDirectory=<工作目录绝对路径>
ExecStart=<工作目录绝对路径>/.relay-venv/bin/mower-relay-server --work-dir <工作目录绝对路径>
UMask=0077

[Install]
WantedBy=multi-user.target
```

保存为 `/etc/systemd/system/mower-relay.service` 后运行 `sudo systemctl daemon-reload`、`sudo systemctl enable --now mower-relay`。状态通过 `sudo systemctl status mower-relay` 查看。证书自动续签工具成功写入完整链和匹配私钥后，执行 `sudo systemctl restart mower-relay`，由管理员给续签任务配置必要的重启权限。

## macOS

可直接在终端运行 `sh ./start.sh`。长期运行时，使用 launchd 的 LaunchAgent 或 LaunchDaemon，将 `ProgramArguments` 设置为虚拟环境内 `mower-relay-server` 的绝对路径、`--work-dir` 和工作目录，将 `WorkingDirectory` 设置为同一目录。按实际服务账号配置文件权限；证书续签完成后通过该任务的 launchd 标签重启服务。

重启使现有连接关闭，Mower 客户端自动重连，浏览器需重新登录。部署验收使用 Windows 指南中的同一组 HTTPS、WSS、准入、bot 管理及吊销检查；Python 测试通过不代表生产证书、DNS、防火墙或服务管理器已验证。
