# Windows 免费 Mower 中转部署

[服务端行为说明](architecture.md)定义准入、认证、用途限制及资源上限。本指南部署内置专用连接，不使用普通 frpc 或 frps 代理端口。

## 1. 准备文件与证书

1. 在 Windows 将独立中转仓库克隆到自行选择的工作目录，安装 Python 3.12。以下命令从仓库根目录运行；启动脚本将当前目录切换到其所在目录，不指定固定磁盘位置。
2. 在构建机从支持协议 v1 的 Mower 对应版本发布包中取得 `ui/dist`，复制到独立的 `.\ui-dist`。该目录只放可发布的前端文件，不放账号文件、注册文件、证书或管理密钥；不要将整个工作目录作为静态目录。前端构建在发布环境执行 `npm ci`、`npm run build`。
3. 将该版本资源包的前端图片合并到相同目录。将 `ui/dist/pages/basement_skill` 的文件复制到 `.\ui-dist\basement_skill`，并将同版本 `arknights_mower/data/building_skill.json` 复制为其中的 `skill.json`，用于服务端提供基建技能静态数据。资源升级时同步这些文件。
4. DNS 中将 `free.mower.work` 和 `*.free.mower.work` 指向该 Windows 主机。检查已签发证书的 Subject Alternative Name 同时覆盖两者；`*.mower.work` 不能覆盖 `用户.free.mower.work`。保留现有自动签发任务，续签后重启中转服务加载新证书。

```powershell
py -3.12 -m venv .relay-venv
.\.relay-venv\Scripts\python.exe -m pip install -r requirements.txt
```

服务端只需要本仓库及网关依赖，不需要复制 Mower 主仓或安装其 Python 包、游戏识别及桌面依赖。前端文件和资源在构建机准备后复制到服务器；服务运行时不读取 Mower 源码。

## 2. 使用证书启动 HTTPS 服务

运行[启动脚本](../start.ps1)：

```powershell
.\start.ps1
```

首次启动在 `.\data` 生成会话签名密钥和管理 API 密钥，并初始化注册文件。通过 Windows 文件权限只允许服务账号和管理员访问此目录；不要把它放在网关静态目录内。将该命令配置为服务或任务计划中的长期进程，工作目录设为管理员选择的仓库根目录；配置失败退出后由管理员检查，不通过无条件重启掩盖错误。

启动脚本直接加载已有证书和私钥，路径相对于工作目录：

```text
.\certificates\free.mower.work.crt
.\certificates\free.mower.work.key
```

证书文件使用 PEM 格式，包含服务器证书及完整中间证书链；私钥须与证书匹配，并使用服务可直接加载的未加密 PEM 文件，由 Windows 文件权限保护。如果现有 `.pem` 才包含完整链，启动时指定该文件：

```powershell
.\start.ps1 -CertificateFile .\certificates\free.mower.work.pem
```

也可用 `-PrivateKeyFile` 指定其他私钥路径。`free.mower.work_issuerCertificate.crt` 是签发机构证书，不能单独代替服务器证书；若需要补齐中间链，应将其与服务器证书按顺序放入完整链文件。服务直接监听 `0.0.0.0:58000`，最低使用 TLS 1.2，无须运行 Nginx。启动前释放原先占用 58000 的监听。证书缺失、格式无效或私钥不匹配时服务退出，不回退到 HTTP。

自动签发任务写入完整证书链和私钥后，在其成功回调中重启中转服务；按实际部署的 Windows 服务或任务名称配置重启命令。重启关闭现有连接，客户端会重新连接，用户需重新登录。不要在仅完成证书或私钥其中一个文件的替换时重启。

Windows 防火墙仅需允许公网入站 TCP 58000，服务不再监听 58001、58002。服务不需要开放 frps 的 7001、7501 或 TCP 65000 至 65100。若原 frps 仅为该免费服务准备，停止该服务并撤销相应入站规则；若另有用途，则单独维护，不能继续开放匿名通用隧道后宣称免费入口仅供 Mower 使用。

## 3. QQBot 管理 API

bot 部署在另一台机器，通过 `https://free.mower.work:58000/admin/` 调用管理 API。管理操作、用户网页和 Mower 连接由同一个 HTTPS 服务处理，共用公网 TCP 58000。管理请求仅接受主域名，用户子域名下的 `/admin/` 返回 404。

将中转机 `.\data\admin-token.txt` 中的管理密钥通过可信渠道配置为 bot 机器上的环境变量 `MOWER_RELAY_ADMIN_TOKEN`。所有请求携带 `Authorization: Bearer <管理密钥>`，不写进公开源码或群聊。以下示例在 bot 机器运行，始终校验 HTTPS 证书：

```powershell
$RelayAdminToken = $env:MOWER_RELAY_ADMIN_TOKEN
$RelayHeaders = @{ Authorization = "Bearer $RelayAdminToken" }
$RelayBody = @{ subdomain = "alice"; subject = "qq:123456789" } | ConvertTo-Json
$IssuedUser = Invoke-RestMethod -Method Post -Uri https://free.mower.work:58000/admin/users -Headers $RelayHeaders -ContentType application/json -Body $RelayBody
```

签发结果包含 `subdomain`、`subject`、`enabled`、`connected`、`url` 和仅本次返回的 `credential`。bot 将凭据交付给已审核用户，避免群聊公开。发生超时不能假定签发没有生效：先查询，再由管理员决定吊销并重新签发，不能覆盖已有启用用户。

```powershell
Invoke-RestMethod -Uri https://free.mower.work:58000/admin/users/alice -Headers $RelayHeaders
Invoke-RestMethod -Uri 'https://free.mower.work:58000/admin/users?subject=qq%3A123456789&offset=0&limit=20' -Headers $RelayHeaders
Invoke-RestMethod -Method Post -Uri https://free.mower.work:58000/admin/users/alice/revoke -Headers $RelayHeaders
```

HTTP 403 表示管理密钥无效；400 表示输入无效；404 表示用户不存在；409 表示名称或外部用户标识已占用。查询不返回凭据原值及其摘要。管理 API 不负责识别 QQ 用户或判断是否通过审核，bot 必须在调用前执行自己的身份与审核规则。

停止网关后也可使用本地 CLI 签发或吊销：

```powershell
.\.relay-venv\Scripts\python.exe -m mower_relay_server.admin --registry .\data\users.json issue alice
.\.relay-venv\Scripts\python.exe -m mower_relay_server.admin --registry .\data\users.json revoke alice
```

## 4. 用户启用与部署验收

1. 用户在本机 Mower 设置的“免费 Mower 中转”填写获批名称、独立凭据、用户名和至少 8 个字符的密码，点击“保存并应用”。密码不要求混合大小写、数字或符号。用户名和密码只在本机配置，管理员无需代为设置。通过多开管理器设置固定实例 token，或使用本次本机浏览器地址中的实例 token。
2. 状态显示连接成功后，打开 `https://alice.free.mower.work:58000`。先通过本地用户名、密码验证，再在 Mower 页面填写实例 token。刷新页面、日志订阅及 AI WebSocket 应保留正常行为。浏览器安全 Cookie 要求 HTTPS；不要改成公网 HTTP 测试。
3. 验证未知凭据、其他用户的子域名、重复连接和未登录 API 请求都被拒绝；密码正确但 token 缺失或错误时，实例操作仍被拒绝。
4. 从异机 bot 经 `https://free.mower.work:58000/admin/` 签发、查询和吊销，确认吊销关闭当前连接，原页面无法继续操作，原凭据不能重新连接。检查错误或缺失管理密钥返回 403，用户子域名下的管理路径返回 404；58001、58002、7001、7501 及原转发端口没有被误暴露。
5. 验证 HTTPS 页面和 WSS 连接的证书链，续签重启后检查新证书的有效期；确认网关未记录账号密码、token 查询参数或管理密钥。网关仅暂存转发内容；不要在其前面加记录请求体或 Authorization 的调试代理。

从独立中转仓库根目录运行服务端测试：

```powershell
.\.relay-venv\Scripts\python.exe -m pip install -e ".[dev]"
.\.relay-venv\Scripts\python.exe -m pytest tests/test_gateway.py
```

服务端测试仅使用临时文件和回环连接，不依赖 Mower 安装、设备或游戏。跨项目联调测试由 Mower 主仓维护；这些检查不替代 Windows 公网验收。
