<div align="center">

# Team Workflow Console

**面向 Windows 与 macOS 的本地优先 Team 工作流控制台**

统一管理空间、账号轮换、顺序队列、浏览器身份快照、CPA Management 与 Sub2API 推送。

[![Python 3.11+](https://img.shields.io/badge/Python-3.11%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![Windows](https://img.shields.io/badge/Platform-Windows-0078D4?logo=windows11&logoColor=white)](#运行环境)
[![macOS](https://img.shields.io/badge/Platform-macOS-111111?logo=apple&logoColor=white)](#运行环境)
[![FastAPI](https://img.shields.io/badge/FastAPI-localhost-009688?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![Tests](https://img.shields.io/badge/tests-232%20passed-2E7D32)](#测试)
[![License: MIT](https://img.shields.io/badge/License-MIT-111111.svg)](LICENSE)

</div>

更新记录见 [CHANGELOG.md](CHANGELOG.md)。

## 项目概览

Team Workflow Console 将原本分散的账号、空间和运行配置收敛到一个仅监听本机回环地址的网页控制台。应用通过 SQLite 保存业务状态，通过系统用户密钥保护敏感值，并用全局串行队列执行完整工作流。Windows 使用 DPAPI，macOS 使用登录钥匙串中的主密钥与 AES-GCM。

| 能力 | 说明 |
| --- | --- |
| 空间任务 | 每个空间独立维护当前账号、下一账号、轮换次数和运行状态 |
| 邮箱库存 | 按需搜索与分配，不会一次性加载大规模邮箱文件 |
| 别名轮换 | 按 `+1` 到 `+5` 顺序使用，耗尽后自动切换下一主邮箱 |
| 顺序队列 | 全局单任务执行，支持暂停、重排、停止、重试与断点恢复 |
| 账号级身份 | 每个账号独立锁定代理、SID、地域、BrowserForge 完整指纹与 HTTP 会话，账号晋升后继续复用 |
| iCloud 子号接力 | 一个 iCloud 资源池可接管多个永久 Team 母号；点击更换时才新建 Alias，并按母号继承独立 S5 |
| 双目标推送 | 工作流完成后可分别推送到 CPA Management 和 Sub2API |
| 加密备份 | 数据库快照、完整性校验、系统密钥解密验证和受控恢复 |
| 本地控制台 | 仅绑定 `127.0.0.1`，写操作同时校验同源与启动期请求令牌 |

## 界面与流程

控制台围绕四个工作面组织：

1. **空间任务**：建立空间与账号对的绑定，批量加入队列，处理额度用完或账号失效。
2. **账号库**：管理 Outlook 库存、iCloud 资源池、永久 Team 母号、轮换子号和已用完池。
3. **执行队列**：观察八阶段进度，调整顺序，暂停领取任务或请求停止当前运行。
4. **设置**：配置代理、PAT、推送目标、输出目录以及加密备份。

```text
邮箱库存 ──按需分配──> 空间账号对 ──加入队列──> 单任务执行器
                                               │
                                               ├─ 旧/新账号各自固定 SID、代理与指纹
                                               ├─ 登录 / 邀请 / 退出 / 注册
                                               ├─ PAT 与 CPA 生成
                                               └─ Management / Sub2API 推送
```

## 运行环境

- Windows 10 / 11，或带登录钥匙串的 macOS
- Python 3.11 或更高版本
- `curl-cffi 0.15.0`、`Playwright 1.58.0`、`BrowserForge 1.2.4`、`cryptography 43+`、`PyYAML 6+`
- Chromium 145（由 Playwright 1.58.0 安装）

敏感数据绑定当前系统用户。Windows 密文由 DPAPI 保护；macOS 的 256 位随机主密钥保存在登录钥匙串的 `Team Workflow Console / secret-store-master-key-v1` 项中，业务字段使用 AES-GCM 加密。数据库和加密备份不能直接复制给其他用户或跨系统解密。

> [!IMPORTANT]
> 使用本项目前，请先在 BugTeam 母号中启用“允许子号创建令牌”。未启用该权限时，子号无法完成“创建令牌”阶段，工作流会失败。

## 快速开始

macOS：

```bash
git clone 'https://github.com/chenli17683185032-ai/Team-Workflow.git'
cd 'Team-Workflow'

python3 -m venv '.venv'
./.venv/bin/python -m pip install --upgrade pip
./.venv/bin/python -m pip install -r './requirements.txt'
./.venv/bin/python -m playwright install chromium
./.venv/bin/python './run_web.py'
```

首次启动会在当前用户的登录钥匙串中创建应用主密钥。控制台默认打开[本地控制台地址](http://127.0.0.1:8765/)。终端按 `Control-C` 可正常停止。

Windows PowerShell：

```powershell
$ErrorActionPreference = 'Stop'
git clone 'https://github.com/chenli17683185032-ai/Team-Workflow.git'
Set-Location '.\Team-Workflow'

python -m venv '.venv'
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -r '.\requirements.txt'
.\.venv\Scripts\python.exe -m playwright install chromium
```

启动本地控制台：

```powershell
$ErrorActionPreference = 'Stop'
.\.venv\Scripts\python.exe '.\run_web.py'
```

浏览器默认打开[本地控制台地址](http://127.0.0.1:8765/)。以下入口等价：

```powershell
$ErrorActionPreference = 'Stop'
.\.venv\Scripts\python.exe -m team_protocol web
.\.venv\Scripts\python.exe -m team_protocol gui
```

`gui` 是网页控制台的兼容别名；项目不再维护独立桌面 GUI。

## 数据安全

| 数据 | 默认位置 | 保护方式 |
| --- | --- | --- |
| 应用数据库（Windows） | `%LOCALAPPDATA%\TeamWorkflowConsole\console.db` | 敏感字段使用 Windows DPAPI 加密 |
| 应用数据库（macOS） | `~/Library/Application Support/TeamWorkflowConsole/console.db` | Keychain 主密钥 + AES-GCM |
| iCloud 资源池、母号与 Alias | 应用数据库内的独立表 | HME Cookie、IMAP 密码、各母号 S5 和远端 ID 分用途认证加密 |
| 加密备份 | 项目目录下的 `backups/` | 完整性校验 + 当前系统用户密钥绑定 |
| CPA / session 导出 | 项目目录下的 `output\` | 明文凭据边界，仅在显式导出时产生 |
| 邮箱源文件 | 用户选择的位置 | 仅在显式导入时读取，不由应用自动删除 |

仓库的 `.gitignore` 默认排除以下内容：

- 邮箱或账号 TXT；
- HAR、CPA、session、PAT 与工作流 JSON；
- SQLite 数据库、加密备份、运行输出和日志；
- 本地迁移状态、内部分析报告与验收产物。

> [!IMPORTANT]
> `output/` 中的 CPA/session 文件属于明文凭据。只在需要时生成，用完后及时删除，禁止提交到版本控制。

可用 `TEAM_WORKFLOW_APP_DIR` 覆盖默认应用数据目录。该变量只改变数据库和实例锁位置，不会移动或导出系统密钥。

## 账号轮换规则

- 邮箱库存只在用户搜索或实际分配时加载所需数据。
- 每个主邮箱最多使用五个别名：`+1`、`+2`、`+3`、`+4`、`+5`。
- 当前账号完成轮换后，下一账号提升为当前账号，并自动分配新的下一账号。
- `+5` 用完后，从下一可用主邮箱的 `+1` 继续。
- 子号不可用时仅替换对应子号；邮箱凭据失效时停用整个主邮箱库存。
- 网络、代理、限流或 OTP 超时不会被误判为邮箱失效。

## 工作流阶段

```text
01 旧号登录
02 新号注册
03 邀请新号
04 旧号退出
05 创建令牌
06 生成 CPA
07 推送 Management
08 推送 Sub2API
```

队列在每个阶段保存 checkpoint。进程异常退出后可以恢复同一次运行，避免重复邀请、重复退出或重复创建远端资源。账号首次参与任务时会先分配稳定 SID，通过该账号代理解析出口国家和 IANA 时区，再生成并加密保存 SessionProfile、BrowserForge 完整 payload 和工具链版本。旧号、新号分别使用独立代理、指纹和 curl 会话；账号由下一账号晋升为当前账号后仍复用原身份。任务开始时会确认代理地域解析、IANA 时区和 UTC 时钟有效；当前出口与已保存地域或语言发生漂移时继续使用账号已锁定的身份。出口 IP 不保存、不写入日志，代理 userinfo 在日志中整体掩码。

账号级 SID 支持 `{sid}` 占位符和 NovProxy 的 `-sid-<value>` 格式。例如：

```text
socks5://tenant-region-BR-sid-{sid}-t-60:password@proxy.example:1000
```

新任务配置了代理时，用户名必须包含 `{sid}`、`-sid-<value>` 或旧版 `{rand}` 占位符；静态无 SID 代理只保留给已有 checkpoint 的兼容恢复。浏览器只改变该上下文的 IANA 时区和语言，不修改操作系统时钟；数据库、令牌时间和 CPA 的 `last_refresh` 始终使用 UTC。主地域请求同时读取 HTTPS `Date` 校验本机 UTC，偏差超过 60 秒或缺少可信时间时会在首个账号请求前中止。地域请求单次上限 8 秒并允许同一 SID 重试一次，旧号与新号并行探测。

### 每个账号独立 S5

在“账号库”的账号行点击“代理”，可为当前账号保存独立的 `s5://`、`s5h://`、`socks5://` 或 `socks5h://` 地址。`s5://` 和 `s5h://` 会自动规范化为标准 scheme。页面只显示是否已配置，不会回显代理 URL、用户名或密码。

```text
socks5://user-a:password-a@proxy-a.example:1080
socks5h://user-b:password-b@proxy-b.example:1080
```

运行时按以下优先级选择：账号独立代理、全局代理模板、直连。独立静态 S5 可以不含 SID；如果独立地址包含 `{sid}` 或 `-sid-<value>`，仍会绑定该账号的稳定 SID。任务首次执行前会分别加密冻结旧号和新号的代理快照，之后的失败重试不会受账号代理设置变化影响。

## iCloud 资源池与子号接力

一个 iCloud 账号对应一个 HME 资源池。资源池可以包含 20 个以上已有隐藏邮箱，其中只接管用户明确选中的 Alias：两个永久 Team 母号、各自当前的轮换子号，以及以后现场创建的新子号。未选中的旧 Alias 保持原样。

| 对象 | 生命周期与用途 |
| --- | --- |
| iCloud 资源池 | 保存一套 HME Session、转发邮箱 IMAP，以及 Apple HME / IMAP 请求使用的 S5 |
| Team 母号 | 从已有 Alias 中接管，永久保护，不进入普通账号池、轮换或已用完池 |
| 轮换子号 | 归属一个 Team 母号，继承该母号自己的 S5，作为空间当前子号或下一子号 |
| 已用完池 | 接力成功后的旧子号只在本地标记并保留计数，不自动删除或停用远端 Alias |

每个空间固定绑定一个 Team 母号，但实际接力由当前子号完成：当前子号邀请现场创建的新子号，随后退出空间；新子号登录并确认空间后晋升为当前子号。空间平时不预建、不占用下一子号。

### 准备信息

1. 登录 [iCloud 网页版](https://www.icloud.com/)，进入 Hide My Email 管理页面。在浏览器开发者工具的 Network 中找到 `/v2/hme/list` 请求，使用“Copy as cURL”，也可以导出包含该请求的 HAR。
2. 准备隐藏邮箱实际转发到的邮箱 IMAP 信息。使用 iCloud Mail 时，通常为 `imap.mail.me.com:993`、完整 iCloud 邮箱地址，以及在 [Apple Account](https://account.apple.com/) 生成的 App 专用密码；其他邮箱使用对应服务商的 IMAP 参数。
3. 按需准备资源池的 HME / IMAP S5。建议使用 `socks5h://user:password@host:port`，让 IMAP 主机名也由代理端解析。
4. 分别准备两个 Team 母号自己的 S5。新建子号会按归属继承对应母号的代理，因此两个空间可以使用完全不同的出口。

#### 两个母号共用一个 Clash/Mihomo

如果两个母号的 LokiProxy 入口使用白名单出口，不需要启动两个 Clash 进程。控制台会在同一个 Mihomo 进程内创建两条互不切换全局选择器的链：

```text
本地母号入口 A -> LokiProxy A -> dialer-proxy: 选定的第一跳 A -> 目标
本地母号入口 B -> LokiProxy B -> dialer-proxy: 选定的第一跳 B -> 目标
```

在“同步 Alias”或已接管母号的“母号 S5”对话框中：

1. 代理类型选择“LokiProxy”。
2. 把 `https://gen.lokiproxy.com/gen?...` 生成链接填入 LokiProxy 字段；不要把生成链接当作 `socks5://host:port` 固定代理保存。
3. 为每个母号分别选择对应的 Mihomo 节点，例如母号 A 选 `US 33`，母号 B 选 `JP 22`。节点名称必须与本机 Clash 配置中的名称一致。
4. 保存后等待两个动态链状态都显示健康，再提交 Alias 接管或开始子号轮换。

应用会把生成链接加密保存，只向 Mihomo 提供本机回环地址的短期 provider；每条链的实际动态 `ip/port` 会经选定的 `dialer-proxy` 出口访问。两个母号的本地 listener、缓存和刷新锁彼此独立，刷新一条链不会切换另一条链的出口。默认生成配置位于 `~/Library/Application Support/TeamWorkflowConsole/clash/teamworkflow.yaml`，权限为用户可读写；主 Clash 原配置保持不变，应用重启后会重新加载该合并层。

macOS 默认使用 Clash Verge 的 Mihomo Unix API（`/tmp/verge/verge-mihomo.sock`、`v1.19.21`）。如本机路径不同，可通过 `TEAM_WORKFLOW_CLASH_CONFIG`、`TEAM_WORKFLOW_CLASH_SOCKET` 和 `TEAM_WORKFLOW_CLASH_BINARY` 覆盖。生成链接失效时，控制台只刷新对应母号的 provider，不会触发 Apple Alias 创建、停用或删除。

HAR 可能包含大量会话信息，不要保存到仓库。控制台只解析允许的 Apple HME host/path，导入原文不落盘；提取后的 Cookie 会立即进入系统密钥保护的密文。

### 控制台操作

1. 打开“账号库”中的“iCloud 隐藏邮箱”，点击“添加 iCloud 资源池”。
2. 填写资源池名称、真实转发邮箱、HME cURL/HAR、IMAP 参数和可选的 HME / IMAP S5，然后保存。
3. 点击“检测”。只有 HME Session、转发目标和 IMAP 登录同时通过，资源池状态才会变为“可用”。
4. 点击“同步 Alias”。远端列表默认全部为“忽略”；只把两个母号选为“Team 母号”，把两个现用子号选为“当前子号”，并为每个子号选择归属母号。
5. 为两个 Team 母号分别填写独立 S5。页面只显示是否已配置，不回显地址、用户名或密码。
6. 新建或编辑两个空间：每个空间选择一个 Team 母号和它当前的子号，下一子号保持为空。
7. 需要轮换时，在空间行点击“更换子号”。控制台此时才调用 Apple 创建一个全新 Alias，按空间母号绑定并继承该母号 S5，然后立即加入接力队列。
8. 接力成功后，新子号晋升为当前子号，旧子号进入“已用完”池，空间重新回到无下一子号状态。下一次点击会再次创建一个新 Alias。

使用 LokiProxy 动态链时，第 5 步改为分别保存两个母号的生成链接和 Clash 第一跳；资源池的 HME/IMAP S5 仍单独填写。动态链是 Team 工作流访问母号及其子号的出口，不能用资源池 S5 字段替代。

若 Apple 已创建并完成本地绑定，但任务暂时未能入队，空间会保留这个下一子号并显示“开始接力”；再次点击只会入队，不会重复创建 Alias。之后仍可在账号行单独覆盖新子号代理；任务开始后使用冻结的账号代理快照。

编辑资源池时，秘密输入留空表示保留已保存值，页面不会回填 Cookie、IMAP 密码或代理。更换 Session、IMAP、转发邮箱或资源池 S5 后必须重新检测；Team 母号 S5 在 Alias 列表中独立维护。

> [!WARNING]
> Hide My Email Web API 不是 Apple 官方稳定 API，Cookie 也会过期。出现“Session 失效”时，重新从已登录的 iCloud 页面复制最新 cURL/HAR，更新资源池并再次检测。控制台不会自动清理未接管 Alias，也不会在接力成功后停用或删除旧子号的远端 Alias。

## 命令行工具

除网页控制台外，项目还保留独立的协议工具：

| 命令 | 用途 |
| --- | --- |
| `python -m team_protocol analyze` | 从 HAR 提取协议时间线 |
| `python -m team_protocol convert` | 将 HAR/session 转为 CPA 格式 |
| `python -m team_protocol push` | 校验并推送 CPA 文件 |
| `python -m team_protocol invite` | 执行单步邀请 |
| `python -m team_protocol leave` | 执行单步退出空间 |
| `python -m team_protocol create-token` | 创建 PAT |
| `python -m team_protocol refresh-session` | 刷新会话 |

查看任一命令的完整参数：

```powershell
$ErrorActionPreference = 'Stop'
python -m team_protocol --help
python -m team_protocol web --help
```

## 项目结构

```text
Team-Workflow/
├─ team_protocol/
│  ├─ registrar_runtime/    # OTP、注册、代理与浏览器流程
│  ├─ web_static/           # 本地控制台前端
│  ├─ icloud_hme.py         # HME cURL/HAR 导入与 Alias 生命周期客户端
│  ├─ database.py           # SQLite 模型、事务与轮换规则
│  ├─ proxy_chain.py        # 单个 Mihomo 进程内的双 LokiProxy 动态链
│  ├─ task_queue.py         # 全局顺序队列与恢复
│  ├─ workflow.py           # 八阶段工作流
│  └─ web_console.py        # FastAPI 控制台服务
├─ tests/                   # 单元与服务层回归测试
├─ run_web.py               # 推荐启动入口
└─ requirements.txt
```

## 测试

```powershell
$ErrorActionPreference = 'Stop'
$env:PYTHONDONTWRITEBYTECODE = '1'
python -B -m unittest discover -s '.\tests' -v
```

当前测试覆盖数据库事务、并发分配、账号轮换、迁移与备份、DPAPI、macOS Keychain/AES-GCM、队列恢复、Web API、账号级独立 S5 与 SID、iCloud HME cURL/HAR、选择性 Alias 接管、母号归属与按需创建、已用完池、IMAP 精确收件与代理隔离、双账号网络隔离、单个 Mihomo 进程双 LokiProxy 链、Unix REST 分块响应、BrowserForge 持久化、Chrome major 门禁、地域时区与 UTC 时钟一致性以及双目标推送。

## 隐私发布检查

提交代码前建议执行：

```powershell
$ErrorActionPreference = 'Stop'
git status --short
git diff --cached --name-only
git grep -n -I -E 'BEGIN .*PRIVATE KEY|github_pat_|ghp_|Bearer [A-Za-z0-9._~-]{20,}' --cached
```

确保暂存区仅包含源码、测试、依赖清单和公开文档，不包含任何运行数据或真实账号信息。

## License

本项目采用 [MIT License](LICENSE)。
