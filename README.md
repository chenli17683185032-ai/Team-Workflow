<div align="center">

# Team Workflow Console

**面向 Windows 与 macOS 的本地优先 Team 工作流控制台**

统一管理空间、账号轮换、顺序队列、浏览器身份快照、CPA Management 与 Sub2API 推送。

[![Python 3.11+](https://img.shields.io/badge/Python-3.11%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![Windows](https://img.shields.io/badge/Platform-Windows-0078D4?logo=windows11&logoColor=white)](#运行环境)
[![macOS](https://img.shields.io/badge/Platform-macOS-111111?logo=apple&logoColor=white)](#运行环境)
[![FastAPI](https://img.shields.io/badge/FastAPI-localhost-009688?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![Tests](https://img.shields.io/badge/tests-276%20passed-2E7D32)](#测试)
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
| iCloud 子号接力 | 一个 iCloud 资源池可接管多个永久 Team 母号；正常换班全部由子号完成，当前子号故障时才允许母号执行独立的应急提拉 |
| Team 两跳代理 | 每个 Team 可直接粘贴 CliProxy 等固定 HTTP/SOCKS 链接，并统一先经过现有本地 Clash；历史 Loki 生成源继续兼容，不写入或 reload Mihomo 配置 |
| 双目标推送 | 工作流完成后可分别推送到 CPA Management 和 Sub2API |
| 加密备份 | 数据库快照、完整性校验、系统密钥解密验证和受控恢复 |
| 本地控制台 | 仅绑定 `127.0.0.1`，写操作同时校验同源与启动期请求令牌 |

## 界面与流程

控制台围绕四个工作面组织：

1. **空间任务**：建立空间与账号对的绑定，批量加入队列，处理额度用完或账号失效。
2. **账号库**：管理 Outlook 库存、iCloud 资源池、永久 Team 母号、轮换子号和已用完池。iCloud 现场新子号会走注册，已有子号只走登录。
3. **执行队列**：观察换班或提拉的分阶段进度，调整顺序，暂停领取任务或请求停止当前运行。
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
| iCloud 资源池、母号与 Alias | 应用数据库内的独立表 | HME Cookie、IMAP 密码、各母号名下子号默认链路和远端 ID 分用途认证加密 |
| iCloud 登录浏览器 profile | 应用数据目录下的 `browser-profiles/icloud-hme/<邮箱 ID 哈希>/` | 每个资源池独立，目录权限 `0700`；包含敏感 Cookie 和本地密码管理状态，不进入 Git 或项目加密备份 |
| 加密备份 | 项目目录下的 `backups/` | 完整性校验 + 当前系统用户密钥绑定 |
| CPA / session 导出 | 项目目录下的 `output\` | 明文凭据边界，仅在显式导出时产生 |
| 邮箱源文件 | 用户选择的位置 | 仅在显式导入时读取，不由应用自动删除 |

仓库的 `.gitignore` 默认排除以下内容：

- 邮箱或账号 TXT；
- HAR、CPA、session、PAT 与工作流 JSON；
- SQLite 数据库、加密备份、运行输出和日志；
- 本地迁移状态、内部分析报告与验收产物。

> [!IMPORTANT]
> `output/` 中的 CPA、Sub2API 和 session 文件属于明文凭据。只在需要时生成，用完后及时删除，禁止提交到版本控制。

可用 `TEAM_WORKFLOW_APP_DIR` 覆盖默认应用数据目录。该变量只改变数据库和实例锁位置，不会移动或导出系统密钥。

可用 `TEAM_WORKFLOW_LOCAL_CLASH_PROXY` 覆盖所有 Team 代理中继共用的 Clash 第一跳；macOS 默认值为 `http://127.0.0.1:7897`。控制台不会写入或 reload Clash 配置。

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
02 校验成员上限并邀请新号
03 旧号退出并确认
04 新号注册入组
05 复核活跃成员不超过 2
06 创建令牌
07 导出 CPA
08 导出 Sub2API JSON
09 推送 CPA（可选）
10 推送 Sub2API（可选）
```

队列在每个阶段保存 checkpoint。进程异常退出后可以恢复同一次运行，避免重复邀请、重复退出或重复创建远端资源。邀请前必须满足活跃成员不超过 2 且不存在其他待接受邀请；旧子号退出后会等待远端成员反馈，只有旧号已消失且剩余成员少于 2，或本次新号已在两名成员之中，才允许继续新号登录/恢复。新子号入组后再次要求总人数不超过 2、旧号缺席且新号存在，验证完成前不能创建 PAT 或提交轮换。

PAT 创建成功后，本地始终生成 CPA 与 Sub2API 两个 `0600` 文件；Management 和 Sub2API 管理员配置只控制后续可选推送，不会阻断本地导出。Sub2API 文件采用 `exported_at / proxies / accounts` 结构，`credentials.access_token` 使用本次 Team 新建的 PAT，Session 只用于补充账号身份，不写入 `sessionToken`。

账号首次参与任务时会先分配稳定 SID，通过该账号代理解析出口国家和 IANA 时区，再生成并加密保存 SessionProfile、BrowserForge 完整 payload 和工具链版本。旧号、新号分别使用独立代理、指纹和 curl 会话；账号由下一账号晋升为当前账号后仍复用原身份。任务开始时会确认代理地域解析、IANA 时区和 UTC 时钟有效；当前出口与已保存地域或语言发生漂移时继续使用账号已锁定的身份。出口 IP 不保存、不写入日志，代理 userinfo 在日志中整体掩码。

在 iCloud 母号空间中，正常“一键换班”的以上十个阶段始终由当前子号和下一子号执行。母号日常仅作为空间归属、子号默认链路和 HME 资源池生成配置的锚点，不会参与正常换班。只有当前子号故障且用户明确点击“提拉”时，独立应急状态机才登录母号、逐人清退其他成员、邀请现场新建的子号，并在远端确认恰好只剩母号与新子号两人后继续创建 PAT 和提交轮换。

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
| Team 母号 | 从已有 Alias 中接管并永久保护；日常只做归属锚点和配置，只有“提拉”可让它登录、清退成员并邀请新子号；不进入普通账号池、轮换或已用完池 |
| 轮换子号 | 归属一个 Team 母号，继承该母号名下子号的默认链路，作为空间当前子号或下一子号，实际执行全部 Team 操作 |
| 已用完池 | 接力成功后的旧子号只在本地标记并保留计数，不自动删除或停用远端 Alias |

每个空间固定绑定一个 Team 母号。正常接力由当前子号完成：当前子号邀请现场创建的新子号，随后退出空间；新子号登录并确认空间后晋升为当前子号。空间平时不预建、不占用下一子号。Team 行保留三个明确入口：“一键换班”执行正常子号接力，“编辑配置”只维护该组的子号默认代理，“提拉”仅用于当前子号已经无法工作的紧急恢复。

### 准备信息

1. 推荐直接使用控制台的“登录更新 HME”：应用会打开独立的可见 Chrome for Testing 窗口，并自动进入 Apple 登录页。首次在其中登录 [中国区 iCloud](https://www.icloud.com.cn/) 并完成双重验证后，同一资源池会长期复用该浏览器的 Cookie 和设备信任状态。登录验证成功后，应用优先等待 `GET /v2/hme/list`，即使 Hide My Email 子页面打不开，也会用当前 Cookie 做一次 HME 只读校验并自动保存。
2. 准备隐藏邮箱实际转发到的邮箱 IMAP 信息。使用 iCloud Mail 时，通常为 `imap.mail.me.com:993`、完整 iCloud 邮箱地址，以及在 [Apple Account](https://account.apple.com/) 生成的 App 专用密码；其他邮箱使用对应服务商的 IMAP 参数。iCloud 转发 OTP 最长等待 90 秒，资源池代理显式留空时 IMAP 不会继承子号工作流代理。
3. 按需准备资源池的 HME / IMAP S5。若希望 iCloud HME 直连，保持此字段为空；应用会显式忽略系统 `HTTP_PROXY/ALL_PROXY` 环境变量。若使用代理，建议填写稳定的 `socks5h://user:password@host:port`，不要使用会频繁轮换的动态源。
4. 分别准备每个 Team 的代理。可以粘贴完整的 `http://user:password@host:port` / SOCKS5 URL，也可以直接粘贴供应商给出的 `curl -x HOST:PORT -U "USER:PASS" TARGET` 或 `curl --socks5 HOST:PORT -U "USER:PASS" TARGET`；历史 Loki `/gen` 链接继续兼容。curl 文本只做受限参数解析，不会执行，探针目标也不会保存。新建子号会按归属继承对应本地中继地址，这不是母号登录代理。

#### 所有 Team 代理共用 Clash 第一跳

控制台为每个母号创建一个仅绑定 `127.0.0.1` 的轻量 SOCKS5 中继。每条中继都先通过本机现有 Clash 连接该组的固定 HTTP/SOCKS 或动态代理，再由第二跳访问目标：

```text
工作流 A -> 本地中继 A -> Clash 127.0.0.1:7897 -> CliProxy/代理 A -> 目标
工作流 B -> 本地中继 B -> Clash 127.0.0.1:7897 -> CliProxy/代理 B -> 目标
```

在“同步 Alias”“导入新母号”或已接管母号的“子号默认链路”对话框中，可粘贴完整 HTTP/SOCKS 代理 URL，或带 `-U` 认证的 `curl -x` / `curl --socks5` 命令。页面会把命令规范化为代理 URL 后加密保存，并固定使用 `Clash 两跳`；只读的“Clash 第一跳”默认是 `http://127.0.0.1:7897`，不能给不同 Team 各选一个第一跳。

固定代理端点连接和历史生成 API 请求都会经过这个统一前置，因此要求受支持来源 IP 或白名单的代理渠道可以使用 Clash 出口。需要切换 Clash 出口时直接在 Clash 中操作；控制台不创建第二个 Clash，不写入 listener/provider/dialer-proxy，不调用 reload，也不覆盖选择器。

如本机 Clash 端口不同，可通过 `TEAM_WORKFLOW_LOCAL_CLASH_PROXY` 覆盖统一前置。HME / IMAP 仍按资源池自己的直连或独立 S5 设置运行，不进入上述工作流链路。

自动捕获为每个 iCloud 资源池使用一个隔离的持久 Chrome for Testing profile，不读取你日常使用的 Chrome profile，也不在不同 iCloud 资源池间共享状态。捕获完成、取消或超时后应用会关闭浏览器进程，但保留 profile 中的 Cookie、站点存储、Apple 设备信任和本地密码管理数据，供下次登录复用。该目录位于 Git 工作区外、权限为 `0700`，不进入项目加密备份；应当按照已登录浏览器处理这个敏感目录。应用不接收或记录 Apple 密码、验证码或 2FA 内容，也不保存 HAR、截图或额外 storage state；只把通过白名单校验并经过 HME 只读列表验证的最小 Session 加密写入资源池。Apple 仍可根据服务端策略让 Cookie 过期或再次要求 2FA。

手动导入仍然可用：如果自动捕获无法启动，在已登录的 iCloud 页面 Network 中找到 `/v2/hme/list`，使用“Copy as cURL”或导出 HAR，再在资源池编辑窗口粘贴。控制台只解析允许的 Apple HME host/path，导入原文不落盘。

### 控制台操作

1. 首次使用时，在“账号库”的“iCloud 隐藏邮箱”中添加资源池，填写真实转发邮箱、IMAP 参数和可选的 HME / IMAP S5。HME Session 可通过“登录更新 HME”自动捕获，也可手动粘贴 cURL/HAR。
2. 回到“空间任务”，点击“导入新母号”，选择 iCloud 资源池后点击“一键读取 iCloud”。Session 失效时会自动打开登录捕获，验证成功后回到同一导入向导。
3. 从完整远端快照中选择一个 Team 母号和它当前的子号，再填写 Team 名称并直接粘贴该组的 CliProxy/完整代理链接。提交时控制台自动经 Clash 第一跳使用当前子号收取 OTP 并只读登录，识别同时包含母号与当前子号且恰好为 2 人的唯一 Team；校验通过后才接管这两条 Alias，其他废 Alias 仍只展示。Workspace ID、Session、Token 和成员明细不需要手填，也不会进入普通日志或页面。
4. 正常轮换点击 Team 行的“一键换班”。控制台现场创建一个新 Alias，沿用当前子号标签的末尾编号递增，并严格执行“旧号登录 -> 校验成员并邀请 -> 旧号退出反馈 -> 新号注册入组 -> 两人复核 -> PAT / CPA / Sub2”。母号不会参与正常换班。
5. “账号库”的刷新按子号状态执行两种闭环。正在使用的当前子号若令牌中途失效，直接点击“刷新”：控制台优先复用 browser cookie，失效时回退邮箱 OTP，随后新建 PAT 并把新的 Sub2API JSON 导出到设置的输出目录，不邀请、不退出、不改变 Team 成员。若新账号已经创建但自动读取 ChatGPT session 失败，则为失败下一子号点击“刷新”并选择手工导出的 Sub2API JSON；本地核对邮箱、Team workspace 与 PAT 类型后自动重试原 run，不会再次注册。
6. 代理源或 Clash 前置异常时点击“编辑配置”。该入口只修改该母号名下的子号默认链路，不登录 Team、不邀请、不退出，也不改变成员。
7. 只有当前子号已经故障时才点击“提拉”。母号会登录 Team，逐人清退除母号外的成员并逐次读取远端确认；只剩母号 1 人后才邀请并登录现场新建的子号，最终必须恰好为母号与新子号 2 人。
8. 换班或提拉成功后，新子号晋升为当前子号，旧子号进入“已用完”池，空间重新回到无下一子号状态。下一次操作会再次现场创建一个新 Alias。
9. 第二个母号重复同一导入流程。控制台会用它所选的当前子号独立识别对应 Team；零匹配、多匹配、成员超员或列表不完整都会停止，不会猜测或复用另一个 Team 的 ID。

新子号登录成功后，控制台会把最小的 ChatGPT browser session cookie 加密绑定到该子号。它成为当前子号后，下一次接力优先复用这份会话；若 cookie 已失效则清除并回退邮箱 OTP。只有下一次接力完成、旧子号退出并提交轮换时，旧子号 cookie 才会与退役状态一起原子删除。完整 Cookie jar、浏览器 profile 和 token 不会进入账号列表、API 或日志。

当前子号刷新时，第一次点击会立即把账号行切换为“刷新中…”并展开底部执行栏；其中以实时详细日志显示本地时间、当前阶段、级别和每一步脱敏消息。正常接力和母号提拉使用同一日志框，不再用步骤卡概括执行过程。日志位于底部时自动跟随新消息，向上查看历史时保持阅读位置，可用向下按钮回到最新；账号表被实时事件重绘后刷新按钮仍保持禁用。同账号成功后 60 秒内的重复请求只返回刚才的导出路径，不会再次创建 PAT，操作结束后日志框继续保留最后状态、脱敏错误和输出路径。

本地直连测试只验证网络可达性，不会自动延长 Apple Session。Session 失效时，点击“登录更新 HME”重新登录即可自动捕获或验证最新会话，不必强行打开隐藏邮箱子页面；如果直连后仍立即失效，应优先检查 Apple 登录状态和 Cookie，而不是反复点击检测。

若 Apple 已创建并完成本地绑定，但任务暂时未能入队，空间会保留这个下一子号并显示“开始接力”；再次点击只会入队，不会重复创建 Alias。之后仍可在账号行单独覆盖新子号代理；任务开始后使用冻结的账号代理快照。

编辑资源池时，秘密输入留空表示保留已保存值，页面不会回填 Cookie、IMAP 密码或代理。更换 Session、IMAP、转发邮箱或资源池 S5 后必须重新检测；Team 行的“编辑配置”保留用于修正对应组的子号默认链路。

> [!WARNING]
> Hide My Email Web API 不是 Apple 官方稳定 API，Cookie 也会过期。出现“Session 失效”时，使用“登录更新 HME”重新捕获并检测；自动捕获不可用时再复制最新 cURL/HAR。控制台不会自动清理未接管 Alias，也不会在接力成功后停用或删除旧子号的远端 Alias。

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
│  ├─ proxy_chain.py        # 统一 Clash 第一跳与按母号隔离的通用代理中继
│  ├─ task_queue.py         # 全局顺序队列与恢复
│  ├─ sub2api.py            # PAT + Session 的 Sub2API 导出与可选推送
│  ├─ workflow.py           # 十阶段接力、两人上限复核与凭据导出工作流
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

当前测试覆盖数据库事务、并发分配、账号轮换、迁移与备份、DPAPI、macOS Keychain/AES-GCM、队列恢复、Web API、账号级独立 S5 与 SID、iCloud HME cURL/HAR、登录后 HME 自动捕获状态机、按资源池隔离的持久登录 profile、Sentinel 预取总时限与超时回收、可见 Chrome/CDP、认证 Cookie 回退与只读 Session 验证、Workspace 自动识别与两人唯一匹配、选择性 Alias 接管、幂等 Team 导入、母号归属与按需创建、已用完池、IMAP 精确收件与代理隔离、现场新号注册、失败下一子号 JSON 恢复、当前子号 PAT 刷新、刷新幂等与详细日志、子号 browser cookie 生命周期、正常子号换班、外部 iCloud 晋升、母号应急提拉、逐人清退反馈、Team 两人硬上限、无关待邀请阻断、退出前成员反馈、入组后成员反馈、双账号网络隔离、统一 Clash 第一跳、固定 HTTP/SOCKS 与受限 curl 命令输入、历史动态源字节流中继、TTL 缓存与并发隔离、BrowserForge 持久化、Chrome major 门禁、地域时区与 UTC 时钟一致性、PAT + Session 的 Sub2API 导出、私有原子文件恢复以及双目标可选推送。当前为 312 项测试，其中 306 项通过，6 项 Windows DPAPI 测试按 macOS 平台跳过。

## 隐私发布检查

提交代码前建议执行：

```powershell
$ErrorActionPreference = 'Stop'
git status --short
git diff --cached --name-only
git grep --cached -n -I -E 'BEGI[N] .*PRIVATE KEY|github[_]pat_|gh[p]_|Beare[r] [A-Za-z0-9._~-]{20,}'
```

确保暂存区仅包含源码、测试、依赖清单和公开文档，不包含任何运行数据或真实账号信息。

## License

本项目采用 [MIT License](LICENSE)。
