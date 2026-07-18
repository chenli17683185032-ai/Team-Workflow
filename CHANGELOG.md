# 更新日志

## 2026-07-18

### 新增

- 支持把一个 iCloud 账号作为共享 HME 资源池，选择性接管已有 Alias，未选择项默认忽略且不写入本地。
- 增加永久 `Team 母号` 与 `轮换子号` 角色；每个空间绑定一个母号，母号不进入普通账号池或退役路径。
- 每个 Team 母号独立加密保存子号 S5，新建子号按母号归属继承代理。
- 空间增加“更换子号”：点击时才现场创建一个全新 HME Alias、绑定为下一子号并启动既有邀请、退出、登录和晋升流程。
- 接力成功后旧子号进入本地“已用完”池并保留累计计数；空间清空下一子号，等待下一次现场创建。
- 控制台增加远端 Alias 同步、角色与归属选择、母号 S5、空间母号绑定、已用完筛选和按母号统计。
- 支持在一个 Mihomo 进程内为两个母号建立独立 LokiProxy 动态链：各自固定本地 listener、缓存、刷新锁和 `dialer-proxy` 白名单出口，不切换全局 Clash 选择器。
- LokiProxy 生成链接与实际动态 `ip/port` 分离处理，生成配置加密保存；增加 loopback-only provider、Mihomo Unix REST reload、重启恢复和分块响应解析。

### 稳定性与安全

- 数据库升级到 schema v6，增加母号/子号归属、空间母号绑定、母号代理密文和已用完时间，并兼容 v5 无损升级与备份恢复。
- 远端同步响应不暴露 Apple `anonymousId`；导入时服务端重新读取远端列表，防止接管过期或伪造项。
- Apple 创建成功但本地持久化失败时尝试安全停用新 Alias；本地已绑定但入队失败时保留下一个子号供重试，避免重复创建。
- 接力成功不自动停用或删除旧 Alias，未接管的 20+ 历史 Alias 保持不变。
- 修复新增 iCloud 关联字段后普通邮箱库存账号视图缺少联接列导致的分配与迁移恢复回归。
- 修复 macOS `/var` 与 `/private/var` 临时目录别名导致的 CPA 产物测试误报。
- SSE 监听 Uvicorn 关闭状态并主动结束，同时增加 10 秒优雅关闭上限，避免长连接让进程退出和实例锁释放无限等待。

### 验证

- macOS：`python -B -m unittest discover -s tests -q`，232 项通过，6 项 Windows DPAPI 测试按平台跳过（共 238 项）。
- `node --check team_protocol/web_static/app.js` 与 Python `compileall`：通过。
- 临时 Mihomo Meta `v1.19.21` 实例验证双动态节点分别绑定 US/JP `dialer-proxy`，两个本地 listener 实际监听；Unix REST `PUT /configs?force=true` reload 后进程与 listener 保持可用。
- 使用模拟 Apple HME 数据验证 5 个远端 Alias 只接管所选 4 个、两个母号 S5 相互隔离、每次更换只创建 1 个新 Alias，且响应不含代理或远端标识。
- 控制台 Alias 对话框扩展为最高 1240px 的宽屏数据表；完成桌面浏览器布局验证时不会触发真实 Alias 创建。

## 2026-07-17

### 新增

- 支持 macOS 原生运行，默认数据目录为 `~/Library/Application Support/TeamWorkflowConsole`。
- macOS 使用登录钥匙串保存随机主密钥，并以 AES-GCM 加密 SQLite 中的敏感字段；Windows 继续使用 DPAPI。
- 支持为每个账号独立配置 S5 / SOCKS5 代理，并按“账号代理、全局模板、直连”的顺序回退。
- 任务分别冻结旧号和新号的加密代理快照，失败重试保持原代理不漂移。
- 支持导入 iCloud Hide My Email cURL/HAR，为每个母号独立配置 HME Session、真实转发邮箱 IMAP 和 S5。
- 支持检测母号连接、批量生成 1-20 个隐藏邮箱，以及启用或停用已接入的 Alias。
- iCloud Alias 生成后直接进入普通账号池，并继承对应母号的账号级 S5。

### 改进

- 增加 `TEAM_WORKFLOW_APP_DIR` 数据目录覆盖变量。
- macOS 终端停止 Web 服务时不再输出 `KeyboardInterrupt` traceback。
- 账号列表只暴露代理配置状态，代理 URL、用户名和密码不进入 API 响应或页面 DOM。
- 邮箱验证码轮询优先读取收件箱最新邮件，并降低垃圾箱与完整历史扫描频率。
- 邮箱请求使用剩余验证码等待时间作为超时上限，避免单次慢请求突破整体等待窗口。
- 数据库升级到 schema v5，新增认证加密的 iCloud 母号和 Alias 元数据，并纳入备份恢复验证。
- 新增 IMAP OTP Provider，以目标 Alias、邮件时间和已消费 UID 隔离同一转发邮箱中的验证码。

### 安全与隐私

- 保留既有代理隔离、旧邮件基线、别名匹配与敏感日志脱敏规则。
- HME Cookie、IMAP 密码、母号 S5 和 Apple 远端标识不进入 API、DOM、日志或 SQLite 明文。
- 本次变更及提交元数据不包含真实账号、邮箱、空间标识、令牌、密钥或本机路径。

### 验证

- macOS：`python -B -m unittest discover -s tests -v`，215 项通过，6 项 Windows DPAPI 测试按平台跳过。
- `node --check team_protocol/web_static/app.js`：通过。
- 真实 macOS Keychain 加密往返、默认数据目录启动、首页与 bootstrap、账号代理保存及正常停止均通过。
- iCloud 使用模拟 HME/IMAP 完成端到端回归，并在 `1440×900` 桌面控制台完成虚拟母号保存、密文扫描和 DOM 秘密清理验收；未使用真实 Apple 凭据或创建远端 Alias。

## 2026-07-16

### 新增

- 为 Sub2API 增加管理员 API Key、管理员密码和 TOTP 密钥的加密设置入口。
- 支持 Sub2API 登录二次验证：登录返回临时令牌后，自动生成 TOTP 验证码并换取管理员会话。
- 支持受保护管理操作的近期身份确认，在账号查重与导入前自动完成 TOTP step-up。
- 为 Sub2API 管理请求补齐用户端和管理员端上下文标识，并在错误中显示失败的请求方法、路径和服务端代码。

### 改进

- CPA 输出直接保存规范化的个人访问令牌，移除旧版会话令牌、过期时间和自定义请求头字段。
- Sub2API 推送继续保留同令牌跳过、身份冲突检测、目标分组校验和创建后验证。
- 设置页可分别安全保存或清除 Sub2API API Key、密码和 TOTP 密钥。
- 旧版配置迁移支持导入 Sub2API API Key 与 TOTP 密钥，并继续使用系统加密存储。

### 安全与隐私

- API Key、密码和 TOTP 密钥只进入加密设置，不返回明文，也加入运行日志脱敏范围。
- 运行数据库、备份、账号清单、CPA、HAR、会话和令牌导出文件继续由 `.gitignore` 排除。
- 提交前已扫描新增内容中的真实邮箱、账号标识、空间标识、本机路径、私有域名和常见密钥格式，未发现隐私数据。

### 验证

- `python -m pytest -q`：179 项测试通过，另有 11 项子测试通过。
- `node --check team_protocol/web_static/app.js`：通过。
- Sub2API 受保护推送流程已完成端到端验证，账号记录创建并校验成功。

### 使用说明

- Sub2API 自动推送需要管理员邮箱、密码和 TOTP 密钥；管理员 API Key 不能替代受保护导入端点要求的双因素会话。
- 更新运行中的控制台后需要重启本地服务，使后端加载最新认证流程。
