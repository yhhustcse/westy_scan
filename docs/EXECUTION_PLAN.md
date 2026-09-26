# westy_scan 执行方案（Execution Plan）

> 配套文档：架构与取舍见 `DESIGN.md`，用法见 `README.md`。
> 工作量以「1 名熟悉 Go 的安全工程师」为基准估算，单位：人日。

---

## 0. 里程碑总览

| 里程碑 | 目标 | 交付物 | 工作量 | 状态 |
| --- | --- | --- | --- | --- |
| **M0 骨架与合规闸门** | 端到端闭环可跑，合规控制到位 | 本仓库 v0.1 | 1–2 | ✅ 已交付 |
| **M1 端口与服务识别强化** | 更快、更准的服务识别 | 协议握手探针、UDP、SYN、基准 | 2–3 | ✅ 已交付（SYN 仅 Linux） |
| **M2 Web 指纹与资产测绘增强** | Web 资产刻画更完整 | favicon mmh3、CDN/WAF 识别、证书 SAN 联动、规则合并 | 3 | ✅ 已交付（目录/子域爆破推迟） |
| **M3 爬虫强化** | 端点与参数发现 | robots/sitemap 入口、表单参数清单、JS 抽取、SimHash 去重 | 4 | ✅ 已交付（无头浏览器推迟） |
| **M4 POC / 模板引擎** | 漏洞发现与验证 | 模板 DSL、匹配器、误报控制、OOB 外带 | 8–10 | ✅ 已交付（DNS 型 OOB 与 nuclei DSL 未做） |
| **M5 分布式 Server/Agent** | 规模化与断点续扫 | 任务切片/租约重派、结果汇聚、断线缓冲 | 10–15 | ✅ 已交付（HTTP+JSON 替代 gRPC） |
| **M6 平台化** | 团队可用 | Web UI、变更对比、报告中心、RBAC + 授权书绑定、通知、持久化 | 15+ | ✅ 已交付（无多租户隔离、无 PDF、无 SSO） |
| **M7 规则库扩张** | 弹药（检出能力） | 指纹 41→256 条、模板 13→130 条、金丝雀门禁 | 5–8 | ✅ 已交付（未经真实目标校准） |
| **M8 工程化补强** | 可被别人验证 | git + CI + LICENSE、覆盖率补课（10 个 0% 包）、7 个缺陷修复 | 2–3 | ✅ 已交付（CI 未在 GitHub 实跑） |

**建议节奏**：M0→M1→M2→M3 连续做完（约 10 人日）就能形成"内网测绘 + Web 攻击面盘点"的
可用工具；M4 是一个独立的、需要严格质量控制的阶段（误报是 POC 引擎的生死线），
建议在 M0–M3 稳定运行 2 周后再启动。

---

## M0 骨架与合规闸门（本次交付）

### 目标
一条能跑通的闭环流水线 + 不可绕过的合规控制 + 可扩展的模块边界。

### 任务清单
- [x] `go.mod`（零第三方依赖，`go 1.21`）
- [x] `internal/model`：统一资产模型、去重 Key、Web 判定
- [x] `internal/scope`：授权闸门（authorized 强制、allow/deny、CIDR/域名、DNS 缓存、解析后复检）
- [x] `internal/ratelimit`：全局令牌桶
- [x] `internal/target`：URL/CIDR/域名解析、端口组、CIDR 规模熔断
- [x] `internal/portscan`：TCP connect 扫描 + Banner 抓取 + 协议探测载荷
- [x] `internal/httpinfo`：HTTP(S) 探测、标题/关键头/证书、连接池复用
- [x] `internal/fingerprint`：声明式规则引擎 + 40 条内置规则 + JSON 外置规则
- [x] `internal/crawl`：BFS 并发爬虫、Cookie Jar、同域限制、端点/表单抽取
- [x] `internal/pipeline`：阶段编排、Web 并发收敛、种子管理、统一落库与审计
- [x] `internal/store`：Store 接口 + 内存去重 + JSONL 流式 + Multi
- [x] `internal/report`：table/json/jsonl/markdown + 统计
- [x] `internal/audit`：JSONL 审计
- [x] `internal/config`：JSON 配置 + 参数体检
- [x] `cmd/westy`：CLI（参数覆盖配置、`-list-rules`、信号取消）
- [x] 单元测试：scope / target / crawl
- [x] 脚本：`build.ps1` / `test.ps1` / `demo-local.ps1`、`Makefile`
- [x] 文档：`README.md` / `docs/DESIGN.md` / `docs/EXECUTION_PLAN.md`

### 验收标准（在装有 Go 1.21+ 的机器上执行）
```bash
go vet ./... && go test ./... -race        # 1) 静态检查与单测通过
powershell -ExecutionPolicy Bypass -File scripts/build.ps1               # 2) 编译出 bin/westy.exe
./bin/westy -version                       # 3) 版本输出
./bin/westy -target 127.0.0.1 -authorized  # 4) 无 allow 时给出告警并放行（非严格模式）
./bin/westy -target 127.0.0.1              # 5) 缺 -authorized：必须拒绝启动，退出码 1
./bin/westy -target 127.0.0.1 -allow 10.0.0.0/8 -authorized   # 6) 目标全部被拦截：退出码非 0
powershell -ExecutionPolicy Bypass -File scripts/demo-local.ps1          # 7) 本地闭环：扫到开放端口 + Web 标题 + 爬虫页面
cat out/audit.jsonl                        # 8) 审计日志含 run_start/port_open/web_alive/run_finish
```
第 5、6 条是**合规回归测试**：任何后续改动都必须保持"未授权拒绝启动、越界目标拒绝扫描、
且范围配错时显式失败而不是静默返回空结果"。

### M0 验证记录（真实执行结果）

在 Windows + Go 1.27.1（便携版，装于 `.tools/go`）环境下实际执行：

| 检查项 | 命令 | 结果 |
| --- | --- | --- |
| 编译 | `go build ./...` | ✅ exit 0 |
| 静态检查 | `go vet ./...` | ✅ exit 0 |
| 代码格式 | `gofmt -l .` | ✅ 无未格式化文件 |
| 单元测试 | `go test ./... -count=1` | ✅ exit 0（crawl / fingerprint / scope / target 四个包全过） |
| 竞态检测 | `go test ./... -race` | ✅ exit 0（并发模型无数据竞争） |
| 构建产物 | `go build -o bin/westy.exe ./cmd/westy` | ✅ 10.33 MB |
| 端到端 | 本机 Python 靶站 127.0.0.1:18080 + `-crawl` | ✅ 端口 → HTTP(200) → 指纹(service=http) → 爬虫(首页/admin.html/表单 action) 全链路，产出 JSONL + 审计 |
| 合规 A | 缺 `-authorized` | ✅ 拒绝启动，exit 1 |
| 合规 B | 目标 `127.0.0.1` 而 allow 为 `10.0.0.0/8` | ✅ 目标被拦截，exit 1 |
| 合规 C | `-strict-scope` 但未配 allow | ✅ 拒绝启动，exit 1 |
| 验证脚本 | `scripts/verify.ps1` | ✅ 0 个失败步骤，日志落 `out/verify.log` |

以上全部在 **零第三方依赖 + `GOPROXY=off`** 条件下完成，说明隔离网环境可直接编译运行。

真实运行暴露并已修复的 5 个缺陷（这正是"必须真跑一遍"的价值）：

1. **IPv6 归一化 bug**：`NormalizeHost("http://[2001:db8::1]:8080/")` 先剥方括号再解析端口，
   导致 `SplitHostPort` 失配、返回 `2001:db8::1]:8080`。已改为"先识别方括号分支"。
2. **非标准端口 Web 服务漏检**：18080 上的 HTTP 服务因不在内置端口表且无 Banner 被跳过，
   爬虫拿不到种子。已引入 `blind_web_probes`（默认 500 次配额）对无 Banner 端口盲试一次 HTTP。
3. **范围全灭时静默成功**：所有目标被拦截时原先 exit 0，自动化场景会把"配错授权范围"
   误判为"扫完无结果"。现在会返回显式错误并非零退出。
4. **指纹误报（最严重）**：规则里的 `x-application-context: ".*"` 等匹配器对**不存在的响应头**
   取到空串，而 `.*` 匹配空串 → Python 静态站被同时误报成 `Spring Boot / WebLogic / GitLab`。
   修复：匹配前判空 + 内置规则收紧为 `.+`，并补 `internal/fingerprint` 回归测试 7 个用例。
   附带修掉"存活 Web 资产 service 为空"的展示缺陷（无产品指纹时兜底填 `http`/`https`）。

> 第 4 条印证了 DESIGN 第 11 节的判断：**误报是 POC 引擎的生死线**，
> 因此 M4 必须把"零误报"作为硬性验收指标，而不是"召回率优先"。

5. **PowerShell 脚本编码陷阱（工程环境问题，非 Go 代码）**：Windows PowerShell 5.1 会把
   UTF-8 **无 BOM** 的 `.ps1` 按系统 ANSI（中文机器上是 GBK）读取，中文注释/字符串被拆坏，
   导致 `test.ps1` 解析失败（`The string is missing the terminator`）。
   修复：所有 `.ps1` 统一保存为 **UTF-8 with BOM**，文档中的调用方式改为
   `powershell -ExecutionPolicy Bypass -File`（PowerShell 5.1 与 7 均可用）。

### M0 结论
M0 验收清单 **11 项全部通过**，可以进入 M1。

### 风险
- DSH 沙箱的受限模式禁止创建管道，Go 工具链（需管道驱动 compile/vet 子工具）无法编译；
  放宽文件策略或使用普通开发机即可，与代码本身无关。
- Banner 抓取在部分服务上会触发噪声日志（正常，属探测行为）。

---

## M1 端口与服务识别强化（2–3 人日）——✅ 已实施

### 目标
把"能扫"变成"扫得快、认得准"。

### 任务与实际落地
1. **扫描方式可插拔** ✅
   - `portscan.Scanner` 接口 + `NewScanner(mode)`；`connect` 为默认实现；
   - SYN 半开扫描：`syn_packet.go`（构包/校验和/拆包，跨平台可单测）+ `syn_linux.go`
     （原始套接字，需 root/CAP_NET_RAW）；非 Linux 由 `syn_other.go` 显式拒绝，
     不做"静默降级"；SYN 实现已通过 `GOOS=linux go build ./...` 交叉编译验证。
   - 原计划用 `golang.org/x/net/bpf`，实际**改用标准库 syscall**，保持零第三方依赖。
2. **UDP Top-N** ✅ DNS(53)/NTP(123)/SNMP(161)/NetBIOS(137)，
   手工构造报文 + 解析响应；UDP 无连接，"有响应即命中、超时即未知"，
   依据写进 `Evidence` 与 `meta.confidence_reason`，并降级为 medium（除结构化应答外）。
3. **服务识别增强** ✅
   - 新增 `internal/probe`：SSH / FTP / SMTP / MySQL / MariaDB / PostgreSQL / Redis / Memcached /
     VNC / SMB2 / RDP / MongoDB / TLS 共 13 类协议握手解析；
   - 端口≠服务纠正：Web 端口上 HTTP/HTTPS 都不通时回落到协议探针；
   - 引入 `model.Confidence`（high/medium/low）+ `model.Evidence`，置信度只升不降。
4. **性能** ✅
   - `scope.PreResolve` 并发预热 DNS（合规判定仍由 Guard 在发包前完成）；
   - `internal/sysinfo` 检查 `RLIMIT_NOFILE`，低于需求时启动告警；
   - 基准测试 + `docs/benchmark.md`（本机 1000 端口 ≈ 30,905 ports/s）。

### 验收（实测，全部在本机执行）
| 检查项 | 命令 | 结果 |
| --- | --- | --- |
| 编译 / 静态检查 / 格式 | `go build ./...`、`go vet ./...`、`gofmt -l .` | ✅ 全部通过（零第三方依赖，`GOPROXY=off`） |
| 单元测试 | `go test ./... -count=1` | ✅ 8 个包、92 个用例全过 |
| 竞态检测 | `go test ./... -race` | ✅ 通过（含并发 UDP 假服务端场景） |
| Linux 交叉编译 | `GOOS=linux go build ./...` | ✅ 通过（SYN 扫描器） |
| **协议识别（TCP+UDP）** | `scripts/demo-m1.ps1` | ✅ **7/7、置信度全 high**：OpenSSH 9.6p1 / MySQL 8.0.35 / PostgreSQL / Redis 7.2.4 / Memcached 1.6.17 / VNC 3.8 / UDP DNS |
| Web 闭环回归 | `scripts/demo-local.ps1` | ✅ 端口 → HTTP → 指纹 → 爬虫 → JSONL/审计 |
| 合规回归 A/B/C | 缺授权 / 越界目标 / strict 缺 allow | ✅ 三种情况均 exit 1 |
| 合规回归 D | Windows 上 `-scan-mode syn` | ✅ exit 1 且提示"仅支持 Linux（需要 root 或 CAP_NET_RAW）" |
| 吞吐基准 | `go test ./internal/portscan -bench .` | ✅ 31,368 ports/s（本机 1000 端口），详见 `docs/benchmark.md` |

> 离线环境无法使用 vulhub，改用 `scripts/fake-services.py`（本地假服务，只监听 127.0.0.1）
> 做等效验收：它按真实协议构造握手报文（MySQL 8.0.35 握手包、SMB2 NEGOTIATE、
> VNC RFB 版本+安全类型、Redis INFO、DNS 应答等），因此验证的是解析器的真实能力。
> `/16 × 1000 端口的真实网络基准需要在授权网段执行，本环境不具备条件，已在文档中给出推算公式。

### M1 暴露并修复的缺陷（真跑一遍的价值）
1. MySQL 握手解析少跳过 13 字节的 `auth-plugin-data-part-2` → 认证插件名被污染；
2. VNC 版本号未归一化（`003.008` → 应为 `3.8`），且**回送时必须用线格式**，
   否则真实 VNC 服务端会直接断开握手；
3. 测试代码 `for range ConnectScanner{}.Scan(...)` 触发 Go 复合字面量歧义
   （`go build` 不编译测试文件，只有 `go vet`/`go test` 才暴露）；
4. 未知端口一律做协议探测会浪费往返 → 改为"只对有专用探针的端口直接探测，
   未知端口交给 Web 路径，失败后再回落"，把 TLS 探测的收敛超时限制在 1.5s；
5. **UDP `finalize` 漏写 `Product`/`Version`/`Confidence`**：产品名只进了 `Products` 列表，
   主字段全空 —— 这类"字段映射漏一个"的 bug 只有跑端到端用例才会暴露；
6. **NetBIOS 名字表偏移错 1 字节**（应为 15 字节名字 + 1 字节后缀 + 2 字节标志），
   导致名字里混入后缀字节、工作组识别不出来；同时答案段缺少**压缩指针**支持；
7. **NTP 时间戳偏移与纪元换算错误**：Transmit 时间戳在报文偏移 40（代码读成了 28），
   且把 32 位秒字段的低 16 位当小数处理；
8. 测试侧的两个反向问题（同样值得记录）：假 UDP 服务端串行处理请求导致并发用例永远测不出并发；
   以及畸形用例里手工计算的字段偏移本身就写错了。

---

## M2 Web 指纹与资产测绘增强（3 人日）——✅ 已实施

### 任务与实际落地
1. **favicon mmh3** ✅
   - 新增 `internal/favhash`：按 python-mmh3 逐位复刻 MurmurHash3 x86_32，
     **零依赖**；提供两种社区约定：`ShodanHash`（base64 每 76 字符换行 + 结尾换行后取 mmh3）
     与 `RawHash`（原始字节，FOFA/hunter 约定），两者都写进资产。
   - 回归向量：`mmh3("")=0`、`mmh3("foo")=-156908512`、`mmh3("hello")=613153351` 全部对齐。
   - `httpinfo` 只在 HTML 页面上抓 favicon：优先 `<link rel="icon">`，回落 `/favicon.ico`，
     并排除"200 + HTML 404 页面"这种常见陷阱。
2. **CDN / WAF 识别** ✅
   - 新增 `internal/cdn`：**纯被动**识别（CNAME 后缀 + 响应头 + Set-Cookie 名），
     覆盖 Cloudflare / Akamai / Fastly / CloudFront / Azure FD / 阿里云 / 腾讯云 / 网宿 /
     百度云加速 / Sucuri / Imperva / F5 / ModSecurity / 安全狗 / 网防G01 / 华为云 WAF；
   - 输出 `CDN`、`WAF`、`BehindCDN` 与 `OriginNote`（"边缘 IP 不代表源站，需在授权范围内
     通过证书 SAN / 历史解析确认，**本工具不主动绕过 WAF**"），判据写进 `evidence` 与审计事件 `cdn_detected`。
3. **证书联动** ✅
   - 从 TLS 证书 SAN 提取域名 → 作为候选纳入扫描（`-san-expand`，默认开，上限 `-san-max-hosts=100`）；
   - **每个候选域名单独过授权闸门**：越界的记 `san_rejected` 审计并跳过，
     通配符证书只做标记不直接扫；已处理主机集合防止 SAN 回环。
4. **规则合并 / enabled** ✅
   - `-rules` 现在是**合并**语义（同名外置规则覆盖内置），`-no-default-rules` 才只用外置规则；
   - `Rule.Enabled`（`enabled:false` 临时停用）、`Rule.FaviconHash`（按 favicon 指纹识别自研系统）。
5. **置信度落地** ✅
   - 规则级别 `confidence`（缺省：特征串 medium、纯端口 low、显式声明优先），
     命中时写入 `Asset.Confidence` 与 `evidence: rule:<名称>`；
   - 存活 HTTP 响应本身记为 `high`（结构化实证），与 M1 的握手结果同级。
6. **目录/子域爆破（可选）——本轮未做（有意推迟）** ⏸
   - 理由：这是**高噪声主动动作**，需要独立词表、强制限速与 `--i-understand-noise` 双重开关，
     并要在审计里单独分级；在 POC 引擎（M4）的误报控制框架落地前做它，收益/风险不划算。
   - 已把接口位置留好：新增模块只需实现 `model.Asset` 流并挂到流水线阶段位。

### 验收（实测）
| 检查项 | 命令 | 结果 |
| --- | --- | --- |
| 编译 / 静态检查 / 格式 | `go build ./...`、`go vet ./...`、`gofmt -l .` | ✅ 全部通过 |
| 单元测试 | `go test ./... -count=1` | ✅ 12 个包、121 个用例全过 |
| 竞态检测 | `go test ./... -race` | ✅ 通过 |
| Linux 交叉编译 | `GOOS=linux go build ./...` | ✅ 通过 |
| M2 端到端（假站点） | `scripts/demo-m2.ps1` | ✅ favicon mmh3=1407517096、CDN/WAF=Cloudflare、BehindCDN=true、源站提示与判据链完整 |
| M2 流水线集成测试 | `go test ./internal/pipeline -run M2 -v` | ✅ favicon + CDN + 证书 SAN 联动；越界 SAN 被 `san_rejected` 拦截且未产生扫描动作 |
| 规则合并 | `go test ./internal/fingerprint -run Merge -v` | ✅ 同名覆盖 / `-no-default-rules` 只用外置规则 / `enabled:false` 生效 |

> favicon 哈希的"与社区工具一致"是通过**算法级回归向量**保证的（mmh3 已知向量 + base64 换行约定），
> 而不是靠某个站点的单点比对；真实站点的交叉验证需要在授权范围内进行（本环境无此条件）。

### M2 暴露并修复的缺陷
1. **明文 HTTP 打到 TLS 端口时未回退 https**（集成测试才暴露）：Go/nginx/Envoy 对明文请求
   打到 TLS 端口会回 `400 Bad Request` + "sent an HTTP request to an HTTPS server"，
   原逻辑把这个 400 当成"成功的 HTTP 资产"记下来，导致**非标准端口的 HTTPS 资产被误判**。
   修复：识别该特征后改用 https 重试。
2. `httpinfo` 的 `<link rel="icon">` 正则**缺少整体捕获组**，`FindSubmatch` 取不到标签内容 →
   favicon 抓取静默失效（只会在断言哈希的测试里暴露）。
3. 测试侧：`httpsRequired` 场景最初被写成"期望 400 也是资产"，属于**测试掩盖了实现缺陷**，
   已改为断言"必须回退到 https 并拿到 200"。

---

## M3 爬虫强化（4 人日）——✅ 已实施

### 任务与实际落地
1. **站点地图入口** ✅ 新增 `internal/seed`：
   - `robots.txt` 解析（`Disallow`/`Allow`/`Sitemap`/`Crawl-delay`，容忍注释与畸形行）；
   - `sitemap.xml` 解析，**同时支持 `<urlset>` 与 `<sitemapindex>` 嵌套索引**，支持 `.xml.gz`；
   - 相对地址（robots 里的 Sitemap、sitemap 里的 loc）统一按所在文档解析成绝对地址；
   - `Disallow` 默认**只作为敏感路径情报**记入审计事件 `robots_disallow`，不主动请求；
     要请求须显式打开 `-sitemap-disallow`，且仍受授权范围与全局限速约束。
2. **表单与参数清单** ✅
   - `model.Form{Action, Method, Fields}` 结构化落盘，action 解析为绝对地址、实体还原；
   - `Asset.Params` 汇总查询串参数 + 表单字段名，报告输出 Top-20 参数清单
     —— 这就是 M4 注入类模板的输入面。
3. **JS 抽取** ✅ 新增 `internal/crawl/js.go`（纯文本，不执行 JS）：
   - 内联 `<script>` **零额外请求**，默认开启；
   - 外链 `.js` 受 `-crawl-max-js`（默认 50）限制，产出一类 `source=crawl-js` 资产；
   - 抽 `fetch/axios/$.ajax/XHR.open` 的目标、引号里的接口路径与绝对 URL（过滤静态资源）；
   - 疑似凭据识别：AWS AKID、Google API Key、GitHub/Slack Token、JWT、私钥块、Bearer、硬编码口令字段；
     **一律掩码落盘**（`AKIA********MPLE(20字符)` + 来源），只留类型/位置/指纹，不把活凭据写进报告。
4. **无头浏览器** ⏸ 本轮未做（有意推迟）
   - 原因：chromedp 是第三方依赖，引入后默认构建不再零依赖；离线环境无法拉取与验证。
   - 已留好位置：`-crawl-engine headless` 会**明确报错并说明需要用 `-tags headless` 构建**，
     而不是静默降级；接入时只需让新引擎产出同样的 `crawl.Page`。
5. **重复内容去重** ✅ 新增 `internal/simhash`：
   - 64 位 SimHash（FNV-1a token 哈希 + 按位加权），汉明距离阈值 `-crawl-dup-gap`（默认 3）；
   - 中文按单字成词、ASCII 按词切分，无需引入分词器；
   - 近似重复页**只标记不丢弃**（`meta.duplicate_of`），因为重复页里仍可能有不同的链接。

### 验收（实测）
| 检查项 | 命令 | 结果 |
| --- | --- | --- |
| 编译 / 静态检查 / 格式 | `go build ./...`、`go vet ./...`、`gofmt -l .` | ✅ 全部通过 |
| 单元测试 | `go test ./... -count=1` | ✅ 16 个包、145 个用例全过 |
| 竞态检测 | `go test ./... -race` | ✅ 通过 |
| Linux 交叉编译 | `GOOS=linux go build ./...` | ✅ 通过 |
| M3 端到端 | `scripts/demo-m3.ps1` | ✅ 站点地图 3 份/3 URL/2 条 Disallow；表单参数与查询参数入清单；JS 接口 7 个、掩码凭据 1 处；`/dup-b` 标记 `duplicate_of=/dup-a` |
| 越界 URL 过滤 | 同上（pipeline 内） | ✅ sitemap 候选逐个过 `scope.Check`，越界不入种子池 |
| headless 未构建 | `-crawl-engine headless` | ✅ 明确报错（非静默降级） |

> 说明：离线环境没有 DVWA / Juice Shop，验收改用 `scripts/fake-services.py` 里的假站点
> （带 robots/sitemap/JS/表单/重复页），覆盖的代码路径与真实站点一致。
> 「1000 页内存 < 200MB」属于需要真实站点的长跑测试，本环境不具备条件，已在 `docs/benchmark.md`
> 记录为待办；当前实现有 `MaxPages` 硬上限与 1MB 单页读取上限，内存增长可预期。

### M3 暴露并修复的缺陷（全部由"真跑一遍"发现）
1. **HTML 实体未还原**：`<a href="/list?cat=1&amp;page=2">` 被爬成 `?cat=1&amp;page=2`，
   参数名解析成 `amp;page` —— 真实站点大量使用 `&amp;`，这是会导致整站 URL 出错的问题；
2. **查询参数未 URL 解码**：`arr%5B%5D=1` 应还原为 `arr[]`；改用 `url.ParseQuery` 并保留正则兜底；
3. **`.js` 从来不在静态资源表里**：导致 `-crawl-js=false` 时仍会把 JS 当页面抓回来
   （关闭开关形同虚设），已在链接过滤里显式处理 JS 路径；
4. **sitemap 相对 loc 未解析**：规范要求绝对 URL，但真实站点常写相对路径，
   原实现会让整份地图被静默丢弃（表现为"urls=0"）；
5. 环境层面的教训：**上一轮演示的假服务进程残留会抢同一端口**，导致验收结果自相矛盾
   （表现为"robots 有响应但解析出 0 条规则"）。演示脚本已改为清理所有同名进程后再启动，
   验收前也先确认端口无残留 —— 这类问题不查清会误判成代码 bug。

---

## M4 POC / 模板引擎（8–10 人日）——✅ 已实施（质量分水岭）

### 任务与实际落地
1. **模板加载 / 编译期校验** ✅
   - 原生格式 **JSON**（零依赖、可校验），同时提供 **nuclei YAML 子集适配器**（`yamlmin.go`）：
     支持块映射/块序列/内联序列与映射/块标量 `|` `>`/注释/引号与转义；
     **明确拒绝**锚点别名、多文档、显式类型标签、tab 缩进，并给出**带行号**的错误 ——
     模板解析错误如果被静默容忍，表现出来就是"漏洞再也扫不出来"。
   - 校验项：id 唯一、必须有 http 段与 path、**必须有 matchers**（没有匹配器的模板只会产生噪声）、
     正则可编译、状态码范围、未知变量（未提供的变量会被原样发出，属静默失效）、
     severity/confidence 取值、**非只读方法必须声明 `intrusive: true`**、
     **破坏性关键字**（`DROP TABLE`/`delete from`/`shutdown`/`rm -rf`…）必须声明 `intrusive: true`。
   - 结构上就**没有**命令执行/文件写入类字段：破坏性动作用类型系统禁止，不靠约定。
2. **matchers / extractors** ✅
   - matchers：`status` / `word` / `regex` / `size` / `header` / `title`，支持
     `part`（body/header/all/title）、`condition`（and/or）、`negative`、`case-insensitive`；
     每个匹配器都返回**可解释的理由**（写进证据，如"and 全部通过: status=200 命中 | 全部包含: …"）。
   - extractors：`regex`（含 group）/ `kval` / `json`（点路径与数组下标）。
   - `matchers-condition`：请求内默认 `and`，模板级默认 `or`（与 nuclei 一致）。
3. **请求构造与变量** ✅
   - `method/path（多备选）/headers/body/redirects`；
   - 变量：`{{BaseURL}} {{RootURL}} {{Hostname}} {{Host}} {{Port}} {{Scheme}} {{Path}} {{File}} {{IP}}`，
     以及每次请求独立的 `{{randstr}} / {{randstr_1..3}}` 与 OOB 的 `{{oob}} {{oob_url}} {{oob_host}}`；
     未知变量保持原样（不误替换），并在编译期拦下。
4. **误报控制三件套** ✅
   - **多匹配器组合 + 强特征**：13 个内置模板全部是"路径 + 状态码 + 多个强特征"的组合；
   - **`-verify` 二次确认**（默认开）：同一请求原样重放，两次都命中才成立；
     有专门用例构造"奇数命中偶数不中"的靶机，验证 verify 能把它压掉；
   - **证据留存**：每条命中都带请求/响应快照与匹配依据，Markdown 报告直接给出可复现的 HTTP 报文，
     且证据里的口令/Token/AK/JWT **一律掩码**。
5. **OOB 外带验证** ✅ `internal/poc/oob.go`
   - 自建 **HTTP 回调监听器**（`-oob-listen`/`-oob-domain`），每个请求登记一次性 token，
     命中回调即把结果升级为"已验证"，并把回连来源写进证据；
   - 不依赖任何第三方 DNSLog 平台（数据合规 + 内网可用）。
   - **DNS 型外带（需要自建权威 DNS）本轮未做**：接口位置已留（token + Wait），后续可直接扩展。
6. **模板生态** ✅
   - 内置 **13 个只读模板**（`.git/config`、`.env`、Actuator `/env` 与 `/health`、Nacos 用户列表、
     Elasticsearch `_cat/indices`、Docker API `/version`、Jenkins `/api/json`、phpinfo、
     Prometheus `/metrics`、目录列表、CORS 反射+凭据、Swagger UI 文档暴露）；
   - 外置模板用 `-templates <文件|目录>` 加载（同名 ID 覆盖内置），支持按 `-poc-tags` / `-poc-severity` 过滤；
   - **兼容性已知边界**：Go 正则（RE2）不支持 lookahead/lookbehind/反向引用，遇到这类 PCRE 语法
     会在加载期报错并**明确提示改写方式**（而不是运行时不命中）；nuclei 的 `dsl`/`xpath`/`raw` 段暂不支持。

### 验收（实测）
| 检查项 | 命令 | 结果 |
| --- | --- | --- |
| 编译 / 静态检查 / 格式 | `go build ./...`、`go vet ./...`、`gofmt -l .` | ✅ 全部通过 |
| 单元测试 | `go test ./... -count=1` | ✅ 17 个包、162 个用例全过 |
| 竞态检测 | `go test ./... -race` | ✅ 通过 |
| Linux 交叉编译 | `GOOS=linux go build ./...` | ✅ 通过 |
| **检出率** | `scripts/demo-m4.ps1`（暴露面靶站） | ✅ **10/10 全部命中且全部通过二次确认**（1 critical / 6 high / 2 medium / 1 low） |
| **误报率** | 同脚本第 2 段（干净静态站点）+ `TestEngineZeroFalsePositiveOnNormalSite` | ✅ **0 误报**（内容含 `open`/`paths`/`status UP` 等近似词也不命中） |
| 证据可复现 | 同上 | ✅ 每条命中带请求报文、响应报文（截断）与匹配依据；Markdown 报告直接给出代码块 |
| 凭据保护 | `TestEvidenceMasksSecrets` | ✅ 证据中 `DB_PASSWORD=`/`AKIA…`/`Bearer …` 全部掩码 |
| 二次确认有效 | `TestEngineVerifySuppressesFlakyMatch` | ✅ 偶发命中被压制 |
| 侵入性闸门 | `TestEngineIntrusiveGated` | ✅ 未放行时不执行写操作模板 |
| OOB 外带 | `TestEngineOOBCallback` | ✅ 假靶机回连后标记 `verified=true` 且证据含回连来源 |
| CI 集成 | `-fail-on <级别>` | ✅ 命中达到阈值时退出码 3（默认 1，正常 0） |

> 说明：离线环境没有 vulhub，验收改用 `scripts/fake-services.py` 里按真实响应构造的靶点
> （`.git/config`、`.env`、Actuator、Nacos、ES、Docker、phpinfo、Prometheus、Swagger…），
> 覆盖的代码路径与真实靶场一致；「30 个 vulhub 靶标召回率 ≥ 90%」需要在有靶场授权的环境补测。

### M4 暴露并修复的缺陷
1. **模板用了 RE2 不支持的 lookahead**（`(?![\\s]*$)`）：这正是移植 nuclei/PCRE 模板的典型坑。
   修复：内置模板改写；同时把错误提示升级为"Go 使用 RE2，不支持 lookahead/lookbehind/反向引用，
   从 PCRE 模板移植时需改写" —— 这条提示本身就是这次踩坑的产出。
2. **YAML 锚点/别名漏检**：只检查了行首，`id: &x a` 这种写法漏网。
   修复：按"值的位置"探测（含 `- *alias`）。
3. **证据掩码漏 `DB_PASSWORD=…`**：`\b` 在 `_` 后不成立，导致下划线前缀的敏感键未被掩码。
4. **证据掩码漏 `Bearer <token>`**：掩码顺序错误 —— `authorization:` 先被替换成 `***` 后，
   Bearer 规则就再也匹配不到了。修复：Bearer/JWT 先于 KV 规则执行。
5. 演示脚本层面的教训：Python `b'...'` 字节字面量不能含中文，导致假服务启动即崩
   （表现为"靶站扫不到资产"）。这类问题会伪装成框架故障，排查时要先确认靶机是否真的活着。

---

## M5 分布式 Server / Agent（10–15 人日）——✅ 已实施（含架构取舍）

### 一个必须先说的取舍：为什么不是 gRPC + Postgres

计划里写的是 gRPC + protobuf + Postgres。实际实施改成了 **JSON over HTTP/1.1 + 标准库**，原因只有一个：
本项目的硬约束是**零第三方依赖、隔离网可编译**。引入 gRPC 要拉 `google.golang.org/grpc` + protobuf
（还要 protoc 代码生成），Postgres 要数据库驱动 —— 一旦引入，"拷源码进内网就能编"这条底线就没了。

做了等价能力映射，并把接口留成可替换：

| 计划 | 实际实现 | 说明 |
| --- | --- | --- |
| gRPC 四类流 | JSON over HTTP：注册 / 拉任务（长轮询）/ 上报 / 控制查询 | 消息类型与 gRPC 方案一致，换传输层只需替换收发实现 |
| protobuf 定义 | `internal/wire` 的 Go 结构体 | 同样的字段语义，不需要代码生成 |
| Postgres 四表 | `store.Store` 接口 + 内存去重聚合 | 换 Postgres 只需实现同一接口；SQL 迁移留待 M6 |
| 双向 TLS | `crypto/tls`：服务端 `-tls-cert/-tls-key`，Agent `-tls-ca/-tls-cert/-tls-key` | 已支持，但端到端未做证书测试（见缺口） |

### 任务与实际落地
1. **协议** ✅ `internal/wire`：`JobSpec/Task/ScanSpec/AgentStatus/Register/Pull/Report/Stats`；
   幂等键 `JobID = hash(scanID + host + 端口集合)`；`TokenOK` 用**常量时间比较**防时序侧信道。
2. **Server** ✅ `internal/server`
   - 任务切片：`(主机 × 端口分片)`，`-job-size`（每任务主机数）与 `-job-ports`（端口分片大小）双维度；
   - 租约与重派：任务带 `lease_until`，清理协程周期回收过期租约 → 回 pending；超过 `-max-tries` 才判 failed；
   - 结果汇聚：资产按 `Asset.Key()` 去重、漏洞按 `(模板,命中地址)` 去重，并打上 `scan_id`/`agent_id`；
   - 生命周期：`ScanInfo` 实时给出 待执行/执行中/完成/失败 与资产/漏洞计数。
3. **Agent** ✅ `internal/agent`
   - 拉任务（长轮询）→ **本地授权复检**（用自己的 allow/deny，Server 无权代授权）
     → 执行完整流水线（复用 M0–M4 全部能力）→ 上报；
   - **流式批量上报**：`reportStore` 实现 `store.Store`，资产一边产出一边按条数/时间（默认 200 条 / 1s）上报；
   - **断线磁盘缓冲**：上报失败写 `-spool` 目录，恢复后先重放缓冲再拉新任务；
   - 被本地闸门拦下的目标单独上报 `rejected`，服务端记 `agent_target_rejected` 审计。
4. **存储** ⚠️ 内存实现（去重 + 聚合）。**Server 重启会丢任务表与结果**，这是当前最大缺口；
   接口已抽象，接 Postgres 只需实现 `store.Store` 与任务表持久化。
5. **安全** ✅ Bearer token（常量时间比较）+ 可选服务端 TLS / Agent 侧 CA 与客户端证书；
   **Agent 必须显式声明本地授权**，否则拒绝启动（与单机同一套闸门语义）。
6. **可观测** ✅ `/healthz`、`/metrics`（**手写 Prometheus 文本**，避免引入客户端库）、
   `/api/v1/stats`（任务/扫描/Agent/资产/漏洞全量视图）。

### 验收（实测）
| 检查项 | 方式 | 结果 |
| --- | --- | --- |
| 编译 / 静态检查 / 格式 | `go build`、`go vet`、`gofmt -l` | ✅ 全部通过 |
| 单元与集成测试 | `go test ./... -count=1` | ✅ 18 个包、169 个用例全过 |
| 竞态检测 | `go test ./... -race` | ✅ 通过（含多 Agent 并发拉取/上报） |
| Linux 交叉编译 | `GOOS=linux go build ./...` | ✅ 通过 |
| **多 Agent 不重不漏** | `TestDistributedScanNoLossNoDup`（2 Agent × 3 主机，真 HTTP Server + 真 Agent） | ✅ 每台主机都有结果、去重键唯一、漏洞按 (模板,地址) 去重、审计含 scan_id |
| **租约重派** | `TestLeaseExpiryReassignsTask` | ✅ 领任务后失联 → 租约过期回 pending → 另一 Agent 接手完成；超上限判 failed |
| **杀 Agent 后任务不丢** | `scripts/demo-m5.ps1`（真进程 + 黑洞端口拖慢任务） | ✅ 4 任务全部完成，`job_dispatched=5 > 任务数 4` —— 确实发生了重派 |
| 幂等 / 分片 / 去重 | `TestCreateScanIdempotent`、`TestCreateScanPortChunking`、`TestDuplicateReportsAreDeduped` | ✅ 全部通过 |
| 鉴权 | `TestAuthRejectsBadToken` | ✅ 无/错 token → 401 并计入指标；`/healthz` 免鉴权 |
| **Agent 本地闸门** | `TestAgentLocalScopeGateRejectsOutOfScope` | ✅ 服务端下发越界目标 → Agent 判失败、**不产生任何资产**、并上报 rejected |
| CLI | `westy help` / `westy server` / `westy agent` | ✅ 三模式可用；Agent 未声明授权时退出码非 0 |

### 已知缺口（诚实清单）
1. ~~**无持久化**：Server 重启丢任务表与结果~~ → **已在 M6 关闭**（`state.json` 快照 + 资产/漏洞 JSONL 追加写）；
   但仍是"单机文件"，换 Postgres 才能支持多实例与检索；
2. **TLS/双向 TLS 未做端到端测试**：代码路径与参数就绪，缺证书测试用例；
3. **规模验收未跑**：「10 Agent × /16 网段」需要真实授权网段与多机环境；
   本地只验证了"小规模下的正确性"（无重无漏、掉线重派），**正确性与规模是两件事**；
4. ES 检索未做；Agent 在线面板在 M6 只做到"统计接口 + 控制台列表"，没有 Agent 详情页。

### M5 暴露并修复的问题
1. **任务切片粒度太粗**：最初"一台主机一个任务"（含全部端口），本地演示里杀掉 Agent 根本观察不到重派
   —— 不是 bug，但暴露了设计不足。补上 `-job-ports` 端口分片后，切片更细、负载更均衡、掉线损失更小；
2. **测试桩两个坑**（同样值得记录）：三个假站点各自绑不同随机端口，而扫描任务对所有主机用同一端口集合
   → 只有第一个站点被扫到；循环变量 `t` 遮蔽 `*testing.T` 导致编译失败。
   这类问题会伪装成"框架漏扫"，排查时先怀疑测试桩。

---

## M6 平台化（15+ 人日）——✅ 已实施（含架构取舍）

### 又一组必须先说的取舍：零依赖约束下的"平台"

| 需求 | 常规做法 | 本框架做法 | 代价（明确认下） |
| --- | --- | --- | --- |
| Web UI | React/Vue + 打包链 + CDN | `go:embed` 单页 + 原生 JS（无构建、无外部资源） | 没有组件生态，复杂交互手写；无前端路由 |
| 持久化 | Postgres / ES | `state.json` 快照（去抖 + 原子重命名）+ `assets.jsonl`/`findings.jsonl` 追加写 | 单机、无 SQL 检索、不支持多实例同时写 |
| 报告 | PDF 库 | HTML（自带打印样式）/ Markdown / JSON | 不直出 PDF，靠浏览器打印 |
| 通知 | 各厂商 SDK | 统一 webhook + 4 种载荷（`json`/`wecom`/`dingtalk`/`slack`） | 邮件、SIEM 适配器要自己加 |
| 调度 | cron 库 | `time.Ticker` 固定间隔 | 无 cron 表达式、无日历级排期 |
| RBAC | OIDC / 外部 IdP | 静态 token → 角色（`admin`/`operator`/`viewer`） | 无 SSO、无细粒度权限、无字段级审计 |

这也是为什么 M6 没有"照抄一个漏洞平台"：**每一个常规做法都要拉一个第三方依赖，而本项目的硬约束是离线零依赖可编译。**

### 任务与实际落地
1. **Web UI** ✅ `go:embed web/index.html` 单页控制台：token 存 localStorage、发起扫描（强制选授权书）、
   任务/进度、按级别过滤的漏洞列表（可展开证据）、资产表格、扫描对比、报告导出（HTML/Markdown 直接下载）。
   **进度靠轮询**（2s），没有上 WebSocket/SSE；
2. **定时任务 + 变更对比** ✅ `-schedule` 固定间隔创建扫描；`/api/v1/scans/diff?scan_id=X&against=Y`
   回答"这次比上次多了什么"：新增/消失/变化资产、新增/已修复漏洞，并单列**新增高危**数量（用于告警排序）；
3. **报告中心** ✅ HTML（自包含、深色主题、带打印样式）/ Markdown / JSON，可按 `scan_id` 切片导出；
4. **RBAC + 授权书绑定** ✅ `-roles admin=tokA,operator=tokB,viewer=tokC`；
   **创建扫描必须引用一份有效授权书**（`authz.Record`：范围/有效期/审批人/工单），越界或无授权书一律 403。
   注意这是**两层闸门**：服务端在创建时判一次，Agent 用自己的 allow/deny 再判一次——
   服务端无权替 Agent 授权，这是刻意保留的设计；
5. **通知集成** ✅ 扫描完成与新发现漏洞（可设 `-notify-min-severity` 阈值）推 webhook，
   载荷格式即上表 4 种；
6. **持久化** ✅ 关闭 M5 的"重启丢状态"缺口：任务/扫描/Agent/授权书进 `state.json`，
   资产/漏洞追加进 JSONL；重启时 `running` 任务一律回到 `pending`（Agent 连接已断，租约无意义）。

### 验收（实测）
| 检查项 | 方式 | 结果 |
| --- | --- | --- |
| 编译 / 静态检查 / 格式 | `go build`、`go vet`、`gofmt -l cmd internal` | ✅ 全部通过（0 个未格式化文件） |
| 单元与集成测试 | `go test ./... -count=1` | ✅ **18 个包、181 个用例全过** |
| 竞态检测 | `go test ./... -race` | ✅ 18 个包全过 |
| Linux 交叉编译 | `GOOS=linux go build ./...` | ✅ 通过 |
| **授权书闸门** | `TestScanRequiresValidAuthorization` + `demo-m6.ps1` 第 2 步 | ✅ 越界目标 403、不关联授权书 403 |
| **RBAC** | `TestRBACRoles` + `demo-m6.ps1` 第 3 步 | ✅ viewer 建扫描 403 / 读资产 200；无 token 401；Agent 接口需 operator+ |
| **变更对比** | `TestDiffEndpoint`、`TestRescanDoesNotReportFixed` + `demo-m6.ps1` 第 4 步 | ✅ 第二次扫描（端口 18081,2222 + 新增 6379）报"新增资产 1、新增漏洞 0、已修复 0" |
| **持久化跨重启** | `TestPersistenceAcrossRestart` + `demo-m6.ps1` 第 6 步 | ✅ 重启后 2 个扫描、11 个资产、10 个漏洞、1 份授权书全部还在 |
| **通知真的发出去了** | `TestNotifyWebhook` + `demo-m6.ps1` 第 5 步（真起 HTTP 接收器收报文） | ✅ 收到 3 条，载荷为企微 `msgtype=markdown` |
| **Web UI 与报告** | `TestWebUIAndReportExport` + `demo-m6.ps1` 第 7 步 | ✅ UI 13,115 字节且含控制台标记；HTML 报告 12,986 字节含漏洞章节 |
| 调度器 | `TestSchedulerCreatesScans` | ✅ 按间隔自动建扫描（仅单测，未做端到端演示，见缺口 5） |

### 已知缺口（诚实清单）
1. **没有多租户数据隔离**：目前是"角色 + 授权书绑定"，所有角色共享同一个资产/漏洞库。
   真正多租户需要按租户分区存储，这一层没做；
2. **无 SSO/OIDC**：token 静态写在命令行参数里，生产环境应改为密钥管理 + 定期轮换；
3. **报告不直出 PDF**（HTML 可打印替代）；报告模板固定，**不支持按客户模板自定义**；
4. **通知只有 webhook**：邮件与 SIEM 适配器未实现；
5. **调度是固定间隔**，不支持 cron 表达式；"定时扫描 → 自动 diff → 变更告警"这条链路
   只有"会按间隔建扫描"的单测，**没有跑过完整端到端演示**；
6. **资产"图"是表格**，没有拓扑图/关系图；
7. **观察集合随扫描次数线性增长**（每次扫描记录一条"看到过哪些键"），
   长期运行需要归档或裁剪策略，目前没做；
8. **观察集合靠 `state.json` 落盘**（2 秒去抖 + 退出时强制保存）。硬杀进程时，
   最后 2 秒内"重复观察到"的记录可能丢；恢复时会退化为按"首次发现归属"重建
   —— 也就是只在**硬杀 + 恰好落在 2 秒窗口内**的交叉情况下，diff 才可能重新出现 M6 修掉的那个假信号。
   彻底解法是把观察记录也做成追加写 JSONL（未做）。

### M6 暴露并修复的问题（依旧靠"真跑一遍"）
1. **最严重的一个：diff 报出"已修复 10"的假信号。**
   演示第 4 步里第二次扫描明明覆盖了第一次的全部端口，却报"已修复 10 个漏洞"。
   根因：资产/漏洞是**全局去重**表，同一条记录只保留首次出现的样本，`scan_id` 记的是"首次发现归属"；
   而 diff/报告用 `scan_id` 反推"这次扫描看到了什么"——第二次扫到同样的目标不会产生新记录，
   于是被判成"这次没扫到"，报成"已消失/已修复"。**这不是显示问题，是会误导处置决策的假信号**：
   运维看到"已修复"就不会去修了。
   修复：新增"每次扫描的观察集合"（`scanObs`：该扫描观察到过的资产键/漏洞键），
   新增/重复上报都记一次观察；diff、扫描报告、按 `scan_id` 过滤的接口全部改用观察集合，
   并把计数同步放进同一把锁里（不再依赖任务回报路径）。回归用例 `TestRescanDoesNotReportFixed`
   同时覆盖"重复扫描零变化"和"重启后不产生假修复"两条；
2. **扫描视图计数只在任务回报路径更新**：直连 `ingest`（测试、后续的导入/补扫）时视图恒为 0，
   是上一条的同一个根因，一并修掉（写入观察集合时同步计数）；
3. **`loadAuthorizations` 先判断 `[` 再剥 BOM**：Windows 下手写/`Set-Content -Encoding UTF8` 的授权书
   带 BOM，判定"是数组还是对象"时先看到 `\ufeff[` → 解析失败、Server 起不来。
   这是 M4 就踩过的 BOM 家族问题，统一收口到 `jsonutil.StripBOM`；
4. **演示脚本自己也会骗人**（值得单独记一条）：PowerShell 5.1 的 `Invoke-RestMethod` 返回数组时
   可能被包成"数组套数组"，`Api ... | Where-Object {...}` 于是没生效，`$s2` 变成集合，
   按属性比较直接抛类型错（`Could not compare "0" to "3 2"`）。
   已把脚本改成对两层都显式展开。教训：**演示脚本报的"绿"要先自己怀疑一遍**，
   真正可信的是"真进程 + 真 HTTP + 真报文"那部分证据。

---

## M7 规则库扩张（弹药补充）——✅ 已实施（含质量门禁）

### 为什么值得单独做一轮

引擎决定"能不能扫"，规则库决定"扫得出什么"。但规则库的失效方式是**静默的**：
路径写错的模板不报错，只是永远不命中；`.*` 正则不报错，只是到处命中。
两种都不会有人告诉你，直到拿它去扫真目标。所以这一轮的重点不是"加规则"，
而是**同时立起三道门禁**，让死模板和误报源在构建期暴露。

### 任务与实际落地
1. **指纹规则 41 → 256 条** ✅
   - 应用层 123 条（Web 服务器/中间件、Java 生态、语言框架、CMS、数据库与面板、
     DevOps/CI、大数据/搜索/消息、监控/日志、代理网关、文件协作与 Web 邮件）；
   - 设备与基础设施层 92 条（网络设备、安全设备/VPN、安防摄像头、打印机、存储、
     国产 OA/ERP/中间件、网管运维平台）；
   - 其中 51 条带端口收敛；纯端口规则显式标 `low`（不装成 high）。
2. **漏洞模板 13 → 130 条** ✅ 全部只读（GET），非 `intrusive`；
   Web/DevOps 方向见 `builtin-exposure-web.json`，国产应用与设备方向见 `builtin-exposure-cn.json`。
3. **三道质量门禁** ✅（新代码，见 `internal/fingerprint/rules_library_gate_test.go`、
   `internal/poc/library_fixtures_test.go`）：
   加载期强校验（非法即整体报错）→ 空匹配门禁（正则不得匹配空串 = 误报源）→
   金丝雀门禁（每条模板必须命中自己的夹具、必须有夹具、干净站点 0 命中）；
4. **金丝雀靶站** ✅ `scripts/fake-services.py` 新增 18082 端口，严格按
   `scripts/rules-fixtures/*.json` 返回，未声明路径一律 404（夹具是"模板↔靶站"的可执行契约）；
5. **CLI 补齐 `-list-templates`** ✅ 与 `-list-rules` 对称：一条命令查清"现在有哪些弹药"；
6. **端到端演示 `scripts/demo-rules.ps1`** ✅ 真进程 + 真 HTTP：指纹规模 → 金丝雀全命中 → 干净站点零误报 → 指纹识别。

### 验收（实测）
| 检查项 | 方式 | 结果 |
| --- | --- | --- |
| 编译 / 静态检查 / 格式 | `go build`、`go vet`、`gofmt -l cmd internal` | ✅ 全部通过 |
| 全量测试 | `go test ./... -count=1` | ✅ 18 个包、204 个用例（含 403 个子测试）全过 |
| 竞态检测 | `go test ./... -race` | ✅ 18 个包全过（并修掉一处既有的时序脆弱测试，见缺陷 7） |
| `scripts/verify.ps1` | 一键验证（含规则库规模统计） | ✅ 0 个失败步骤，日志报告"指纹规则 256 条 / 金丝雀夹具 128 条" |
| **指纹规则库规模** | `bin/westy -list-rules` | ✅ **256 条**（基础 41 + 应用层 123 + 设备层 92） |
| **规则质量门禁** | `TestDefaultRules{CompileAndCount,NoDuplicateNames,NoEmptyMatchingRegex,HaveEvidence}` | ✅ 无重名（大小写不敏感）、**无任何"能匹配空串"的正则**、high 置信度必有特征串 |
| **模板库规模** | `bin/westy -list-templates` | ✅ **130 条**（critical 1 / high 29 / medium 72 / low 27 / info 1） |
| **金丝雀：无死模板** | `scripts/demo-rules.ps1`（真进程打 18082） | ✅ **130/130 全部命中**，0 条死模板 |
| **误报门禁** | 同批模板打干净静态站点 + 合成 404 页 | ✅ **0 命中**（干净站点与 404 页都不误报） |
| 夹具与模板一一对应 | `TestLibraryEveryTemplateHasFixture` | ✅ 每条模板都有夹具（缺一条即失败） |
| 指纹真实识别 | `demo-rules.ps1` 第 4 步（真实 HTTP 响应） | ✅ `http://127.0.0.1:18082 → product=Nginx confidence=high` |

### 已知缺口（诚实清单）
完整清单见 `docs/RULES.md` 第 7 节，要点：
1. **规则是人写的，不是抓包来的**——所有正样本按产品真实响应风格手写，
   **没有在真实设备/系统上回归过**；"63/63 命中、0 误报"只证明"模板不是死的、不滥杀"，
   **不证明它在真实网络上够准**；
2. 28 条规则依赖"产品专有响应头存在性"（值正则故意宽松），头名冲突时会误报；
3. **favicon 哈希一条没填**（mm3 值必须用真实 favicon 计算，宁缺勿错）；
4. 模板只覆盖只读暴露面，不含注入/反序列化等利用类；
5. 达梦/人大金仓/东方通/BES/中创等国产管理端路径**版本差异大**，可能需按现场调整；
6. 冷门设备型号覆盖差，工控协议只做端口级 low 置信度。

### M7 暴露并修复的问题
1. **3 条"真机必漏"的模板被门禁抓出**：深信服 AC/AF、华天 OA 的面板模板只认 `status 200`，
   而这类设备管理口真实行为是 **302 跳转到登录页** —— 模板在真机上永远不会命中。
   修复：模板声明 `"redirects": true`（引擎早就有这个能力，**默认是不跟随跳转**的：
   "跳转后的页面往往是没漏洞的假象"），夹具在声明路径上给出最终登录页内容。
   **如果只看"跑通了"，这 3 条会一直躺在库里当摆设**；
2. **门禁自己也有 bug**：`TestDefaultRulesNoDuplicateNames` 原来按大小写敏感计数，
   而规则合并语义是大小写不敏感的 → `Cacti` 与 `cacti` 这种重名它抓不到；已改为 EqualFold。
   （这个重名是真实发生的：两个并行批次都写了 `Cacti`，一个改名为 `Cacti Monitoring` 才通过）；
3. **"指纹规则 1 条 / 夹具 2 条"的假象**：PowerShell 5.1 的 `ConvertFrom-Json` 遇到 JSON 数组
   会把整个数组当"一个对象"返回，再套 `@(...)` 就变成数组套数组。演示脚本据此报出
   "指纹规则 1 条"，看起来像规则库崩了，实际是脚本坏了 —— **和 M6 那个 `Where-Object` 失效是同一个坑**，
   已统一收口到一个 `Get-JsonList` 助手；
4. **`Write-Host "..." -f $x` 不是合法写法**（`-f` 是格式化运算符，不是 Write-Host 参数）：
   演示脚本因此中断，让"全绿"变成假绿。已改为 `Write-Host ("..." -f $x)`；
5. **改规则不重建二进制 = 自欺**：第一次跑演示时用的是旧 `bin/westy.exe`，
   于是"报 41 条规则、只命中 13 条模板"，看起来像新增内容全丢了。
   实际是没有重新构建 —— 演示脚本必须在开头确保二进制是新的（或用 `-list-rules` 自证）；
6. **端口语义重叠**：ClickHouse 与 QuestDB 都占 9000（前者 native 协议、后者 HTTP），
   TimescaleDB 与 PostgreSQL 必然叠加命中 —— 靠 body 字面量区分，已在 RULES.md 记录；
7. **修掉一处既有的"时序脆弱测试"**：`TestCrawlerM3EndToEnd` 断言"必须是 `/dup2` 被标记 `duplicate_of`"，
   但爬虫是并发的、谁先被处理不确定 —— 这条断言会随调度随机失败（最终验证时在 `-race` 下暴露）。
   已改成断言真正的属性："两个近似相同的页面里**恰好有一个**被标记"，
   `go test ./internal/crawl/ -race -count=20` 连续 20 次稳定；
8. **"静默覆盖"两处隐患已封堵**（由子代理在交付时指出，属于同一类问题）：
   ① `poc.Load` 跨模板文件按 id 覆盖是"后者胜"，两个**内置**文件撞 id 时会让一条模板永远不生效
   且毫无提示 → 现在内置之间撞 id 直接报错（外置覆盖内置仍然允许，附单元测试锁定策略）；
   ② 金丝雀站 `load_fixtures` 遇到夹具路径重复只打 stderr 警告并静默覆盖
   → 现在直接 `SystemExit` 报错退出（重复路径=一条模板永远测不到）；
9. **同一个 PowerShell 5.1 数组陷阱又踩了一次**：`verify.ps1` 里我新加的规则库统计
   用了 `@(Get-Content -Raw | ConvertFrom-Json)`，把 256 条规则报成"1 条"、128 条夹具报成"3 条"。
   已按同一套展开逻辑修掉 —— **这个坑在同一轮里出现三次（演示脚本、M6 演示、verify 脚本），
   说明它不是"偶发失误"而是该环境下必须固化的写法**。

---

## M8 工程化补强（版本管理 / CI / 覆盖率 / 缺陷修复）——✅ 已实施

### 为什么单独做这一轮

M0–M7 交付后，功能与规则库都够用了，但有三个"诚实但难看"的事实：

1. **没有版本管理**：没有 git 仓库、没有 CI、没有 LICENSE —— 面试官/协作者无法核对改动边界，
   也无法一键复现验证；
2. **10 个包测试覆盖率是 0.0%**（`agent` `ratelimit` `store` `audit` `sysinfo` `wire`
   `report` `notify` `config` `model`），其中 `agent` 是分布式执行端的核心，
   最容易被追问"这块怎么测的"；
3. **性能数字没有上下文**：31,368 ports/s 孤零零摆着，既不说明和谁比，也不说明不是什么。

这一轮不写新功能，只做"让别人能验证我"这件事 —— 结果**在补测过程中抓出了 7 个真实缺陷**。

### 任务与实际落地
1. **版本管理 + CI** ✅ `git init`（单次提交、描述当前状态）+ `LICENSE`（MIT）+
   `.github/workflows/ci.yml`（`verify` 任务跑 Ubuntu/Windows 双平台矩阵：gofmt/vet/build/test -race/
   单二进制/规则库规模；`cross-build` 任务跑 linux-amd64/arm64、windows-amd64、darwin-arm64）；
   `.gitignore` 补 `__pycache__/`；`personal/`（简历与面试材料）**只保留在本地、不入库**；
2. **覆盖率补课** ✅ 10 个 0% 包全部补测：**29 个包全部有测试，平均 87.4%，7 个包 100%**；
   用例数 204 → **345**（子测试 403 → 655）；
3. **同类工具定位对照** ✅ `docs/benchmark.md` 新增第 7 节：与 masscan/nmap/fscan/nuclei 的
   能力边界对照 + 三条差异化 + 四条"明显不如它们"的说明，并明确"**没有做同机性能对比**"；
4. **可发布的技术文章草稿** ✅ 两篇（假"已修复"排查 + 规则库门禁）写在本地 `personal/` 目录，
   **刻意不入库**：该目录还包含简历与面试准备材料，不适合随公开仓库分发；
5. **`verify.ps1` 从 5 步扩到 7 步** ✅ 新增逐包覆盖率与竞态检测，让 README 里的数字随时可复现。

### 验收（实测）
| 检查项 | 方式 | 结果 |
| --- | --- | --- |
| 一键验证 | `scripts/verify.ps1` | ✅ **7 个步骤 0 失败**（build / vet / test / **cover** / **race** / 单二进制 / 规则库规模） |
| 全量测试 | `go test ./... -count=1` | ✅ 29 个包、**345 个用例（655 个子测试）**全过 |
| 竞态检测 | `go test ./... -race` | ✅ 29 个包全过 |
| 覆盖率 | `go test ./internal/... -cover` | ✅ 平均 **87.4%**，7 个包 100%，最低 `scope` 49.4% |
| 静态检查 | `gofmt -l cmd internal`、`go vet ./...` | ✅ 干净 |
| Linux 交叉编译 | `GOOS=linux go build ./...` | ✅ 通过 |
| 回归演示 | `demo-m6.ps1`、`demo-rules.ps1` | ✅ 均无异常（M6 七步全绿、规则库 256/130/128 不变） |

### 已知缺口（诚实清单）
1. 覆盖率最低的四个包是 `scope` 49.4% / `pipeline` 56.0% / `portscan` 56.1% / `probe` 61.7%：
   它们**主要靠集成测试与 demo 真跑覆盖**（按包统计时那些执行算在被调包上），
   想提高必须补桩（DNS 解析、原始套接字、真实握手收发）—— 这是明确的待办，不做美化；
2. CI 的 YAML **没有在 GitHub 上实跑验证过**（本环境离线，无 GitHub 访问）：
   它调用的命令与 `verify.ps1` 完全一致（后者本地 0 失败），首次 push 后如有格式问题需微调；
3. `sysinfo` 的 Linux/darwin RLIMIT 分支在 Windows 上不编译，未运行；
4. 覆盖率是"语句覆盖率"，不代表"分支/边界覆盖充分"。

### M8 暴露并修复的问题（**全部来自"为了补测而认真读代码"**）
1. **按字节截断会切坏多字节字符（4 处重复实现）** 🔴
   `crawl` / `httpinfo` / `poc` / `report` 各有一份 `s[:max]` 的截断，中文标题、中文 banner、
   中文页面抽出的证据落在边界上会产生无效 UTF-8（报告里显示成乱码）。
   这类 bug 不报错、不 panic，只是**悄悄损坏交付物**。
   修复：抽出 `internal/textutil`（在字符边界回退 + 保证合法 UTF-8），四处统一收口，
   并补了含 emoji/汉字/边界/真实预算（Host 40、Banner 44、HTML 标题 80…）的专项测试。
2. **产品统计漏算单值 `Product` 字段** 🟠
   `report.Compute` 只遍历 `Asset.Products` 切片，而 `probe`/`fingerprint` 经 `Identify()`
   写的是**单值** `Product` → "产品指纹"分布系统性低估覆盖面（表格里显示 OpenSSH，分布里却没有）。
   修复：两个字段都统计，同一资产内按产品名去重，并断言"统计口径与表格输出一致"。
3. **报告写入错误被静默吞掉** 🟠
   `WriteMarkdown`/`WriteFindingsMarkdown`/`WriteHTML` 不检查 `Fprintln/Fprintf` 返回值、永远返回 nil：
   磁盘满/权限错误会产出"看起来成功、其实内容不完整"的交付物。
   修复：用 `errTrackingWriter` 包一层记录首个错误（函数体一行未改），失败时返回带报告类型的错误。
4. **`wire.JobID` 分隔符歧义 + 端口顺序敏感** 🟠
   `JobID("a|b","c",[1,2])` 与 `JobID("a","b|c",[1,2])` 碰撞；且 `[80,443]` 与 `[443,80]`
   得到不同键 —— 而 HTTP 路径（`Server.CreateScan`）不排序 `spec.Ports`，
   于是"同一批端口换个顺序"会生成两套任务，**幂等与掉线重派一起失效**。
   修复：字段改长度前缀编码；端口排序 + 去重 + 不改调用方切片；`CreateScan` 入口也排序。
5. **`store.JSONL` 写失败会静默丢数据** 🟠
   `seen[key]=true` 写在 `Encode` 之前：写失败后重试会静默返回 nil 且永不落盘（Len 也不增）。
   修复：先写成功再标记 seen，并加断言"写失败不得污染 seen"。
6. **`wire.TokenOK` 的前缀剥离顺序反了** 🟡
   先 `TrimPrefix` 再 `TrimSpace`，导致 `"  Bearer xxx"`（前导空格，部分客户端/网关会加）
   **鉴权失败**，而 `"Bearer  xxx"`（多余空格）却能通过 —— 不一致且会误拒合法请求。
   修复：先 `TrimSpace` 再剥前缀；同时在注释里写明
   `subtle.ConstantTimeCompare` 只在等长时才是常量时间的边界。
7. **靠错误字符串做控制流判定（3 处）** 🟡
   `agent.noteRejected` 用 `Contains(err, "授权范围")` 判"被闸门拦下"、
   `cmd/westy/server.go` 用 `Contains(err, "已存在")` 判授权书重复、
   `m6.handleCreateScan` 用 `Contains(err, "授权书")` 决定 403/400 ——
   改一次错误文案就会**静默改变行为**（审计漏记、状态码漂移）。
   修复：引入哨兵错误（`scope.ErrOutOfScope`/`ErrResolveFailed`、
   `pipeline.ErrAllTargetsRejected`、`server.ErrAuthzDenied`/`ErrAuthzExists`/`ErrScanExists`），
   判定一律走 `errors.Is`，文案只负责给人看；
   顺带修正了一个真实遗漏：**DNS 解析失败**以前不会进 `rejected` 审计。
8. **`audit` 注释与实现不符** 🟢 注释称"fields 键统一小写"，实现原样写入 → 改注释说明真实契约。
9. **CI 在两个平台都红，根因是"测试与真实时钟赛跑"** 🔴（首次 push 后由 CI 抓出）
   - 现象：`verify` 在 ubuntu 与 windows 都失败，但 `gofmt`/`go vet`/`go build` 全过 —— 只有
     `go test ./... -race` 挂；
   - 定位过程（**没有日志也要能查**）：① GitHub API 只给到步骤级结论（失败步骤 =
     `go test（含竞态检测）`）；② job 日志需要鉴权，改用**下载 CI 同版本工具链**
     （`setup-go` 按 `go.mod` 的 `go 1.21` 装了 go1.21.13）在本地跑**完全相同的命令**复现，
     一次就抓到了失败：`--- FAIL: TestBurstIsCappedByCapacity`；
   - 根因：`ratelimit` 的三个测试都是"sleep 一会儿等真实 ticker 灌满桶 → 断言**恰好**能取到
     perSecond 个 → 断言下一个取不到"。补充是真实 ticker 在跑，只要某次调度跨过一个补充间隔，
     断言就随机失败（`-race` 把执行拖慢约 1.8 倍，正好跨过去；其中一个测试按窗口相位算
     **约 1/4 概率翻车**）。本地快机器上完全看不出来，一到 CI 就变随机红；
   - 修复：给 `Limiter` 增加 `newWithTicks`（**把"令牌何时到达"变成可注入的时钟**，`New` 行为不变），
     所有"精确条数"断言改用注入时钟；真实时钟只保留一处 smoke 测试（证明 `New` 真接了 ticker、
     首个令牌不是瞬发），上下界放宽到 `[50ms, 3s]`；
   - 过程中的额外收获：第一次改成注入时钟后，测试**立刻抓出我修复里的一个错误** ——
     多推的补充信号会"在途"补上来，导致"取空后不该再有令牌"仍然失败；
     改成"恰好灌满、不多推"才真正确定（已写进 `fillBucket` 的注释）；
   - 验证：CI 同版本（go1.21.13）`go test ./... -count=1 -race` **29 个包全过**，
     `go test ./internal/ratelimit/ -count=10 -race` 连跑 10 次全过（原来 1 次就可能挂）。

> **这一轮的第二个元教训**：CI 的价值不在于"证明代码对"，而在于**它跑在一个和你不同的环境里**。
> 本地 16 核 + go1.27 全绿，CI 2 核 + go1.21 + `-race` 就红 —— 差异本身就是信息。
> 而"下载 CI 同版本工具链在本地复现"是拿回这条信息的最低成本手段（本项目已内置在 `.tools/go121`，
> 见 README 的"CI 等价本地复现"小节）。
10. **`udpscan` / `crawl` 测试里的 data race** 🔴（CI 第二次红，只在 `-race` 下暴露）
    - 现象：拆开"无竞态/带竞态"两步后定位到 —— **不带竞态全过，只有 `-race` 挂**，
      失败包是 `udpscan`（`TestScan_DNS_EndToEnd`、`TestScan_ConcurrencyBound`）；
    - 根因（代码审查确认，不是检测器误报）：假服务端 handler 在**另一个协程**里访问测试变量，
      测试协程随后直接读写，两者之间没有任何同步边：
      ① `gotQueryType`/`gotQueryClass` 是裸 `uint16`（handler 写、测试读）；
      ② `TestScan_ConcurrencyBound` 的 `peak` 用 `atomic.AddInt32` 累加、收尾却**直接读**
      （对原子变量的非原子读取同样是 race）；③ `crawl/m3_test.go` 的 `fetchedJS` 是裸 `bool`；
      ④ 生产侧 `udpscan.portResolver` 是"测试写全局、扫描 worker 协程读"的裸函数变量；
    - 修复：`portResolver` 改为带 `RWMutex` 的 `resolveProbePort`/`setPortResolver`；
      共享量改 `atomic.Uint32`/`atomic.Bool`；`peak` 读取走 `atomic.LoadInt32`；
    - **为什么本地不复现**：取决于竞态检测器的记录窗口与协程调度 —— 本地快机器上
      handler 协程往往在测试读取前就退出，检测器看不到冲突。所以这次是**按"有没有同步边"推导**的修复，
      本地 `-race -count=30` 通过只是不矛盾的旁证。
11. **SAN 越界断言的写法错误** 🟠（CI 转绿前的最后一红，Windows 特有）
    - 现象：`verify / windows-latest` 挂在**不带竞态**那一步：
      `--- FAIL: TestPipelineM2WebAndSAN: 越界域名被扫描了（严重问题）`；
    - 根因：断言在**整份日志**上做两个独立的 `strings.Contains`：
      `Contains(logText, "san_asset") && Contains(logText, "out-of-scope.example")`。
      而越界域名必然出现在 `san_rejected` 的 reason 里，`san_asset` 事件却可能来自**合法**域名
      （allow 内的 localhost）→ 只要合法扩展产出过一条资产事件，就误判成"越界被扫描"。
      Linux 上恰好没产出 `san_asset`（SAN 端口 443/80 没有服务在听），Windows runner 上产出了；
    - 修复：改为**逐行**判断"同一条事件里既有 `san_asset` 又有越界域名"，
      这样既能抓住真实越界，也不受合法扩展影响；
    - 附带价值：这条断言是合规性质的（越界扫描是红线），把它写对比让它"看起来绿"重要得多。

### CI 工程化（本轮顺带补齐）
- **失败摘要输出为 check-run annotation**：GitHub 的 job 日志需要账号鉴权才能读（API 403），
  而 annotation 公开可读。把诊断逻辑抽成 `scripts/ci-run-tests.sh`（两步共用），
  失败时输出环境信息 + 失败行（`%` 已转义）+ 日志尾部。**这一改动直接让"没有仓库权限也能排查 CI"成立**
  —— 上面两个缺陷就是靠它拿到的真实输出；
- 测试拆成"**不含竞态**"和"**含竞态**"两步：一旦红了能立刻区分"测试逻辑问题"还是"竞态特有"，
  本次定位就受益于此（第一次红在两步都挂→逻辑/环境；第二次红只挂竞态步→同步问题）；
- `cross-build` 任务独立跑 4 个目标（linux/amd64、linux/arm64、windows/amd64、darwin/arm64）。

> 这一轮的元教训：**这些缺陷全都是在"为 0% 覆盖率的包补测试"时暴露的**。
> 覆盖率本身不是目的，但"为了写测试而逐行读懂别人的模块契约"是**目前最有效的缺陷发现手段**——
> 它同时抓出了报告乱码、统计口径错误、幂等键失效、静默丢数据与三处靠文案判定的控制流。

---

## 工程质量保障（贯穿所有里程碑）

| 项 | 要求 |
| --- | --- |
| CI | GitHub Actions / GitLab CI：`gofmt -l`、`go vet`、`go test -race`、`staticcheck`；Windows + Linux 双平台构建 |
| 覆盖率 | 核心包（scope/target/fingerprint/crawl）行覆盖率 ≥ 80%，CI 加阈值门禁 |
| 依赖策略 | 默认构建零第三方依赖；引入依赖必须走 ADR 评审并锁定版本 + 校验和 |
| 发布 | `goreleaser` 多平台二进制 + SHA256 校验和；`-trimpath` 构建保证可复现 |
| 版本 | SemVer；规则文件与二进制分别版本化（规则可热更新） |
| 变更纪律 | 任何影响发包行为的改动必须附"本地 httptest 闭环测试"；任何影响范围判定的改动必须附合规回归用例 |

---

## 立即可做的三件事（Next Actions）

M0–M6 都已实施并在本机实测（每节都有验收表与"已知缺口"）。**下一步的瓶颈不是功能，是没有真实授权目标**：

1. **准备一个授权靶场**：本机 Docker 起 vulhub / DVWA，或内网授权网段。
   用 `-rules`/`-templates` 迭代你的第一版指纹与模板规则 —— 这是投入产出比最高的工作；
2. **压规模**：在授权网段上跑「Server + N Agent × /16」，验证租约/重派/限速在真实延迟下的表现
   （本地只验证了小规模正确性，**正确性 ≠ 规模能力**）；
3. **按需换实现**（都留了接口，不动上层）：
   `persister` → Postgres（多实例与检索）、`crawl` → headless（`-tags headless`）、
   `notify` → 邮件/SIEM 适配器、`sched` → cron 表达式。

---

## 交付物清单

```
go.mod
cmd/westy/{main,server,agent}.go
internal/{model,scope,ratelimit,target,portscan,probe,udpscan,httpinfo,fingerprint,crawl,seed,
          simhash,favhash,cdn,poc,wire,server,agent,diff,authz,notify,jsonutil,
          pipeline,store,report,audit,sysinfo,config}/
internal/server/web/index.html           M6 控制台（go:embed）
rules/fingerprint.json
configs/westy.example.json
scripts/{build,test,verify,demo-local,demo-m1..m6,fake-services.py}
Makefile
README.md
docs/{DESIGN,EXECUTION_PLAN,benchmark}.md
```
