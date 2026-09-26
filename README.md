# westy_scan

![Go](https://img.shields.io/badge/Go-1.21%2B-00ADD8)
![dependencies](https://img.shields.io/badge/dependencies-0-brightgreen)
![license](https://img.shields.io/badge/license-MIT-blue)
![tests](https://img.shields.io/badge/tests-204%20passed%20%2F%20race%20clean-brightgreen)

<!-- 推到 GitHub 后，把 <OWNER> 换成你的用户名即可显示 CI 状态徽章：
[![ci](https://github.com/<OWNER>/westy_scan/actions/workflows/ci.yml/badge.svg)](https://github.com/<OWNER>/westy_scan/actions/workflows/ci.yml)
-->

一个**面向授权渗透测试的资产测绘与攻击面发现框架**（Go，零第三方依赖）。

> ⚠️ **合规声明**：本框架只允许用于**你拥有书面授权**的目标。代码里内置了强制的
> "授权闸门"（未声明 `authorized` 直接拒绝启动）与范围管控（allow/deny + 解析后二次校验），
> 但技术手段不能替代法律授权。未授权扫描在中国属违法行为（《网络安全法》《刑法》285/286 条）。

---

## 1. 它解决什么问题

渗透测试的**前 60% 时间花在信息收集**上：目标有哪些 IP、开了哪些端口、跑着什么服务、
Web 资产有哪些端点、有没有暴露的中间件。这些工作重复、易漏、难复用。

westy_scan 把这段流程做成一条**可解释、可审计、可扩展**的流水线：

```
目标表达式 ─► 授权闸门 ─► TCP 端口扫描 ─► 服务指纹 ─┐
                                              │
                                              ├─► HTTP/HTTPS 探测 ─► Web 指纹 ─► 爬虫
                                              │
                            全部资产 ◄─────────┘
                                 │
                    ┌────────────┼────────────┐
                 去重存储      审计日志      多格式报告
                 (JSONL)      (JSONL)    (table/json/md)
```

**能力边界（当前版本）**：
资产发现 + 端口/服务**协议级识别**（M1） + Web 探测（M2：favicon mmh3、CDN/WAF 被动识别、证书 SAN 联动）
+ 攻击面梳理（M3：robots/sitemap 入口、表单与参数清单、JS 接口与疑似凭据、页面去重）
+ **只读漏洞验证**（M4：模板引擎、二次确认、OOB 外带、可复现证据）。
**不做利用**：模板模型里根本没有执行命令/写文件/删数据的字段，破坏性动作用类型系统禁止。
M5（分布式）、M6（平台化）尚未开始，见 `docs/EXECUTION_PLAN.md`。

## 2. 快速开始

```bash
# 0) 前置：Go 1.21+
#    本工作区已内置便携版 Go 1.27.1 于 .tools/go，脚本会自动识别（优先用 PATH 里的 go）
go version

# 1) 构建（零第三方依赖，GOPROXY=off 也能编过）
powershell -ExecutionPolicy Bypass -File scripts/build.ps1          # Windows
make build                            # Linux/macOS

# 2) 一键验证：编译 + 静态检查 + 单测（输出写到 out/verify.log）
powershell -ExecutionPolicy Bypass -File scripts/verify.ps1

# 3) 自证可运行：扫描本机演示站点，不接触任何第三方目标
powershell -ExecutionPolicy Bypass -File scripts/demo-local.ps1

# 4) M1 验收：起本地假服务（SSH/MySQL/PostgreSQL/Redis/Memcached/VNC + UDP DNS）验证协议识别
powershell -ExecutionPolicy Bypass -File scripts/demo-m1.ps1

# 5) M2 验收：favicon mmh3 + CDN/WAF 被动识别 + 报告新列
powershell -ExecutionPolicy Bypass -File scripts/demo-m2.ps1

# 6) M3 验收：robots/sitemap 入口 + JS 抽取 + 表单参数清单 + 去重
powershell -ExecutionPolicy Bypass -File scripts/demo-m3.ps1

# 7) M4 验收：漏洞模板验证（暴露面靶站命中 + 干净站点零误报）
powershell -ExecutionPolicy Bypass -File scripts/demo-m4.ps1

# 8) M5 验收：Server + Agent 分布式（杀 Agent 观察任务重派）
powershell -ExecutionPolicy Bypass -File scripts/demo-m5.ps1

# 9) M6 验收：授权书闸门 / RBAC / 变更对比 / 重启不丢 / webhook / Web UI / 报告
powershell -ExecutionPolicy Bypass -File scripts/demo-m6.ps1

# 10) M7 规则库体检：指纹规则数 + 模板金丝雀全命中 + 干净站点零误报
powershell -ExecutionPolicy Bypass -File scripts/demo-rules.ps1
```

真实使用（示例）：

```bash
# 单站点
./bin/westy -target https://demo.example.com \
  -allow demo.example.com -authorized -strict-scope -crawl -v

# 网段（含限速，避免把目标打挂）
./bin/westy -target 10.0.0.0/24 -ports common \
  -allow 10.0.0.0/24 -deny 10.0.0.1 -authorized -strict-scope \
  -concurrency 100 -rate 300 -crawl \
  -format markdown -report out/report.md -o out/assets.jsonl -audit out/audit.jsonl

# 用配置文件
./bin/westy -config configs/westy.example.json
```

## 3. 命令行参数

| 参数 | 说明 |
| --- | --- |
| `-target` | 目标，可重复；支持 `URL` / `IP` / `CIDR` / 域名 |
| `-target-file` | 目标文件，每行一个，`#` 开头为注释 |
| `-allow` / `-deny` | 授权范围规则（CIDR/IP/域名），deny 优先 |
| `-authorized` | **必填**：声明已获得书面授权 |
| `-strict-scope` | 严格模式：必须配置 `allow`，否则拒绝启动 |
| `-ports` | `common`(默认) / `web` / `db` / `all` / `80,443` / `1-1024` |
| `-concurrency` | 并发数（默认 200，Web 探测自动收敛到 1/4，上限 64） |
| `-rate` | 全局限速（包/秒），0 为不限速；端口/HTTP/爬虫共享同一令牌桶 |
| `-timeout` | 单次连接/请求超时（秒） |
| `-banner` | 是否抓取 TCP Banner（默认 true） |
| `-crawl` `-crawl-depth` `-crawl-pages` | 爬虫开关、深度、页数上限 |
| `-scan-mode` | `connect`(默认) / `syn`（SYN 半开扫描，**仅 Linux**，需 root 或 CAP_NET_RAW；无法抓 Banner） |
| `-service-detect` | 协议握手识别开关（默认开）：SSH/MySQL/PostgreSQL/Redis/Memcached/VNC/SMB2/RDP/MongoDB/TLS |
| `-service-timeout` | 单次协议握手超时（秒，默认 2） |
| `-udp` `-udp-ports` `-udp-timeout` | UDP 探测（DNS/NTP/SNMP/NetBIOS），默认端口 `53,123,161,137`；UDP 无连接，判定为启发式 |
| `-san-expand` `-san-max-hosts` | 证书 SAN 联动扩展（默认开，上限 100 台）：同证书下的其它域名会被纳入扫描，**每个域名仍逐个过授权闸门**，越界的记入审计并跳过 |
| `-no-default-rules` | 只使用 `-rules` 指定的外置规则，不加载内置规则（默认是**合并**：同名外置规则覆盖内置） |
| `-sitemap` `-sitemap-disallow` | 用 robots.txt/sitemap.xml 补充爬取种子（默认开）；`-sitemap-disallow` 才会把 Disallow 路径也作为请求候选（默认只记录情报） |
| `-crawl-js` `-crawl-max-js` | 从 JS（内联 + 外链）抽取接口与疑似凭据（默认开）；外链 JS 分析数量上限（默认 50）。凭据一律**掩码**落盘 |
| `-crawl-dup-gap` | SimHash 近似重复判定阈值（汉明距离，默认 3）；命中的页面标 `duplicate_of`，不丢链接 |
| `-crawl-engine` | 目前只支持 `http`；`headless` 需要引入 chromedp 并加 `-tags headless` 构建（默认构建保持零依赖），未构建时会明确报错 |
| `-poc` | 启用漏洞模板验证（默认开）。内置 **13 个只读模板**；写操作类模板必须声明 `intrusive:true` 才能加载 |
| `-templates` `-no-builtin-templates` `-poc-tags` `-poc-severity` | 外置模板文件/目录（同名 ID 覆盖内置）；只用外置；按标签/级别过滤 |
| `-verify` | **二次确认**（默认开）：同一请求原样重放一次，两次都命中才算（压制偶发误报） |
| `-allow-intrusive` | 放行有副作用的模板（写方法 / 破坏性关键字），会单独记审计 |
| `-oob-listen` `-oob-domain` | 自建 HTTP 回调监听，用于无回显漏洞的外带验证（不依赖第三方 DNSLog 平台） |
| `-vulns` `-fail-on` | 漏洞结果 JSONL 输出；命中不低于该级别时以退出码 3 结束（CI 集成） |

**分布式子命令**：`westy server ...`（编排端）、`westy agent ...`（执行端），见第 7 节；平台化参数见第 8 节。
| `-blind-web-probes` | 无 Banner 端口上盲试 HTTP 的次数上限（默认 500，0 表示关闭）。非标准端口的 Web 服务只能靠这一步发现 |
| `-format` | `table`(默认) / `json` / `jsonl` / `markdown` |
| `-o` | 结果 JSONL 落盘文件（流式，适合大规模） |
| `-report` | 格式化报告输出文件（默认 stdout） |
| `-rules` | 自定义指纹规则 JSON（**覆盖**内置规则） |
| `-audit` | 审计日志 JSONL（谁在何时对哪个目标做了什么） |
| `-list-rules` | 打印当前生效的指纹规则（JSON）后退出 |
| `-list-templates` | 打印当前生效的漏洞模板（JSON：id/级别/方法/路径/是否跟随跳转/来源）后退出 |
| `-v` | 详细日志 |

## 4. 目录结构

```
westy_scan/
├── cmd/westy/main.go             CLI 入口：参数解析、装配、输出
├── internal/
│   ├── model/                    共享数据模型（Asset/Host/TLSInfo/置信度）——模块间唯一契约
│   ├── scope/                    授权范围闸门（allow/deny/CIDR/域名/DNS 缓存+并发预热/解析后复检）
│   ├── ratelimit/                全局令牌桶限速
│   ├── target/                   目标与端口解析（URL/CIDR 展开/端口组）
│   ├── portscan/                 TCP 扫描：Scanner 接口 + connect 实现 + SYN(linux) + 构包拆包
│   ├── probe/                    M1 协议握手识别：13 类协议探针 + 结构化解析（置信度 high）
│   ├── udpscan/                  M1 UDP 探测：DNS / NTP / SNMP / NetBIOS（启发式判定）
│   ├── favhash/                  M2 favicon mmh3 哈希（Shodan 与 FOFA 两种约定）
│   ├── cdn/                      M2 CDN/WAF 被动识别（CNAME + 响应头 + Cookie）
│   ├── httpinfo/                 HTTP(S) 探测：状态码/标题/关键头/证书/favicon
│   ├── fingerprint/              声明式指纹规则引擎（内置规则 + JSON 外置规则）
│   ├── crawl/                    BFS 并发爬虫（Cookie Jar、同域限制、表单参数、JS 抽取、去重）
│   ├── seed/                     M3 站点地图入口：robots.txt + sitemap.xml（含嵌套索引与 gzip）
│   ├── simhash/                  M3 64 位 SimHash 近似重复检测（含 HTML 转纯文本）
│   ├── poc/                      M4 漏洞模板引擎：加载校验 / matchers / extractors / OOB / 内置模板
│   │   └── templates/            内置只读模板（基础 + Web/DevOps + 国产应用与设备，随二进制分发）
│   ├── wire/                     M5 分布式协议消息（JSON over HTTP，替代 gRPC 的零依赖实现）
│   ├── server/                   M5/M6 编排端：任务切片、租约重派、结果汇聚、指标
│   │   ├── persist.go            M6 持久化：state.json 快照 + 资产/漏洞 JSONL 追加写
│   │   ├── m6.go                 M6 平台化：RBAC / 授权书绑定 / 变更对比 / 报告 / 调度 / 通知
│   │   └── web/index.html        M6 控制台（go:embed，原生 JS，无构建链）
│   ├── agent/                    M5 执行端：拉任务、本地授权复检、流式上报、断线缓冲
│   ├── diff/                     M6 扫描间变更对比（新增/消失/变化 + 新增高危）
│   ├── authz/                    M6 授权书与审批单（范围/有效期/审批人/工单）
│   ├── notify/                   M6 通知 webhook（json / 企业微信 / 钉钉 / Slack 载荷）
│   ├── jsonutil/                 BOM 容错 JSON（Windows 上手写/导出的文件常带 BOM）
│   ├── pipeline/                 流水线编排（阶段串联、并发收敛、端口错配纠正、种子管理）
│   ├── store/                    存储抽象：内存去重 / JSONL 流式落盘 / Multi
│   ├── report/                   table / JSON / JSONL / Markdown 报告 + 统计
│   ├── audit/                    审计日志 JSONL
│   ├── sysinfo/                  RLIMIT_NOFILE 容量提示
│   └── config/                   JSON 配置 + 参数校验
├── rules/fingerprint.json        外置指纹规则示例
├── configs/westy.example.json    配置示例（默认 authorized=false，防误用）
├── docs/                         DESIGN / EXECUTION_PLAN / RULES / benchmark
└── scripts/                      find-go / build / test / verify / demo-local / demo-m1..m6 / demo-rules / fake-services.py
    └── rules-fixtures/           金丝雀夹具（模板 ↔ 靶站的契约，M7）
```

## 5. 安全设计（这是框架的"骨架"，不是装饰）

1. **单点合规出口**：所有出网动作都必须先过 `scope.Guard()`，扫描模块拿不到"绕过"的路径。
2. **解析后二次校验**：域名解析出的 IP 会再过一遍 `deny`，防"外网域名指向内网"绕过范围。
3. **规模熔断**：CIDR 展开受 `max_hosts` 限制，超限直接报错而不是把机器和目标一起打爆。
4. **全局限速**：端口扫描、HTTP 探测、爬虫共享一个令牌桶，`-rate` 一处生效。
5. **全量审计**：`run_start / target_rejected / port_open / web_alive / crawl_hit / run_finish`
   全部落到 JSONL，可被 SIEM 采集，也可作为授权范围的执行证据。
6. **默认拒绝**：配置文件默认 `authorized: false`，缺省不提供"随便扫"的路径。

## 6. 扩展点

| 想扩展 | 怎么做 |
| --- | --- |
| 加指纹 | 写 `rules/*.json`，用 `-rules` 指定；或提 PR 进 `fingerprint.DefaultRules()` |
| 加扫描模块（目录爆破、子域枚举、POC 验证） | 实现"输入 `model.Asset` → 输出 `model.Asset` 流"，挂到 `pipeline.Engine.Run` 的阶段位 |
| 换存储 | 实现 `store.Store` 接口（Postgres/ES/远端 Sink） |
| 分布式 | `portscan.Scan` / `crawler.Run` 返回的都是 channel，替换为 gRPC 流即可，见 DESIGN 文档第 8 节 |
| 无头浏览器 | 在 `crawl` 旁边加 `headless` 模块，产出同样的 `Page` 结构 |

## 7. 分布式模式（M5）

单机跑不动的大网段可以用 Server + 多 Agent 并行，且**授权闸门仍在执行侧**：

```bash
# 编排端：下发扫描（-job-ports 控制端口分片，切得越细越均衡、掉线损失越小）
westy server -listen 0.0.0.0:8899 -token <token> \
  -targets 10.0.0.0/24 -ports common -job-ports 100 -lease 60 -max-tries 3 \
  -audit out/server-audit.jsonl -report out/report.md -format markdown

# 执行端（可起多个）：本地授权范围必须显式声明，Server 无权代它授权
westy agent -server http://10.0.0.1:8899 -token <token> \
  -authorized -allow 10.0.0.0/24 -strict-scope -config configs/westy.example.json \
  -spool out/agent-spool
```

接口（全部需要 `Authorization: Bearer <token>`，`/healthz` 除外）：

| 端点 | 作用 |
| --- | --- |
| `POST /api/v1/agents/register` | 注册/心跳，服务端分配 `agent_id` 与租约 |
| `POST /api/v1/agents/pull` | 拉任务（长轮询，`wait_seconds` 内无任务则挂起） |
| `POST /api/v1/agents/report` | 批量上报资产/漏洞/任务结果/被拒目标 |
| `GET /api/v1/stats` | 扫描与任务全量视图（待执行/执行中/完成/失败、资产、漏洞、Agent） |
| `GET /metrics` | Prometheus 文本指标（任务、资产、去重数、拒绝数、鉴权失败…） |

关键设计：
- **幂等任务键** `hash(scan_id + host + 端口集合)`：Agent 重连后重复拉取不会产生重复数据；
- **租约 + 超时重派**：Agent 掉线后任务自动回到待执行，超过 `-max-tries` 才判失败；
- **结果汇聚去重**：资产按 `Key()`、漏洞按 `(模板, 命中地址)` 去重；
- **Agent 侧最终闸门**：Agent 用自己的 allow/deny 复检每个目标，越界的判失败、不产生资产并上报 `rejected`；
- **断线缓冲**：上报失败写本地 spool，恢复后先重放再拉新任务。

> 与计划的差异（取舍说明）：原计划用 gRPC + protobuf + Postgres，但为守住**零第三方依赖、隔离网可编译**
> 这条底线，改成了 **JSON over HTTP/1.1 + 标准库**，消息类型一一对应、传输层可替换。
> 服务端持久化已在 M6 用「`state.json` 快照 + JSONL 追加写」补上（见第 9 节），
> 换 Postgres 时只需替换 `persister`，上层接口不动。

---

## 8. 平台化：授权、对比、报告与 UI（M6）

```bash
# 编排端：开持久化 + RBAC + 授权书 + 定时扫描 + 通知
westy server -listen 127.0.0.1:18899 \
  -roles admin=<tokA>,operator=<tokB>,viewer=<tokC> \
  -data-dir out/data -authz-file out/authz.json \
  -targets 10.0.0.0/24 -ports common -authorization AB-2026-0001 \
  -schedule 24h -job-ports 100 \
  -notify-url https://qyapi.weixin.qq.com/... -notify-format wecom -notify-min-severity high

# 浏览器打开 http://127.0.0.1:18899/ 填 token 即为控制台
```

| 新增参数 | 说明 |
| --- | --- |
| `-roles` | `角色=token` 列表（`admin`/`operator`/`viewer`）。不配则退回单 token 开发模式 |
| `-data-dir` | 持久化目录：`state.json`（任务/扫描/Agent/授权书）+ `assets.jsonl` + `findings.jsonl` |
| `-authz-file` | 授权书文件（JSON，支持数组或对象），也可用 `POST /api/v1/authorizations` 登记 |
| `-authorization` | 启动时自动创建的扫描所引用的**授权书 ID**（没有它创建扫描会被拒绝） |
| `-schedule` | 定时扫描间隔（如 `30m`/`24h`），空为关闭 |
| `-notify-url` / `-notify-format` / `-notify-min-severity` | 通知 webhook 与载荷格式、触发阈值 |

| 端点 | 作用 |
| --- | --- |
| `GET /` | 控制台（单文件，`go:embed` 进二进制） |
| `POST /api/v1/scans` | 创建扫描，**必须带 `authorization`**；范围不符/授权过期/越界一律 403 |
| `GET /api/v1/scans` | 扫描列表（任务数/完成/失败/资产/漏洞计数） |
| `GET /api/v1/scans/diff?scan_id=X&against=Y` | **变更对比**：新增/消失/变化资产、新增/已修复漏洞、新增高危 |
| `GET /api/v1/assets?scan_id=&host=&limit=` | 资产列表（按某次扫描切片） |
| `GET /api/v1/findings?scan_id=&min_severity=&limit=` | 漏洞列表（按级别排序，含证据） |
| `GET /api/v1/report?format=html\ markdown\ json&scan_id=` | 报告导出 |
| `GET/POST /api/v1/authorizations` | 授权书查看（viewer+）/登记（仅 admin） |

**三层权限**：`viewer` 读 → `operator` 建扫描/调 Agent 接口 → `admin` 管授权书；无/错 token 一律 401。

**授权与合规**：创建扫描必须先绑定一份**有效授权书**（范围 + 有效期 + 审批人 + 工单），
且目标要落在授权范围内；这套判定在服务端和 Agent 侧**各做一次**——
服务端无权替 Agent 授权，Agent 用自己的 `allow/deny` 再复检，越界的不产生任何数据并上报 `rejected`。

**变更对比的语义**（这里踩过一个大坑，值得单独说明）：资产/漏洞是全局去重的，同一条记录
只保留**首次出现**的样本，记录上的 `scan_id` 是"首次发现归属"，**不能**用来回答"这次扫描看到了什么"。
否则第二次扫到同样的目标会被判成"这次没扫到"，diff 报出"已修复/已消失"的**假信号**。
所以每次扫描单独记录一份"观察到过的键集合"，对比与报告都基于它：

```bash
# 这轮比上轮多了什么？（演示里新增端口 6379 → 新增资产 1、新增漏洞 0、已修复 0）
curl -H "Authorization: Bearer <token>" \
  "http://127.0.0.1:18899/api/v1/scans/diff?scan_id=scan-new&against=scan-old"
```

---

## 9. 规则库：指纹与漏洞模板（M7）

引擎决定"能不能扫"，**规则库决定"扫得出什么"**。详见 `docs/RULES.md`。

| 库 | 规模 | 明细 |
| --- | --- | --- |
| 指纹规则 | **256 条**（原 41） | 基础 41 + 应用层 123 + 设备/基础设施层 92；51 条带端口收敛 |
| 漏洞模板 | **130 条**（原 13） | 基础暴露面 13 + Web/DevOps 67 + 国产应用与设备 50；**全部只读 GET** |

```bash
bin/westy -list-rules                     # 指纹规则（JSON）
bin/westy -list-templates                 # 漏洞模板（JSON：级别/方法/路径/是否跟随跳转/来源文件）
bin/westy -poc-tags exposure -list-templates   # 只看"暴露面"这一类
```

**三道质量门禁**（这是 M7 的重点，比条数更重要）：

| 门禁 | 挡什么 | 在哪 |
| --- | --- | --- |
| 加载期强校验 | 格式非法、变量拼错、RE2 不支持的语法、写操作未声明 `intrusive` | `poc.Load` / `fingerprint.New`，**任何一条非法即整体报错**，绝不静默跳过 |
| 空匹配门禁 | 能匹配空串的正则（`.*` 会在空响应头/空 body 上到处命中 = 误报源） | `rules_library_gate_test.go`、`library_fixtures_test.go` |
| **金丝雀门禁** | **死模板**（路径写错、匹配器太严 → 永远不命中）与误报 | `scripts/rules-fixtures/*.json` + `fake-services.py:18082` + `library_fixtures_test.go` |

金丝雀门禁的机制：每条模板都要有一份夹具（声明"命中它时长什么样"），
本地金丝雀站点严格按夹具返回，于是三件事被自动验证——**每条模板都能命中、每条模板都有夹具、
同一批模板打干净站点 0 命中**。

```bash
# 三道门禁 + 端到端（真进程打金丝雀站，再打干净站点）
go test ./internal/fingerprint/ ./internal/poc/ -count=1
powershell -ExecutionPolicy Bypass -File scripts/demo-rules.ps1
```

> 加了模板没写夹具、或模板在夹具上不命中，`go test` 会**直接失败**。
> 这是刻意的：规则库最贵的错误不是"少一条规则"，而是"一条永远不命中的规则躺在库里当摆设"。

---

## 10. 开发与验证状态

```bash
go test ./...            # 单元测试（scope / target / crawl / fingerprint / poc / server ...）
go vet ./...             # 静态检查
gofmt -l cmd internal    # 格式化检查（不要对仓库根跑，会走进 .tools/go 的工具链源码）
```

**M0–M8 已在 Windows + Go 1.27.1 上实测通过**：

| 检查项 | 结果 |
| --- | --- |
| `go build ./...` / `go vet ./...` / `gofmt -l cmd internal` | ✅ 全部通过（零第三方依赖，GOPROXY=off） |
| `go test ./... -count=1` | ✅ **29 个包全过、345 个用例（655 个子测试）** |
| `go test ./... -race` | ✅ 通过（并发模型无数据竞争，含多 Agent 并发拉取/上报） |
| 测试覆盖率（`go test ./internal/... -cover`） | ✅ **平均 87.4%**，7 个包 100%；最低 `scope` 49.4%（详见下文） |
| Linux 交叉编译（SYN 扫描器） | ✅ `GOOS=linux go build ./...` 通过 |
| M1 协议识别（`scripts/demo-m1.ps1`） | ✅ 7/7：OpenSSH 9.6p1、MySQL 8.0.35、PostgreSQL、Redis 7.2.4、Memcached 1.6.17、VNC 3.8、UDP DNS（全部 high） |
| M2 Web 指纹（`scripts/demo-m2.ps1`） | ✅ favicon mmh3=1407517096、CDN/WAF=Cloudflare、BehindCDN=true、源站提示与判据链完整 |
| M2 流水线集成测试 | ✅ favicon + CDN + 证书 SAN 联动；越界 SAN 被 `san_rejected` 拦截且不被扫描 |
| M3 攻击面梳理（`scripts/demo-m3.ps1`） | ✅ 站点地图 3 份/3 URL/2 条 Disallow；表单与查询参数入清单；JS 接口 7 个；掩码凭据 1 处；`/dup-b` 标记 `duplicate_of` |
| **M4 检出率**（`scripts/demo-m4.ps1`） | ✅ **10/10 命中且全部通过二次确认**（1 critical / 6 high / 2 medium / 1 low），每条带可复现证据 |
| **M4 误报率** | ✅ **0 误报**：同一批模板打干净静态站点（内容含 `open`/`paths`/`status UP` 近似词）零命中 |
| **M5 分布式正确性** | ✅ 2 Agent × 3 主机无重无漏；租约过期任务重派；去掉一个 Agent 后 4 任务仍全部完成（`job_dispatched=5 > 4`） |
| **M5 Agent 本地闸门** | ✅ 服务端下发越界目标 → Agent 拒绝、不产生资产、上报 `rejected` |
| **M5 鉴权与可观测** | ✅ 无/错 token 返回 401；`/metrics` 输出 12 项指标；审计可按 `scan_id` 对齐 |
| **M6 授权书闸门**（`demo-m6.ps1`） | ✅ 越界目标 403、不绑定授权书 403；`viewer` 建扫描 403、读资产 200 |
| **M6 变更对比** | ✅ 第二次扫描（18081,2222 + 新端口 6379）→ 新增资产 1、新增漏洞 0、**已修复 0**（不是假信号） |
| **M6 重启不丢** | ✅ 重启后 2 个扫描 / 11 资产 / 10 漏洞 / 1 份授权书全在；`running` 任务回到 `pending` |
| **M6 通知真的发出去了** | ✅ 真起 HTTP 接收器，收到 3 条企微 markdown 报文（非"调用了发送函数"） |
| **M6 Web UI 与报告** | ✅ 控制台 13,115 字节；HTML 报告 12,986 字节含漏洞章节与证据 |
| 端到端（本机 Python 靶站 + 爬虫） | ✅ 端口 → HTTP → 指纹 → 爬虫 → JSONL/审计 全链路 |
| **M7 规则库规模** | ✅ `-list-rules` **256 条**指纹；`-list-templates` **130 条**模板 |
| **M7 无死模板**（`demo-rules.ps1`） | ✅ 真进程打金丝雀站 **130/130 全部命中**（每条模板都有夹具并被真实匹配器验证过） |
| **M7 误报门禁** | ✅ 同批模板打干净站点与 404 页：**0 命中**；且无任何正则可匹配空串 |
| 合规回归（缺授权 / 越界目标 / strict 缺 allow） | ✅ 三种情况均非零退出 |
| `scripts/verify.ps1` | ✅ 0 个失败步骤（含规则库规模、**逐包覆盖率**、竞态检测；日志 `out/verify.log`） |

### 测试覆盖率（`go test ./internal/... -cover`）

**29 个包全部有测试**，平均 **87.4%**，其中 7 个包 100%：

| 覆盖率档 | 包 |
| --- | --- |
| 100% | `config` `jsonutil` `model` `report` `sysinfo` `textutil` `wire` |
| 90–99% | `agent` 98.1 · `favhash` 98.5 · `store` 98.4 · `notify` 98.2 · `simhash` 98.1 · `ratelimit` 96.3 · `audit` 95.5 · `fingerprint` 94.3 |
| 80–89% | `cdn` 89.6 · `authz` 87.8 · `udpscan` 87.9 · `crawl` 87.6 · `server` 85.6 · `httpinfo` 84.3 · `diff` 80.3 · `seed` 81.4 |
| 70–79% | `target` 76.8 · `poc` 74.1 |
| < 70% | `probe` 61.7 · `portscan` 56.1 · `pipeline` 56.0 · `scope` 49.4 |

> 低覆盖的几个包不是"没测"，而是**主要靠集成测试覆盖**：
> `pipeline`（阶段串联）与 `scope`（DNS 解析/预热等分支依赖真实网络）在 `internal/server` 的
> 端到端测试与各 demo 脚本里被真跑验证，但按包统计时那些执行算在被调包上。
> 这几个数字不做美化 —— 想提高就得补桩，这是已知的待办。
>
> 覆盖率的提升路径（M8）：`agent` `ratelimit` `store` `audit` `sysinfo` `wire` `report` `notify`
> `config` `model` 这 10 个包此前是 **0.0%**，靠一轮专项补测到现在的水平，
> 并**在补测过程中抓出了 3 个真实缺陷**（见下）。

性能基准见 `docs/benchmark.md`：本机 connect 扫描 **31,368 ports/s**（1000 端口、并发 200，可复现）；
该文档还给出了真实网络的吞吐推算模型（**限速几乎总是主导因素**）与
**与 masscan/nmap/fscan/nuclei 的定位对照**（明确说明没有做同机性能对比，只对照能力边界）。

真实运行抓出并已修复的缺陷（M0–M8，逐条记在 `docs/EXECUTION_PLAN.md` 各里程碑的"暴露并修复的问题"）：
IPv6 归一化、非标准端口 Web 漏检、范围全灭时静默成功、指纹 `.*` 匹配空响应头导致误报、
PowerShell `.ps1` 编码陷阱、MySQL 握手少跳 13 字节、VNC 版本号未归一化、
`for range T{}.Method()` 复合字面量歧义、UDP `finalize` 漏写 Product/Version/Confidence、
NetBIOS 名字表偏移与压缩指针、NTP 时间戳偏移与纪元换算、favicon `<link>` 正则缺捕获组、
明文 HTTP 打到 TLS 端口未回退 https、HTML 实体 `&amp;` 未还原、查询参数未 URL 解码、
`.js` 不在静态资源表、sitemap 相对 loc 未解析、
**模板用了 RE2 不支持的 lookahead**、YAML 锚点漏检、证据掩码漏下划线前缀键与 `Bearer` 顺序错误、
任务切片粒度太粗（掉线观察不到重派）、
**diff 把重复扫到的资产/漏洞报成"已修复"（最严重的一个：会误导处置决策）**、
`loadAuthorizations` 先判 `[` 后剥 BOM 导致带 BOM 的授权书解析失败、
**3 条"真机必漏"的模板**（设备管理口实际是 302 跳转，模板却只认 200 → 由金丝雀门禁抓出）、
规则重名（`Cacti` 两批撞名，且原门禁大小写敏感、抓不到）、
既有的时序脆弱测试（爬虫并发下断言"必须是 `/dup2` 被标记"）、
两处"静默覆盖"隐患（内置模板撞 id、金丝雀夹具撞路径 —— 都会让一条规则永远不生效且无提示）、
PowerShell 5.1 `ConvertFrom-Json` 数组套数组（同一坑踩了三次：演示脚本/verify 脚本）、
`Write-Host "..." -f $x` 非法写法导致演示假绿、改规则不重建二进制导致"假回归"、
**按字节截断切坏多字节字符（4 处重复实现 → 收口到 `internal/textutil`）**、
**产品统计漏算单值 `Product` 字段导致报告低估覆盖面**、
**报告写入错误被静默吞掉（磁盘满会产出"看起来成功但不完整"的交付物）**、
**幂等键 `JobID` 分隔符歧义 + 端口顺序敏感（同一任务会生成两套 ID，重派语义失效）**、
**`store.JSONL` 写失败时提前标记 seen 导致静默丢数据**、
**`TokenOK` 前缀剥离顺序反了（带前导空格的合法 Bearer 头被拒）**、
**3 处靠错误字符串做控制流判定**（改文案就静默改变审计与状态码 → 全部换成哨兵错误 +
`errors.Is`，顺带修好"DNS 解析失败不进 rejected 审计"）、
**`ratelimit` 三个测试"与真实时钟赛跑"**（本地全绿、CI 上 `-race` 随机失败 →
把令牌到达改成可注入时钟，精确条数断言不再依赖真实 ticker）。

### CI 等价本地复现（用 CI 同版本工具链）

CI 按 `go.mod` 里的 `go 1.21` 安装工具链，而本机是更新的版本 —— **差异本身会制造"本地绿、CI 红"**。
仓库内置了一份 go1.21 便携工具链的用法（`.tools/go121`，不入库）：

```powershell
$env:GOROOT="$PWD\.tools\go121\go"; $env:GOCACHE="$PWD\.tools\gocache121"; $env:GOTOOLCHAIN='local'
& ".tools\go121\go\bin\go.exe" test ./... -count=1 -race    # 与 CI verify 步骤完全一致
```

## 11. 后续路线

M0 骨架 → M1 端口 → M2 Web 指纹 → M3 爬虫 → M4 POC/模板引擎 → M5 分布式 Server/Agent →
M6 平台化（授权/RBAC/变更对比/报告/Web UI/通知）→ M7 规则库扩张（256 条指纹 + 130 条模板 + 金丝雀门禁）
→ **M8 工程化补强（版本管理 + CI + 覆盖率补课 + 缺陷修复）**
均已实施并实测（见 `docs/EXECUTION_PLAN.md`）。

下一步的真实瓶颈不在功能数量，而在**没有真实授权目标**：
规则库现在的"130/130 命中、干净站点 0 误报"只证明"模板不是死的、不滥杀"，
**不证明它在真实网络上够准**。建议先在授权靶场（vulhub/DVWA）或授权内网段跑一轮，
把漏报与误报收集回来再迭代规则（详见 `docs/RULES.md` 第 8 节优先级）。

架构与取舍详见 `docs/DESIGN.md`。
