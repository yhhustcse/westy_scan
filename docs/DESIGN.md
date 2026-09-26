# westy_scan 架构设计（思路篇）

> 面向授权渗透测试的资产测绘与攻击面发现框架。
> 本文回答"**为什么这么设计**"，执行步骤见 `EXECUTION_PLAN.md`，用法见 `README.md`。

---

## 1. 定位：先做"眼睛"，再做"手"

渗透测试的工作量分布大致是：

| 阶段 | 占比 | 输出 | 风险 |
| --- | --- | --- | --- |
| 信息收集 / 攻击面测绘 | ~50% | 资产清单、服务、端点、指纹 | 低（只要限速） |
| 漏洞发现与验证 | ~30% | 可复现的漏洞证据 | 中（可能触发告警/崩溃） |
| 利用与后渗透 | ~20% | 权限、横向、影响证明 | 高（可能影响业务） |

很多人一上手就想做"一键 getshell"，结果是：**误报压不住、授权说不清、目标被打挂**。
所以本框架第一阶段**只做第一层**，但把第二层（POC 引擎）的接口和数据结构提前留好。

**明确的能力边界（v0.1）**

做的：目标解析 → 授权校验 → 端口扫描 → 服务指纹 → HTTP(S) 探测 → Web 指纹 → 爬虫 → 去重存储 → 报告/审计。

不做的：漏洞验证、口令爆破、利用编排、后渗透、绕过 WAF 的对抗性 payload。

原因：这些能力一旦内置，框架就从"测绘工具"变成"攻击武器"，对工程严谨性（误报率、幂等、
可回滚）和合规要求（授权留痕、动作分级）的要求会陡增。**分层交付**比一次做全更专业。

---

## 2. 合规是本框架的第一性设计约束

技术框架里"合规"通常被写成 README 里的一句免责声明。本框架把它做成**代码里的强制闸门**：

```
                    ┌──────────────────────────────────────────┐
   用户输入目标 ───► │  scope.Guard(target)                     │
                    │  1. authorized 未声明 → 直接拒绝启动      │
                    │  2. deny 命中 → 拒绝（优先级高于 allow）  │
                    │  3. allow 未命中 → 拒绝                   │
                    │  4. DNS 解析（带缓存，集中出口）           │
                    │  5. 解析出的 IP 再过一遍 deny             │
                    └───────────────────┬──────────────────────┘
                                        │ 只有通过的目标才能进入扫描
                                        ▼
                              端口扫描 / HTTP / 爬虫
```

四个关键点：

1. **单一出口**：所有模块都拿不到"直接 dial 任意地址"的路径。要在框架里发包，必须经过
   `Scope`，这是可审计、可 review 的收敛点（对应 `internal/scope/scope.go`）。
2. **解析后复检**：只校验域名是不够的 —— `evil.com` 可以解析到 `10.0.0.1`（DNS 重绑定 /
   内网穿透）。所以 `Guard()` 在解析出 IP 之后，再用 IP 过一遍 `deny`。
3. **规模熔断**：`10.0.0.0/8` 不会静默展开成 1600 万任务，而是超过 `max_hosts` 直接报错。
   这是防止"手滑把整个内网打爆"的最后一道保险。
4. **全量审计**：每一次运行、每一个被拒绝的目标、每一个开放端口都写 JSONL 审计日志，
   事后可自证"我只碰了授权范围内的资产"。

> 法律提示：技术闸门不能替代授权文件。未授权的扫描探测在中国可适用《网络安全法》与
> 《刑法》第 285/286 条。请务必拿到盖章的授权书并约定测试窗口。

---

## 3. 总体架构

### 3.1 分层视图

```
┌──────────────────────────────────────────────────────────────────────┐
│  输入层  Input                                                        │
│  命令行参数 / JSON 配置文件 / 目标文件       （未来：平台 API、任务队列）  │
└───────────────────────────────┬──────────────────────────────────────┘
                                │ config.Config
┌───────────────────────────────▼──────────────────────────────────────┐
│  编排层  Orchestration  (internal/pipeline)                           │
│  · 目标汇总去重      · 阶段串联        · Web 并发收敛                   │
│  · 取消/超时传播     · 爬虫种子管理     · 统一落库+审计                 │
└───────┬───────────────────────────────────────────────┬──────────────┘
        │ 阶段 1-2                                      │ 阶段 3-4
┌───────▼───────────────────────┐            ┌──────────▼───────────────┐
│  执行层  Modules              │            │  执行层  Modules          │
│  target  目标/端口解析         │            │  httpinfo  HTTP(S) 探测   │
│  portscan TCP 扫描 + Banner    │            │  fingerprint 指纹引擎     │
│                                │            │  crawl    BFS 爬虫        │
└───────┬───────────────────────┘            └──────────┬───────────────┘
        │                model.Asset 流                  │
┌───────▼───────────────────────────────────────────────▼──────────────┐
│  数据层  Data  (internal/store, internal/audit)                       │
│  内存去重表（Key 唯一） + JSONL 落盘 + 审计日志  （未来：Postgres/ES）    │
└───────────────────────────────┬──────────────────────────────────────┘
                                │ []model.Asset
┌───────────────────────────────▼──────────────────────────────────────┐
│  输出层  Report  (internal/report)                                    │
│  table / json / jsonl / markdown  +  统计摘要（未来：HTML 报告、Web UI）│
└──────────────────────────────────────────────────────────────────────┘

横切关注点（贯穿所有层）：authorized 闸门 · allow/deny 范围 · 全局限速 ·
                            结构化日志 · 审计留痕 · context 取消
```

### 3.2 运行时数据流（时序）

```
main ──► pipeline.New ──► scope.New(拒绝未授权) ──► fingerprint.Load
  │
  ├─► Run(ctx)
  │     │
  │     ├─ resolveTargets()            命令行 + 文件 → 去重 []model.Host
  │     ├─ target.ParsePorts("common") → []int
  │     │
  │     ├─ 启动 N 个 Web worker（N = concurrency/4，上限 64）
  │     │
  │     ├─ for a := range portscan.Scan(...)        ← 端口扫描流
  │     │       ├─ fp.Apply(banner)                 服务指纹
  │     │       ├─ record(a, "port_open")           落库 + 审计
  │     │       └─ if 值得探 Web → webJobs <- a
  │     │
  │     ├─ 每个 web worker：http 失败再试 https → fp.Apply(headers, body)
  │     │                    → record(..., "web_alive") → addSeed(url)
  │     │
  │     └─ if crawl: crawler.Run(seeds) → 每页 fp.Apply → record("crawl_hit")
  │
  └─► mem.Assets() ──► report.Compute/Write*  →  stdout / 文件
```

---

## 4. 六个关键设计决策（含取舍）

### 决策 1：用"一个 Asset 结构体"承载所有阶段的产物，而不是 Domain/Port/URL 三套模型

**怎么做**：`model.Asset` 有 `Host/IP/Port/Scheme/URL/Service/Products/Title/TLS/Depth/Source/Meta`，
`Source` 与 `Depth` 记录血缘，`Key()` 定义去重语义（URL > Host:Port > Host）。

**为什么**：信息收集阶段的资产是**不断生长**的 —— 一个 IP 先有端口，端口长出服务，
服务长出 URL，URL 长出端点。三套模型之间要写大量转换代码，且"半成品"状态无处安放。
单一结构体 + 阶段标记，序列化、去重、报告全都只写一遍。

**代价**：字段会有稀疏（URL 类资产没有 Port 之外的信息）。用 `omitempty` 与 `Meta` 兜住即可。

### 决策 2：合规闸门做成"唯一出口"，而不是"每个模块自己判断"

见第 2 节。取舍是：扫描模块都必须接收 `*scope.Scope` 参数，稍微增加了耦合，
换来的是"任何新增模块都不可能绕过授权校验"的结构性保证。

### 决策 3：指纹用声明式规则，内置一份、允许外置覆盖

**怎么做**：`fingerprint.Rule{Name, Service, Ports, Banner/Title/Header/Body 正则}`；
`DefaultRules()` 内置 40 条常见服务与中间件；`-rules rules/fingerprint.json` 用外置覆盖。

**为什么**：
- 指纹是**高频变更**的（新中间件、新版本 banner），要求"改指纹 = 重新发版"是反模式；
- 规则引擎是 POC 引擎的前身。**漏洞模板 = 指纹 + 验证请求 + 匹配器**，先把规则加载、
  正则编译、端口约束、匹配器求值这套跑通，M4 加"发请求 + 判定"就是自然延伸。

**取舍**：外置规则当前是**整体覆盖**而非合并（简单、可预测）。M2 会加 `default_rules: true`
开关支持合并。

### 决策 4：模块之间用 channel 连接，这是未来分布式的天然边界

**怎么做**：`portscan.Scan(ctx, ...) <-chan model.Asset`、`crawler.Run(ctx, seeds) <-chan Page`。

**为什么**：单机时 channel 是零成本的内存队列；分布式时把这一根 channel 换成
gRPC 流（`Agent → Server` 的资产上报流、`Server → Agent` 的任务下发流），
**扫描逻辑一行不改**。这就是"单机 CLI 优先，预留分布式接口"的落地方式。

### 决策 5：零第三方依赖

**怎么做**：只用标准库：`net`、`net/http`（含 `cookiejar`）、`crypto/tls`、`regexp`、
`text/tabwriter`、`encoding/json`。

**为什么**：渗透测试经常在**隔离网 / 客户内网跳板机**上执行，那里 `go mod download` 是奢望。
零依赖意味着"拷贝源码到目标环境，`go build` 即可"，也避免了供应链风险
（安全工具自身被投毒是真实存在的攻击面）。

**代价**：favicon mmh3 哈希、无头浏览器、YAML 配置这些需要自己实现或推迟（见 M2/M3）。

### 决策 6：有界并发 + 单一令牌桶

**怎么做**：
- 端口扫描：`concurrency` 个 worker（默认 200）；
- Web 探测：`concurrency/4`，上限 64（HTTP 请求比 TCP 建连重得多，且更容易触发 WAF）；
- 爬虫：固定 10 并发 × 深度分层（batch 屏障，避免指数级并发膨胀）；
- 三者共享一个 `ratelimit.Limiter` 令牌桶，`-rate` 一处生效。

**为什么**：扫描框架最常见的生产事故是"把客户业务系统打死"。
限速与并发收敛不是性能调优，而是**可用性保护**。

---

## 5. 模块职责与关键接口

| 包 | 职责 | 关键接口 |
| --- | --- | --- |
| `internal/model` | 模块间唯一契约 | `Asset{...}`、`Asset.Key()`、`Asset.IsWeb()` |
| `internal/scope` | 授权范围闸门 | `New(allow,deny,maxHosts,strict,authorized)`、`Guard(ctx,raw)`、`Check(raw)`、`Resolve(ctx,host)` |
| `internal/ratelimit` | 全局令牌桶 | `New(perSecond)`、`Wait(ctx)`、`Stop()` |
| `internal/target` | 输入解析 | `ParseAll`、`ParseFile`、`ParsePorts`、`IsWebPort` |
| `internal/portscan` | TCP connect 扫描 + Banner | `Scan(ctx, scope, hosts, ports, Options) <-chan Asset` |
| `internal/httpinfo` | HTTP(S) 探测 | `New(timeout, ua)`、`Probe(ctx,host,ip,port,scheme) (*Result,error)`、`BuildURL`、`GuessScheme` |
| `internal/fingerprint` | 指纹规则引擎 | `Load(path)`、`Default()`、`Apply(asset, headers, body)`、`MatchTCP`、`MatchHTTP` |
| `internal/crawl` | BFS 并发爬虫 | `New(Options)`、`Run(ctx,seeds) <-chan Page` |
| `internal/pipeline` | 阶段编排 | `New(cfg, store, audit, logger)`、`Run(ctx)` |
| `internal/store` | 存储抽象 | `Store` 接口、`Memory`、`JSONL`、`Multi` |
| `internal/report` | 结果呈现 | `Compute`、`WriteTable/JSON/JSONL/Markdown`、`SummaryText` |
| `internal/audit` | 审计日志 | `Open(path)`、`Log(event, fields)` |
| `internal/config` | 配置与校验 | `Default()`、`Load(path)`、`Validate()` |

**依赖方向**：`cmd → pipeline → {target, portscan, httpinfo, crawl, fingerprint, store, audit, scope, ratelimit} → model`。
单向、无环、`model` 是叶子。任何模块都不反向依赖 `pipeline`。

---

## 6. 并发模型详解

```
                      ┌─────────────────────── ratelimit.Limiter ───────────────────────┐
                      │         （所有出网动作先 Wait 一个令牌，全局限速）                 │
                      └───────▲───────────────────▲───────────────────────▲────────────┘
                              │                   │                       │
  hosts[] ──► feed goroutine  │        webJobs    │        seeds          │
              │  jobs chan    │        chan       │   ┌───────────────────┘
              ▼               │         │         │   │
     ┌────────────────┐       │         ▼         │   ▼
     │ N=concurrency  │───────┘  ┌─────────────┐  │  ┌──────────────────────┐
     │ portscan worker│          │ M=conc/4    │  │  │ crawler BFS          │
     │  （TCP 建连）   │          │ ≤64 Web 探针 │  │  │ 每层 batch 并行 +     │
     └───────┬────────┘          └──────┬──────┘  │  │ semaphore 限并发      │
             │ out chan (256)           │         │  └──────────┬───────────┘
             ▼                          ▼         │             ▼
        pipeline 主循环 ──► fp.Apply ──► record() ─┴──► store.Add + audit.Log
```

**取消语义**：`context` 从 `main` 一路往下传（`signal.NotifyContext` 捕获 Ctrl-C）。
所有 goroutine 都在 `select { case ...: case <-ctx.Done(): }` 上等待，保证"按一次 Ctrl-C
就收敛"而不是留一堆后台连接。发送侧用带缓冲 channel，避免消费者退出时生产侧永久阻塞。

**去重语义**：`store.Memory` 用 `map[key]bool` 做第一道去重，`JSONL` 自带一份
`seen` 集合（多进程并发写同一文件时不会重复）。同一资产被多个模块发现（例如
端口扫描发现的 `host:port` 与 HTTP 探测发现的 `url`）会产生不同 Key，这是刻意的 ——
它们是两条独立事实，报告里分别呈现。

---

## 7. 指纹引擎设计

```
Rule ──compile──► compiledRule{ ports map[int]bool, banner/title/body []*regexp.Regexp,
                                header map[string]*regexp.Regexp }
```

匹配优先级（`Apply` 内部）：

1. `MatchTCP(port, banner)`：Banner 特征命中 → 定 `Service`/`Products`；
2. `MatchHTTP(asset, headers, body)`：`Title` → `Header` → `Body` 依次短路命中；
3. **纯端口规则**（如 RDP 3389、无特征协议）：显式声明 `ports` 且无任何特征串 → 仅凭端口定服务。

工程细节：
- 正则在**加载时**编译，非法正则直接拒绝启动（而不是运行时静默失效）；
- `Ports` 为空表示"任意端口生效"（如 Nginx 的 `Server` 头）；
- 产品名走 `AddProduct` 去重，避免同一资产重复列出 `nginx, nginx`；
- HTTP 探测结果会把 TCP Banner 带上，让两层特征在同一次 `Apply` 中都能用上。

---

## 7.1 协议握手识别（M1 新增）：把"猜"变成"证"

指纹规则的本质是**文本猜测**——看到 `Server: nginx` 就认为有 nginx。
它便宜、通用，但拿不到版本号，也无法区分"80 端口上跑的其实是 SSH"。

M1 增加了第二条识别路径：**主动发起一次协议握手，从报文的定长字段里读出结构化事实**。
两条路径互补，结果写进同一个 `model.Asset`：

```
                  ┌───────────────────────────────────────────────┐
   开放端口 ──────►│  internal/probe.Detect                        │
                  │                                               │
                  │  ① 复用端口扫描抓到的 Banner（零成本）          │
                  │     SSH/FTP/SMTP/VNC 这类"服务端先说话"的协议   │
                  │                                               │
                  │  ② 建立连接，按端口选探针：                     │
                  │     SSH  MySQL  PostgreSQL  Redis  Memcached   │
                  │     VNC  SMB2   RDP         MongoDB  TLS       │
                  │                                               │
                  │  ③ 解析出：Service / Product / Version / Extra │
                  └───────────────────┬───────────────────────────┘
                                      │ Result.Apply(asset)
                                      ▼
   internal/fingerprint.Apply ──► 置信度只升不降，已有结论不被覆盖
```

### 置信度模型（这是误报控制的核心）

| 等级 | 来源 | 例子 |
| --- | --- | --- |
| `high` | 协议握手解析出的结构化字段 | `mysql-handshake:8.0.35`、`smb2-negotiate:dialect=3.1.1`、`ssh-banner:OpenSSH_9.6p1` |
| `medium` | 特征串 / Banner 正则命中 | `Server: nginx`、`ftp-banner:vsFTPd/3.0.3` |
| `low` | 仅凭端口推断 | 3389 → RDP |

`Asset.RaiseConfidence()` 只升不降：**端口猜测永远不会覆盖握手实证**。
`Asset.Evidence[]` 记录每一条判定依据，报告与误报复盘都能追溯到"凭什么这么判"。

### 探针的设计约束

1. **只发只读命令**：`INFO`、`VERSION`、`NEGOTIATE`、`SSLRequest` 这类不改变服务状态的请求。
   不发任何写入/修改/认证尝试类命令 —— 这是和"漏洞利用"的分界线。
2. **畸形数据必须安全**：所有解析器对截断/垃圾输入返回错误而非 panic（有专门的回归用例）。
3. **按端口选探针，未知端口只试 TLS**：避免对陌生服务乱发包。已知服务端口最多试 3 个探针。
4. **服务端先说话的协议不复用连接**：SSH/FTP/SMTP 直接吃端口扫描抓到的 Banner，省一次往返。
5. **Web 端口不重复探测**：交给 httpinfo 走 HTTP(S)，证书信息顺带拿到。
6. **端口≠服务能被纠正**：Web 端口上 HTTP/HTTPS 都不通时，回落到协议探针
   （例如 80 上跑 SSH、8443 上跑 MySQL，都会被识别出来而不是简单标记"无响应"）。

### 与 POC 引擎的关系

这套"探针 → 解析器 → 结构化结果 + 置信度"的管线，正是 M4 POC 引擎需要的骨架：
把"发一个只读请求"换成"发一个验证性请求"、把"解析字段"换成"匹配器求值"，
模板引擎就有了。**先把识别的准确率做扎实，再谈漏洞判定**，这也是 M1 排在 M4 前面的原因。

---

## 7.2 资产关联三件套（M2）：favicon / CDN / 证书 SAN

信息收集的难点不在"发现一个资产"，而在**把孤立资产串成关系网**。
M2 加的三件事，都是在回答"这台机器和那台机器是不是一伙的"。

### favicon 指纹：把自研系统接入社区指纹库

```
favicon 字节 ──► base64（每 76 字符换行 + 结尾换行）──► MurmurHash3 x86_32 ──► 有符号 32 位
                 └─ Shodan 约定；FOFA/hunter 则直接对原始字节取 mmh3，两种都记录
```

为什么要自己实现 mmh3：这是**唯一**能让我们与 Shodan/FOFA 数据对齐的算法，
而引入 `python-mmh3` 或第三方 Go 包会破坏"零依赖、隔离网可编译"的底线。
已知向量（`mmh3("foo") = -156908512`）保证实现与社区一致。

**置信度是 medium 而不是 high**：哈希会碰撞，一个 favicon 相同不等于系统相同。
真实的攻防价值在于"同一个自研系统在 20 个域上都用了同一个图标"——
它把资产从"一堆域名"变成"一套业务系统"。

### CDN / WAF：只做被动识别，绝不主动探测

| 证据强度 | 来源 | 说明 |
| --- | --- | --- |
| 最强 | CNAME 后缀 | 直接说明流量被谁接管（`.cdn.cloudflare.net`、`.kunlun.com`…） |
| 中 | 响应头 | `CF-RAY`、`X-Amz-Cf-Id`、`X-Akamai-*`、`EagleId`、`X-Ws-Request-Id`… |
| 中 | Set-Cookie 名 | `__cfduid`、`incap_ses_*`、`BIGipServer*`、`HWWAFSESID`… |

**为什么不主动探测 WAF**：发一个明显的攻击 payload 看会不会被拦，既会污染目标日志、
又会被 WAF 记成攻击行为，还要求操作者对该动作有独立授权。
本框架的选择是：**只用已有事实推断，并明确提示"边缘 IP 不代表源站、需要人工在授权范围内确认源站"**。

### 证书 SAN 联动：一次扩展，两道闸门

```
TLS 证书 ──► SAN 域名列表 ──► ① 授权闸门（allow/deny + 解析后 deny 复检）
                              ├─ 通过 → 纳入扫描（-san-max-hosts 限流）→ 记 san_asset
                              └─ 拒绝 → 记 san_rejected（审计留痕，不发包）
```

这是本框架里**唯一会"自己长出新目标"**的功能，所以控制做得最严：

1. 每个候选域名**单独**过 `scope.Guard`，不是"父域名在范围内子域名就自动放行"；
2. 通配符证书（`*.example.com`）**不展开**，只打标记 —— 无边界枚举不属于信息收集；
3. 上限 100 台（可配），且候选池上限 512，避免一张大证书把任务炸开；
4. 越界域名写入 `san_rejected` 审计，扫描动作与拒绝动作都可回溯。

### 这三件事共同依赖的底座

`Asset.Confidence` + `Asset.Evidence[]`：

```json
{
  "host": "www.example.com", "port": 443, "service": "http",
  "favicon_hash": 1407517096, "cdn": "Cloudflare", "behind_cdn": true,
  "confidence": "high",
  "evidence": ["http:status=200", "favicon:mmh3=1407517096",
               "header:cf-ray", "header:server", "cookie:__cfduid"]
}
```

报告里的每一行结论都能回答"凭什么这么判"。**没有证据链的结论等于误报**，
这条纪律从 M1 一直贯穿到 M4 的漏洞验证。

---

## 8. 分布式演进设计（M5 预留）

当前代码已经具备三个可替换点，分布式改造**不需要重写扫描逻辑**：

```
                        ┌──────────────────────────────┐
                        │  Server（编排 + 存储 + 报告）  │
                        │  · TaskSource：切片任务        │
                        │  · Registry：Agent 注册/心跳   │
                        │  · Aggregator：资产汇聚去重    │
                        └───────┬──────────────▲────────┘
                     任务流(gRPC)│              │资产流(gRPC)
                                ▼              │
                        ┌──────────────────────────────┐
                        │  Agent（执行 + 本地 Scope）    │
                        │  · 拉任务 → 跑 pipeline 阶段   │
                        │  · 结果批量上报（背压 + 重试）  │
                        └──────────────────────────────┘
```

设计要点：

1. **任务分片键**：以 `(host, portRange)` 为最小可重试单元，`job_id = hash(host+ports)`，
   天然幂等 —— Agent 掉线重连后重复执行不会产生重复数据（服务端 `Key()` 去重兜底）。
2. **Agent 侧仍保留 `Scope`**：范围校验必须在**发包的那台机器**上也生效，
   否则一个被攻陷的 Server 就能指挥全网 Agent 随便打。
3. **背压与批量**：Agent 本地聚合 1s / 200 条再上报，减少 RPC 次数；Server 端限流保护。
4. **断点续扫**：任务表带 `status(pending/running/done/failed)` + `heartbeat_at`，
   Server 定期把超时 `running` 任务重置为 `pending`（租约模型）。
5. **资产归属**：`Asset.Meta["job_id"] / ["agent_id"]` 记录来源，便于溯源与复扫对比。

---

## 9. 可观测性与审计

| 维度 | 现状 | 计划 |
| --- | --- | --- |
| 结构化日志 | `log` 到 stderr，`-v` 输出每条发现 | 换 `log/slog`，支持 `-log-format json` |
| 审计 | JSONL：`run_start/target_rejected/port_open/web_alive/crawl_hit/web_probe_failed/run_finish/run_error` | 增加操作者身份、授权书编号、审批单号 |
| 指标 | 结束时打印统计摘要（服务/端口/产品/状态码 TopN） | Prometheus `/metrics`（扫描速率、成功率、错误分类） |
| 结果可复现 | `-o out.jsonl` 全量落盘，含 `found_at` | 加 `scan_id` 与配置快照，支持"两次扫描差异对比" |

---

## 10. 测试策略

| 层次 | 手段 | 覆盖内容 |
| --- | --- | --- |
| 单元测试 | `go test ./...` | `scope.Check/NormalizeHost/Guard`、`target.ParsePorts/ParseAll/CIDR 展开熔断`、`crawl` 链接抽取与深度控制、`fingerprint` 规则编译与匹配 |
| 集成测试 | `httptest.Server` 起假站点 | 端口扫描 → HTTP 探测 → 指纹 → 爬虫 全链路（不需要外部靶机） |
| 端到端 | `scripts/demo-local.ps1` | 本地起 Python 静态站，扫描并产出 JSONL，验证闭环与审计 |
| 靶场验证 | vulhub / DVWA / OWASP Juice Shop（M2 之后） | 真实中间件指纹准确率；M4 起用于 POC 误报率回归 |
| 回归基线 | 固定靶场 + 期望结果 JSON 比对 | 防止改指纹/改并发导致结果漂移 |

> 原则：**任何会发网络包的改动，必须能在本地 `httptest` 环境里跑一遍**，
> 不依赖外部靶机，这样 CI 里也能跑。

---

## 11. 主要风险与对策

| 风险 | 后果 | 对策 |
| --- | --- | --- |
| 误扫未授权目标 | 法律风险 | 强制 `authorized` + `allow/deny` + `strict_scope` + 审计留痕 |
| 把目标打挂 | 业务事故 | 全局限速、Web 并发收敛、CIDR 熔断、`timeout` 上限 |
| DNS 重绑定绕过范围 | 打到内网 | `Guard` 解析后按 IP 复检 deny |
| 指纹误报 | 报告不可信 | 规则多特征组合、纯端口规则必须显式声明、M2 引入置信度字段 |
| 结果数据泄露 | 客户资产外泄 | 本地 JSONL、不内置任何外发上报；审计与报告文件权限 0644 可调 |
| 工具自身被投毒 | 供应链攻击 | 零第三方依赖；发布物用 `-trimpath` 构建并附校验和 |
| 沙箱/隔离网无法拉依赖 | 无法交付 | 零依赖设计；`go build` 离线可用 |

---

## 12. 已知限制（v0.1 诚实清单）

1. **未经编译验证**：交付环境无 Go 工具链且无外网，代码需在 Go 1.21+ 环境首次编译。
2. 端口扫描为 connect 扫描，无 SYN 半开 / 无 UDP（M1 计划）。
3. 爬虫不执行 JS，SPA 站点覆盖有限（M3 接无头浏览器）。
4. 指纹无 favicon mmh3 哈希（需自实现 mmh3，M2）。
5. 外置规则整体覆盖内置规则，暂不支持合并（M2）。
6. 无目录爆破 / 子域枚举（M2/M3，属于更高风险动作，需单独开关与更严格限速）。
7. 单机模式无断点续扫，进程中断后需重跑（M5 由 Server 任务表解决）。
