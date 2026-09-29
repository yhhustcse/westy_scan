# 真实目标校准记录（CALIBRATION）

> 目的：把"未经真实目标校准"这条已知缺口，用**可复现的记录**逐步补上。
> 与金丝雀靶站的区别很关键：金丝雀的响应是**我们自己写的**（证明"模板不是死的"），
> 真实应用的内容是**别人写的**（才能暴露"漏报"和"误报"）。

---

## 1. 本轮目标与合规

| 项 | 值 |
| --- | --- |
| 目标 | `http://127.0.0.1:4455` —— DVWA（Damn Vulnerable Web Application），phpstudy 部署 |
| 授权依据 | 作者自有机器上的本地靶场应用（DVWA 本身就是"故意有漏洞、供授权测试"的应用） |
| 扫描范围 | `-allow 127.0.0.1/32 -strict-scope`，仅 1 个端口 |
| 动作边界 | **只有只读 GET**（未执行 `-allow-intrusive`）；未做登录、未写任何数据、未触碰 `setup.php` 的初始化动作 |
| 目标地址空间 | ⚠️ `Get-NetTCPConnection` 显示该端口监听在 **`0.0.0.0:4455`**（不只是 127.0.0.1），见第 5 节 |

**目标性质（为什么它比金丝雀靶站更有价值）**：DVWA 是一个"内容不由我们控制"的真实 Web 应用——
有登录、有会话、有 CSRF token、有跳转、有 403/404 的真实分布。这正是校准"漏报/误报"所需要的。

## 2. 已知答案对照表（校准的核心方法）

先**独立**用只读请求把每个路径的真实响应记录下来（`AllowAutoRedirect=false`），
再与扫描器的判定对比——这样"命中/漏报/误报"才有客观依据。

| 路径 | 真实响应 | 扫描器是否命中 | 判定 |
| --- | --- | --- | --- |
| `/` | 302 → `login.php` | —（跳转，正常） | 无模板，预期不命中 |
| `/login.php` | 200，`Login :: Damn Vulnerable Web Application (DVWA)` | — | 无模板（登录页不是漏洞） |
| `/phpinfo.php` | **302 → `login.php`**（需登录） | ❌ 未命中 | **机制性不命中**（见第 5.2 节，不算误判） |
| `/setup.php` | **200，`Setup :: DVWA`（未授权可访问）** | ❌ 未命中 | **能力缺口**：没有覆盖 DVWA 安装页的模板 |
| `/robots.txt` | 200 | —（进种子，不是漏洞） | 预期不命中 |
| `/server-status` | **200，`Apache Status`** | ✅ **命中**（`apache-server-status-exposure`，medium，已验证） | **真阳性** |
| `/server-info` | **200，`Server Information`** | ✅ **命中**（`apache-server-info-exposure`，medium，已验证） | **真阳性** |
| `/config/config.inc.php` | 200，**空 body**（PHP 执行后无输出） | 未命中 | **正确不命中**：模板要求内容特征，不靠"200 就算源码泄露"（经典误报点） |
| `/.git/config` | 404 | 未命中 | **正确不命中**（负样本通过） |
| `/.env` | 404 | 未命中 | **正确不命中**（负样本通过） |
| `/dvwa/` | 403（目录列表被禁） | 未命中 | 合理（无目录爆破能力，见第 6 节） |
| `/instructions.php`、`/about.php` | 200 | 未命中 | 正常业务页 |

## 3. 本轮统计

| 指标 | 数值 | 说明 |
| --- | --- | --- |
| 真阳性（TP） | **2** | 两条 Apache 状态页暴露，逐条独立复核为真实存在 |
| 误报（FP） | **0** | 扫描只报了这 2 条；另有两个"故意 404"的路径（`/.git/config`、`/.env`）未被误报 |
| 漏报（FN，能力缺口） | **1** | `setup.php` 未授权可访问（无模板覆盖） |
| 机制性不命中 | **1** | `phpinfo.php` 需登录（302），非模板缺陷 |
| 指纹识别 | Apache httpd + PHP ✅ | 正确；**DVWA 自身未被识别**（见第 6 节） |
| 爬虫/参数抽取 | ✅ | 跟随 302 到 `login.php`，抽出登录表单字段 `username`/`password`/`Login`/`user_token` |
| 证据抽取 | ✅ | `apache-server-status-exposure` 抽到 `apache_version=2.4.39` |

> 这轮的意义不在"命中了几条"，而在于：**数值第一次不是我们自己造出来的**。
> 尤其 `/.env`、`/.git/config` 这两个 404 负样本与"空 body 的 config.inc.php"——
> 它们验证的是"不误报"，而这恰恰是扫描器最容易翻车的地方。

## 4. 复现命令

```powershell
# 基础扫描（只读；-verify 二次确认）
bin\westy.exe -target http://127.0.0.1:4455 `
  -allow 127.0.0.1/32 -authorized -strict-scope -ports 4455 `
  -poc -verify `
  -o out\dvwa-assets.jsonl -vulns out\dvwa-vulns.jsonl `
  -audit out\dvwa-audit.jsonl -report out\dvwa-report.md -format markdown

# 带爬虫 + 站点地图（看攻击面输入面：表单/参数/JS 接口）
bin\westy.exe -target http://127.0.0.1:4455 `
  -allow 127.0.0.1/32 -authorized -strict-scope -ports 4455 `
  -crawl -crawl-depth 3 -crawl-pages 100 -sitemap -poc -verify `
  -o out\dvwa2-assets.jsonl -vulns out\dvwa2-vulns.jsonl -audit out\dvwa2-audit.jsonl
```

## 5. 两条真实结论

### 5.1 真阳性：phpstudy 的 Apache 默认开着了 `mod_status` / `mod_info`

- `/server-status` 泄露**实时请求日志**（访问的 URL、客户端 IP、耗时）；
- `/server-info` 泄露**完整的模块与配置信息**；
- 更值得注意：该端口监听在 **`0.0.0.0:4455`**，不只是回环。
  也就是说**同一局域网内的其他人可以直接访问这两个页面**。

**加固建议**（phpstudy 用户请注意）：在 Apache 的 `httpd.conf` 里把 `server-status` / `server-info` 的
`<Location>` 段注释掉，或至少限制为 `Require local`；开发机不要绑 `0.0.0.0`。

> 这条结论正好说明这类工具的价值：**它不是"扫描靶场"，而是把你机器上真实存在的配置问题指出来**。

### 5.2 机制性不命中：`phpinfo.php` 需要登录，模板要求 200

`phpinfo-exposure` 模板的匹配器是"`status 200` + body 含 `phpinfo()`/`php.ini`"，
而 DVWA 的 `/phpinfo.php` 直接 **302 到 `login.php`**；引擎默认**不跟随跳转**
（"跳转后的页面往往是没漏洞的假象"），因此看到的是 302 → 不命中。

**这不是模板写错**，而且"打开 `redirects: true` 也救不了"：跟到 `login.php` 后拿到的是登录页，
仍然不含 phpinfo 特征。真正的阻塞是**认证**——即 README 里写的已知缺口"**无登录态扫描**"，
这次被真实环境证实了。

> 诚实补充：本轮**未能完成**"带会话访问验证"的实验——该 DVWA 实例的数据库尚未初始化
> （`setup.php` 可访问、默认口令登录不成功，DVWA 需要先点 "Create/Reset Database"）。
> 那一步是**写操作**，我没有替作者执行。所以"认证后模板会命中"目前是**推断**（机制清晰）
> 而非实测结论，记录在此以免夸大。

## 6. 暴露出的能力缺口（诚实清单）

| # | 缺口 | 影响 | 是否已列入路线 |
| --- | --- | --- | --- |
| 1 | **无登录态扫描** | 登录后的全部功能面（DVWA 的 SQLi/XSS/命令注入等）都扫不到 | 是（README 已知缺口） |
| 2 | **无目录爆破** | `/dvwa/` 这类 403 背后的真实路径发现不了；只靠爬虫与已知模板路径 | 是（推迟项） |
| 3 | **DVWA 自身无指纹规则** | 页面标题里 `Damn Vulnerable Web Application (DVWA)` 特征极其明确却未被识别 | 否（可作为"写第一条规则"的练习） |
| 4 | **无 DVWA 安装页模板** | `setup.php` 未授权可访问未被覆盖 | 否（靶场产品专有，实战价值低，属于练流程） |
| 5 | 目标不是"生产系统" | DVWA 是刻意脆弱的靶场应用，**不代表真实企业资产的复杂度与噪声** | 是（需付费靶机网段或授权内网） |

## 7. 下一步（校准升级路径）

| 步骤 | 目标 | 能补什么 |
| --- | --- | --- |
| ✅ 本轮 | DVWA（真实 Web 应用） | 误报/漏报的第一次客观对照 |
| 下一步 1 | **vulhub** 按 CVE 起环境（`docker compose up -d`） | **模板级**校准：130 条模板对已知 CVE 的命中率 |
| 下一步 2 | Juice Shop（SPA + REST API） | 爬虫在 SPA 上的覆盖率、JS 接口抽取的有效性 |
| 下一步 3 | Metasploitable2/3（多服务） | **端口/协议指纹**的识别率（真实 banner） |
| 下一步 4 | 付费靶机网段（HTB Pro Labs / OffSec PG） | **网络测绘 + 限速 + 变更对比**的真实规模验证 |

> 三条纪律（沿用本项目一贯做法）：**每条结论都要有独立复核**、**每个数字都要可复现**、
> **做不到的事情如实写成"推断"而不是"实测"**。
