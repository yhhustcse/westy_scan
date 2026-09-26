# 规则库：指纹与漏洞模板（M7）

> 这份文档回答一个问题：**这个扫描器的"弹药"有多少、靠不靠谱、怎么往里加。**

---

## 1. 为什么规则库值得单独做一轮

引擎决定"能不能扫"，规则库决定"扫得出什么"。同一个引擎，41 条指纹和 256 条指纹
是两种工具；13 个模板和 130 个模板也是两种工具。

但规则库有个反直觉的陷阱：**它的失效方式是静默的**。
一条路径写错的模板不会报错，它只是永远不命中；一条 `.*` 正则也不会报错，
它只是到处命中。两种都不会有人告诉你——直到你拿它去扫真目标。

所以 M7 不只是"加规则"，而是同时立了三道门禁（见第 3 节），
让"死模板"和"误报源"在构建期就暴露。

---

## 2. 当前规模

### 指纹规则：41 → 256 条

| 分组 | 条数 | 覆盖 |
| --- | --- | --- |
| 基础（M0–M5 期） | 41 | 协议 banner（SSH/FTP/SMTP/MySQL/PostgreSQL/Redis/Memcached/MongoDB/VNC/RDP）+ 常见 Web 中间件 |
| 应用层（`rules_library_app.go`） | 123 | Web 服务器/中间件、Java 生态、语言框架、CMS、数据库与面板、DevOps/CI/制品、大数据/搜索/消息、监控/日志、代理网关、文件协作与 Web 邮件 |
| 设备与基础设施层（`rules_library_net.go`） | 92 | 网络设备、安全设备/VPN、安防摄像头、打印机、存储、国产 OA/ERP/中间件、网管运维平台 |

其中 51 条带端口收敛（`ports`），3 条是纯端口规则（显式标 `low`，例如 RDP、工控协议）。

```bash
bin/westy -list-rules          # 导出当前生效的全部指纹规则（JSON）
bin/westy -list-rules | find /c "\"name\""     # Windows 下快速数条数
```

### 漏洞模板：13 → 130 条

| 分组 | 文件 | 条数 | 方向 |
| --- | --- | --- | --- |
| 基础暴露面 | `builtin-exposure.json` | 13 | .git/.env/actuator/nacos/ES/Docker API/Jenkins/phpinfo/Prometheus/目录遍历/CORS/Swagger |
| Web 与 DevOps | `builtin-exposure-web.json` | 67 | actuator 系列、Druid、API 文档、大数据与搜索、CI/制品、监控、容器编排、配置与备份泄露、数据库面板 |
| 国产应用与设备 | `builtin-exposure-cn.json` | 50 | 国产 OA/ERP、国产数据库与中间件控制台、网管运维、安防设备、网络/安全设备管理口、堡垒机、打印机与 NAS |

```bash
bin/westy -list-templates      # 导出当前生效的模板（含级别/方法/路径/是否跟随跳转/来源文件）
bin/westy -poc-tags exposure -list-templates    # 只看某一类
```

**全部模板都是只读的**：非 `intrusive` 模板只能用 GET/HEAD/OPTIONS，
写方法（POST/PUT/PATCH/DELETE）在加载期就会被拒绝，必须显式声明 `intrusive: true`
并由执行端用 `-allow-intrusive` 二次放行。这是刻意设计的闸门。

---

## 3. 三道质量门禁

### 门禁一：加载期强校验（挡"格式非法"）

`poc.Load` 与 `fingerprint.New` 都是"任何一条非法就整体报错"，绝不静默跳过：

- 正则必须能被 RE2 编译 —— **不支持 lookahead/lookbehind/反向引用**（M4 踩过）；
- 模板必须声明方法、路径、至少一个匹配器；
- 模板引用的变量必须在白名单内（`{{BaseURL}}`/`{{Hostname}}`/`{{randstr}}`…），
  变量名写错会被拦下（否则它会原样发出去，属于静默失效）；
- 指纹规则必须有 `name`，`banner_regex` 等字段必须能编译。

### 门禁二：空匹配门禁（挡"误报源"）

`internal/fingerprint/rules_library_gate_test.go` + `internal/poc/library_fixtures_test.go`：

- 指纹规则的正则**不得匹配空串**（空响应头 / 空响应体在真实世界极其常见，
  一条 `.*` 规则就等于"在任何目标上都命中"）；
- 同上检查模板的所有正则；
- 指纹规则名不得重复（**大小写不敏感**，与合并语义一致）；
- 声明 `high` 置信度的规则必须有实打实的特征串；
- 内置规则数不得低于下限（防误删）。

### 门禁三：金丝雀门禁（挡"死模板"）

这是三道门禁里最有价值的一道：

```
scripts/rules-fixtures/*.json   ← 夹具：声明"某模板命中时，真实响应长什么样"
scripts/fake-services.py:18082  ← 金丝雀站点：严格按夹具返回，未声明的路径一律 404
```

于是三件事都能自动验证：

1. **每条模板都能命中自己的金丝雀**（不命中=死模板，测试直接失败）；
2. **每条模板都有金丝雀**（加了模板忘了夹具，同样失败）；
3. **同一批模板打在干净站点上必须 0 命中**（误报门禁）。

```bash
go test ./internal/fingerprint/ ./internal/poc/ -count=1      # 三道门禁
powershell -ExecutionPolicy Bypass -File scripts/demo-rules.ps1   # 真进程端到端：金丝雀 + 干净站点
```

> 夹具里可以写 `"expect": "no-match"` 表示"这个响应**不该**命中"。
> 典型场景：设备先 302 跳到登录页，跳转那一步的空 body 绝不能算命中。
> 负样本和正样本一样重要——只测正样本的门禁，是能被"每条模板配一个假夹具"骗过去的。

---

## 4. 怎么加一条指纹规则

内置规则写在 `internal/fingerprint/rules_library_{app,net}.go`，
外置规则写 JSON 用 `-rules` 指定（默认与内置**合并**，同名外置覆盖内置；
`-no-default-rules` 可只留外置）。

```json
{
  "name": "H3C iMC",
  "service": "http",
  "ports": [8080, 8443],
  "title_regex": ["(?i)\\biMC\\b"],
  "header_regex": { "server": "(?i)iMC" },
  "body_regex": ["/imc/"],
  "confidence": "medium",
  "enabled": true
}
```

写规则的红线（都是踩过的坑）：

| 红线 | 原因 |
| --- | --- |
| 正则里必须有具体字面量 | 靠 `\d+`/`.+` 单独成规则等于没有规则 |
| header 值用 `.+` 而不是 `.*` | `.*` 能匹配空响应头，任何站点都命中（M2 事故） |
| 显式写 `(?i)` | 否则大小写一变就漏 |
| 只用 RE2 语法 | lookahead/反向引用编译不过，加载期直接失败 |
| 能用 `ports` 收敛就收敛 | 减少跨服务误报 |
| 纯端口规则显式标 `low` | 纯端口推断本来就不可靠，别装成 high |
| **不要写 favicon_hash** | mmh3 值必须用真实 favicon 计算，离线拍脑袋写=永久漏报 |

加完必须做两件事：**在 `rules_library_*_test.go` 里补一个正样本**（造出该产品的真实风格响应，
断言 `product` 命中），并跑一次完整门禁。

---

## 5. 怎么加一条漏洞模板

```json
{
  "id": "actuator-heapdump-exposure",
  "info": {
    "name": "Spring Boot Actuator heapdump 可下载",
    "severity": "high",
    "description": "堆转储文件可未授权下载，攻击者可从中提取内存中的凭据与密钥。",
    "tags": ["exposure", "springboot", "actuator"],
    "confidence": "high"
  },
  "http": [
    {
      "method": "GET",
      "path": ["{{BaseURL}}/actuator/heapdump"],
      "redirects": true,
      "matchers-condition": "and",
      "matchers": [
        { "type": "status", "status": [200] },
        { "type": "word", "part": "body", "words": ["JAVA PROFILE"] },
        { "type": "header", "headers": { "Content-Type": "(?i)octet-stream|application/java" } }
      ]
    }
  ]
}
```

字段语义要点：

| 字段 | 说明 |
| --- | --- |
| `method` | 只读方法（GET/HEAD/OPTIONS）可直接用；写方法必须 `"intrusive": true` |
| `path` | 可写多个，**命中任一即算命中**；带 `{{BaseURL}}` 变量 |
| `redirects` / `max-redirects` | 默认**不跟随**跳转（跳转后的页面常是"没漏洞"的假象）。设备类模板（先 302 到登录页）需要显式打开 |
| `matchers-condition` | `and`（默认）/ `or`，作用于同一请求的多个匹配器 |
| `extractors` | 抽取证据（版本号等），密钥类内容会被自动掩码 |
| `-verify` | 引擎默认二次确认：同一请求原样重放，两次都命中才算 |

写模板的红线：

1. **必须"状态码 + 至少一个产品专有特征"**，绝不能靠 `login`/`welcome`/`管理`/`系统` 这类泛化词；
2. 匹配器要能解释"凭什么命中"（证据链），否则复核的人无法判断真假；
3. 不改数据：能用 GET 判断的，绝不发 POST；
4. 加完必须写夹具（见第 6 节），否则门禁三会失败。

---

## 6. 怎么给模板写金丝雀夹具

夹具放在 `scripts/rules-fixtures/<主题>.json`：

```json
[
  {
    "template_id": "actuator-heapdump-exposure",
    "path": "/actuator/heapdump",
    "status": 200,
    "content_type": "application/octet-stream",
    "headers": { "Server": "nginx/1.24.0" },
    "body": "JAVA PROFILE 1.0.2\u0000\u0000\u0000..."
  }
]
```

规则：

- `template_id` 必须与模板 id **完全一致**（拼错=没有夹具，门禁三会失败）；
- `path` 是**精确路径**（去掉查询串后精确匹配），不同夹具的 `path` 不能重复；
- `body` 写成"最小但真实"的响应，刚好满足该模板的匹配器，**不要**顺带满足别的模板；
- 两个模板必须打同一路径时，用一条夹具 + `"also_serves": ["另一个模板id"]`；
- 想声明"这个响应不该命中"，加 `"expect": "no-match"`。

> **夹具是"命中时的响应长什么样"，不是网络抓包流水**。
> 门禁在合成响应上判定，不跟随跳转；所以对于"先 302 再跳登录页"的设备类模板，
> 夹具直接在声明路径上给出最终登录页内容（模板里照旧保留 `"redirects": true`，
> 真机由引擎跟随跳转拿到同一份内容）。这样门禁测的是"匹配器能不能认出这个产品"，
> 而不是"HTTP 客户端会不会跟跳转"——后者由引擎自己的测试负责。

写完跑 `scripts/demo-rules.ps1`，它会打印"命中 N/N"与干净站点的误报数。

---

## 7. 已知薄弱点（诚实清单）

1. **规则是人写的，不是抓包来的**。所有正样本都是按产品真实响应风格手写的，
   **没有在真实设备/系统上回归过**。冷门型号覆盖差，运气不好会漏；
2. **28 条规则依赖"产品专有响应头存在性"**（值正则故意宽松，例如 `x-nextcloud: .+`）。
   这是业界常规做法（头名唯一时可靠），但头名冲突时会误报；
3. **favicon 哈希一条都没填**：mmh3 值必须用真实 favicon 计算，无法离线凭记忆写出，
   宁可空着也不写错（写错=永久漏报）；
4. **设备类规则偏"文本特征"**：banner/header/title 认得出的就认，认不出的一律不猜；
   工控协议（S7/Modbus）只做了端口级 low 置信度；
5. **模板只覆盖"只读暴露面"**：不做注入/反序列化/文件上传类利用，
   这类模板需要强副作用控制与真实靶场验证，属于另一个阶段；
6. **OOB 只有 HTTP 回调**，DNS 型外带未做，部分无回显漏洞验证不了；
7. **没有真实目标上的检出率/误报率数据**：目前的"130/130 命中、干净站点 0 误报"
   只证明"模板不是死的、不滥杀"，**不证明它在真实网络上够准**。

---

## 8. 下一步扩库优先级

| 优先级 | 做什么 | 为什么 |
| --- | --- | --- |
| P0 | 在授权靶场（vulhub / DVWA / 真实内网授权段）跑一轮，记录漏报与误报 | 现在全部质量结论都建立在合成样本上 |
| P1 | 用真实 favicon 批量计算 mmh3，补齐 favicon 指纹 | 这是同类工具最有效的资产识别手段之一 |
| P1 | 导入 nuclei 模板子集（YAML 子集解析器已就绪），只收只读类 | 模板数从 130 到几百的最快路径 |
| P2 | 给设备类规则补真实 banner 样本 | 现在的写法是"有则命中"，样本能让它变准 |
| P2 | 按客户场景做规则分组（如"只扫 Web 暴露面"/"只扫设备"），配合 `-poc-tags` | 减少无关噪声 |
| P3 | 规则库版本化与热更新（外置 JSON 已支持，缺签名与版本元数据） | 规则比二进制更新频率高得多 |
