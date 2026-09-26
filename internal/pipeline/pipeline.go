// Package pipeline 把各个模块编排成一条扫描流水线。
//
// 流水线形状（单机版）：
//
//	目标表达式 ──► Scope 闸门 ──► TCP 端口扫描 ──► 指纹(服务)
//	                                   │
//	                                   └─► HTTP/HTTPS 探测 ──► 指纹(Web) ──► 爬虫(可选)
//	                                                                          │
//	                                    所有资产 ──► Store(去重/落盘) + Audit(审计)
//
// 每个阶段的"输入/输出"都是 model.Asset 流，因此后续要把某个阶段
// 搬到远端 Agent 上执行，只需要替换这一段的 channel 为网络流。
package pipeline

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"westy_scan/internal/audit"
	"westy_scan/internal/cdn"
	"westy_scan/internal/config"
	"westy_scan/internal/crawl"
	"westy_scan/internal/fingerprint"
	"westy_scan/internal/httpinfo"
	"westy_scan/internal/model"
	"westy_scan/internal/poc"
	"westy_scan/internal/portscan"
	"westy_scan/internal/probe"
	"westy_scan/internal/ratelimit"
	"westy_scan/internal/scope"
	"westy_scan/internal/seed"
	"westy_scan/internal/store"
	"westy_scan/internal/sysinfo"
	"westy_scan/internal/target"
	"westy_scan/internal/udpscan"
)

// ErrAllTargetsRejected 表示本次运行的**所有**目标都被授权范围拦截或无法解析。
//
// 为什么单独做成哨兵错误：调用方需要区分"扫完了没结果"和"一个都没扫成"。
// Agent 尤其需要——它要把这种任务记进 rejected 审计，让服务端看得出"Agent 拒绝了什么"。
// 以前 Agent 靠匹配错误文案里的「授权范围」四个字来判断，改一次文案就静默失效。
var ErrAllTargetsRejected = errors.New("全部目标均被授权范围拦截或无法解析")

// Engine 是一次扫描运行的上下文。
type Engine struct {
	cfg   config.Config
	scope *scope.Scope
	limit *ratelimit.Limiter
	fp    *fingerprint.Engine
	probe *httpinfo.Prober
	store store.Store
	audit *audit.Logger
	log   *log.Logger

	mu          sync.Mutex
	seeds       []string
	blindProbes int64 // 已用掉的"盲试 HTTP"配额，见 shouldProbeWeb

	// M2：证书 SAN 联动扩展
	cnameCache map[string]string // host -> CNAME（避免重复 DNS 查询）
	sans       []string          // 待扩展的 SAN 候选域名
	scanned    map[string]bool   // 已处理过的主机，防止 SAN 回环重复扫描

	// M4：漏洞模板验证
	poc      *poc.Engine
	oob      *poc.OOB
	findings []poc.Finding
}

// Findings 返回本次运行的漏洞验证结果。
func (e *Engine) Findings() []poc.Finding {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]poc.Finding(nil), e.findings...)
}

// New 组装流水线。Scope 构造失败（未声明授权、规则非法）会在这里直接返回错误，
// 保证任何扫描动作都不可能绕过合规闸门。
func New(cfg config.Config, st store.Store, aud *audit.Logger, logger *log.Logger) (*Engine, error) {
	sc, err := scope.New(cfg.Allow, cfg.Deny, cfg.MaxHosts, cfg.StrictScope, cfg.Authorized)
	if err != nil {
		return nil, err
	}
	fp, err := fingerprint.LoadMerged(cfg.RulesFile, !cfg.NoDefaultRules)
	if err != nil {
		return nil, err
	}
	timeout := time.Duration(cfg.TimeoutSec) * time.Second
	limiter := ratelimit.New(cfg.RateLimit)

	// M4：模板在启动期加载并校验，配置错误立刻暴露，而不是扫到一半才发现
	var pocEngine *poc.Engine
	var oob *poc.OOB
	if cfg.POCEnabled {
		loadOpt := poc.LoadOptions{
			IncludeBuiltin: !cfg.POCNoBuiltin,
			Tags:           cfg.POCTags,
			Severity:       cfg.POCSeverity,
		}
		if strings.TrimSpace(cfg.POCTemplates) != "" {
			loadOpt.Paths = []string{cfg.POCTemplates}
		}
		tpls, err := poc.Load(loadOpt)
		if err != nil {
			return nil, err
		}
		if strings.TrimSpace(cfg.OOBListen) != "" {
			oob, err = poc.NewOOB(cfg.OOBListen, cfg.OOBDomain)
			if err != nil {
				return nil, err
			}
		}
		pocOpt := poc.Options{
			Timeout:        timeout,
			Concurrency:    min(max(cfg.Concurrency/20, 4), 16),
			Limiter:        limiter,
			UserAgent:      cfg.UserAgent,
			Verify:         cfg.POCVerify,
			AllowIntrusive: cfg.POCAllowIntrusive,
			OOB:            oob,
			Logf:           logger.Printf,
		}
		pocEngine = poc.NewEngine(tpls, pocOpt)
		logger.Printf("漏洞模板已加载: %d 个（二次确认=%v，外带验证=%v）",
			len(tpls), cfg.POCVerify, oob != nil)
	}

	return &Engine{
		cfg:        cfg,
		scope:      sc,
		limit:      limiter,
		fp:         fp,
		probe:      httpinfo.New(timeout, cfg.UserAgent),
		store:      st,
		audit:      aud,
		log:        logger,
		cnameCache: make(map[string]string),
		scanned:    make(map[string]bool),
		poc:        pocEngine,
		oob:        oob,
	}, nil
}

// Scope 暴露授权范围，供 main 打印启动横幅。
func (e *Engine) Scope() *scope.Scope { return e.scope }

// Run 执行完整流水线，直到所有阶段结束或 ctx 被取消。
func (e *Engine) Run(ctx context.Context) error {
	defer e.limit.Stop()

	hosts, err := e.resolveTargets()
	if err != nil {
		return err
	}
	if len(hosts) == 0 {
		return errors.New("没有可用目标")
	}
	ports, err := target.ParsePorts(e.cfg.Ports)
	if err != nil {
		return err
	}

	hostNames := make([]string, 0, len(hosts))
	for _, h := range hosts {
		hostNames = append(hostNames, h.Host)
		e.markScanned(h.Host)
	}
	e.logf("目标 %d 个，端口 %d 个，并发 %d，限速 %s", len(hostNames), len(ports), e.cfg.Concurrency, rateText(e.cfg.RateLimit))
	e.audit.Log("run_start", map[string]string{
		"targets":    strconv.Itoa(len(hostNames)),
		"ports":      strconv.Itoa(len(ports)),
		"scope":      e.scope.Describe(),
		"crawl":      strconv.FormatBool(e.cfg.Crawl),
		"rate_limit": strconv.Itoa(e.cfg.RateLimit),
		"max_hosts":  strconv.Itoa(e.cfg.MaxHosts),
		"user_agent": e.cfg.UserAgent,
	})

	// 扫描器（connect / syn 可插拔）
	scanner, err := portscan.NewScanner(e.cfg.ScanMode)
	if err != nil {
		return err
	}
	e.logf("扫描方式: %s", scanner.Name())

	// DNS 并发预热：避免串行解析成为吞吐瓶颈（授权判定仍由 Guard 在发包前完成）
	e.scope.PreResolve(ctx, hostNames, 64)

	// 文件描述符容量提示：每个并发连接占一个 fd，上限过低会直接导致大批连接失败
	if soft, ok := sysinfo.FDSoftLimit(); ok {
		need := uint64(e.cfg.Concurrency)*2 + 64
		if soft < need {
			e.logf("警告: 文件描述符上限 %d 低于当前并发需求 %d，建议先执行 ulimit -n %d，否则会大量出现连接失败",
				soft, need, need)
		}
	}

	// ---- 阶段 2/3：端口扫描 → 服务识别 → Web 探测 ----
	// Web 探测与协议握手都会产生额外请求，两者并发都单独收敛，避免把目标打挂
	webWorkers := e.cfg.Concurrency / 4
	if webWorkers < 4 {
		webWorkers = 4
	}
	if webWorkers > 64 {
		webWorkers = 64
	}
	svcWorkers := e.cfg.Concurrency / 2
	if svcWorkers < 4 {
		svcWorkers = 4
	}
	if svcWorkers > 128 {
		svcWorkers = 128
	}

	webJobs := make(chan model.Asset, 256)
	var webWG sync.WaitGroup
	for i := 0; i < webWorkers; i++ {
		webWG.Add(1)
		go func() {
			defer webWG.Done()
			for a := range webJobs {
				if ctx.Err() != nil {
					return
				}
				e.handleWeb(ctx, a)
			}
		}()
	}

	svcJobs := make(chan model.Asset, 256)
	var svcWG sync.WaitGroup
	for i := 0; i < svcWorkers; i++ {
		svcWG.Add(1)
		go func() {
			defer svcWG.Done()
			for a := range svcJobs {
				if ctx.Err() != nil {
					return
				}
				e.handleService(ctx, &a)
				if e.shouldProbeWeb(a) {
					select {
					case webJobs <- a:
					case <-ctx.Done():
					}
				}
			}
		}()
	}

	var rejected int64
	for a := range scanner.Scan(ctx, e.scope, hostNames, ports, portscan.Options{
		Timeout:       time.Duration(e.cfg.TimeoutSec) * time.Second,
		Concurrency:   e.cfg.Concurrency,
		Banner:        e.cfg.Banner,
		BannerTimeout: time.Duration(e.cfg.TimeoutSec) * time.Second,
		Limiter:       e.limit,
		OnError: func(t string, err error) {
			atomic.AddInt64(&rejected, 1)
			e.logf("跳过目标 %s: %v", t, err)
			e.audit.Log("target_rejected", map[string]string{"target": t, "reason": err.Error()})
		},
	}) {
		if ctx.Err() != nil {
			break
		}
		select {
		case svcJobs <- a:
		case <-ctx.Done():
		}
	}
	close(svcJobs)
	svcWG.Wait()
	close(webJobs)
	webWG.Wait()

	// 授权范围全灭时必须显式失败：否则自动化场景会把"配错范围"当成"扫完没结果"
	if rejected > 0 && int(rejected) >= len(hostNames) {
		return fmt.Errorf("%w：全部 %d 个目标均被授权范围拦截或无法解析，未执行任何扫描（请检查 allow/deny 配置）",
			ErrAllTargetsRejected, rejected)
	}

	// ---- 阶段 3.5：UDP 探测（可选）----
	if e.cfg.UDP {
		e.runUDP(ctx, hostNames)
	}

	// ---- 阶段 3.6：证书 SAN 联动扩展（M2）----
	// 同一张证书上的其它域名往往是同一业务方的资产，这是"低成本高价值"的攻击面扩展；
	// 每个候选域名都要单独过授权闸门，越界的会被审计为 san_rejected 并跳过。
	if e.cfg.SanExpand {
		e.runSANExpansion(ctx)
	}

	// ---- 阶段 4：Web 爬虫 ----
	if e.cfg.Crawl {
		seeds := e.takeSeeds()
		// M3：站点地图入口（robots.txt / sitemap.xml）——站点自己公开的路径清单
		if e.cfg.SitemapSeeds && len(seeds) > 0 {
			seeds = append(seeds, e.discoverSeeds(ctx, seeds)...)
		}
		if len(seeds) == 0 {
			e.logf("爬虫已启用，但没有可用的 Web 种子（未发现存活 HTTP 服务）")
		} else {
			if len(seeds) > 1000 {
				seeds = seeds[:1000]
			}
			e.logf("开始爬取，种子 %d 个，深度 %d，上限 %d 页", len(seeds), e.cfg.CrawlDepth, e.cfg.CrawlMaxPages)
			crawler := crawl.New(crawl.Options{
				MaxDepth:     e.cfg.CrawlDepth,
				MaxPages:     e.cfg.CrawlMaxPages,
				Concurrency:  webWorkers,
				Timeout:      time.Duration(e.cfg.TimeoutSec) * time.Second,
				UserAgent:    e.cfg.UserAgent,
				SameHost:     e.cfg.CrawlSameHost,
				Limiter:      e.limit,
				Scope:        e.scope,
				DisableJS:    !e.cfg.CrawlJS,
				MaxJSFiles:   e.cfg.CrawlMaxJS,
				MaxBodyBytes: int64(e.cfg.CrawlMaxBodyKB) << 10,
				DuplicateGap: e.cfg.CrawlDupGap,
			})
			for page := range crawler.Run(ctx, seeds) {
				a := page.Asset
				e.fp.Apply(&a, page.Headers, page.Body)
				e.record(a, "crawl_hit", map[string]string{
					"url":    a.URL,
					"depth":  strconv.Itoa(a.Depth),
					"status": strconv.Itoa(a.StatusCode),
				})
			}
		}
	}

	// ---- 阶段 5：漏洞模板验证（M4，只读）----
	if e.poc != nil {
		e.runPOC(ctx)
	}

	e.audit.Log("run_finish", map[string]string{"stored": strconv.Itoa(e.store.Len())})
	return nil
}

// runPOC 对已发现的 Web 资产执行漏洞模板验证（M4）。
//
// 只做"读"：内置模板全部是只读 GET；写操作类模板必须显式声明 intrusive 并用
// -allow-intrusive 放行，且单独记入审计。
func (e *Engine) runPOC(ctx context.Context) {
	defer func() {
		if e.oob != nil {
			_ = e.oob.Stop()
		}
	}()

	targets := e.pocTargets()
	if len(targets) == 0 {
		e.logf("漏洞验证：没有可用的 Web 目标，跳过")
		return
	}
	e.logf("漏洞验证开始：目标 %d 个，模板 %d 个，二次确认=%v，允许侵入性=%v",
		len(targets), len(e.poc.Templates()), e.cfg.POCVerify, e.cfg.POCAllowIntrusive)
	e.audit.Log("poc_start", map[string]string{
		"targets":         strconv.Itoa(len(targets)),
		"templates":       strconv.Itoa(len(e.poc.Templates())),
		"verify":          strconv.FormatBool(e.cfg.POCVerify),
		"allow_intrusive": strconv.FormatBool(e.cfg.POCAllowIntrusive),
		"oob":             strconv.FormatBool(e.oob != nil),
	})

	found := poc.FindingsBySeverity(poc.DedupFindings(e.poc.ScanTargets(ctx, targets)))
	e.mu.Lock()
	e.findings = append(e.findings, found...)
	e.mu.Unlock()

	for _, f := range found {
		e.logf("[漏洞] %s %s → %s（模板 %s，已验证=%v）",
			strings.ToUpper(f.Severity), f.Name, f.MatchedAt, f.TemplateID, f.Verified)
		e.audit.Log("vuln_found", map[string]string{
			"template":   f.TemplateID,
			"severity":   f.Severity,
			"matched_at": f.MatchedAt,
			"confidence": f.Confidence,
			"verified":   strconv.FormatBool(f.Verified),
		})
	}
	e.audit.Log("poc_done", map[string]string{"findings": strconv.Itoa(len(found))})

	if e.cfg.VulnFile != "" {
		if err := writeFindingsJSONL(e.cfg.VulnFile, found); err != nil {
			e.logf("写入漏洞结果失败: %v", err)
		}
	}
	e.logf("漏洞验证完成：命中 %d 条", len(found))
}

// pocTargets 从已发现资产派生验证目标（同一 host:port 只留一个）。
func (e *Engine) pocTargets() []poc.Target {
	limit := e.cfg.POCMaxTargets
	if limit <= 0 {
		limit = 200
	}
	seen := map[string]bool{}
	var out []poc.Target
	for _, a := range e.store.Assets() {
		if a.URL == "" {
			continue
		}
		t, ok := poc.TargetFromURL(a.URL, a.IP)
		if !ok {
			continue
		}
		key := t.BaseURL()
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, t)
		if len(out) >= limit {
			break
		}
	}
	return out
}

// writeFindingsJSONL 把漏洞结果写成 JSONL（供平台二次消费）。
func writeFindingsJSONL(path string, findings []poc.Finding) error {
	if err := os.MkdirAll(dirOf(path), 0o755); err != nil {
		return err
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	for _, item := range findings {
		if err := enc.Encode(item); err != nil {
			return err
		}
	}
	return nil
}

func dirOf(path string) string {
	if i := strings.LastIndexAny(path, `/\`); i > 0 {
		return path[:i]
	}
	return "."
}

// resolveTargets 汇总命令行与文件里的目标并去重。
func (e *Engine) resolveTargets() ([]model.Host, error) {
	var hosts []model.Host
	seen := make(map[string]bool)
	add := func(list []model.Host) {
		for _, h := range list {
			if seen[h.Host] {
				continue
			}
			seen[h.Host] = true
			hosts = append(hosts, h)
		}
	}

	if len(e.cfg.Targets) > 0 {
		parsed, err := target.ParseAll(e.cfg.Targets, e.cfg.MaxHosts)
		if err != nil {
			return nil, err
		}
		add(parsed)
	}
	if e.cfg.TargetFile != "" {
		parsed, err := target.ParseFile(e.cfg.TargetFile, e.cfg.MaxHosts)
		if err != nil {
			return nil, err
		}
		add(parsed)
	}
	return hosts, nil
}

// shouldProbeWeb 判断一个开放端口是否值得做 HTTP 探测。
//
// 三层判定：已知 Web 端口 → 已识别的 Web 特征 → 无 Banner 端口盲试（有配额上限）。
// 第三层是必要的：真实环境里大量业务系统跑在 18080/18081/9001 这类非标准端口上，
// 且不会主动发 Banner，只靠端口表会漏掉一大片攻击面。
func (e *Engine) shouldProbeWeb(a model.Asset) bool {
	if target.IsWebPort(a.Port) || a.IsWeb() {
		return true
	}
	if strings.HasPrefix(strings.ToUpper(a.Banner), "HTTP/") {
		return true
	}
	if a.Banner == "" && a.Service == "" {
		if e.cfg.BlindWebProbes <= 0 {
			return false
		}
		return int(atomic.AddInt64(&e.blindProbes, 1)) <= e.cfg.BlindWebProbes
	}
	return false
}

// handleService 对开放端口做协议握手识别（M1 核心）。
//
// 只对"有专门探针"的非 Web 端口直接探测：
//   - Web 端口交给 httpinfo 走 HTTP(S) 路径，避免对同一端口重复发包；
//   - 未知端口交给 Web 探测路径（先试 HTTP，失败再回落到协议探测做端口错配纠正）。
func (e *Engine) handleService(ctx context.Context, a *model.Asset) {
	if e.cfg.ServiceDetect && !target.IsWebPort(a.Port) && probe.HasSpecificProbe(a.Port) {
		if res := e.detectProtocol(ctx, *a); res != nil {
			res.Apply(a)
			e.audit.Log("service_identified", map[string]string{
				"host":    a.Host,
				"port":    strconv.Itoa(a.Port),
				"service": res.Service,
				"product": res.Product,
				"version": res.Version,
			})
		}
	}
	// 指纹规则兜底/补充：只填 probe 没给出的字段（置信度只升不降）
	e.fp.Apply(a, nil, []byte(a.Banner))
	e.record(*a, "port_open", map[string]string{
		"host":     a.Host,
		"ip":       a.IP,
		"port":     strconv.Itoa(a.Port),
		"service":  a.Service,
		"product":  a.Product,
		"version":  a.Version,
		"evidence": strings.Join(a.Evidence, "|"),
	})
}

func (e *Engine) detectProtocol(ctx context.Context, a model.Asset) *probe.Result {
	timeout := time.Duration(e.cfg.ServiceTimeoutSec) * time.Second
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	return probe.Detect(ctx, a.Host, a.IP, a.Port, a.Banner, probe.Options{
		Timeout:   timeout,
		MaxProbes: 3,
	})
}

// runUDP 执行 UDP 探测阶段。
//
// UDP 无连接：收不到响应既可能是 filtered 也可能是 open|filtered，
// 因此结果一律带"依据"（Evidence / meta.confidence_reason），不做过度断言。
func (e *Engine) runUDP(ctx context.Context, hostNames []string) {
	ports, err := target.ParsePorts(e.cfg.UDPPorts)
	if err != nil {
		e.logf("UDP 端口表达式非法，跳过 UDP 阶段: %v", err)
		return
	}
	supported := udpscan.SupportedPorts()
	kept := make([]int, 0, len(ports))
	for _, p := range ports {
		for _, s := range supported {
			if p == s {
				kept = append(kept, p)
				break
			}
		}
	}
	if len(kept) == 0 {
		e.logf("UDP 阶段跳过：请求的端口 %v 都没有内置探针（支持 %v）", ports, supported)
		return
	}

	udpWorkers := e.cfg.Concurrency / 4
	if udpWorkers < 4 {
		udpWorkers = 4
	}
	if udpWorkers > 64 {
		udpWorkers = 64
	}
	e.logf("UDP 探测开始：端口 %v，超时 %ds，并发 %d", kept, e.cfg.UDPTimeoutSec, udpWorkers)

	var hits int64
	for a := range udpscan.Scan(ctx, e.scope, hostNames, kept, udpscan.Options{
		Timeout:     time.Duration(e.cfg.UDPTimeoutSec) * time.Second,
		Concurrency: udpWorkers,
		Limiter:     e.limit,
		OnError: func(t string, err error) {
			e.logf("UDP 跳过目标 %s: %v", t, err)
			e.audit.Log("target_rejected", map[string]string{
				"target": t, "reason": err.Error(), "transport": "udp",
			})
		},
	}) {
		e.fp.Apply(&a, nil, []byte(a.Banner))
		e.record(a, "udp_open", map[string]string{
			"host":     a.Host,
			"port":     strconv.Itoa(a.Port),
			"service":  a.Service,
			"product":  a.Product,
			"version":  a.Version,
			"evidence": strings.Join(a.Evidence, "|"),
		})
		atomic.AddInt64(&hits, 1)
	}
	e.logf("UDP 探测完成：%d 个端口有响应", hits)
}

// handleWeb 依次尝试两种协议，成功一次即返回（避免重复计入资产）。
func (e *Engine) handleWeb(ctx context.Context, a model.Asset) {
	schemes := []string{httpinfo.GuessScheme(a.Port)}
	if schemes[0] == "http" {
		schemes = append(schemes, "https")
	} else {
		schemes = append(schemes, "http")
	}
	for _, scheme := range schemes {
		if ctx.Err() != nil {
			return
		}
		// Web 探测也要走全局令牌桶：favicon 抓取会产生额外的第二个请求
		if err := e.limit.Wait(ctx); err != nil {
			return
		}
		res, err := e.probe.Probe(ctx, a.Host, a.IP, a.Port, scheme)
		if err != nil {
			continue
		}
		// 明文 HTTP 打到 TLS 端口时，服务端通常回 400 并附带明确的提示
		// （Go/nginx/Envoy 都会这么做）。这种情况必须换 https 再试，
		// 否则非标准端口的 HTTPS 资产会被误判成"一个 400 的 HTTP 服务"。
		if scheme == "http" && httpsRequired(res) {
			continue
		}
		res.Asset.Banner = a.Banner // 保留 TCP Banner，指纹引擎两侧都能用
		e.fp.Apply(&res.Asset, res.Headers, res.Body)
		e.detectCDN(ctx, &res.Asset, res.Headers)
		e.collectSAN(&res.Asset)
		e.record(res.Asset, "web_alive", map[string]string{
			"url":    res.Asset.URL,
			"status": strconv.Itoa(res.Asset.StatusCode),
			"title":  res.Asset.Title,
		})
		e.addSeed(res.Asset.URL)
		return
	}

	// HTTP/HTTPS 都不通：可能是"端口≠服务"的错配（如 80 上跑 SSH、8443 上跑 MySQL）。
	// 用协议握手探针纠正端口猜测，这正是 M1 要解决的识别盲区。
	if e.cfg.ServiceDetect {
		if res := e.detectProtocol(ctx, a); res != nil {
			res.Apply(&a)
			e.record(a, "service_identified", map[string]string{
				"host": a.Host, "port": strconv.Itoa(a.Port),
				"service": res.Service, "product": res.Product, "version": res.Version,
				"reason": "Web 端口上发现非 HTTP 服务（端口错配）",
			})
			return
		}
	}
	e.audit.Log("web_probe_failed", map[string]string{
		"host": a.Host, "port": strconv.Itoa(a.Port), "reason": "HTTP/HTTPS 均无响应",
	})
}

// detectCDN 做 CDN/WAF 被动识别：只看 CNAME、响应头与 Set-Cookie，不发额外请求。
func (e *Engine) detectCDN(ctx context.Context, a *model.Asset, headers http.Header) {
	det := cdn.Detect(e.lookupCNAME(ctx, a.Host), headers, cdn.CookieNames(headers))
	if det.Empty() {
		return
	}
	a.CDN = det.CDN
	a.WAF = det.WAF
	a.BehindCDN = det.BehindCDN
	a.OriginNote = det.OriginHint()
	a.AddEvidence(det.Evidence...)
	a.SetMeta("cdn.evidence", strings.Join(det.Evidence, ","))
	e.audit.Log("cdn_detected", map[string]string{
		"host":     a.Host,
		"cdn":      det.CDN,
		"waf":      det.WAF,
		"evidence": strings.Join(det.Evidence, "|"),
	})
	e.logf("%s 命中 CDN/WAF: CDN=%q WAF=%q 判据=%s", a.Host, det.CDN, det.WAF, strings.Join(det.Evidence, ","))
}

// lookupCNAME 查 CNAME 链（带缓存；IP 目标直接返回空）。
func (e *Engine) lookupCNAME(ctx context.Context, host string) string {
	if host == "" || net.ParseIP(host) != nil {
		return ""
	}
	e.mu.Lock()
	if v, ok := e.cnameCache[host]; ok {
		e.mu.Unlock()
		return v
	}
	e.mu.Unlock()

	cname := ""
	if c, err := net.DefaultResolver.LookupCNAME(ctx, host); err == nil {
		c = strings.TrimSuffix(strings.TrimSpace(c), ".")
		if !strings.EqualFold(c, host) {
			cname = c
		}
	}
	e.mu.Lock()
	e.cnameCache[host] = cname
	e.mu.Unlock()
	return cname
}

// collectSAN 收集证书 SAN 里的域名作为联动扩展候选。
// 通配符（*.example.com）无法直接当主机名扫描，只记录标记。
func (e *Engine) collectSAN(a *model.Asset) {
	if a == nil || !e.cfg.SanExpand || a.TLS == nil || len(a.TLS.DNSNames) == 0 {
		return
	}
	wildcard := false
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, name := range a.TLS.DNSNames {
		n := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
		if n == "" {
			continue
		}
		if strings.Contains(n, "*") {
			wildcard = true
			continue
		}
		if e.scanned[n] {
			continue
		}
		dup := false
		for _, s := range e.sans {
			if s == n {
				dup = true
				break
			}
		}
		if dup || len(e.sans) >= 512 {
			continue
		}
		e.sans = append(e.sans, n)
	}
	if wildcard {
		a.SetMeta("tls.wildcard_cert", "true")
	}
}

func (e *Engine) markScanned(host string) {
	if host == "" {
		return
	}
	e.mu.Lock()
	if e.scanned == nil {
		e.scanned = make(map[string]bool)
	}
	e.scanned[host] = true
	e.mu.Unlock()
}

func (e *Engine) isScanned(host string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.scanned[host]
}

// runSANExpansion 执行证书 SAN 联动：把同证书下的其它域名纳入扫描。
//
// 这是"资产扩展"而不是"越界扫描"：每个候选域名都要单独过授权闸门，
// 越界的会被审计为 san_rejected 并跳过，不消耗配额。
func (e *Engine) runSANExpansion(ctx context.Context) {
	e.mu.Lock()
	candidates := e.sans
	e.sans = nil
	e.mu.Unlock()
	if len(candidates) == 0 {
		return
	}
	limit := e.cfg.SanMaxHosts
	if limit <= 0 {
		limit = 100
	}
	e.logf("证书 SAN 联动：候选域名 %d 个（本次最多新增 %d 台主机）", len(candidates), limit)

	added, rejected := 0, 0
	for _, h := range candidates {
		if added >= limit || ctx.Err() != nil {
			break
		}
		if e.isScanned(h) {
			continue
		}
		host, ip, err := e.scope.Guard(ctx, h)
		if err != nil {
			rejected++
			e.audit.Log("san_rejected", map[string]string{"host": h, "reason": err.Error()})
			continue
		}
		e.markScanned(host)
		added++
		for _, port := range []int{443, 80} {
			if err := e.limit.Wait(ctx); err != nil {
				return
			}
			res, err := e.probe.Probe(ctx, host, ip, port, httpinfo.GuessScheme(port))
			if err != nil {
				continue
			}
			a := res.Asset
			a.Source = "cert-san"
			e.fp.Apply(&a, res.Headers, res.Body)
			e.detectCDN(ctx, &a, res.Headers)
			e.record(a, "san_asset", map[string]string{
				"host": host, "port": strconv.Itoa(port), "url": a.URL, "title": a.Title,
			})
			e.addSeed(a.URL)
			break
		}
	}
	e.audit.Log("san_expand_done", map[string]string{
		"candidates": strconv.Itoa(len(candidates)),
		"added":      strconv.Itoa(added),
		"rejected":   strconv.Itoa(rejected),
	})
	e.logf("证书 SAN 联动完成：新增主机 %d 个，越界跳过 %d 个", added, rejected)
}

// httpsRequired 判断"明文 HTTP 被 HTTPS 端口拒绝"的响应。
//
// 这类响应是 TLS 端口的强特征，遇到就应当换 https 重试而不是当成 Web 资产记录。
func httpsRequired(res *httpinfo.Result) bool {
	if res == nil || res.Asset.StatusCode != http.StatusBadRequest {
		return false
	}
	body := strings.ToLower(string(res.Body))
	for _, marker := range []string{
		"sent an http request to an https server",
		"the plain http request was sent to https port",
		"plain text http",
		"https port",
		"client sent an http request",
	} {
		if strings.Contains(body, marker) {
			return true
		}
	}
	return false
}

// discoverSeeds 用 robots.txt / sitemap.xml 补充爬取种子（M3）。
//
// 这两个文件是站点**主动公开**的路径清单，噪声远低于目录爆破，
// 且经常直接暴露后台、接口与文档路径。Disallow 默认只做情报记录、不主动请求。
func (e *Engine) discoverSeeds(ctx context.Context, seeds []string) []string {
	origins := make([]string, 0, 8)
	seen := map[string]bool{}
	for _, s := range seeds {
		u, err := url.Parse(s)
		if err != nil || u.Host == "" {
			continue
		}
		o := u.Scheme + "://" + u.Host
		if seen[o] {
			continue
		}
		seen[o] = true
		origins = append(origins, o)
		if len(origins) >= 20 {
			break
		}
	}

	var extra []string
	for _, o := range origins {
		if ctx.Err() != nil {
			break
		}
		res := seed.Discover(ctx, o, seed.Options{
			Timeout:     time.Duration(e.cfg.TimeoutSec) * time.Second,
			UserAgent:   e.cfg.UserAgent,
			MaxSitemaps: 5,
			MaxURLs:     500,
			UseDisallow: e.cfg.SitemapDisallow,
			Limiter:     e.limit,
		})
		if res.Empty() {
			continue
		}
		kept := 0
		for _, u := range res.URLs {
			if _, ok, _ := e.scope.Check(u); !ok {
				continue // 越界 URL 不进种子池
			}
			extra = append(extra, u)
			kept++
		}
		if len(res.Disallow) > 0 {
			paths := res.Disallow
			if len(paths) > 50 {
				paths = paths[:50]
			}
			// Disallow 是很有价值的"敏感路径情报"，单独记一条审计
			e.audit.Log("robots_disallow", map[string]string{
				"origin": o, "paths": strings.Join(paths, ","),
			})
		}
		e.logf("站点地图入口 %s: %s（采用 %d 个候选）", o, res.Note(), kept)
	}
	if len(extra) > 0 {
		e.logf("站点地图补充种子 %d 个", len(extra))
	}
	return extra
}

// record 统一负责落库、审计与详细日志。
func (e *Engine) record(a model.Asset, event string, fields map[string]string) {
	if err := e.store.Add(a); err != nil {
		e.logf("写入结果失败: %v", err)
	}
	e.audit.Log(event, fields)
	if e.cfg.Verbose {
		e.logf("[%s] %s:%d %s %s %v", event, a.Host, a.Port, a.Service, a.Title, a.Products)
	}
}

func (e *Engine) addSeed(u string) {
	if u == "" {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, s := range e.seeds {
		if s == u {
			return
		}
	}
	if len(e.seeds) >= 512 {
		return
	}
	e.seeds = append(e.seeds, u)
}

func (e *Engine) takeSeeds() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := e.seeds
	e.seeds = nil
	return out
}

func (e *Engine) logf(format string, args ...any) {
	if e.log != nil {
		e.log.Printf(format, args...)
	}
}

func rateText(rate int) string {
	if rate <= 0 {
		return "不限速（风险自负）"
	}
	return strconv.Itoa(rate) + " 包/秒"
}
