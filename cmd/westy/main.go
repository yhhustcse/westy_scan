// Command westy 是 westy_scan 扫描框架的命令行入口。
//
// 使用示例：
//
//	westy -target https://demo.example.com -authorized -allow demo.example.com
//	westy -target 10.0.0.0/24 -ports common -allow 10.0.0.0/24 -authorized -crawl
//	westy -config configs/westy.example.json
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"westy_scan/internal/audit"
	"westy_scan/internal/config"
	"westy_scan/internal/fingerprint"
	"westy_scan/internal/model"
	"westy_scan/internal/pipeline"
	"westy_scan/internal/poc"
	"westy_scan/internal/report"
	"westy_scan/internal/store"
)

const version = "0.1.0"

// errVulnFound 表示命中达到 -fail-on 阈值的漏洞（退出码 3，便于 CI 集成）。
var errVulnFound = errors.New("命中达到阈值的漏洞")

// loggerFor 返回统一的日志器（子命令共用）。
func loggerFor() *log.Logger { return log.New(os.Stderr, "[westy] ", log.LstdFlags) }

func printUsage() {
	fmt.Fprint(os.Stderr, `westy_scan —— 授权渗透测试的资产测绘与攻击面梳理框架

用法：
  westy [扫描参数]                单机扫描（默认）
  westy scan [扫描参数]           同上，显式写法
  westy server [参数]             分布式编排端（下发任务、汇聚结果）
  westy agent  [参数]             分布式执行端（拉任务、本地授权复检、执行、上报）

常用示例：
  westy -target https://demo.example.com -allow demo.example.com -authorized -crawl -poc
  westy server -listen 0.0.0.0:8899 -token <token> -targets 10.0.0.0/24 -ports common
  westy agent  -server http://10.0.0.1:8899 -token <token> -authorized -allow 10.0.0.0/24 -config cfg.json

注意：Server 只能下发目标，**授权的最终判定在 Agent 侧**；Agent 必须显式声明本地授权范围。
`)
}

func main() {
	err := run(os.Args[1:])
	if err == nil {
		return
	}
	fmt.Fprintln(os.Stderr, "错误: "+err.Error())
	if errors.Is(err, errVulnFound) {
		os.Exit(3)
	}
	os.Exit(1)
}

type stringList []string

func (s *stringList) String() string { return strings.Join(*s, ",") }

func (s *stringList) Set(v string) error {
	*s = append(*s, v)
	return nil
}

func run(args []string) error {
	// 子命令：单机扫描（默认）/ 分布式 Server / 分布式 Agent
	if len(args) > 0 {
		switch args[0] {
		case "server":
			return runServer(args[1:])
		case "agent":
			return runAgent(args[1:])
		case "scan":
			args = args[1:]
		case "help", "-help", "--help":
			printUsage()
			return nil
		}
	}

	fs := flag.NewFlagSet("westy", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	var (
		targets   stringList
		allow     stringList
		deny      stringList
		cfgPath   = fs.String("config", "", "JSON 配置文件路径")
		targetF   = fs.String("target-file", "", "目标文件（每行一个，支持 # 注释）")
		ports     = fs.String("ports", "", "端口表达式：common/web/db/all/80,443/1-1024")
		format    = fs.String("format", "", "输出格式：table|json|jsonl|markdown")
		outFile   = fs.String("o", "", "结果 JSONL 落盘文件")
		reportTo  = fs.String("report", "", "格式化报告输出文件（默认标准输出）")
		rulesFile = fs.String("rules", "", "指纹规则 JSON 文件（缺省用内置规则）")
		auditFile = fs.String("audit", "", "审计日志 JSONL 文件")
		listRules = fs.Bool("list-rules", false, "打印当前指纹规则后退出")
		listTpls  = fs.Bool("list-templates", false, "打印当前生效的漏洞模板后退出")
		showVer   = fs.Bool("version", false, "打印版本后退出")

		authorized = fs.Bool("authorized", false, "声明已获得目标书面授权（必须）")
		strict     = fs.Bool("strict-scope", false, "严格模式：必须配置 allow 范围")
		maxHosts   = fs.Int("max-hosts", 0, "CIDR 展开的最大地址数")
		conc       = fs.Int("concurrency", 0, "并发数")
		rate       = fs.Int("rate", -1, "全局限速（包/秒），0 表示不限速")
		timeout    = fs.Int("timeout", 0, "单次连接/请求超时（秒）")
		banner     = fs.Bool("banner", true, "抓取 TCP Banner")
		crawl      = fs.Bool("crawl", false, "启用 Web 爬虫")
		crawlDepth = fs.Int("crawl-depth", 0, "爬虫最大深度")
		crawlPages = fs.Int("crawl-pages", 0, "爬虫最大页数")
		ua         = fs.String("user-agent", "", "自定义 User-Agent")
		blindWeb   = fs.Int("blind-web-probes", -1, "无 Banner 端口上盲试 HTTP 的次数上限（0 表示不盲试）")
		scanMode   = fs.String("scan-mode", "", "端口扫描方式：connect(默认) / syn(仅 Linux, 需 CAP_NET_RAW)")
		svcDetect  = fs.Bool("service-detect", true, "开启协议握手识别（SSH/MySQL/PostgreSQL/Redis/VNC/SMB/RDP/MongoDB/TLS）")
		svcTimeout = fs.Int("service-timeout", 0, "单次协议握手超时（秒）")
		udpScan    = fs.Bool("udp", false, "启用 UDP 探测（DNS/NTP/SNMP/NetBIOS）")
		udpPorts   = fs.String("udp-ports", "", "UDP 探测端口（默认 53,123,161,137）")
		udpTimeout = fs.Int("udp-timeout", 0, "UDP 等待应答超时（秒）")
		noDefaults = fs.Bool("no-default-rules", false, "只使用 -rules 指定的外置规则，不加载内置规则")
		sanExpand  = fs.Bool("san-expand", true, "用证书 SAN 联动扩展资产（候选域名仍逐个受授权范围约束）")
		sanMax     = fs.Int("san-max-hosts", 0, "SAN 联动最多新增的主机数")
		crawlEng   = fs.String("crawl-engine", "", "爬虫引擎：http（默认）；headless 需 -tags headless 构建")
		crawlJS    = fs.Bool("crawl-js", true, "从 JS（内联 + 外链）抽取接口与疑似凭据")
		crawlMaxJS = fs.Int("crawl-max-js", 0, "单次爬取最多分析的外链 JS 数量")
		sitemap    = fs.Bool("sitemap", true, "用 robots.txt / sitemap.xml 补充爬取种子")
		sitemapDis = fs.Bool("sitemap-disallow", false, "把 robots 的 Disallow 路径也作为候选请求（默认只记录情报）")
		crawlDup   = fs.Int("crawl-dup-gap", 0, "SimHash 近似重复判定阈值（汉明距离，默认 3）")
		pocOn      = fs.Bool("poc", true, "启用漏洞模板验证（只读检查，不做利用）")
		templates  = fs.String("templates", "", "额外模板文件或目录（.json/.yaml/.yml）；内置模板始终可用")
		pocTags    = fs.String("poc-tags", "", "只运行这些标签的模板（逗号分隔）")
		pocSev     = fs.String("poc-severity", "", "只运行不低于该级别的模板（info/low/medium/high/critical）")
		verify     = fs.Bool("verify", true, "对命中做二次确认（默认开：同一请求重放一次，两次都命中才算）")
		intrusive  = fs.Bool("allow-intrusive", false, "放行有副作用的模板（写方法/破坏性关键字），会单独审计")
		noBuiltin  = fs.Bool("no-builtin-templates", false, "只使用 -templates 指定的模板")
		oobListen  = fs.String("oob-listen", "", "外带验证监听地址，如 127.0.0.1:8899（空表示关闭）")
		oobDomain  = fs.String("oob-domain", "", "目标可访问的回调地址（默认用监听地址）")
		vulnFile   = fs.String("vulns", "", "漏洞结果 JSONL 输出文件")
		failOn     = fs.String("fail-on", "", "命中不低于该级别漏洞时以退出码 3 结束（便于 CI 集成）")
		verbose    = fs.Bool("v", false, "输出详细日志")
	)
	fs.Var(&targets, "target", "扫描目标（可重复；支持 URL/IP/CIDR/域名）")
	fs.Var(&allow, "allow", "授权范围 allow 规则（可重复；CIDR/IP/域名）")
	fs.Var(&deny, "deny", "授权范围 deny 规则（可重复，优先级高于 allow）")

	if err := fs.Parse(args); err != nil {
		return err
	}
	if *showVer {
		fmt.Printf("westy_scan %s\n", version)
		return nil
	}

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}

	// 命令行覆盖配置文件：只覆盖显式传入的参数
	set := make(map[string]bool)
	fs.Visit(func(f *flag.Flag) { set[f.Name] = true })
	if len(targets) > 0 {
		cfg.Targets = append(cfg.Targets, targets...)
	}
	if len(allow) > 0 {
		cfg.Allow = append(cfg.Allow, allow...)
	}
	if len(deny) > 0 {
		cfg.Deny = append(cfg.Deny, deny...)
	}
	if set["target-file"] {
		cfg.TargetFile = *targetF
	}
	if set["ports"] {
		cfg.Ports = *ports
	}
	if set["format"] {
		cfg.OutputFormat = *format
	}
	if set["o"] {
		cfg.OutputFile = *outFile
	}
	if set["report"] {
		cfg.ReportFile = *reportTo
	}
	if set["rules"] {
		cfg.RulesFile = *rulesFile
	}
	if set["audit"] {
		cfg.AuditFile = *auditFile
	}
	if set["authorized"] {
		cfg.Authorized = *authorized
	}
	if set["strict-scope"] {
		cfg.StrictScope = *strict
	}
	if set["max-hosts"] {
		cfg.MaxHosts = *maxHosts
	}
	if set["concurrency"] {
		cfg.Concurrency = *conc
	}
	if set["rate"] {
		cfg.RateLimit = *rate
	}
	if set["timeout"] {
		cfg.TimeoutSec = *timeout
	}
	if set["banner"] {
		cfg.Banner = *banner
	}
	if set["crawl"] {
		cfg.Crawl = *crawl
	}
	if set["crawl-depth"] {
		cfg.CrawlDepth = *crawlDepth
	}
	if set["crawl-pages"] {
		cfg.CrawlMaxPages = *crawlPages
	}
	if set["user-agent"] {
		cfg.UserAgent = *ua
	}
	if set["blind-web-probes"] {
		cfg.BlindWebProbes = *blindWeb
	}
	if set["scan-mode"] {
		cfg.ScanMode = *scanMode
	}
	if set["service-detect"] {
		cfg.ServiceDetect = *svcDetect
	}
	if set["service-timeout"] {
		cfg.ServiceTimeoutSec = *svcTimeout
	}
	if set["udp"] {
		cfg.UDP = *udpScan
	}
	if set["udp-ports"] {
		cfg.UDPPorts = *udpPorts
	}
	if set["udp-timeout"] {
		cfg.UDPTimeoutSec = *udpTimeout
	}
	if set["no-default-rules"] {
		cfg.NoDefaultRules = *noDefaults
	}
	if set["san-expand"] {
		cfg.SanExpand = *sanExpand
	}
	if set["san-max-hosts"] {
		cfg.SanMaxHosts = *sanMax
	}
	if set["crawl-engine"] {
		cfg.CrawlEngine = *crawlEng
	}
	if set["crawl-js"] {
		cfg.CrawlJS = *crawlJS
	}
	if set["crawl-max-js"] {
		cfg.CrawlMaxJS = *crawlMaxJS
	}
	if set["sitemap"] {
		cfg.SitemapSeeds = *sitemap
	}
	if set["sitemap-disallow"] {
		cfg.SitemapDisallow = *sitemapDis
	}
	if set["crawl-dup-gap"] {
		cfg.CrawlDupGap = *crawlDup
	}
	if set["poc"] {
		cfg.POCEnabled = *pocOn
	}
	if set["templates"] {
		cfg.POCTemplates = *templates
	}
	if set["poc-tags"] {
		for _, t := range strings.Split(*pocTags, ",") {
			if t = strings.TrimSpace(t); t != "" {
				cfg.POCTags = append(cfg.POCTags, t)
			}
		}
	}
	if set["poc-severity"] {
		cfg.POCSeverity = *pocSev
	}
	if set["verify"] {
		cfg.POCVerify = *verify
	}
	if set["allow-intrusive"] {
		cfg.POCAllowIntrusive = *intrusive
	}
	if set["no-builtin-templates"] {
		cfg.POCNoBuiltin = *noBuiltin
	}
	if set["oob-listen"] {
		cfg.OOBListen = *oobListen
	}
	if set["oob-domain"] {
		cfg.OOBDomain = *oobDomain
	}
	if set["vulns"] {
		cfg.VulnFile = *vulnFile
	}
	if set["v"] {
		cfg.Verbose = *verbose
	}
	if cfg.OutputFormat == "" {
		cfg.OutputFormat = "table"
	}

	if *listRules {
		engine, err := fingerprint.LoadMerged(cfg.RulesFile, !cfg.NoDefaultRules)
		if err != nil {
			return err
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(engine.Rules())
	}

	if *listTpls {
		// 与 -list-rules 对称：让"当前到底有哪些弹药"可以一条命令查清，
		// 而不是靠翻文档或数 JSON 文件（规则库越大越需要这个）。
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
			return err
		}
		type tplView struct {
			ID         string   `json:"id"`
			Name       string   `json:"name"`
			Severity   string   `json:"severity"`
			Confidence string   `json:"confidence,omitempty"`
			Tags       []string `json:"tags,omitempty"`
			Method     string   `json:"method"`
			Path       []string `json:"path"`
			Intrusive  bool     `json:"intrusive,omitempty"`
			Redirects  bool     `json:"redirects,omitempty"`
			Source     string   `json:"source"`
		}
		out := make([]tplView, 0, len(tpls))
		for _, tpl := range tpls {
			v := tplView{
				ID: tpl.ID, Name: tpl.Info.Name, Severity: tpl.Info.Severity,
				Confidence: tpl.Info.Confidence, Tags: tpl.Info.Tags,
				Intrusive: tpl.Intrusive, Source: tpl.Source,
			}
			if len(tpl.HTTP) > 0 {
				v.Method = tpl.HTTP[0].Method
				v.Path = tpl.HTTP[0].Path
				v.Redirects = tpl.HTTP[0].Redirects
			}
			out = append(out, v)
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(out); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "已加载 %d 个模板\n", len(out))
		return nil
	}

	if err := cfg.Validate(); err != nil {
		return err
	}

	logger := log.New(os.Stderr, "[westy] ", log.LstdFlags)
	logger.Printf("westy_scan %s 启动", version)

	// 结果存储：内存去重 + 可选 JSONL 落盘
	mem := store.NewMemory()
	var st store.Store = mem
	var closers []func() error
	if cfg.OutputFile != "" {
		jsonl, err := store.NewJSONL(cfg.OutputFile)
		if err != nil {
			return err
		}
		st = store.NewMulti(mem, jsonl)
		closers = append(closers, jsonl.Close)
	}
	defer func() {
		for _, c := range closers {
			_ = c()
		}
	}()

	aud, err := audit.Open(cfg.AuditFile)
	if err != nil {
		return err
	}
	defer aud.Close()

	engine, err := pipeline.New(cfg, st, aud, logger)
	if err != nil {
		return err
	}
	sc := engine.Scope()
	logger.Printf("授权范围: %s", sc.Describe())
	if len(cfg.Allow) == 0 {
		logger.Printf("警告: 未配置 allow 授权范围，当前对任意目标放行；请确认你拥有书面授权")
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	if err := engine.Run(ctx); err != nil {
		aud.Log("run_error", map[string]string{"error": err.Error()})
		return err
	}

	assets := mem.Assets()
	findings := engine.Findings()

	fmt.Fprintln(os.Stderr, "---------- 扫描结果统计 ----------")
	fmt.Fprint(os.Stderr, report.SummaryText(report.Compute(assets)))
	fmt.Fprint(os.Stderr, report.SummaryFindings(findings))

	if err := writeReport(cfg, assets, findings); err != nil {
		return err
	}
	if cfg.OutputFile != "" {
		logger.Printf("结果已写入 %s", cfg.OutputFile)
	}
	if cfg.VulnFile != "" {
		logger.Printf("漏洞结果已写入 %s", cfg.VulnFile)
	}

	if *failOn != "" {
		for _, f := range findings {
			if poc.SeverityAtLeast(f.Severity, *failOn) {
				return fmt.Errorf("%w: %s（模板 %s @ %s，阈值 %s）",
					errVulnFound, strings.ToUpper(f.Severity), f.TemplateID, f.MatchedAt, *failOn)
			}
		}
	}
	return nil
}

func writeReport(cfg config.Config, assets []model.Asset, findings []poc.Finding) error {
	var w *os.File = os.Stdout
	if cfg.ReportFile != "" {
		f, err := os.Create(cfg.ReportFile)
		if err != nil {
			return err
		}
		defer f.Close()
		w = f
	}
	switch cfg.OutputFormat {
	case "json":
		return report.WriteJSON(w, assets)
	case "jsonl":
		return report.WriteJSONL(w, assets)
	case "markdown":
		if err := report.WriteMarkdown(w, assets); err != nil {
			return err
		}
		return report.WriteFindingsMarkdown(w, findings)
	default:
		if err := report.WriteTable(w, assets); err != nil {
			return err
		}
		fmt.Fprintln(w)
		fmt.Fprintln(w, "---------- 漏洞验证结果 ----------")
		return report.WriteFindings(w, findings)
	}
}
