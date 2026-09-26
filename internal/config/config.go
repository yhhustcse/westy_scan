// Package config 定义配置模型与加载逻辑。
//
// 优先级：命令行参数 > 配置文件 > 内置默认值。
// 配置用 JSON 而不是 YAML，是为了保持"零第三方依赖"——
// 任何 `go build` 都不需要联网拉包，这在隔离网环境做渗透时非常重要。
package config

import (
	"fmt"
	"os"
	"strings"
	"westy_scan/internal/jsonutil"
)

// Config 是运行一次扫描所需的全部参数。
type Config struct {
	// 目标
	Targets    []string `json:"targets"`
	TargetFile string   `json:"target_file"`

	// 授权与范围
	Authorized  bool     `json:"authorized"`
	Allow       []string `json:"allow"`
	Deny        []string `json:"deny"`
	StrictScope bool     `json:"strict_scope"`
	MaxHosts    int      `json:"max_hosts"`

	// 扫描行为
	Ports       string `json:"ports"`
	Concurrency int    `json:"concurrency"`
	RateLimit   int    `json:"rate_limit"`
	TimeoutSec  int    `json:"timeout_sec"`
	Banner      bool   `json:"banner"`
	UserAgent   string `json:"user_agent"`
	// BlindWebProbes 限制"无 Banner 端口"上盲试 HTTP 的次数（0 表示不盲试）。
	// 非标准端口的 Web 服务只能靠这一步发现，但全端口扫描时需要上限兜底。
	BlindWebProbes int `json:"blind_web_probes"`

	// 服务识别（M1）
	ScanMode          string `json:"scan_mode"`           // connect | syn（syn 仅 Linux，需 CAP_NET_RAW）
	ServiceDetect     bool   `json:"service_detect"`      // 是否做协议握手识别（SSH/MySQL/SMB/RDP/TLS...）
	ServiceTimeoutSec int    `json:"service_timeout_sec"` // 单次协议握手超时

	// UDP 探测（M1）
	UDP           bool   `json:"udp"`             // 是否启用 UDP 探测
	UDPPorts      string `json:"udp_ports"`       // UDP 端口表达式，默认 53,123,161,137
	UDPTimeoutSec int    `json:"udp_timeout_sec"` // UDP 等待应答超时

	// 爬虫
	Crawl         bool `json:"crawl"`
	CrawlDepth    int  `json:"crawl_depth"`
	CrawlMaxPages int  `json:"crawl_max_pages"`
	CrawlSameHost bool `json:"crawl_same_host"`

	// 资产扩展（M2）：用证书 SAN 联动发现同一证书下的其它域名
	SanExpand   bool `json:"san_expand"`
	SanMaxHosts int  `json:"san_max_hosts"`

	// 爬虫强化（M3）
	CrawlEngine     string `json:"crawl_engine"`      // http（默认）；headless 需 -tags headless 构建
	CrawlJS         bool   `json:"crawl_js"`          // 从 JS（内联 + 外链）抽取接口与疑似凭据
	CrawlMaxJS      int    `json:"crawl_max_js"`      // 单次爬取最多分析多少外链 JS
	CrawlMaxBodyKB  int    `json:"crawl_max_body_kb"` // 单页最大读取体积（KB）
	CrawlDupGap     int    `json:"crawl_dup_gap"`     // SimHash 近似重复阈值（汉明距离）
	SitemapSeeds    bool   `json:"sitemap_seeds"`     // 用 robots.txt / sitemap.xml 补充爬取种子
	SitemapDisallow bool   `json:"sitemap_disallow"`  // 是否把 Disallow 路径也作为候选（默认只记录）

	// 规则（M2）：只用外置规则，不加载内置规则
	NoDefaultRules bool `json:"no_default_rules"`

	// 漏洞模板验证（M4）：只做只读验证，不做利用
	POCEnabled        bool     `json:"poc_enabled"`
	POCTemplates      string   `json:"poc_templates"`
	POCNoBuiltin      bool     `json:"poc_no_builtin"`
	POCTags           []string `json:"poc_tags"`
	POCSeverity       string   `json:"poc_severity"`
	POCVerify         bool     `json:"poc_verify"`
	POCAllowIntrusive bool     `json:"poc_allow_intrusive"`
	POCMaxTargets     int      `json:"poc_max_targets"`
	OOBListen         string   `json:"oob_listen"`
	OOBDomain         string   `json:"oob_domain"`
	VulnFile          string   `json:"vuln_file"`

	// 输出
	OutputFormat string `json:"output_format"` // table | json | jsonl | markdown
	OutputFile   string `json:"output_file"`
	ReportFile   string `json:"report_file"`
	RulesFile    string `json:"rules_file"`
	AuditFile    string `json:"audit_file"`
	Verbose      bool   `json:"verbose"`
}

// Default 返回内置默认配置。
func Default() Config {
	return Config{
		Ports:             "common",
		Concurrency:       200,
		RateLimit:         0,
		TimeoutSec:        3,
		Banner:            true,
		UserAgent:         "Mozilla/5.0 (compatible; westy-scan/0.1; authorized-testing)",
		CrawlDepth:        2,
		CrawlMaxPages:     500,
		CrawlSameHost:     true,
		SanExpand:         true,
		SanMaxHosts:       100,
		CrawlEngine:       "http",
		CrawlJS:           true,
		CrawlMaxJS:        50,
		CrawlMaxBodyKB:    1024,
		CrawlDupGap:       3,
		SitemapSeeds:      true,
		SitemapDisallow:   false,
		POCEnabled:        true,
		POCVerify:         true,
		POCMaxTargets:     200,
		MaxHosts:          4096,
		OutputFormat:      "table",
		BlindWebProbes:    500,
		ScanMode:          "connect",
		ServiceDetect:     true,
		ServiceTimeoutSec: 2,
		UDP:               false,
		UDPPorts:          "53,123,161,137",
		UDPTimeoutSec:     2,
	}
}

// Load 读取 JSON 配置文件并与默认值合并。
func Load(path string) (Config, error) {
	cfg := Default()
	if strings.TrimSpace(path) == "" {
		return cfg, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return cfg, fmt.Errorf("读取配置 %s 失败: %w", path, err)
	}
	if err := jsonutil.Unmarshal(data, &cfg); err != nil {
		return cfg, fmt.Errorf("解析配置 %s 失败: %w", path, err)
	}
	return cfg, nil
}

// Validate 做参数体检，把错误挡在扫描开始之前。
func (c *Config) Validate() error {
	switch c.OutputFormat {
	case "", "table", "json", "jsonl", "markdown":
	default:
		return fmt.Errorf("非法的 output_format %q（可选 table/json/jsonl/markdown）", c.OutputFormat)
	}
	if c.Concurrency < 1 || c.Concurrency > 5000 {
		return fmt.Errorf("concurrency 必须在 1-5000 之间，当前 %d", c.Concurrency)
	}
	if c.TimeoutSec < 1 || c.TimeoutSec > 300 {
		return fmt.Errorf("timeout_sec 必须在 1-300 之间，当前 %d", c.TimeoutSec)
	}
	if c.MaxHosts < 1 {
		return fmt.Errorf("max_hosts 必须为正整数")
	}
	if c.CrawlDepth < 1 || c.CrawlDepth > 10 {
		return fmt.Errorf("crawl_depth 必须在 1-10 之间，当前 %d", c.CrawlDepth)
	}
	if c.CrawlMaxPages < 1 || c.CrawlMaxPages > 100000 {
		return fmt.Errorf("crawl_max_pages 必须在 1-100000 之间，当前 %d", c.CrawlMaxPages)
	}
	if c.RateLimit < 0 {
		return fmt.Errorf("rate_limit 不能为负")
	}
	if c.BlindWebProbes < 0 {
		return fmt.Errorf("blind_web_probes 不能为负")
	}
	switch c.ScanMode {
	case "", "connect", "syn":
	default:
		return fmt.Errorf("非法的 scan_mode %q（可选 connect / syn）", c.ScanMode)
	}
	if c.ServiceTimeoutSec < 1 || c.ServiceTimeoutSec > 30 {
		return fmt.Errorf("service_timeout_sec 必须在 1-30 之间，当前 %d", c.ServiceTimeoutSec)
	}
	if c.UDPTimeoutSec < 1 || c.UDPTimeoutSec > 30 {
		return fmt.Errorf("udp_timeout_sec 必须在 1-30 之间，当前 %d", c.UDPTimeoutSec)
	}
	if c.SanMaxHosts < 0 || c.SanMaxHosts > 5000 {
		return fmt.Errorf("san_max_hosts 必须在 0-5000 之间，当前 %d", c.SanMaxHosts)
	}
	if c.CrawlEngine != "" && c.CrawlEngine != "http" {
		return fmt.Errorf("crawl_engine=%q 暂不支持：无头浏览器需要引入 chromedp 并加 -tags headless 构建，默认构建保持零第三方依赖", c.CrawlEngine)
	}
	if c.CrawlMaxJS < 0 || c.CrawlMaxJS > 2000 {
		return fmt.Errorf("crawl_max_js 必须在 0-2000 之间，当前 %d", c.CrawlMaxJS)
	}
	if c.CrawlMaxBodyKB < 16 || c.CrawlMaxBodyKB > 65536 {
		return fmt.Errorf("crawl_max_body_kb 必须在 16-65536 之间，当前 %d", c.CrawlMaxBodyKB)
	}
	if c.CrawlDupGap < 0 || c.CrawlDupGap > 32 {
		return fmt.Errorf("crawl_dup_gap 必须在 0-32 之间，当前 %d", c.CrawlDupGap)
	}
	if c.POCMaxTargets < 0 || c.POCMaxTargets > 10000 {
		return fmt.Errorf("poc_max_targets 必须在 0-10000 之间，当前 %d", c.POCMaxTargets)
	}
	switch strings.ToLower(strings.TrimSpace(c.POCSeverity)) {
	case "", "info", "low", "medium", "high", "critical":
	default:
		return fmt.Errorf("非法 poc_severity %q（可选 info/low/medium/high/critical）", c.POCSeverity)
	}
	if len(c.Targets) == 0 && c.TargetFile == "" {
		return fmt.Errorf("未指定目标：请用 -target、-target-file 或配置文件 targets 字段")
	}
	if c.StrictScope && len(c.Allow) == 0 {
		return fmt.Errorf("strict_scope 为真时必须配置 allow 授权范围")
	}
	return nil
}
