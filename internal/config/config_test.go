package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// valid 返回一份能通过 Validate() 的最小配置（默认值 + 目标）。
func valid() Config {
	c := Default()
	c.Targets = []string{"example.com"}
	return c
}

// TestDefaultValues 验证内置默认值（这些数字是"开箱可用"的承诺）。
func TestDefaultValues(t *testing.T) {
	d := Default()
	cases := []struct {
		name string
		got  any
		want any
	}{
		{"Ports", d.Ports, "common"},
		{"Concurrency", d.Concurrency, 200},
		{"RateLimit", d.RateLimit, 0},
		{"TimeoutSec", d.TimeoutSec, 3},
		{"Banner", d.Banner, true},
		{"UserAgent", d.UserAgent, "Mozilla/5.0 (compatible; westy-scan/0.1; authorized-testing)"},
		{"CrawlDepth", d.CrawlDepth, 2},
		{"CrawlMaxPages", d.CrawlMaxPages, 500},
		{"CrawlSameHost", d.CrawlSameHost, true},
		{"SanExpand", d.SanExpand, true},
		{"SanMaxHosts", d.SanMaxHosts, 100},
		{"CrawlEngine", d.CrawlEngine, "http"},
		{"CrawlJS", d.CrawlJS, true},
		{"CrawlMaxJS", d.CrawlMaxJS, 50},
		{"CrawlMaxBodyKB", d.CrawlMaxBodyKB, 1024},
		{"CrawlDupGap", d.CrawlDupGap, 3},
		{"SitemapSeeds", d.SitemapSeeds, true},
		{"SitemapDisallow", d.SitemapDisallow, false},
		{"POCEnabled", d.POCEnabled, true},
		{"POCVerify", d.POCVerify, true},
		{"POCMaxTargets", d.POCMaxTargets, 200},
		{"MaxHosts", d.MaxHosts, 4096},
		{"OutputFormat", d.OutputFormat, "table"},
		{"BlindWebProbes", d.BlindWebProbes, 500},
		{"ScanMode", d.ScanMode, "connect"},
		{"ServiceDetect", d.ServiceDetect, true},
		{"ServiceTimeoutSec", d.ServiceTimeoutSec, 2},
		{"UDP", d.UDP, false},
		{"UDPPorts", d.UDPPorts, "53,123,161,137"},
		{"UDPTimeoutSec", d.UDPTimeoutSec, 2},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if c.got != c.want {
				t.Fatalf("默认 %s = %#v，期望 %#v", c.name, c.got, c.want)
			}
		})
	}
	if len(d.Targets) != 0 || d.TargetFile != "" {
		t.Fatalf("默认不应带目标: targets=%v target_file=%q", d.Targets, d.TargetFile)
	}
	if d.Authorized {
		t.Fatal("默认 authorized 必须为 false（合规闸门默认关闭）")
	}
	if d.StrictScope {
		t.Fatal("默认 strict_scope 必须为 false")
	}
}

// TestDefaultPassesValidate 验证默认值本身（补上目标后）就是合法配置。
func TestDefaultPassesValidate(t *testing.T) {
	c := valid()
	if err := c.Validate(); err != nil {
		t.Fatalf("默认配置 + targets 应当通过校验，却报错: %v", err)
	}
}

// TestLoadEmptyPathReturnsDefault 验证空路径直接返回默认值、不读文件。
func TestLoadEmptyPathReturnsDefault(t *testing.T) {
	for _, p := range []string{"", "   ", "\t"} {
		cfg, err := Load(p)
		if err != nil {
			t.Fatalf("Load(%q) 出错: %v", p, err)
		}
		if cfg.Concurrency != 200 || cfg.Ports != "common" || cfg.OutputFormat != "table" {
			t.Fatalf("Load(%q) 未返回默认值: %+v", p, cfg)
		}
	}
}

// TestLoadMissingFile 验证读文件失败时返回错误且默认值仍可用。
func TestLoadMissingFile(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "nope.json")
	cfg, err := Load(missing)
	if err == nil {
		t.Fatal("读取不存在的配置文件应当报错")
	}
	if !strings.Contains(err.Error(), "读取配置") {
		t.Fatalf("错误信息未说明读取失败: %v", err)
	}
	if cfg.Concurrency != 200 {
		t.Fatalf("失败时未退回默认值: %+v", cfg)
	}
}

// TestLoadInvalidJSON 验证非法 JSON 报错。
func TestLoadInvalidJSON(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(p, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(p); err == nil {
		t.Fatal("非法 JSON 应当报错")
	} else if !strings.Contains(err.Error(), "解析配置") {
		t.Fatalf("错误信息未说明解析失败: %v", err)
	}
}

// TestLoadMergesWithDefault 验证"配置文件覆盖默认值、未提及项保留默认值"的合并语义。
func TestLoadMergesWithDefault(t *testing.T) {
	dir := t.TempDir()

	t.Run("部分字段", func(t *testing.T) {
		p := filepath.Join(dir, "partial.json")
		if err := os.WriteFile(p, []byte(`{"targets":["a.example.com"],"concurrency":7,"verbose":true}`), 0o600); err != nil {
			t.Fatal(err)
		}
		cfg, err := Load(p)
		if err != nil {
			t.Fatalf("Load 出错: %v", err)
		}
		if cfg.Concurrency != 7 {
			t.Fatalf("Concurrency = %d，期望 7", cfg.Concurrency)
		}
		if !cfg.Verbose {
			t.Fatal("Verbose 未从配置读入")
		}
		if len(cfg.Targets) != 1 || cfg.Targets[0] != "a.example.com" {
			t.Fatalf("Targets = %v", cfg.Targets)
		}
		// 未提及项保留默认值。
		if cfg.Ports != "common" || cfg.MaxHosts != 4096 || cfg.ServiceTimeoutSec != 2 || cfg.UDPPorts != "53,123,161,137" {
			t.Fatalf("未提及项丢失默认值: %+v", cfg)
		}
		if err := cfg.Validate(); err != nil {
			t.Fatalf("合并后应当合法: %v", err)
		}
	})

	t.Run("显式零值与默认值的合并语义", func(t *testing.T) {
		// 记录代码的真实语义：先 Default() 再 Unmarshal，所以显式写 0/false
		// 只能"覆盖"非零默认值（这里 0 会覆盖 200）；而写 false 无法把
		// 默认 true 的开关关掉（true 已被 JSON 的 false 覆盖，可以关掉）。
		p := filepath.Join(dir, "zero.json")
		if err := os.WriteFile(p, []byte(`{"targets":["a"],"concurrency":0,"banner":false,"crawl":false,"san_expand":false}`), 0o600); err != nil {
			t.Fatal(err)
		}
		cfg, err := Load(p)
		if err != nil {
			t.Fatalf("Load 出错: %v", err)
		}
		if cfg.Concurrency != 0 {
			t.Fatalf("显式 0 未覆盖默认 200: %d", cfg.Concurrency)
		}
		if cfg.Banner {
			t.Fatal("显式 false 未覆盖默认 true（banner）")
		}
		if cfg.SanExpand {
			t.Fatal("显式 false 未覆盖默认 true（san_expand）")
		}
		// 于是校验会拒绝 concurrency=0 —— 说明"显式 0"确实会被沿用。
		err = cfg.Validate()
		if err == nil || !strings.Contains(err.Error(), "concurrency") {
			t.Fatalf("concurrency=0 应当被拒绝，实际: %v", err)
		}
	})

	t.Run("带 BOM 的配置", func(t *testing.T) {
		p := filepath.Join(dir, "bom.json")
		body := append([]byte{0xEF, 0xBB, 0xBF}, []byte(`{"targets":["bom.example.com"],"timeout_sec":9}`)...)
		if err := os.WriteFile(p, body, 0o600); err != nil {
			t.Fatal(err)
		}
		cfg, err := Load(p)
		if err != nil {
			t.Fatalf("带 BOM 的配置应当能读（jsonutil 会剥 BOM）: %v", err)
		}
		if cfg.TimeoutSec != 9 {
			t.Fatalf("TimeoutSec = %d，期望 9", cfg.TimeoutSec)
		}
	})

	t.Run("目标文件字段", func(t *testing.T) {
		p := filepath.Join(dir, "targetfile.json")
		if err := os.WriteFile(p, []byte(`{"target_file":"targets.txt"}`), 0o600); err != nil {
			t.Fatal(err)
		}
		cfg, err := Load(p)
		if err != nil {
			t.Fatalf("Load 出错: %v", err)
		}
		if cfg.TargetFile != "targets.txt" {
			t.Fatalf("TargetFile = %q", cfg.TargetFile)
		}
		// target_file 也算"指定了目标"。
		if err := cfg.Validate(); err != nil {
			t.Fatalf("只给 target_file 应当通过校验: %v", err)
		}
	})
}

// TestValidateRejectsInvalid 逐条覆盖 Validate() 的拒绝分支。
func TestValidateRejectsInvalid(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(*Config)
		wantSub string
	}{
		{
			name:    "非法 output_format",
			mutate:  func(c *Config) { c.OutputFormat = "xml" },
			wantSub: "非法",
		},
		{
			name:    "concurrency 为 0",
			mutate:  func(c *Config) { c.Concurrency = 0 },
			wantSub: "concurrency",
		},
		{
			name:    "concurrency 超上限",
			mutate:  func(c *Config) { c.Concurrency = 5001 },
			wantSub: "concurrency",
		},
		{
			name:    "timeout_sec 为 0",
			mutate:  func(c *Config) { c.TimeoutSec = 0 },
			wantSub: "timeout_sec",
		},
		{
			name:    "timeout_sec 超上限",
			mutate:  func(c *Config) { c.TimeoutSec = 301 },
			wantSub: "timeout_sec",
		},
		{
			name:    "max_hosts 非正",
			mutate:  func(c *Config) { c.MaxHosts = 0 },
			wantSub: "max_hosts",
		},
		{
			name:    "max_hosts 为负",
			mutate:  func(c *Config) { c.MaxHosts = -1 },
			wantSub: "max_hosts",
		},
		{
			name:    "crawl_depth 为 0",
			mutate:  func(c *Config) { c.CrawlDepth = 0 },
			wantSub: "crawl_depth",
		},
		{
			name:    "crawl_depth 超上限",
			mutate:  func(c *Config) { c.CrawlDepth = 11 },
			wantSub: "crawl_depth",
		},
		{
			name:    "crawl_max_pages 为 0",
			mutate:  func(c *Config) { c.CrawlMaxPages = 0 },
			wantSub: "crawl_max_pages",
		},
		{
			name:    "crawl_max_pages 超上限",
			mutate:  func(c *Config) { c.CrawlMaxPages = 100001 },
			wantSub: "crawl_max_pages",
		},
		{
			name:    "rate_limit 为负",
			mutate:  func(c *Config) { c.RateLimit = -1 },
			wantSub: "rate_limit",
		},
		{
			name:    "blind_web_probes 为负",
			mutate:  func(c *Config) { c.BlindWebProbes = -1 },
			wantSub: "blind_web_probes",
		},
		{
			name:    "非法 scan_mode",
			mutate:  func(c *Config) { c.ScanMode = "udp" },
			wantSub: "scan_mode",
		},
		{
			name:    "service_timeout_sec 为 0",
			mutate:  func(c *Config) { c.ServiceTimeoutSec = 0 },
			wantSub: "service_timeout_sec",
		},
		{
			name:    "service_timeout_sec 超上限",
			mutate:  func(c *Config) { c.ServiceTimeoutSec = 31 },
			wantSub: "service_timeout_sec",
		},
		{
			name:    "udp_timeout_sec 为 0",
			mutate:  func(c *Config) { c.UDPTimeoutSec = 0 },
			wantSub: "udp_timeout_sec",
		},
		{
			name:    "udp_timeout_sec 超上限",
			mutate:  func(c *Config) { c.UDPTimeoutSec = 31 },
			wantSub: "udp_timeout_sec",
		},
		{
			name:    "san_max_hosts 为负",
			mutate:  func(c *Config) { c.SanMaxHosts = -1 },
			wantSub: "san_max_hosts",
		},
		{
			name:    "san_max_hosts 超上限",
			mutate:  func(c *Config) { c.SanMaxHosts = 5001 },
			wantSub: "san_max_hosts",
		},
		{
			name:    "crawl_engine 不支持",
			mutate:  func(c *Config) { c.CrawlEngine = "headless" },
			wantSub: "crawl_engine",
		},
		{
			name:    "crawl_max_js 超上限",
			mutate:  func(c *Config) { c.CrawlMaxJS = 2001 },
			wantSub: "crawl_max_js",
		},
		{
			name:    "crawl_max_js 为负",
			mutate:  func(c *Config) { c.CrawlMaxJS = -1 },
			wantSub: "crawl_max_js",
		},
		{
			name:    "crawl_max_body_kb 过小",
			mutate:  func(c *Config) { c.CrawlMaxBodyKB = 15 },
			wantSub: "crawl_max_body_kb",
		},
		{
			name:    "crawl_max_body_kb 过大",
			mutate:  func(c *Config) { c.CrawlMaxBodyKB = 65537 },
			wantSub: "crawl_max_body_kb",
		},
		{
			name:    "crawl_dup_gap 为负",
			mutate:  func(c *Config) { c.CrawlDupGap = -1 },
			wantSub: "crawl_dup_gap",
		},
		{
			name:    "crawl_dup_gap 超上限",
			mutate:  func(c *Config) { c.CrawlDupGap = 33 },
			wantSub: "crawl_dup_gap",
		},
		{
			name:    "poc_max_targets 为负",
			mutate:  func(c *Config) { c.POCMaxTargets = -1 },
			wantSub: "poc_max_targets",
		},
		{
			name:    "poc_max_targets 超上限",
			mutate:  func(c *Config) { c.POCMaxTargets = 10001 },
			wantSub: "poc_max_targets",
		},
		{
			name:    "非法 poc_severity",
			mutate:  func(c *Config) { c.POCSeverity = "urgent" },
			wantSub: "poc_severity",
		},
		{
			name:    "缺目标",
			mutate:  func(c *Config) { c.Targets = nil; c.TargetFile = "" },
			wantSub: "未指定目标",
		},
		{
			name:    "strict_scope 缺 allow",
			mutate:  func(c *Config) { c.StrictScope = true; c.Allow = nil },
			wantSub: "strict_scope",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cfg := valid()
			c.mutate(&cfg)
			err := cfg.Validate()
			if err == nil {
				t.Fatalf("期望校验失败（%s），却通过了: %+v", c.name, cfg)
			}
			if !strings.Contains(err.Error(), c.wantSub) {
				t.Fatalf("错误信息 %q 未包含 %q", err.Error(), c.wantSub)
			}
		})
	}
}

// TestValidateAcceptsLegal 验证合法配置（含边界值）通过校验。
func TestValidateAcceptsLegal(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*Config)
	}{
		{"默认值 + targets", func(c *Config) {}},
		{"只给 targets", func(c *Config) { c.Targets = []string{"10.0.0.1"} }},
		{"只给 target_file", func(c *Config) { c.Targets = nil; c.TargetFile = "t.txt" }},
		{"output_format 空串（由 CLI 兜底）", func(c *Config) { c.OutputFormat = "" }},
		{"output_format=jsonl", func(c *Config) { c.OutputFormat = "jsonl" }},
		{"output_format=markdown", func(c *Config) { c.OutputFormat = "markdown" }},
		{"output_format=json", func(c *Config) { c.OutputFormat = "json" }},
		{"concurrency 下边界 1", func(c *Config) { c.Concurrency = 1 }},
		{"concurrency 上边界 5000", func(c *Config) { c.Concurrency = 5000 }},
		{"timeout_sec 边界", func(c *Config) { c.TimeoutSec = 300 }},
		{"scan_mode 空串", func(c *Config) { c.ScanMode = "" }},
		{"scan_mode=syn", func(c *Config) { c.ScanMode = "syn" }},
		{"max_hosts=1", func(c *Config) { c.MaxHosts = 1 }},
		{"san_max_hosts=0", func(c *Config) { c.SanMaxHosts = 0 }},
		{"san_max_hosts=5000", func(c *Config) { c.SanMaxHosts = 5000 }},
		{"crawl_max_js=0", func(c *Config) { c.CrawlMaxJS = 0 }},
		{"crawl_max_js=2000", func(c *Config) { c.CrawlMaxJS = 2000 }},
		{"crawl_max_body_kb=16", func(c *Config) { c.CrawlMaxBodyKB = 16 }},
		{"crawl_max_body_kb=65536", func(c *Config) { c.CrawlMaxBodyKB = 65536 }},
		{"crawl_dup_gap=32", func(c *Config) { c.CrawlDupGap = 32 }},
		{"poc_max_targets=0", func(c *Config) { c.POCMaxTargets = 0 }},
		{"poc_max_targets=10000", func(c *Config) { c.POCMaxTargets = 10000 }},
		{"crawl_engine 空串", func(c *Config) { c.CrawlEngine = "" }},
		{"poc_severity 空串", func(c *Config) { c.POCSeverity = "" }},
		{"poc_severity 大小写与空白（代码会 ToLower+Trim）", func(c *Config) { c.POCSeverity = "  HIGH  " }},
		{"strict_scope + allow（已授权）", func(c *Config) {
			c.Authorized = true
			c.StrictScope = true
			c.Allow = []string{"10.0.0.0/24"}
		}},
		{"rate_limit=0", func(c *Config) { c.RateLimit = 0 }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cfg := valid()
			c.mutate(&cfg)
			if err := cfg.Validate(); err != nil {
				t.Fatalf("合法配置被判为非法: %v（配置 %+v）", err, cfg)
			}
		})
	}
}

// TestValidateFirstErrorWins 验证多条错误时的顺序（输出格式最先被检查）。
func TestValidateFirstErrorWins(t *testing.T) {
	cfg := valid()
	cfg.OutputFormat = "bogus"
	cfg.Concurrency = 0
	err := cfg.Validate()
	if err == nil {
		t.Fatal("应当报错")
	}
	if !strings.Contains(err.Error(), "output_format") {
		t.Fatalf("应当先报 output_format，实际: %v", err)
	}

	cfg = valid()
	cfg.Concurrency = 0
	cfg.TimeoutSec = 0
	err = cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "concurrency") {
		t.Fatalf("应当先报 concurrency，实际: %v", err)
	}
}

// TestValidateDoesNotCheckAuthorized 记录真实语义：Validate() 不检查 authorized。
// 授权闸门在 scope.New 与 CLI 层（cmd/westy/main.go）里，属于"读代码确认"的结论。
func TestValidateDoesNotCheckAuthorized(t *testing.T) {
	cfg := valid()
	cfg.Authorized = false
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() 目前不校验 authorized，应当通过: %v", err)
	}
}

// TestConfigJSONRoundTrip 验证配置结构可 JSON 往返（配置文件契约）。
func TestConfigJSONRoundTrip(t *testing.T) {
	cfg := valid()
	cfg.StrictScope = true
	cfg.Allow = []string{"10.0.0.0/24", "example.com"}
	cfg.Deny = []string{"10.0.0.1"}
	cfg.POCTags = []string{"cve", "rce"}
	cfg.VulnFile = "vulns.jsonl"
	cfg.OutputFile = "out.json"
	cfg.RulesFile = "rules.json"

	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("Marshal 失败: %v", err)
	}
	var back Config
	if err := json.Unmarshal(data, &back); err != nil {
		t.Fatalf("Unmarshal 失败: %v", err)
	}
	if err := back.Validate(); err != nil {
		t.Fatalf("往返后配置非法: %v", err)
	}
	if len(back.Allow) != 2 || back.Allow[1] != "example.com" {
		t.Fatalf("Allow 往返丢失: %v", back.Allow)
	}
	if len(back.POCTags) != 2 || back.Deny[0] != "10.0.0.1" {
		t.Fatalf("切片字段往返丢失: tags=%v deny=%v", back.POCTags, back.Deny)
	}
	if back.VulnFile != "vulns.jsonl" || back.OutputFile != "out.json" || back.RulesFile != "rules.json" {
		t.Fatalf("路径字段往返丢失: %+v", back)
	}
}
