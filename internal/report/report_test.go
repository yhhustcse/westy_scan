package report

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"westy_scan/internal/model"
	"westy_scan/internal/poc"
)

// sampleAssets 返回一组字段齐全的资产，供四种输出格式共用。
func sampleAssets() []model.Asset {
	return []model.Asset{
		{
			Input:      "example.com",
			Host:       "example.com",
			IP:         "93.184.216.34",
			Port:       443,
			Scheme:     "https",
			URL:        "https://example.com/",
			Service:    "https",
			Product:    "nginx",
			Version:    "1.24.0",
			Products:   []string{"nginx", "OpenSSL"},
			Title:      "Example Domain",
			StatusCode: 200,
			Server:     "nginx",
			Banner:     "HTTP/1.1 200 OK",
			TLS:        &model.TLSInfo{Subject: "CN=example.com", Expired: true},
			Source:     "httpinfo",
			Confidence: model.ConfidenceHigh,
			Evidence:   []string{"Server 头命中"},
			CDN:        "cloudflare",
			BehindCDN:  true,
			OriginNote: "源站疑似 203.0.113.7",
			Params:     []string{"id", "q"},
			Meta:       map[string]string{"js.endpoint_count": "4", "js.secret_count": "2"},
			FoundAt:    time.Date(2024, 1, 2, 3, 4, 5, 0, time.UTC),
		},
		{
			Host:       "10.0.0.5",
			Port:       22,
			Service:    "ssh",
			Product:    "OpenSSH",
			Version:    "9.6p1",
			Source:     "probe",
			Confidence: model.ConfidenceMedium,
			WAF:        "cloudflare",
			Meta:       map[string]string{"duplicate_of": "https://example.com/"},
			FoundAt:    time.Date(2024, 1, 2, 3, 4, 6, 0, time.UTC),
		},
		{
			Host: "only-host.example.com",
		},
	}
}

func sampleFindings() []poc.Finding {
	return []poc.Finding{
		{
			TemplateID: "cve-2021-41773",
			Name:       "Apache 路径穿越",
			Severity:   poc.SeverityCritical,
			Target:     "https://example.com",
			MatchedAt:  "https://example.com/cgi-bin/.%2e/.%2e/etc/passwd",
			Confidence: "high",
			Verified:   true,
			Extracted:  map[string][]string{"version": {"2.4.49"}},
			Evidence: poc.Evidence{
				Request:  "GET /cgi-bin/.%2e/.%2e/etc/passwd HTTP/1.1",
				Response: "root:x:0:0:root:/root:/bin/bash",
				Matcher:  "status==200 && contains(body, \"root:\")",
			},
			Description: "路径穿越导致任意文件读取",
			Reference:   []string{"https://httpd.apache.org/security/vulnerabilities_24.html"},
			FoundAt:     time.Date(2024, 1, 2, 3, 5, 0, 0, time.UTC),
		},
		{
			TemplateID: "exposed-git",
			Name:       "Git 目录泄露",
			Severity:   poc.SeverityMedium,
			Target:     "http://10.0.0.5",
			MatchedAt:  "http://10.0.0.5/.git/config",
			Confidence: "medium",
			Verified:   false,
			Evidence: poc.Evidence{
				Request:  "GET /.git/config HTTP/1.1",
				Response: "[core]\n\trepositoryformatversion = 0",
				Matcher:  "contains(body, \"[core]\")",
			},
			FoundAt: time.Date(2024, 1, 2, 3, 5, 1, 0, time.UTC),
		},
		{
			// 相同模板的第二个命中：用于验证模板去重计数。
			TemplateID: "exposed-git",
			Name:       "Git 目录泄露",
			Severity:   poc.SeverityLow,
			MatchedAt:  "http://10.0.0.5/.git/HEAD",
			Verified:   false,
			FoundAt:    time.Date(2024, 1, 2, 3, 5, 2, 0, time.UTC),
		},
	}
}

// TestComputeStats 验证统计口径（含 CDN/WAF 折叠、JS 计数、非法计数容错）。
func TestComputeStats(t *testing.T) {
	st := Compute(sampleAssets())
	if st.Total != 3 {
		t.Fatalf("Total = %d，期望 3", st.Total)
	}
	if st.OpenPorts != 2 {
		t.Fatalf("OpenPorts = %d，期望 2", st.OpenPorts)
	}
	if st.WebTargets != 1 {
		t.Fatalf("WebTargets = %d，期望 1", st.WebTargets)
	}
	if st.ExpiredCerts != 1 {
		t.Fatalf("ExpiredCerts = %d，期望 1", st.ExpiredCerts)
	}
	if st.BehindCDN != 1 {
		t.Fatalf("BehindCDN = %d，期望 1", st.BehindCDN)
	}
	if st.WithParams != 1 {
		t.Fatalf("WithParams = %d，期望 1", st.WithParams)
	}
	if st.Duplicates != 1 {
		t.Fatalf("Duplicates = %d，期望 1", st.Duplicates)
	}
	if st.JSEndpoints != 4 || st.JSSecrets != 2 {
		t.Fatalf("JS 计数 = %d/%d，期望 4/2", st.JSEndpoints, st.JSSecrets)
	}
	if st.ByService["https"] != 1 || st.ByService["ssh"] != 1 || len(st.ByService) != 2 {
		t.Fatalf("ByService = %v", st.ByService)
	}
	if st.ByPort["443"] != 1 || st.ByPort["22"] != 1 {
		t.Fatalf("ByPort = %v", st.ByPort)
	}
	// ByProduct 同时统计 Products 切片与 Product 单值字段（probe/fingerprint 经 Identify()
	// 写的是单值字段），同一条资产内的重复产品只算一次。
	if st.ByProduct["nginx"] != 1 || st.ByProduct["OpenSSL"] != 1 || st.ByProduct["OpenSSH"] != 1 || len(st.ByProduct) != 3 {
		t.Fatalf("ByProduct = %v", st.ByProduct)
	}
	if st.ByStatus["200"] != 1 {
		t.Fatalf("ByStatus = %v", st.ByStatus)
	}
	// CDN 优先于 WAF：第二条资产只有 WAF，也进 ByCDN。
	if st.ByCDN["cloudflare"] != 2 {
		t.Fatalf("ByCDN = %v，期望 cloudflare=2", st.ByCDN)
	}
	if st.ByParam["id"] != 1 || st.ByParam["q"] != 1 {
		t.Fatalf("ByParam = %v", st.ByParam)
	}

	// 空输入不 panic，且各 map 已初始化（避免调用方写 nil map panic）。
	empty := Compute(nil)
	if empty.Total != 0 || len(empty.ByService) != 0 {
		t.Fatalf("空输入统计异常: %+v", empty)
	}
	empty.ByService["x"] = 1 // nil map 会 panic，能跑到这里说明已初始化
}

// TestComputeTolerantJSCounters 验证非法的 js.* 计数被当作 0 而不是 panic/负数。
func TestComputeTolerantJSCounters(t *testing.T) {
	assets := []model.Asset{
		{Meta: map[string]string{"js.endpoint_count": "abc", "js.secret_count": "-5"}},
		{Meta: map[string]string{"js.endpoint_count": " 7 ", "js.secret_count": ""}},
	}
	st := Compute(assets)
	if st.JSEndpoints != 7 {
		t.Fatalf("JSEndpoints = %d，期望 7（带空白的 7 应被接受，abc 计 0）", st.JSEndpoints)
	}
	if st.JSSecrets != 0 {
		t.Fatalf("JSSecrets = %d，期望 0（负数与空串都计 0）", st.JSSecrets)
	}
}

// TestSummaryText 验证人类可读总结包含关键信息，且兼容空统计。
func TestSummaryText(t *testing.T) {
	st := Compute(sampleAssets())
	got := SummaryText(st)
	for _, want := range []string{
		"资产总数: 3",
		"开放端口: 2",
		"Web 目标: 1",
		"过期证书: 1",
		"经 CDN/WAF: 1",
		"攻击面输入面",
		"服务分布:",
		"端口分布:",
		"产品指纹:",
		"CDN/WAF:",
		"参数清单:",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("SummaryText 缺少 %q:\n%s", want, got)
		}
	}
	// 服务按出现次数降序、同次数按字典序。
	if !strings.Contains(got, "https(1), ssh(1)") && !strings.Contains(got, "ssh(1), https(1)") {
		t.Fatalf("服务分布格式异常:\n%s", got)
	}

	// 空统计：只有首行，不 panic。
	emptyOut := SummaryText(Stats{})
	if !strings.Contains(emptyOut, "资产总数: 0") {
		t.Fatalf("空统计输出异常: %q", emptyOut)
	}
	if strings.Contains(emptyOut, "服务分布") || strings.Contains(emptyOut, "攻击面输入面") {
		t.Fatalf("空统计不应输出分布行: %q", emptyOut)
	}

	// topPairs 的 limit 生效（服务多于 12 种时截断）。
	st2 := Stats{ByService: map[string]int{}}
	for i := 0; i < 20; i++ {
		st2.ByService[string(rune('a'+i))] = 20 - i
	}
	out2 := SummaryText(st2)
	if strings.Count(out2, "(") != 12 {
		t.Fatalf("服务分布未截断到 12 项:\n%s", out2)
	}
}

// TestCountAndSummaryFindings 验证漏洞计数与摘要（含空输入语义）。
func TestCountAndSummaryFindings(t *testing.T) {
	findings := sampleFindings()
	counts := CountBySeverity(findings)
	if counts["critical"] != 1 || counts["medium"] != 1 || counts["low"] != 1 {
		t.Fatalf("CountBySeverity = %v", counts)
	}
	// 大小写归一化。
	up := CountBySeverity([]poc.Finding{{Severity: "HIGH"}, {Severity: "high"}})
	if up["high"] != 2 || len(up) != 1 {
		t.Fatalf("严重级别未做小写归一化: %v", up)
	}

	if got := SummaryFindings(nil); !strings.Contains(got, "未发现") {
		t.Fatalf("空漏洞摘要异常: %q", got)
	}
	got := SummaryFindings(findings)
	for _, want := range []string{"命中 3 条", "模板 2 个", "已验证 1 条", "critical(1)", "medium(1)", "low(1)"} {
		if !strings.Contains(got, want) {
			t.Fatalf("SummaryFindings 缺少 %q: %q", want, got)
		}
	}
	// 严重级别按 critical→info 顺序输出。
	idxCrit := strings.Index(got, "critical(1)")
	idxMed := strings.Index(got, "medium(1)")
	idxLow := strings.Index(got, "low(1)")
	if !(idxCrit < idxMed && idxMed < idxLow) {
		t.Fatalf("严重级别顺序错误: %q", got)
	}
}

// TestWriteTable 验证表格输出：表头齐全、字段落位、空输入只有表头。
func TestWriteTable(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteTable(&buf, sampleAssets()); err != nil {
		t.Fatalf("WriteTable 出错: %v", err)
	}
	out := buf.String()
	for _, h := range []string{"HOST", "PORT", "SERVICE", "PRODUCT", "VERSION", "CONF", "STATUS", "TITLE/SERVER", "CDN/WAF", "SOURCE"} {
		if !strings.Contains(out, h) {
			t.Fatalf("表格缺少表头 %q:\n%s", h, out)
		}
	}
	for _, want := range []string{"example.com", "443", "https", "nginx", "1.24.0", "high", "200", "Example Domain", "cloudflare", "httpinfo", "10.0.0.5", "only-host.example.com"} {
		if !strings.Contains(out, want) {
			t.Fatalf("表格缺少 %q:\n%s", want, out)
		}
	}
	// 无端口的资产端口列留空、无 Title 时回落到 Server/Banner。
	if !strings.Contains(out, "only-host.example.com") {
		t.Fatalf("无端口资产未输出:\n%s", out)
	}

	var empty bytes.Buffer
	if err := WriteTable(&empty, nil); err != nil {
		t.Fatalf("空输入 WriteTable 出错: %v", err)
	}
	if !strings.Contains(empty.String(), "HOST") {
		t.Fatalf("空输入也应输出表头: %q", empty.String())
	}
	if strings.Count(empty.String(), "\n") != 1 {
		t.Fatalf("空输入表格应只有表头一行: %q", empty.String())
	}

	// Title 为空时回落到 Server。
	var fallback bytes.Buffer
	if err := WriteTable(&fallback, []model.Asset{{Host: "h", Port: 80, Server: "nginx/1.24"}}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(fallback.String(), "nginx/1.24") {
		t.Fatalf("Title 为空时未回落到 Server:\n%s", fallback.String())
	}
	// Server 也为空时回落到 Banner。
	var banner bytes.Buffer
	if err := WriteTable(&banner, []model.Asset{{Host: "h", Port: 80, Banner: "SSH-2.0-OpenSSH_9.6"}}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(banner.String(), "SSH-2.0-OpenSSH_9.6") {
		t.Fatalf("Title/Server 都为空时未回落到 Banner:\n%s", banner.String())
	}
}

// TestCDNWAFColumn 覆盖 cdnWAF() 的四个分支。
func TestCDNWAFColumn(t *testing.T) {
	cases := []struct {
		name string
		a    model.Asset
		want string
	}{
		{"都为空", model.Asset{Host: "h"}, ""},
		{"只有 CDN", model.Asset{CDN: "cloudflare"}, "cloudflare"},
		{"只有 WAF", model.Asset{WAF: "cloudflare"}, "cloudflare"},
		{"CDN 与 WAF 相同", model.Asset{CDN: "cloudflare", WAF: "cloudflare"}, "cloudflare"},
		{"CDN 与 WAF 不同", model.Asset{CDN: "cloudflare", WAF: "aliyun"}, "cloudflare+aliyun"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := cdnWAF(c.a); got != c.want {
				t.Fatalf("cdnWAF = %q，期望 %q", got, c.want)
			}
		})
	}
}

// TestWriteJSONRoundTrip 验证 JSON 输出可被 Unmarshal 回读且字段齐全。
func TestWriteJSONRoundTrip(t *testing.T) {
	assets := sampleAssets()
	var buf bytes.Buffer
	if err := WriteJSON(&buf, assets); err != nil {
		t.Fatalf("WriteJSON 出错: %v", err)
	}
	if buf.Len() == 0 {
		t.Fatal("JSON 输出为空")
	}
	if !strings.HasPrefix(buf.String(), "[\n") {
		t.Fatalf("JSON 应为缩进数组，实际开头: %q", buf.String()[:20])
	}
	var back []model.Asset
	if err := json.Unmarshal(buf.Bytes(), &back); err != nil {
		t.Fatalf("JSON 无法回读: %v\n%s", err, buf.String())
	}
	if len(back) != len(assets) {
		t.Fatalf("回读条数 = %d，期望 %d", len(back), len(assets))
	}
	first := back[0]
	if first.Key() != assets[0].Key() {
		t.Fatalf("回读后 Key 变化: %q -> %q", assets[0].Key(), first.Key())
	}
	if first.Title != "Example Domain" || first.StatusCode != 200 || first.Server != "nginx" {
		t.Fatalf("回读后关键字段缺失: %+v", first)
	}
	if first.TLS == nil || !first.TLS.Expired {
		t.Fatalf("回读后 TLS 缺失: %+v", first.TLS)
	}
	if first.MetaValue("js.endpoint_count") != "4" {
		t.Fatalf("回读后 Meta 缺失: %v", first.Meta)
	}
	if len(first.Products) != 2 || len(first.Params) != 2 {
		t.Fatalf("回读后切片缺失: products=%v params=%v", first.Products, first.Params)
	}

	// 空资产列表也必须输出合法 JSON（`[]` 或 `null` 都能被 json 解析）。
	var empty bytes.Buffer
	if err := WriteJSON(&empty, nil); err != nil {
		t.Fatalf("空输入 WriteJSON 出错: %v", err)
	}
	if !json.Valid(empty.Bytes()) {
		t.Fatalf("空输入的 JSON 非法: %q", empty.String())
	}
}

// TestWriteJSONL 验证 JSON Lines：每行一个可独立解析的对象，空输入输出为空。
func TestWriteJSONL(t *testing.T) {
	assets := sampleAssets()
	var buf bytes.Buffer
	if err := WriteJSONL(&buf, assets); err != nil {
		t.Fatalf("WriteJSONL 出错: %v", err)
	}
	lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
	if len(lines) != len(assets) {
		t.Fatalf("JSONL 行数 = %d，期望 %d:\n%s", len(lines), len(assets), buf.String())
	}
	for i, ln := range lines {
		if strings.TrimSpace(ln) == "" {
			t.Fatalf("第 %d 行为空行", i)
		}
		var one model.Asset
		if err := json.Unmarshal([]byte(ln), &one); err != nil {
			t.Fatalf("第 %d 行无法解析: %v（%q）", i, err, ln)
		}
		if one.Key() != assets[i].Key() {
			t.Fatalf("第 %d 行 Key = %q，期望 %q", i, one.Key(), assets[i].Key())
		}
	}

	var empty bytes.Buffer
	if err := WriteJSONL(&empty, nil); err != nil {
		t.Fatalf("空输入 WriteJSONL 出错: %v", err)
	}
	if empty.Len() != 0 {
		t.Fatalf("空输入的 JSONL 应为空: %q", empty.String())
	}
}

// TestWriteMarkdown 验证 Markdown 报告：标题、统计、表头、CDN 提示、脚注。
func TestWriteMarkdown(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteMarkdown(&buf, sampleAssets()); err != nil {
		t.Fatalf("WriteMarkdown 出错: %v", err)
	}
	out := buf.String()
	for _, want := range []string{
		"# 资产测绘与攻击面报告",
		"- 资产条目: 3",
		"- 开放端口: 2",
		"- Web 目标: 1",
		"**证书已过期: 1**",
		"服务分布:",
		"CDN 分布:",
		"参数清单（M4 注入类测试的输入面）:",
		"前端代码情报: JS 接口 4 个，疑似硬编码凭据 2 处",
		"## 资产清单",
		"| 主机 | 端口 | 服务 | 产品 | 版本 | 置信度 | 标题 | CDN/WAF | 状态码 | 来源 |",
		"| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |",
		"| example.com | 443 | https | nginx | 1.24.0 | high | Example Domain | cloudflare | 200 | httpinfo |",
		"## CDN / WAF 提示",
		"源站疑似 203.0.113.7",
		"> 本报告由 westy_scan 在授权范围内自动生成",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("Markdown 缺少 %q:\n%s", want, out)
		}
	}

	var empty bytes.Buffer
	if err := WriteMarkdown(&empty, nil); err != nil {
		t.Fatalf("空输入 WriteMarkdown 出错: %v", err)
	}
	eo := empty.String()
	if !strings.Contains(eo, "# 资产测绘与攻击面报告") || !strings.Contains(eo, "| 主机 |") {
		t.Fatalf("空输入的 Markdown 结构不完整:\n%s", eo)
	}
	if strings.Contains(eo, "## CDN / WAF 提示") {
		t.Fatalf("空输入不应输出 CDN 提示章节:\n%s", eo)
	}
	if strings.Contains(eo, "- 资产条目: 1") {
		t.Fatalf("空输入统计错误:\n%s", eo)
	}
}

// TestMarkdownEscapesPipeAndNewline 验证 Markdown 表格单元格里的 | 与换行被转义，
// 否则一条含竖线的 Title 会把整张表拆错列。
func TestMarkdownEscapesPipeAndNewline(t *testing.T) {
	assets := []model.Asset{{Host: "h", Port: 80, Title: "a|b", Product: "p\nq", Source: "s|x"}}
	var buf bytes.Buffer
	if err := WriteMarkdown(&buf, assets); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if strings.Contains(out, "| a|b |") {
		t.Fatalf("Title 中的竖线未转义:\n%s", out)
	}
	if !strings.Contains(out, `a\|b`) {
		t.Fatalf("Title 中的竖线应被转义为 \\|:\n%s", out)
	}
	if !strings.Contains(out, "p q") {
		t.Fatalf("Product 中的换行未替换为空格:\n%s", out)
	}
	if !strings.Contains(out, `s\|x`) {
		t.Fatalf("Source 中的竖线未转义:\n%s", out)
	}
}

// TestWriteFindingsTable 验证漏洞清单表格：表头、字段、以及空输入提示。
func TestWriteFindingsTable(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteFindings(&buf, sampleFindings()); err != nil {
		t.Fatalf("WriteFindings 出错: %v", err)
	}
	out := buf.String()
	for _, h := range []string{"SEVERITY", "TEMPLATE", "NAME", "MATCHED AT", "CONF", "VERIFIED", "EXTRACTED"} {
		if !strings.Contains(out, h) {
			t.Fatalf("漏洞表格缺少表头 %q:\n%s", h, out)
		}
	}
	for _, want := range []string{"CRITICAL", "cve-2021-41773", "Apache 路径穿越", "true", "version=2.4.49"} {
		if !strings.Contains(out, want) {
			t.Fatalf("漏洞表格缺少 %q:\n%s", want, out)
		}
	}
	// 严重级别统一大写。
	if strings.Contains(out, "\tcritical\t") {
		t.Fatalf("严重级别未大写:\n%s", out)
	}

	var empty bytes.Buffer
	if err := WriteFindings(&empty, nil); err != nil {
		t.Fatalf("空输入 WriteFindings 出错: %v", err)
	}
	if !strings.Contains(empty.String(), "未发现漏洞") {
		t.Fatalf("空输入应输出提示: %q", empty.String())
	}
}

// TestWriteFindingsMarkdown 验证漏洞 Markdown 章节（"漏洞验证结果"）与证据代码块。
func TestWriteFindingsMarkdown(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteFindingsMarkdown(&buf, sampleFindings()); err != nil {
		t.Fatalf("WriteFindingsMarkdown 出错: %v", err)
	}
	out := buf.String()
	for _, want := range []string{
		"## 漏洞验证结果",
		"- CRITICAL: 1",
		"- MEDIUM: 1",
		"- LOW: 1",
		"| 级别 | 模板 | 名称 | 命中地址 | 置信度 | 已确认 | 提取信息 |",
		"| --- | --- | --- | --- | --- | --- | --- |",
		"cve-2021-41773",
		"### Apache 路径穿越（CRITICAL）",
		"- 说明: 路径穿越导致任意文件读取",
		"- 参考: https://httpd.apache.org/security/vulnerabilities_24.html",
		"路径穿越导致任意文件读取",
		"- 匹配依据:",
		"```http",
		"GET /cgi-bin/.%2e/.%2e/etc/passwd HTTP/1.1",
		"root:x:0:0:root:/root:/bin/bash",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("漏洞 Markdown 缺少 %q:\n%s", want, out)
		}
	}
	if strings.Count(out, "```http") != 2*len(sampleFindings()) {
		t.Fatalf("每条漏洞应有请求/响应两个代码块，实际 ```http 出现 %d 次", strings.Count(out, "```http"))
	}
	// 严重级别顺序。
	if strings.Index(out, "- CRITICAL: 1") > strings.Index(out, "- INFO") && strings.Contains(out, "- INFO") {
		t.Fatalf("严重级别顺序错误:\n%s", out)
	}

	var empty bytes.Buffer
	if err := WriteFindingsMarkdown(&empty, nil); err != nil {
		t.Fatalf("空输入 WriteFindingsMarkdown 出错: %v", err)
	}
	eo := empty.String()
	if !strings.Contains(eo, "## 漏洞验证结果") {
		t.Fatalf("空输入也必须包含章节标题: %q", eo)
	}
	if !strings.Contains(eo, "未发现漏洞") {
		t.Fatalf("空输入应说明未发现漏洞: %q", eo)
	}
	if strings.Contains(eo, "| 级别 |") {
		t.Fatalf("空输入不应输出表格: %q", eo)
	}
}

// TestWriteHTMLBasics 验证 HTML 报告的自包含结构与关键信息。
func TestWriteHTMLBasics(t *testing.T) {
	meta := HTMLMeta{
		Title:         "测试报告",
		ScanID:        "scan-42",
		Authorization: "AUTH-2024-001",
		Operator:      "tester",
		GeneratedAt:   time.Date(2024, 5, 6, 7, 8, 9, 0, time.UTC),
	}
	var buf bytes.Buffer
	if err := WriteHTML(&buf, sampleAssets(), sampleFindings(), meta); err != nil {
		t.Fatalf("WriteHTML 出错: %v", err)
	}
	out := buf.String()
	for _, want := range []string{
		"<!DOCTYPE html>",
		`<html lang="zh-CN">`,
		`<meta charset="utf-8">`,
		"<title>测试报告</title>",
		"测试报告",
		"2024-05-06 07:08:09",
		"scan-42",
		"AUTH-2024-001",
		"tester",
		"资产条目",
		"开放端口",
		"Web 目标",
		"漏洞条目",
		"严重",
		"高危",
		"经 CDN/WAF",
		"过期证书",
		"服务分布:",
		"参数清单:",
		"<h2>漏洞验证结果</h2>",
		"<h2>证据（可复现）</h2>",
		"<h2>资产清单</h2>",
		"Apache 路径穿越",
		"cve-2021-41773",
		"https://example.com/cgi-bin/.%2e/.%2e/etc/passwd",
		"root:x:0:0:root:/root:/bin/bash",
		"example.com",
		"nginx",
		"cloudflare",
		"<h2>CDN / WAF 提示</h2>",
		"源站疑似 203.0.113.7",
		"本报告由 westy_scan 在授权范围内自动生成",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("HTML 缺少 %q", want)
		}
	}
	// 自包含：不允许引用任何外部资源（脚本/样式/图片）。
	for _, forbidden := range []string{"<script", "<link", "<img", "<iframe", "src=\"http", "@import"} {
		if strings.Contains(out, forbidden) {
			t.Fatalf("HTML 不应引用外部资源 %q", forbidden)
		}
	}
	// 未闭合的标签粗检（自包含报告必须能被浏览器正确解析）。
	if strings.Count(out, "<table>") != strings.Count(out, "</table>") {
		t.Fatalf("table 标签不配对: %d/%d", strings.Count(out, "<table>"), strings.Count(out, "</table>"))
	}
	if strings.Count(out, "<details>") != strings.Count(out, "</details>") {
		t.Fatalf("details 标签不配对")
	}
}

// TestWriteHTMLDefaultsAndEmptyInput 验证默认标题/时间/脚注与空输入不 panic。
func TestWriteHTMLDefaultsAndEmptyInput(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteHTML(&buf, nil, nil, HTMLMeta{}); err != nil {
		t.Fatalf("空输入 WriteHTML 出错: %v", err)
	}
	out := buf.String()
	if !strings.HasPrefix(out, "<!DOCTYPE html>") {
		t.Fatalf("HTML 缺少 DOCTYPE，实际开头: %q", out[:40])
	}
	if !strings.Contains(out, "<title>资产测绘与漏洞验证报告</title>") {
		t.Fatal("空 Title 未回落到默认标题")
	}
	if !strings.Contains(out, "生成时间 20") {
		t.Fatal("GeneratedAt 为零值时未自动填充当前时间")
	}
	if !strings.Contains(out, "未发现漏洞") {
		t.Fatal("空漏洞列表未提示未发现漏洞")
	}
	if strings.Contains(out, "<h2>CDN / WAF 提示</h2>") {
		t.Fatal("无 CDN 资产时不应输出提示章节")
	}
	if !strings.Contains(out, "本报告由 westy_scan 在授权范围内自动生成") {
		t.Fatal("空 Note 未回落到默认脚注")
	}
	// 自定义 Note 生效。
	var buf2 bytes.Buffer
	if err := WriteHTML(&buf2, nil, nil, HTMLMeta{Note: "仅限内部使用"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf2.String(), "仅限内部使用") {
		t.Fatal("自定义 Note 未生效")
	}
}

// TestWriteHTMLEscapesUserData 验证 HTML 转义：含 <script> 的标题/URL 必须以实体出现，
// 不能被原样注入（这是报告作为交付物时最重要的一条安全属性）。
func TestWriteHTMLEscapesUserData(t *testing.T) {
	assets := []model.Asset{{
		Host:       `evil"><script>alert(1)</script>`,
		Port:       80,
		Service:    `<img src=x onerror=alert(2)>`,
		Product:    "a&b",
		Version:    `"><svg onload=alert(3)>`,
		Title:      `</td><script>alert(4)</script>`,
		Source:     `<b>bold</b>`,
		Confidence: `"quoted"`,
		CDN:        `<i>cdn</i>`,
		BehindCDN:  true,
		OriginNote: `<script>alert(5)</script>`,
	}}
	findings := []poc.Finding{{
		TemplateID: `t<script>`,
		Name:       `<script>alert(6)</script>`,
		Severity:   `high"><script>`,
		MatchedAt:  `http://x/?a="><script>alert(7)</script>`,
		Confidence: `"c"`,
		Evidence: poc.Evidence{
			Request:  `<script>alert(8)</script>`,
			Response: `<script>alert(9)</script>`,
			Matcher:  `"<script>alert(10)</script>`,
		},
	}}
	meta := HTMLMeta{
		Title:         `<script>alert(11)</script>`,
		ScanID:        `"><script>alert(12)</script>`,
		Authorization: `<script>alert(13)</script>`,
		Operator:      `<script>alert(14)</script>`,
		Note:          `<script>alert(15)</script>`,
	}
	var buf bytes.Buffer
	if err := WriteHTML(&buf, assets, findings, meta); err != nil {
		t.Fatalf("WriteHTML 出错: %v", err)
	}
	out := buf.String()

	if strings.Contains(out, "<script>alert(") {
		t.Fatalf("HTML 报告存在注入：原始 <script> 被原样写入")
	}
	// 应当以转义形式出现。
	if !strings.Contains(out, "&lt;script&gt;alert(11)&lt;/script&gt;") {
		t.Fatalf("meta.Title 未被转义")
	}
	if !strings.Contains(out, "&lt;script&gt;alert(6)&lt;/script&gt;") {
		t.Fatalf("finding.Name 未被转义")
	}
	if !strings.Contains(out, "&lt;img src=x onerror=alert(2)&gt;") {
		t.Fatalf("asset.Service 未被转义")
	}
	if !strings.Contains(out, "a&amp;b") {
		t.Fatalf("asset.Product 中的 & 未被转义为 &amp;")
	}
	if !strings.Contains(out, "&lt;b&gt;bold&lt;/b&gt;") {
		t.Fatalf("asset.Source 未被转义")
	}
	// StatusCode/Port 是数字，不允许出现引号逃逸。
	if strings.Contains(out, `class="sev high"><script>`) {
		t.Fatalf("severity 进入 class 属性时未转义")
	}
}

// TestWriteHTMLTableIncludesConfidence 验证 HTML 资产表确实输出置信度列
// （并要求其中的引号被转义）。
func TestWriteHTMLTableIncludesConfidence(t *testing.T) {
	assets := []model.Asset{{Host: "h", Port: 80, Confidence: `"quoted"`, Service: "http", Title: "t"}}
	var buf bytes.Buffer
	if err := WriteHTML(&buf, assets, nil, HTMLMeta{}); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	// 表头必须有置信度列，否则"置信度"这项信息在交付物里丢失。
	if !strings.Contains(out, "<th>置信度</th>") {
		t.Fatalf("HTML 资产表缺少置信度列")
	}
	// 资产行必须存在，且其中出现被转义的置信度值。
	rows := htmlRowsAfterAssets(out)
	if len(rows) != 1 {
		t.Fatalf("资产清单应有 1 行，实际 %d 行：%v", len(rows), rows)
	}
	// html.EscapeString 把 " 转成数字实体 &#34;。
	if !strings.Contains(rows[0], "&#34;quoted&#34;") {
		t.Fatalf("HTML 资产行中的置信度未被转义: %s", rows[0])
	}
	if strings.Contains(rows[0], `"quoted"`) {
		t.Fatalf("HTML 资产行中存在未转义的引号: %s", rows[0])
	}
}

// htmlRowsAfterAssets 取"资产清单"表头之后的所有 <tr> 行（仅用于测试断言）。
func htmlRowsAfterAssets(out string) []string {
	idx := strings.Index(out, "<h2>资产清单</h2>")
	if idx < 0 {
		return nil
	}
	rest := out[idx:]
	var rows []string
	for {
		start := strings.Index(rest, "<tr>")
		if start < 0 {
			break
		}
		end := strings.Index(rest[start:], "</tr>")
		if end < 0 {
			break
		}
		row := rest[start : start+end+len("</tr>")]
		if !strings.Contains(row, "<th>") { // 跳过表头行
			rows = append(rows, row)
		}
		rest = rest[start+end+len("</tr>"):]
	}
	return rows
}

// TestWriteHTMLSeverityClass 验证严重级别进入 CSS class 时被白名单化处理
// （代码的做法是 ToLower + 转义；非法级别不会破坏 class 结构）。
func TestWriteHTMLSeverityClass(t *testing.T) {
	findings := []poc.Finding{
		{TemplateID: "t1", Name: "n1", Severity: poc.SeverityCritical, MatchedAt: "u"},
		{TemplateID: "t2", Name: "n2", Severity: poc.SeverityHigh, MatchedAt: "u"},
		{TemplateID: "t3", Name: "n3", Severity: poc.SeverityMedium, MatchedAt: "u"},
		{TemplateID: "t4", Name: "n4", Severity: `x" onmouseover="e`, MatchedAt: "u"},
	}
	var buf bytes.Buffer
	if err := WriteHTML(&buf, nil, findings, HTMLMeta{}); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, `class="sev critical"`) {
		t.Fatal("critical 级别 class 缺失")
	}
	if !strings.Contains(out, `class="sev high"`) || !strings.Contains(out, `class="sev medium"`) {
		t.Fatal("high/medium 级别 class 缺失")
	}
	if strings.Contains(out, `onmouseover="e"`) {
		t.Fatal("非法 severity 未转义，可注入属性")
	}
}

// TestComputeEmptySliceNotNil 验证 Compute 对空切片与 nil 一致。
func TestComputeEmptySliceNotNil(t *testing.T) {
	a := Compute([]model.Asset{})
	b := Compute(nil)
	if a.Total != 0 || b.Total != 0 {
		t.Fatalf("空输入统计非零: %+v / %+v", a, b)
	}
	if SummaryText(a) != SummaryText(b) {
		t.Fatal("空切片与 nil 的摘要不一致")
	}
}

// TestTruncateAndEscapeHelpers 直接覆盖截断/转义助手的行为。
func TestTruncateAndEscapeHelpers(t *testing.T) {
	if got := truncate("abcdef", 3); got != "abc" {
		t.Fatalf("truncate = %q", got)
	}
	if got := truncate("abc", 10); got != "abc" {
		t.Fatalf("短串不应截断: %q", got)
	}
	if got := truncate("abc", 0); got != "abc" {
		t.Fatalf("max<=0 表示不截断: %q", got)
	}
	if got := truncate("", -1); got != "" {
		t.Fatalf("空串: %q", got)
	}
	if got := escape("a|b\nc"); got != `a\|b c` {
		t.Fatalf("escape = %q", got)
	}
	long := strings.Repeat("x", 200)
	if len(escape(long)) != 120 {
		t.Fatalf("escape 未截断到 120: %d", len(escape(long)))
	}
	if got := portText(0); got != "" {
		t.Fatalf("portText(0) = %q", got)
	}
	if got := portText(443); got != "443" {
		t.Fatalf("portText(443) = %q", got)
	}
	if got := statusText(-1); got != "" {
		t.Fatalf("statusText(-1) = %q", got)
	}
	if got := statusText(200); got != "200" {
		t.Fatalf("statusText(200) = %q", got)
	}
}

// TestJoinExtractedDeterministic 验证提取信息按 key 排序输出（避免 map 随机序）。
func TestJoinExtractedDeterministic(t *testing.T) {
	f := poc.Finding{Extracted: map[string][]string{
		"z": {"1", "2"},
		"a": {"9"},
		"m": {"x"},
	}}
	want := "a=9; m=x; z=1|2"
	for i := 0; i < 20; i++ {
		if got := joinExtracted(f); got != want {
			t.Fatalf("joinExtracted = %q，期望 %q", got, want)
		}
	}
	if got := joinExtracted(poc.Finding{}); got != "" {
		t.Fatalf("无提取信息应返回空串: %q", got)
	}
}

// TestWriteJSONLPropagatesWriteError 验证 JSONL 写入失败时把错误抛给调用方
// （而不是静默截断输出）。
func TestWriteJSONLPropagatesWriteError(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteJSONL(&buf, sampleAssets()); err != nil {
		t.Fatalf("正常写入不应报错: %v", err)
	}

	err := WriteJSONL(errWriter{}, sampleAssets())
	if err == nil {
		t.Fatal("写入器报错时 WriteJSONL 应当返回错误")
	}
	if !strings.Contains(err.Error(), "write failed") {
		t.Fatalf("错误信息异常: %v", err)
	}

	// 读取端失败同样要报错。
	var buf2 bytes.Buffer
	if err := WriteJSON(&buf2, sampleAssets()); err != nil {
		t.Fatalf("WriteJSON 正常写入不应报错: %v", err)
	}
	if err := WriteJSON(errWriter{}, sampleAssets()); err == nil {
		t.Fatal("写入器报错时 WriteJSON 应当返回错误")
	}
}

type errWriter struct{}

func (errWriter) Write([]byte) (int, error) { return 0, errors.New("write failed") }

// TestWritersPropagateErrors 验证会传播写入错误的 API 确实传播（tabwriter.Flush / json.Encode）。
func TestWritersPropagateErrors(t *testing.T) {
	cases := []struct {
		name string
		call func() error
	}{
		{"WriteTable", func() error { return WriteTable(errWriter{}, sampleAssets()) }},
		{"WriteJSON", func() error { return WriteJSON(errWriter{}, sampleAssets()) }},
		{"WriteJSONL", func() error { return WriteJSONL(errWriter{}, sampleAssets()) }},
		{"WriteFindings", func() error { return WriteFindings(errWriter{}, sampleFindings()) }},
		{"WriteFindings 空输入", func() error { return WriteFindings(errWriter{}, nil) }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if err := c.call(); err == nil {
				t.Fatalf("%s 未把写入错误抛出", c.name)
			}
		})
	}
}

// TestWritersReportWriteErrors 验证写入错误会被抛出（曾经被静默吞掉）。
//
// 报告是交付物：磁盘满/管道断开/权限不足时，"看起来成功、其实内容被截断"比直接报错危险得多。
func TestWritersReportWriteErrors(t *testing.T) {
	if err := WriteMarkdown(errWriter{}, sampleAssets()); err == nil {
		t.Fatal("WriteMarkdown 应当把写入错误抛出")
	}
	if err := WriteFindingsMarkdown(errWriter{}, sampleFindings()); err == nil {
		t.Fatal("WriteFindingsMarkdown 应当把写入错误抛出")
	}
	if err := WriteHTML(errWriter{}, sampleAssets(), sampleFindings(), HTMLMeta{}); err == nil {
		t.Fatal("WriteHTML 应当把写入错误抛出")
	}
	// 出错信息要能看出是哪份报告失败（便于定位），不能只有一个裸 err。
	err := WriteMarkdown(errWriter{}, sampleAssets())
	if err == nil || !strings.Contains(err.Error(), "Markdown") {
		t.Fatalf("错误信息应标明报告类型，实际: %v", err)
	}
	// 对照：正常 writer 必须返回 nil（别把成功路径也搞坏）。
	var ok bytes.Buffer
	if err := WriteMarkdown(&ok, sampleAssets()); err != nil {
		t.Fatalf("正常写入不应报错: %v", err)
	}
	if err := WriteHTML(&ok, sampleAssets(), sampleFindings(), HTMLMeta{}); err != nil {
		t.Fatalf("正常写入不应报错: %v", err)
	}
	// 对照：tabwriter 那条路径（WriteTable）本来就是检查 Flush 的。
	if err := WriteTable(errWriter{}, sampleAssets()); err == nil {
		t.Fatal("WriteTable 应当能报出写入错误")
	}
}

// TestComputeProductCountsBothFields 验证产品统计口径与表格输出一致：
// probe/fingerprint 经 Identify() 写的是**单值 Product**，只看 Products 切片会低估覆盖面。
func TestComputeProductCountsBothFields(t *testing.T) {
	assets := []model.Asset{
		{Host: "a", Product: "OpenSSH", Products: nil},                         // 只有单值字段
		{Host: "b", Product: "nginx", Products: []string{"nginx"}},             // 两个字段都有（不能重复计数）
		{Host: "c", Product: "", Products: []string{"OpenSSL", "OpenSSL", ""}}, // 切片内含重复与空值
	}
	st := Compute(assets)
	if st.ByProduct["OpenSSH"] != 1 {
		t.Fatalf("单值 Product 未被统计: %v", st.ByProduct)
	}
	if st.ByProduct["nginx"] != 1 {
		t.Fatalf("同一条资产里 Product 与 Products 重复时只应计数一次: %v", st.ByProduct)
	}
	if st.ByProduct["OpenSSL"] != 1 {
		t.Fatalf("切片内重复产品只应计数一次: %v", st.ByProduct)
	}
	if _, ok := st.ByProduct[""]; ok {
		t.Fatalf("空产品名不应进统计: %v", st.ByProduct)
	}
	// 统计口径必须与表格/Markdown 输出一致（以前表格显示 OpenSSH、分布里却没有）。
	var buf bytes.Buffer
	if err := WriteTable(&buf, assets); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "OpenSSH") {
		t.Fatal("资产表格应当显示单值 Product")
	}
	if !strings.Contains(SummaryText(st), "OpenSSH") {
		t.Fatalf("产品分布里应当出现 OpenSSH: %s", SummaryText(st))
	}
}

// TestTruncateKeepsUTF8Valid 验证截断不会切坏多字节字符。
//
// 曾经的实现按字节切片（s[:max]），中文标题/中文 banner 落在边界上时会在报告里
// 显示成乱码（U+FFFD）——不报错、不 panic，只是静静损坏交付物。
// 修复方式是把截断收口到 internal/textutil（在字符边界上回退）。
func TestTruncateKeepsUTF8Valid(t *testing.T) {
	cases := []struct {
		name string
		in   string
		max  int
	}{
		{"汉字边界不整齐(119/150)", strings.Repeat("洞", 50), 119},
		{"emoji 混排(120/129)", strings.Repeat("洞", 39) + "🔴🔴🔴", 120},
		{"上限小于单个汉字", "漏洞", 2},
		{"正好等于长度", "中文", 6},
		{"纯 ASCII", strings.Repeat("a", 100), 40},
		{"max<=0 视为不限", "中文标题", 0},
	}
	for _, c := range cases {
		got := truncate(c.in, c.max)
		if !utf8.ValidString(got) {
			t.Errorf("[%s] 截断结果不是合法 UTF-8: %q", c.name, got)
		}
		if c.max > 0 && len(got) > c.max {
			t.Errorf("[%s] 截断结果超预算: %d > %d", c.name, len(got), c.max)
		}
		if c.max <= 0 && got != c.in {
			t.Errorf("[%s] max<=0 应原样返回", c.name)
		}
	}
	// 边界：上限正好落在一个汉字中间时，必须退回到上一个完整字符（宁可少几字节）。
	if got := truncate("漏洞", 4); got != "漏" {
		t.Errorf("应回退到完整字符边界，实际 %q", got)
	}

	// 真实触发路径：Markdown 单元格转义、资产表格（Host/Banner）、HTML 标题。
	if esc := escape(strings.Repeat("洞", 39) + "🔴🔴🔴"); !utf8.ValidString(esc) {
		t.Errorf("Markdown 单元格转义破了 UTF-8: %q", esc)
	}
	var buf bytes.Buffer
	if err := WriteTable(&buf, []model.Asset{{Host: strings.Repeat("漏", 20), Port: 80, Banner: strings.Repeat("洞", 30)}}); err != nil {
		t.Fatal(err)
	}
	if !utf8.ValidString(buf.String()) {
		t.Error("资产表格输出破了 UTF-8")
	}
	buf.Reset()
	if err := WriteHTML(&buf, []model.Asset{{Host: "h", Title: strings.Repeat("洞", 40)}}, nil, HTMLMeta{}); err != nil {
		t.Fatal(err)
	}
	if !utf8.ValidString(buf.String()) {
		t.Error("HTML 报告输出破了 UTF-8")
	}
	buf.Reset()
	if err := WriteMarkdown(&buf, []model.Asset{{Host: "h", Title: strings.Repeat("洞", 60)}}); err != nil {
		t.Fatal(err)
	}
	if !utf8.ValidString(buf.String()) {
		t.Error("Markdown 报告输出破了 UTF-8")
	}
}
