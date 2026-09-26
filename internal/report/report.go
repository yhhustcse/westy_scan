// Package report 负责结果呈现：控制台表格、JSON、JSONL、Markdown 报告。
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"text/tabwriter"

	"westy_scan/internal/model"
	"westy_scan/internal/poc"
	"westy_scan/internal/textutil"
)

// errTrackingWriter 记录**第一个**写失败，之后的写入直接短路。
//
// 为什么需要：Markdown/HTML 报告以前把 Fprintln/Fprintf 的错误全丢了，
// 永远返回 nil。磁盘满、管道断开、权限不足时会产出"看起来成功、其实被截断"的报告文件 ——
// 报告是交付物，静默截断比直接报错危险得多。
// 用它包一层，函数体里的 fmt.Fprintln(w, ...) 一行都不用改。
type errTrackingWriter struct {
	w   io.Writer
	err error
}

func (e *errTrackingWriter) Write(p []byte) (int, error) {
	if e.err != nil {
		return 0, e.err
	}
	n, err := e.w.Write(p)
	if err != nil {
		e.err = err
	}
	return n, err
}

// Stats 是结果统计，用于结束时的总结与 HTML/Markdown 报告头部。
type Stats struct {
	Total        int
	OpenPorts    int
	WebTargets   int
	ExpiredCerts int
	BehindCDN    int
	WithParams   int // 带参数的资产数（M4 的输入面规模）
	Duplicates   int // 近似重复页面数
	JSEndpoints  int // 从 JS 抽出的接口总数
	JSSecrets    int // 从 JS 抽出的疑似凭据数
	ByService    map[string]int
	ByPort       map[string]int
	ByProduct    map[string]int
	ByStatus     map[string]int
	ByCDN        map[string]int
	ByParam      map[string]int
}

// Compute 统计资产集合。
func Compute(assets []model.Asset) Stats {
	st := Stats{
		ByService: make(map[string]int),
		ByPort:    make(map[string]int),
		ByProduct: make(map[string]int),
		ByStatus:  make(map[string]int),
		ByCDN:     make(map[string]int),
		ByParam:   make(map[string]int),
	}
	st.Total = len(assets)
	for _, a := range assets {
		if a.Port > 0 {
			st.OpenPorts++
			st.ByPort[fmt.Sprintf("%d", a.Port)]++
		}
		if a.URL != "" {
			st.WebTargets++
		}
		if a.Service != "" {
			st.ByService[a.Service]++
		}
		// 产品统计要同时看两个字段：probe/fingerprint 经 Identify() 写的是**单值 Product**，
		// 而多规则命中时会同时进 Products 切片。只看 Products 会让分布漏掉大多数产品
		// （表格里显示 OpenSSH，分布里却没有）。同一条资产里的重复产品只算一次。
		seenProduct := make(map[string]bool, len(a.Products)+1)
		for _, p := range a.Products {
			if p != "" && !seenProduct[p] {
				seenProduct[p] = true
				st.ByProduct[p]++
			}
		}
		if a.Product != "" && !seenProduct[a.Product] {
			seenProduct[a.Product] = true
			st.ByProduct[a.Product]++
		}
		if a.StatusCode > 0 {
			st.ByStatus[fmt.Sprintf("%d", a.StatusCode)]++
		}
		if a.TLS != nil && a.TLS.Expired {
			st.ExpiredCerts++
		}
		if a.BehindCDN {
			st.BehindCDN++
		}
		if a.CDN != "" {
			st.ByCDN[a.CDN]++
		} else if a.WAF != "" {
			st.ByCDN[a.WAF]++
		}
		if len(a.Params) > 0 {
			st.WithParams++
			for _, p := range a.Params {
				st.ByParam[p]++
			}
		}
		if a.MetaValue("duplicate_of") != "" {
			st.Duplicates++
		}
		st.JSEndpoints += atoiSafe(a.MetaValue("js.endpoint_count"))
		st.JSSecrets += atoiSafe(a.MetaValue("js.secret_count"))
	}
	return st
}

func atoiSafe(s string) int {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil || n < 0 {
		return 0
	}
	return n
}

// SummaryText 生成人类可读的总结。
func SummaryText(st Stats) string {
	var b strings.Builder
	fmt.Fprintf(&b, "资产总数: %d | 开放端口: %d | Web 目标: %d | 过期证书: %d",
		st.Total, st.OpenPorts, st.WebTargets, st.ExpiredCerts)
	if st.BehindCDN > 0 {
		fmt.Fprintf(&b, " | 经 CDN/WAF: %d（真实 IP 可能被隐藏）", st.BehindCDN)
	}
	b.WriteString("\n")
	if st.WithParams > 0 || st.JSEndpoints > 0 || st.JSSecrets > 0 {
		fmt.Fprintf(&b, "攻击面输入面: 带参数资产 %d | JS 接口 %d | 疑似凭据 %d", st.WithParams, st.JSEndpoints, st.JSSecrets)
		if st.Duplicates > 0 {
			fmt.Fprintf(&b, " | 近似重复页面 %d", st.Duplicates)
		}
		b.WriteString("\n")
	}
	if len(st.ByService) > 0 {
		fmt.Fprintf(&b, "服务分布: %s\n", topPairs(st.ByService, 12))
	}
	if len(st.ByPort) > 0 {
		fmt.Fprintf(&b, "端口分布: %s\n", topPairs(st.ByPort, 12))
	}
	if len(st.ByProduct) > 0 {
		fmt.Fprintf(&b, "产品指纹: %s\n", topPairs(st.ByProduct, 12))
	}
	if len(st.ByCDN) > 0 {
		fmt.Fprintf(&b, "CDN/WAF: %s\n", topPairs(st.ByCDN, 8))
	}
	if len(st.ByParam) > 0 {
		fmt.Fprintf(&b, "参数清单: %s\n", topPairs(st.ByParam, 20))
	}
	return b.String()
}

func topPairs(m map[string]int, limit int) string {
	type kv struct {
		k string
		v int
	}
	pairs := make([]kv, 0, len(m))
	for k, v := range m {
		pairs = append(pairs, kv{k, v})
	}
	sort.Slice(pairs, func(i, j int) bool {
		if pairs[i].v != pairs[j].v {
			return pairs[i].v > pairs[j].v
		}
		return pairs[i].k < pairs[j].k
	})
	if len(pairs) > limit {
		pairs = pairs[:limit]
	}
	parts := make([]string, 0, len(pairs))
	for _, p := range pairs {
		parts = append(parts, fmt.Sprintf("%s(%d)", p.k, p.v))
	}
	return strings.Join(parts, ", ")
}

// CountBySeverity 统计各严重级别的漏洞数量。
func CountBySeverity(findings []poc.Finding) map[string]int {
	out := map[string]int{}
	for _, f := range findings {
		out[strings.ToLower(f.Severity)]++
	}
	return out
}

// SummaryFindings 生成漏洞摘要（stderr 用）。
func SummaryFindings(findings []poc.Finding) string {
	if len(findings) == 0 {
		return "漏洞验证: 未发现（内置模板全部通过二次确认）\n"
	}
	counts := CountBySeverity(findings)
	order := []string{"critical", "high", "medium", "low", "info"}
	var parts []string
	for _, sev := range order {
		if n := counts[sev]; n > 0 {
			parts = append(parts, fmt.Sprintf("%s(%d)", sev, n))
		}
	}
	verified := 0
	templates := map[string]bool{}
	for _, f := range findings {
		if f.Verified {
			verified++
		}
		templates[f.TemplateID] = true
	}
	return fmt.Sprintf("漏洞验证: 命中 %d 条（模板 %d 个，已验证 %d 条）| %s\n",
		len(findings), len(templates), verified, strings.Join(parts, ", "))
}

// WriteFindings 输出漏洞清单表格。
func WriteFindings(w io.Writer, findings []poc.Finding) error {
	if len(findings) == 0 {
		_, err := fmt.Fprintln(w, "（未发现漏洞）")
		return err
	}
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "SEVERITY\tTEMPLATE\tNAME\tMATCHED AT\tCONF\tVERIFIED\tEXTRACTED")
	for _, f := range findings {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%v\t%s\n",
			strings.ToUpper(f.Severity), f.TemplateID, truncate(f.Name, 30),
			truncate(f.MatchedAt, 60), f.Confidence, f.Verified, truncate(joinExtracted(f), 50))
	}
	return tw.Flush()
}

func joinExtracted(f poc.Finding) string {
	if len(f.Extracted) == 0 {
		return ""
	}
	keys := make([]string, 0, len(f.Extracted))
	for k := range f.Extracted {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var parts []string
	for _, k := range keys {
		parts = append(parts, k+"="+strings.Join(f.Extracted[k], "|"))
	}
	return strings.Join(parts, "; ")
}

// WriteFindingsMarkdown 输出 Markdown 漏洞章节，含可复现证据。
func WriteFindingsMarkdown(w io.Writer, findings []poc.Finding) error {
	tw := &errTrackingWriter{w: w}
	w = tw
	fmt.Fprintln(w, "## 漏洞验证结果")
	fmt.Fprintln(w)
	if len(findings) == 0 {
		fmt.Fprintln(w, "本次运行未发现漏洞（内置模板均为只读检查，且默认开启二次确认）。")
		fmt.Fprintln(w)
		return tw.err
	}
	counts := CountBySeverity(findings)
	for _, sev := range []string{"critical", "high", "medium", "low", "info"} {
		if n := counts[sev]; n > 0 {
			fmt.Fprintf(w, "- %s: %d\n", strings.ToUpper(sev), n)
		}
	}
	fmt.Fprintln(w)
	fmt.Fprintln(w, "| 级别 | 模板 | 名称 | 命中地址 | 置信度 | 已确认 | 提取信息 |")
	fmt.Fprintln(w, "| --- | --- | --- | --- | --- | --- | --- |")
	for _, f := range findings {
		fmt.Fprintf(w, "| %s | `%s` | %s | %s | %s | %v | %s |\n",
			strings.ToUpper(f.Severity), f.TemplateID, escape(f.Name),
			escape(f.MatchedAt), f.Confidence, f.Verified, escape(joinExtracted(f)))
	}
	fmt.Fprintln(w)

	// 证据：可复现是漏洞报告的生命线
	for _, f := range findings {
		fmt.Fprintf(w, "### %s（%s）\n\n", f.Name, strings.ToUpper(f.Severity))
		fmt.Fprintf(w, "- 模板: `%s`\n- 命中: `%s`\n- 置信度: %s｜二次确认: %v\n",
			f.TemplateID, f.MatchedAt, f.Confidence, f.Verified)
		if f.Description != "" {
			fmt.Fprintf(w, "- 说明: %s\n", f.Description)
		}
		if len(f.Reference) > 0 {
			fmt.Fprintf(w, "- 参考: %s\n", strings.Join(f.Reference, " , "))
		}
		fmt.Fprintf(w, "- 匹配依据: %s\n\n", escape(f.Evidence.Matcher))
		fmt.Fprintln(w, "```http")
		fmt.Fprintln(w, f.Evidence.Request)
		fmt.Fprintln(w, "```")
		fmt.Fprintln(w)
		fmt.Fprintln(w, "```http")
		fmt.Fprintln(w, f.Evidence.Response)
		fmt.Fprintln(w, "```")
		fmt.Fprintln(w)
	}
	return tw.err
}

func WriteTable(w io.Writer, assets []model.Asset) error {
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "HOST\tPORT\tSERVICE\tPRODUCT\tVERSION\tCONF\tSTATUS\tTITLE/SERVER\tCDN/WAF\tSOURCE")
	for _, a := range assets {
		port := ""
		if a.Port > 0 {
			port = fmt.Sprintf("%d", a.Port)
		}
		status := ""
		if a.StatusCode > 0 {
			status = fmt.Sprintf("%d", a.StatusCode)
		}
		desc := a.Title
		if desc == "" {
			desc = a.Server
		}
		if desc == "" {
			desc = truncate(a.Banner, 60)
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			truncate(a.Host, 40), port, a.Service,
			truncate(a.Product, 24), truncate(a.Version, 16), a.Confidence,
			status, truncate(desc, 44), cdnWAF(a), a.Source)
	}
	return tw.Flush()
}

// cdnWAF 把 CDN/WAF 折叠成一列（两者不同厂商时用 + 连接），空则留空。
func cdnWAF(a model.Asset) string {
	switch {
	case a.CDN == "" && a.WAF == "":
		return ""
	case a.WAF == "" || a.WAF == a.CDN:
		return a.CDN
	case a.CDN == "":
		return a.WAF
	default:
		return a.CDN + "+" + a.WAF
	}
}

// WriteJSON 输出缩进 JSON。
func WriteJSON(w io.Writer, assets []model.Asset) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(assets)
}

// WriteJSONL 输出 JSON Lines。
func WriteJSONL(w io.Writer, assets []model.Asset) error {
	enc := json.NewEncoder(w)
	for _, a := range assets {
		if err := enc.Encode(a); err != nil {
			return err
		}
	}
	return nil
}

// WriteMarkdown 输出可直接交付给客户的 Markdown 报告。
func WriteMarkdown(w io.Writer, assets []model.Asset) error {
	tw := &errTrackingWriter{w: w}
	w = tw
	st := Compute(assets)
	fmt.Fprintln(w, "# 资产测绘与攻击面报告")
	fmt.Fprintln(w)
	fmt.Fprintf(w, "- 资产条目: %d\n", st.Total)
	fmt.Fprintf(w, "- 开放端口: %d\n", st.OpenPorts)
	fmt.Fprintf(w, "- Web 目标: %d\n", st.WebTargets)
	if st.ExpiredCerts > 0 {
		fmt.Fprintf(w, "- **证书已过期: %d**\n", st.ExpiredCerts)
	}
	fmt.Fprintln(w)
	if len(st.ByService) > 0 {
		fmt.Fprintf(w, "服务分布: %s\n\n", topPairs(st.ByService, 12))
	}
	if len(st.ByCDN) > 0 {
		fmt.Fprintf(w, "CDN 分布: %s\n\n", topPairs(st.ByCDN, 8))
	}
	if len(st.ByParam) > 0 {
		fmt.Fprintf(w, "参数清单（M4 注入类测试的输入面）: %s\n\n", topPairs(st.ByParam, 20))
	}
	if st.JSEndpoints > 0 || st.JSSecrets > 0 {
		fmt.Fprintf(w, "前端代码情报: JS 接口 %d 个，疑似硬编码凭据 %d 处（已掩码，详见 JSONL 的 `js.*` 字段）\n\n",
			st.JSEndpoints, st.JSSecrets)
	}
	fmt.Fprintln(w, "## 资产清单")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "| 主机 | 端口 | 服务 | 产品 | 版本 | 置信度 | 标题 | CDN/WAF | 状态码 | 来源 |")
	fmt.Fprintln(w, "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |")
	for _, a := range assets {
		port := ""
		if a.Port > 0 {
			port = fmt.Sprintf("%d", a.Port)
		}
		status := ""
		if a.StatusCode > 0 {
			status = fmt.Sprintf("%d", a.StatusCode)
		}
		fmt.Fprintf(w, "| %s | %s | %s | %s | %s | %s | %s | %s | %s | %s |\n",
			escape(a.Host), port, escape(a.Service), escape(a.Product), escape(a.Version),
			escape(a.Confidence), escape(a.Title), escape(cdnWAF(a)), status, escape(a.Source))
	}
	fmt.Fprintln(w)

	// CDN/WAF 提示：边缘 IP 不代表源站，这直接影响后续测试策略
	seen := map[string]bool{}
	var behind []string
	for _, a := range assets {
		if a.BehindCDN && a.OriginNote != "" && !seen[a.Host] {
			seen[a.Host] = true
			behind = append(behind, fmt.Sprintf("- `%s`：%s", a.Host, a.OriginNote))
		}
	}
	if len(behind) > 0 {
		fmt.Fprintln(w, "## CDN / WAF 提示")
		fmt.Fprintln(w)
		for _, line := range behind {
			fmt.Fprintln(w, line)
		}
		fmt.Fprintln(w)
	}

	fmt.Fprintln(w, "> 本报告由 westy_scan 在授权范围内自动生成，仅用于委托方资产的安全评估。")
	if tw.err != nil {
		return fmt.Errorf("写入 Markdown 报告失败: %w", tw.err)
	}
	return nil
}

func escape(s string) string {
	s = strings.ReplaceAll(s, "|", "\\|")
	s = strings.ReplaceAll(s, "\n", " ")
	return truncate(s, 120)
}

// truncate 按字节预算截断，但保证不切坏多字节字符。
// 报告是交付物：切出半个汉字（中文标题/中文 banner 极常见）比截短严重得多。
func truncate(s string, max int) string {
	return textutil.Truncate(s, max)
}
