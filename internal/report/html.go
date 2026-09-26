package report

import (
	"fmt"
	"html"
	"io"
	"sort"
	"strings"
	"time"

	"westy_scan/internal/model"
	"westy_scan/internal/poc"
)

// HTMLMeta 是 HTML 报告的头部信息。
type HTMLMeta struct {
	Title         string
	ScanID        string
	Authorization string // 授权书编号（合规留痕）
	Operator      string
	GeneratedAt   time.Time
	Note          string
}

// WriteHTML 输出**自包含** HTML 报告：内联 CSS、无外部资源，
// 可直接浏览器打开或"打印为 PDF"（真正生成 PDF 需要第三方库，本项目刻意不引入）。
func WriteHTML(w io.Writer, assets []model.Asset, findings []poc.Finding, meta HTMLMeta) error {
	tw := &errTrackingWriter{w: w}
	w = tw
	if meta.GeneratedAt.IsZero() {
		meta.GeneratedAt = time.Now()
	}
	if meta.Title == "" {
		meta.Title = "资产测绘与漏洞验证报告"
	}
	st := Compute(assets)
	fmt.Fprintf(w, `<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>%s</title>
<style>
:root{--bg:#0f1115;--card:#171a21;--fg:#e6e6e6;--muted:#9aa4b2;--line:#2a2f3a;--ok:#3fb950;--warn:#d29922;--crit:#f85149}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.6 -apple-system,Segoe UI,Roboto,"Helvetica Neue",Arial,"PingFang SC","Microsoft YaHei",sans-serif}
.wrap{max-width:1200px;margin:0 auto;padding:24px}
h1{font-size:22px;margin:0 0 4px}
h2{font-size:17px;margin:28px 0 10px;padding-bottom:6px;border-bottom:1px solid var(--line)}
.meta{color:var(--muted);font-size:13px;margin-bottom:18px}
.cards{display:flex;flex-wrap:wrap;gap:12px;margin:16px 0}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:12px 16px;min-width:120px}
.card .n{font-size:22px;font-weight:600}
.card .k{color:var(--muted);font-size:12px}
table{width:100%%;border-collapse:collapse;margin:8px 0 20px;font-size:13px}
th,td{border:1px solid var(--line);padding:6px 8px;text-align:left;vertical-align:top}
th{background:#1d2129;color:var(--muted);font-weight:600}
tr:nth-child(even) td{background:#141820}
.sev{padding:1px 8px;border-radius:999px;font-size:12px;font-weight:600}
.critical{background:var(--crit);color:#fff}
.high{background:#b62324;color:#fff}
.medium{background:var(--warn);color:#1a1a1a}
.low{background:#2d6a8a;color:#fff}
.info{background:#39414d;color:#fff}
details{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:10px 12px;margin:8px 0}
summary{cursor:pointer;font-weight:600}
pre{background:#0b0d11;border:1px solid var(--line);border-radius:6px;padding:10px;overflow:auto;font-size:12px}
code{font-family:ui-monospace,SFMono-Regular,Consolas,monospace}
.muted{color:var(--muted)}
.note{margin-top:28px;color:var(--muted);font-size:12px}
</style></head><body><div class="wrap">
`, html.EscapeString(meta.Title))

	fmt.Fprintf(w, "<h1>%s</h1>\n", html.EscapeString(meta.Title))
	fmt.Fprintf(w, `<div class="meta">生成时间 %s`, html.EscapeString(meta.GeneratedAt.Format("2006-01-02 15:04:05")))
	if meta.ScanID != "" {
		fmt.Fprintf(w, " ｜ 扫描 ID <code>%s</code>", html.EscapeString(meta.ScanID))
	}
	if meta.Authorization != "" {
		fmt.Fprintf(w, " ｜ 授权书 <code>%s</code>", html.EscapeString(meta.Authorization))
	}
	if meta.Operator != "" {
		fmt.Fprintf(w, " ｜ 操作人 %s", html.EscapeString(meta.Operator))
	}
	fmt.Fprint(w, "</div>\n")

	// 概览卡片
	crit, high := 0, 0
	for _, f := range findings {
		switch strings.ToLower(f.Severity) {
		case poc.SeverityCritical:
			crit++
		case poc.SeverityHigh:
			high++
		}
	}
	fmt.Fprint(w, `<div class="cards">`)
	card := func(n any, k string) {
		fmt.Fprintf(w, `<div class="card"><div class="n">%v</div><div class="k">%s</div></div>`, n, html.EscapeString(k))
	}
	card(st.Total, "资产条目")
	card(st.OpenPorts, "开放端口")
	card(st.WebTargets, "Web 目标")
	card(len(findings), "漏洞条目")
	card(crit, "严重")
	card(high, "高危")
	if st.BehindCDN > 0 {
		card(st.BehindCDN, "经 CDN/WAF")
	}
	if st.ExpiredCerts > 0 {
		card(st.ExpiredCerts, "过期证书")
	}
	fmt.Fprint(w, "</div>\n")

	if len(st.ByService) > 0 {
		fmt.Fprintf(w, "<p class=\"muted\">服务分布: %s</p>\n", html.EscapeString(topPairs(st.ByService, 12)))
	}
	if len(st.ByParam) > 0 {
		fmt.Fprintf(w, "<p class=\"muted\">参数清单: %s</p>\n", html.EscapeString(topPairs(st.ByParam, 20)))
	}

	// 漏洞清单
	fmt.Fprintln(w, "<h2>漏洞验证结果</h2>")
	if len(findings) == 0 {
		fmt.Fprintln(w, `<p class="muted">未发现漏洞（模板均为只读检查，且默认开启二次确认）。</p>`)
	} else {
		fmt.Fprintln(w, "<table><tr><th>级别</th><th>模板</th><th>名称</th><th>命中地址</th><th>置信度</th><th>已确认</th><th>提取信息</th></tr>")
		for _, f := range findings {
			fmt.Fprintf(w, "<tr><td><span class=\"sev %s\">%s</span></td><td><code>%s</code></td><td>%s</td><td>%s</td><td>%s</td><td>%v</td><td>%s</td></tr>\n",
				html.EscapeString(strings.ToLower(f.Severity)), html.EscapeString(strings.ToUpper(f.Severity)),
				html.EscapeString(f.TemplateID), html.EscapeString(f.Name), html.EscapeString(f.MatchedAt),
				html.EscapeString(f.Confidence), f.Verified, html.EscapeString(joinExtracted(f)))
		}
		fmt.Fprintln(w, "</table>")

		fmt.Fprintln(w, "<h2>证据（可复现）</h2>")
		for _, f := range findings {
			fmt.Fprintf(w, `<details><summary><span class="sev %s">%s</span> %s — <code>%s</code></summary>`,
				html.EscapeString(strings.ToLower(f.Severity)), html.EscapeString(strings.ToUpper(f.Severity)),
				html.EscapeString(f.Name), html.EscapeString(f.MatchedAt))
			fmt.Fprintf(w, "<p class=\"muted\">匹配依据: %s</p>", html.EscapeString(f.Evidence.Matcher))
			fmt.Fprintf(w, "<pre>%s</pre>", html.EscapeString(f.Evidence.Request))
			fmt.Fprintf(w, "<pre>%s</pre>", html.EscapeString(f.Evidence.Response))
			fmt.Fprintln(w, "</details>")
		}
	}

	// 资产清单
	fmt.Fprintln(w, "<h2>资产清单</h2>")
	fmt.Fprintln(w, "<table><tr><th>主机</th><th>端口</th><th>服务</th><th>产品</th><th>版本</th><th>置信度</th><th>标题</th><th>CDN/WAF</th><th>状态码</th><th>来源</th></tr>")
	for _, a := range assets {
		fmt.Fprintf(w, "<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>\n",
			html.EscapeString(a.Host), portText(a.Port), html.EscapeString(a.Service), html.EscapeString(a.Product),
			html.EscapeString(a.Version), html.EscapeString(a.Confidence), html.EscapeString(truncate(a.Title, 80)),
			html.EscapeString(cdnWAF(a)), statusText(a.StatusCode), html.EscapeString(a.Source))
	}
	fmt.Fprintln(w, "</table>")

	// CDN/WAF 提示
	var hints []string
	seen := map[string]bool{}
	for _, a := range assets {
		if a.BehindCDN && a.OriginNote != "" && !seen[a.Host] {
			seen[a.Host] = true
			hints = append(hints, a.Host+"："+a.OriginNote)
		}
	}
	if len(hints) > 0 {
		sort.Strings(hints)
		fmt.Fprintln(w, "<h2>CDN / WAF 提示</h2><ul>")
		for _, h := range hints {
			fmt.Fprintf(w, "<li>%s</li>\n", html.EscapeString(h))
		}
		fmt.Fprintln(w, "</ul>")
	}

	note := meta.Note
	if note == "" {
		note = "本报告由 westy_scan 在授权范围内自动生成，仅用于委托方资产的安全评估。"
	}
	fmt.Fprintf(w, `<p class="note">%s</p>
</div></body></html>
`, html.EscapeString(note))
	if tw.err != nil {
		return fmt.Errorf("写入 HTML 报告失败: %w", tw.err)
	}
	return nil
}

func portText(p int) string {
	if p <= 0 {
		return ""
	}
	return fmt.Sprintf("%d", p)
}

func statusText(s int) string {
	if s <= 0 {
		return ""
	}
	return fmt.Sprintf("%d", s)
}
