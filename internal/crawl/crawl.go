// Package crawl 实现一个轻量 Web 爬虫（BFS + 并发抓取）。
//
// 它只做三件事：发现 URL、抓取页面、抽出更多 URL 与端点。
// 不做 JS 渲染（那是后续接 headless 浏览器插件的活），
// 但会带上 Cookie Jar，保证登录态下的目录结构也能被爬到。
package crawl

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"westy_scan/internal/model"
	"westy_scan/internal/ratelimit"
	"westy_scan/internal/scope"
	"westy_scan/internal/simhash"
	"westy_scan/internal/textutil"
)

var (
	reLink  = regexp.MustCompile(`(?is)(?:href|src|action|data-url)\s*=\s*["']([^"'>\s]+)["']`)
	reTitle = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)
	reForm  = regexp.MustCompile(`(?is)<form[^>]*action\s*=\s*["']([^"']*)["']`)
	reSpace = regexp.MustCompile(`\s+`)
	// M3：内联脚本内容（属性里带 src 的标签内容为空，天然被跳过）
	reInlineScript = regexp.MustCompile(`(?is)<script(?:\s[^>]*)?>(.*?)</script>`)
)

var staticExt = map[string]bool{
	".png": true, ".jpg": true, ".jpeg": true, ".gif": true, ".svg": true, ".ico": true,
	".css": true, ".woff": true, ".woff2": true, ".ttf": true, ".eot": true, ".map": true,
	".mp4": true, ".mp3": true, ".avi": true, ".zip": true, ".rar": true, ".7z": true,
	".gz": true, ".tar": true, ".pdf": true, ".doc": true, ".docx": true, ".xls": true,
}

// Options 是爬虫参数。
type Options struct {
	MaxDepth     int
	MaxPages     int
	Concurrency  int
	Timeout      time.Duration
	UserAgent    string
	SameHost     bool // 只爬同一主机（默认 true，跨站爬取需显式开启）
	IncludeAsset bool // 是否把静态资源也作为资产输出
	Limiter      *ratelimit.Limiter
	Scope        *scope.Scope

	// M3：爬虫强化
	DisableJS    bool  // 关闭 JS 抽取（默认开启：内联 JS 零成本，外链 JS 受 MaxJSFiles 限制）
	MaxJSFiles   int   // 单次爬取最多分析多少个外链 JS 文件
	MaxBodyBytes int64 // 单个响应最多读多少字节
	DuplicateGap int   // SimHash 汉明距离阈值，≤ 该值视为近似重复（0 用默认值 3）
}

func (o Options) withDefaults() Options {
	if o.MaxDepth <= 0 {
		o.MaxDepth = 2
	}
	if o.MaxPages <= 0 {
		o.MaxPages = 500
	}
	if o.Concurrency <= 0 {
		o.Concurrency = 10
	}
	if o.Timeout <= 0 {
		o.Timeout = 8 * time.Second
	}
	if o.UserAgent == "" {
		o.UserAgent = "Mozilla/5.0 (compatible; westy-scan/0.1; authorized-testing)"
	}
	if o.MaxJSFiles <= 0 {
		o.MaxJSFiles = 50
	}
	if o.MaxBodyBytes <= 0 {
		o.MaxBodyBytes = 1 << 20
	}
	if o.DuplicateGap <= 0 {
		o.DuplicateGap = 3
	}
	return o
}

// Page 是一页的抓取结果。
type Page struct {
	Asset   model.Asset
	Headers http.Header
	Body    []byte
}

// Crawler 是爬虫本体。
type Crawler struct {
	opt     Options
	client  *http.Client
	jsCount int64 // 已分析的外链 JS 数量（受 MaxJSFiles 限制）
}

// New 构造爬虫。
func New(opt Options) *Crawler {
	opt = opt.withDefaults()
	jar, _ := cookiejar.New(nil)
	transport := &http.Transport{
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // 授权测试场景
		DialContext:         (&net.Dialer{Timeout: opt.Timeout}).DialContext,
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 4,
		IdleConnTimeout:     30 * time.Second,
	}
	return &Crawler{
		opt: opt,
		client: &http.Client{
			Transport: transport,
			Jar:       jar,
			Timeout:   opt.Timeout,
		},
	}
}

type item struct {
	url   string
	depth int
}

// Run 从 seeds 出发做 BFS 爬取，结果按发现顺序流出。
func (c *Crawler) Run(ctx context.Context, seeds []string) <-chan Page {
	out := make(chan Page, 64)

	go func() {
		defer close(out)

		visited := make(map[string]bool)
		hosts := make(map[string]bool)
		var queue []item

		// M3：近似重复页面检测（同一模板的页面太多会把报告淹没）
		type seenPage struct {
			hash uint64
			url  string
		}
		var seenPages []seenPage

		for _, s := range seeds {
			u, err := normalizeURL(s)
			if err != nil || visited[u] {
				continue
			}
			visited[u] = true
			if h, err := url.Parse(u); err == nil {
				hosts[h.Hostname()] = true
			}
			queue = append(queue, item{url: u, depth: 0})
		}

		var pages int64
		for len(queue) > 0 {
			if ctx.Err() != nil {
				return
			}
			batch := queue
			queue = nil

			var mu sync.Mutex
			var wg sync.WaitGroup
			sem := make(chan struct{}, c.opt.Concurrency)

			for _, it := range batch {
				if ctx.Err() != nil {
					break
				}
				if atomic.LoadInt64(&pages) >= int64(c.opt.MaxPages) {
					break
				}
				wg.Add(1)
				sem <- struct{}{}
				go func(it item) {
					defer wg.Done()
					defer func() { <-sem }()

					page, links, err := c.fetch(ctx, it.url)
					if err != nil {
						return
					}
					atomic.AddInt64(&pages, 1)
					page.Asset.Depth = it.depth

					// 近似重复标记：只标注不丢弃（页面里的链接仍然有价值）
					if h, ok := parseSimhash(page.Asset.MetaValue("content.simhash")); ok {
						mu.Lock()
						for _, seen := range seenPages {
							if simhash.Distance(seen.hash, h) <= c.opt.DuplicateGap {
								page.Asset.SetMeta("duplicate_of", seen.url)
								break
							}
						}
						if len(seenPages) < 5000 {
							seenPages = append(seenPages, seenPage{hash: h, url: page.Asset.URL})
						}
						mu.Unlock()
					}

					select {
					case out <- page:
					case <-ctx.Done():
						return
					}
					if it.depth >= c.opt.MaxDepth {
						return
					}
					mu.Lock()
					defer mu.Unlock()
					for _, l := range links {
						if visited[l] {
							continue
						}
						parsed, err := url.Parse(l)
						if err != nil {
							continue
						}
						if c.opt.SameHost && !hosts[parsed.Hostname()] {
							continue
						}
						if c.opt.Scope != nil {
							if _, ok, _ := c.opt.Scope.Check(parsed.Hostname()); !ok {
								continue
							}
						}
						visited[l] = true
						queue = append(queue, item{url: l, depth: it.depth + 1})
					}
				}(it)
			}
			wg.Wait()
		}
	}()

	return out
}

func (c *Crawler) fetch(ctx context.Context, raw string) (Page, []string, error) {
	if err := c.opt.Limiter.Wait(ctx); err != nil {
		return Page{}, nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, raw, nil)
	if err != nil {
		return Page{}, nil, err
	}
	req.Header.Set("User-Agent", c.opt.UserAgent)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")

	resp, err := c.client.Do(req)
	if err != nil {
		return Page{}, nil, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, c.opt.MaxBodyBytes))
	u, _ := url.Parse(raw)
	contentType := resp.Header.Get("Content-Type")
	asset := model.Asset{
		Host:       u.Hostname(),
		Port:       portOf(u),
		Scheme:     u.Scheme,
		URL:        raw,
		StatusCode: resp.StatusCode,
		Server:     resp.Header.Get("Server"),
		Source:     "crawl",
		FoundAt:    time.Now(),
	}

	// JS 文件：只做接口/凭据抽取，不做 HTML 解析
	if isJavaScriptURL(raw, contentType) {
		asset.Source = "crawl-js"
		asset.SetMeta("body_len", itoa(len(body)))
		if atomic.AddInt64(&c.jsCount, 1) > int64(c.opt.MaxJSFiles) {
			asset.SetMeta("js.skipped", "超过 JS 分析数量上限，未做抽取")
			return Page{Asset: asset, Body: body}, nil, nil
		}
		f := ExtractJS(string(body), raw)
		links := applyJSFinding(&asset, f, raw)
		return Page{Asset: asset, Body: body}, links, nil
	}

	if m := reTitle.FindSubmatch(body); len(m) == 2 {
		asset.Title = truncate(clean(string(m[1])), 200)
	}
	asset.SetMeta("body_len", itoa(len(body)))
	if contentType != "" {
		asset.SetMeta("content_type", truncate(clean(contentType), 120))
	}

	// M3：表单与参数 —— M4 注入类模板的输入面
	forms := ExtractForms(raw, body)
	if len(forms) > 0 {
		asset.Forms = forms
		asset.SetMeta("form.count", itoa(len(forms)))
		asset.SetMeta("form_action", truncate(forms[0].Action, 300)) // 兼容旧字段
	}
	if params := MergeParams(ExtractQueryParams(raw), FormFieldNames(forms)); len(params) > 0 {
		asset.Params = params
	}

	// M3：内容指纹（近似重复检测）
	if text := simhash.PlainText(body); text != "" {
		asset.SetMeta("content.simhash", strconv.FormatUint(simhash.Hash(text), 16))
		asset.SetMeta("content.text_len", itoa(len(text)))
	}

	links := c.extractLinks(raw, body)

	// M3：内联 JS 抽取（零额外请求）
	if !c.opt.DisableJS {
		if inline := collectInlineJS(body); inline != "" {
			f := ExtractJS(inline, raw)
			links = append(links, applyJSFinding(&asset, f, raw)...)
		}
	}
	return Page{Asset: asset, Headers: resp.Header, Body: body}, dedupStrings(links, 3000), nil
}

// applyJSFinding 把 JS 抽取结果写进资产，并返回可继续爬取的绝对地址。
func applyJSFinding(a *model.Asset, f JSFinding, base string) []string {
	var abs []string
	if len(f.Endpoints) > 0 {
		for _, e := range f.Endpoints {
			abs = append(abs, resolve(base, e))
		}
		abs = dedupStrings(abs, 200)
		a.SetMeta("js.endpoints", truncate(strings.Join(abs, ","), 1500))
		a.SetMeta("js.endpoint_count", itoa(len(abs)))
		a.AddEvidence("js:endpoints=" + itoa(len(abs)))
	}
	if len(f.Calls) > 0 {
		a.SetMeta("js.calls", truncate(strings.Join(dedupStrings(f.Calls, 50), ","), 800))
	}
	if len(f.Secrets) > 0 {
		a.SetMeta("js.secrets", truncate(strings.Join(f.Secrets, "; "), 800))
		a.SetMeta("js.secret_count", itoa(len(f.Secrets)))
		a.AddEvidence("js:secrets=" + itoa(len(f.Secrets)))
	}
	return abs
}

// collectInlineJS 收集页面内联脚本内容（零额外请求，因此默认开启）。
func collectInlineJS(body []byte) string {
	var sb strings.Builder
	for _, m := range reInlineScript.FindAllSubmatch(body, 50) {
		if len(m) == 2 && len(m[1]) > 0 {
			sb.Write(m[1])
			sb.WriteByte('\n')
			if sb.Len() > 256*1024 {
				break
			}
		}
	}
	return sb.String()
}

// isJavaScriptURL 判断目标是否需要按 JS 分析。
func isJavaScriptURL(raw, contentType string) bool {
	ct := strings.ToLower(contentType)
	if strings.Contains(ct, "javascript") || strings.Contains(ct, "ecmascript") {
		return true
	}
	return isJavaScriptPath(raw)
}

func isJavaScriptPath(raw string) bool {
	lower := strings.ToLower(raw)
	if i := strings.IndexAny(lower, "?#"); i >= 0 {
		lower = lower[:i]
	}
	return strings.HasSuffix(lower, ".js") || strings.HasSuffix(lower, ".mjs")
}

// parseSimhash 解析 meta 里的十六进制 SimHash。
func parseSimhash(v string) (uint64, bool) {
	if v == "" {
		return 0, false
	}
	h, err := strconv.ParseUint(v, 16, 64)
	if err != nil || h == 0 {
		return 0, false
	}
	return h, true
}

// extractLinks 抽出站内可爬链接与值得记录的端点。
func (c *Crawler) extractLinks(base string, body []byte) []string {
	seen := make(map[string]bool)
	var out []string
	for _, m := range reLink.FindAllSubmatch(body, 2000) {
		if len(m) != 2 {
			continue
		}
		raw := unescapeHTMLAttr(strings.TrimSpace(string(m[1])))
		if raw == "" || strings.HasPrefix(raw, "#") {
			continue
		}
		lower := strings.ToLower(raw)
		if strings.HasPrefix(lower, "javascript:") || strings.HasPrefix(lower, "mailto:") ||
			strings.HasPrefix(lower, "tel:") || strings.HasPrefix(lower, "data:") {
			continue
		}
		abs := resolve(base, raw)
		parsed, err := url.Parse(abs)
		if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") {
			continue
		}
		if !c.opt.IncludeAsset {
			switch {
			case isJavaScriptPath(parsed.Path):
				// JS 文件：只在开启 JS 抽取时抓（里面可能藏着接口与凭据）。
				// 注意 .js 不在静态资源表里，必须在这里显式处理，
				// 否则关闭 JS 抽取后仍会把 JS 当页面抓回来。
				if c.opt.DisableJS {
					continue
				}
			case isStatic(parsed.Path):
				continue
			}
		}
		parsed.Fragment = ""
		key := parsed.String()
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, key)
	}
	return out
}

func isStatic(path string) bool {
	p := strings.ToLower(path)
	idx := strings.LastIndex(p, ".")
	if idx < 0 {
		return false
	}
	return staticExt[p[idx:]]
}

// htmlAttrUnescaper 还原 href/action 里的常见 HTML 实体。
// 真实站点大量使用 `&amp;` 分隔查询参数，不还原就会爬成
// `/list?cat=1&amp;page=2` 这种错误 URL（参数名也会变成 `amp;page`）。
var htmlAttrUnescaper = strings.NewReplacer(
	"&amp;", "&", "&#38;", "&", "&#x26;", "&", "&#X26;", "&",
	"&quot;", `"`, "&#34;", `"`,
	"&#39;", "'", "&apos;", "'",
	"&lt;", "<", "&gt;", ">",
)

func unescapeHTMLAttr(s string) string {
	if !strings.Contains(s, "&") {
		return s
	}
	return htmlAttrUnescaper.Replace(s)
}

func normalizeURL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", errInvalid
	}
	if !strings.Contains(raw, "://") {
		raw = "http://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", err
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", errInvalid
	}
	u.Fragment = ""
	if u.Path == "" {
		u.Path = "/"
	}
	return u.String(), nil
}

func resolve(base, ref string) string {
	b, err := url.Parse(base)
	if err != nil {
		return ref
	}
	r, err := url.Parse(ref)
	if err != nil {
		return ref
	}
	return b.ResolveReference(r).String()
}

func portOf(u *url.URL) int {
	if u == nil {
		return 0
	}
	if p := u.Port(); p != "" {
		var port int
		for _, ch := range p {
			if ch < '0' || ch > '9' {
				return 0
			}
			port = port*10 + int(ch-'0')
		}
		return port
	}
	if u.Scheme == "https" {
		return 443
	}
	if u.Scheme == "http" {
		return 80
	}
	return 0
}

func clean(s string) string {
	return strings.TrimSpace(reSpace.ReplaceAllString(s, " "))
}

// truncate 按字节上限截断，保证不切坏多字节字符（中文标题/参数很常见）。
// 实现收口在 textutil，避免每个包各写一份切坏 UTF-8 的版本。
func truncate(s string, max int) string {
	return textutil.Truncate(s, max)
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

type crawlError string

func (e crawlError) Error() string { return string(e) }

const errInvalid = crawlError("非法的 URL")
