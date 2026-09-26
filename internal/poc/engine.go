package poc

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"westy_scan/internal/ratelimit"
)

// Options 是引擎参数。
type Options struct {
	Timeout        time.Duration
	Concurrency    int
	Limiter        *ratelimit.Limiter
	UserAgent      string
	Verify         bool // 二次确认：同一请求重放一次，两次都命中才算成立
	AllowIntrusive bool
	OOB            *OOB
	MaxRespBytes   int64
	OnFinding      func(Finding)
	Logf           func(format string, args ...any)
}

func (o Options) withDefaults() Options {
	if o.Timeout <= 0 {
		o.Timeout = 8 * time.Second
	}
	if o.Concurrency <= 0 {
		o.Concurrency = 4
	}
	if o.UserAgent == "" {
		o.UserAgent = "Mozilla/5.0 (compatible; westy-scan/0.1; authorized-testing)"
	}
	if o.MaxRespBytes <= 0 {
		o.MaxRespBytes = 1 << 20
	}
	return o
}

// Engine 执行模板。
type Engine struct {
	templates []*Template
	opt       Options
	client    *http.Client

	mu       sync.Mutex
	hostLock map[string]*sync.Mutex // 同主机串行化：避免并发把业务打崩
}

// NewEngine 构造引擎。
func NewEngine(templates []*Template, opt Options) *Engine {
	opt = opt.withDefaults()
	transport := &http.Transport{
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // 授权测试需接受自签名证书
		DialContext:           (&net.Dialer{Timeout: opt.Timeout}).DialContext,
		MaxIdleConns:          64,
		MaxIdleConnsPerHost:   2,
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   opt.Timeout,
		ExpectContinueTimeout: time.Second,
	}
	return &Engine{
		templates: templates,
		opt:       opt,
		hostLock:  make(map[string]*sync.Mutex),
		client: &http.Client{
			Transport: transport,
			Timeout:   opt.Timeout,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse // 默认不跟随跳转：跳转后的页面往往是"没漏洞"的假象
			},
		},
	}
}

// Templates 返回已加载模板。
func (e *Engine) Templates() []*Template { return e.templates }

func (e *Engine) logf(format string, args ...any) {
	if e.opt.Logf != nil {
		e.opt.Logf(format, args...)
	}
}

func (e *Engine) lockFor(host string) *sync.Mutex {
	e.mu.Lock()
	defer e.mu.Unlock()
	l, ok := e.hostLock[host]
	if !ok {
		l = &sync.Mutex{}
		e.hostLock[host] = l
	}
	return l
}

// ScanTargets 并发扫描多个目标，同主机内部串行。
func (e *Engine) ScanTargets(ctx context.Context, targets []Target) []Finding {
	sem := make(chan struct{}, e.opt.Concurrency)
	var wg sync.WaitGroup
	var mu sync.Mutex
	var findings []Finding

	for _, t := range targets {
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(t Target) {
			defer wg.Done()
			defer func() { <-sem }()
			for _, f := range e.ScanOne(ctx, t) {
				mu.Lock()
				findings = append(findings, f)
				mu.Unlock()
			}
		}(t)
	}
	wg.Wait()
	return findings
}

// ScanOne 用全部模板扫描单个目标。
func (e *Engine) ScanOne(ctx context.Context, t Target) []Finding {
	lock := e.lockFor(t.Host)
	lock.Lock()
	defer lock.Unlock()

	var out []Finding
	for _, tpl := range e.templates {
		if ctx.Err() != nil {
			break
		}
		if tpl.Intrusive && !e.opt.AllowIntrusive {
			e.logf("跳过侵入性模板 %s（需要 -allow-intrusive）", tpl.ID)
			continue
		}
		if f := e.runTemplate(ctx, tpl, t); f != nil {
			out = append(out, *f)
			if e.opt.OnFinding != nil {
				e.opt.OnFinding(*f)
			}
		}
	}
	return out
}

// runTemplate 执行一个模板；返回 nil 表示未命中。
func (e *Engine) runTemplate(ctx context.Context, tpl *Template, t Target) *Finding {
	condition := strings.ToLower(strings.TrimSpace(tpl.MatchersCondition))
	if condition == "" {
		condition = "or" // 与 nuclei 一致：多请求默认任一命中
	}

	var matched []*Finding
	for i := range tpl.HTTP {
		if ctx.Err() != nil {
			return nil
		}
		f := e.runRequest(ctx, tpl, &tpl.HTTP[i], t)
		if f == nil {
			if condition == "and" {
				return nil // and 语义下只要有一个请求没命中就整体不成立
			}
			continue
		}
		matched = append(matched, f)
		if condition == "or" {
			break
		}
	}
	if len(matched) == 0 {
		return nil
	}

	// and 语义：把多个请求的提取结果合并到第一条证据上
	base := matched[0]
	if len(matched) > 1 {
		for _, f := range matched[1:] {
			for k, vals := range f.Extracted {
				base.Extracted[k] = append(base.Extracted[k], vals...)
			}
			base.Evidence.Matcher += " ; " + f.Evidence.Matcher
		}
	}
	return base
}

// runRequest 执行单个请求（含多 path 备选与二次确认）。
func (e *Engine) runRequest(ctx context.Context, tpl *Template, req *HTTPRequest, t Target) *Finding {
	for _, rawPath := range req.Path {
		if ctx.Err() != nil {
			return nil
		}
		vars := e.baseVars(t)

		// OOB：模板用到外带地址时登记一次性 token
		token := ""
		if e.opt.OOB != nil && usesOOB(tpl) {
			token = e.opt.OOB.NewToken(t.Host, tpl.ID)
			vars["oob"] = token
			vars["oob_host"] = e.opt.OOB.Host()
			vars["oob_url"] = e.opt.OOB.URL(token)
		}

		target := Render(rawPath, vars)
		if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
			// 允许模板写相对路径（nuclei 里也常见）
			target = strings.TrimRight(t.BaseURL(), "/") + "/" + strings.TrimLeft(target, "/")
		}

		resp, reqDump, err := e.do(ctx, req, target, vars)
		if err != nil {
			e.logf("模板 %s 请求 %s 失败: %v", tpl.ID, target, err)
			continue
		}
		mr := EvaluateMatchers(req.Matchers, req.MatchersCondition, resp, vars)
		if !mr.Hit {
			continue
		}

		verified := false
		if e.opt.Verify {
			// 二次确认：同一请求原样重放，两次都命中才算成立（压制偶发误报）
			vars2 := e.baseVars(t)
			if token != "" {
				vars2["oob"] = token
				vars2["oob_host"] = e.opt.OOB.Host()
				vars2["oob_url"] = e.opt.OOB.URL(token)
			}
			resp2, _, err2 := e.do(ctx, req, target, vars2)
			if err2 == nil {
				mr2 := EvaluateMatchers(req.Matchers, req.MatchersCondition, resp2, vars2)
				if mr2.Hit {
					verified = true
				} else {
					e.logf("模板 %s 在 %s 上首次命中但二次确认失败，已丢弃（避免误报）", tpl.ID, target)
					continue
				}
			}
		}

		// 外带验证：等待回调
		oobHit := (*OOBCallback)(nil)
		if token != "" && e.opt.OOB != nil {
			oobHit = e.opt.OOB.Wait(ctx, token, e.opt.Timeout)
			if oobHit != nil {
				verified = true
			}
		}

		f := &Finding{
			TemplateID:  tpl.ID,
			Name:        tpl.Info.Name,
			Severity:    defaultSeverity(tpl.Info.Severity),
			Tags:        tpl.Info.Tags,
			Target:      t.BaseURL(),
			MatchedAt:   target,
			Confidence:  defaultConfidence(tpl.Info.Confidence),
			Verified:    verified,
			Intrusive:   tpl.Intrusive,
			Extracted:   ExtractAll(req.Extractors, resp, vars),
			Description: tpl.Info.Description,
			Reference:   tpl.Info.Reference,
			FoundAt:     time.Now(),
			Evidence: Evidence{
				Request:  reqDump,
				Response: dumpResponse(resp),
				Matcher:  mr.Why,
			},
		}
		if oobHit != nil {
			f.Evidence.Matcher += fmt.Sprintf(" | OOB 回连来自 %s（%s %s）", oobHit.RemoteAddr, oobHit.Method, oobHit.Path)
		}
		return f
	}
	return nil
}

// do 发一次请求并返回响应快照与请求证据。
func (e *Engine) do(ctx context.Context, req *HTTPRequest, target string, vars Vars) (*Response, string, error) {
	if err := e.opt.Limiter.Wait(ctx); err != nil {
		return nil, "", err
	}
	method := strings.ToUpper(strings.TrimSpace(req.Method))
	if method == "" {
		method = http.MethodGet
	}
	var bodyReader io.Reader
	bodyText := ""
	if req.Body != "" {
		bodyText = Render(req.Body, vars)
		bodyReader = strings.NewReader(bodyText)
	}
	httpReq, err := http.NewRequestWithContext(ctx, method, target, bodyReader)
	if err != nil {
		return nil, "", err
	}
	httpReq.Header.Set("User-Agent", e.opt.UserAgent)
	httpReq.Header.Set("Accept", "*/*")
	httpReq.Header.Set("Connection", "close")
	for k, v := range req.Headers {
		httpReq.Header.Set(k, Render(v, vars))
	}

	client := e.client
	if req.Redirects {
		max := req.MaxRedirects
		if max <= 0 {
			max = 3
		}
		c2 := *e.client
		c2.CheckRedirect = func(r *http.Request, via []*http.Request) error {
			if len(via) >= max {
				return http.ErrUseLastResponse
			}
			return nil
		}
		client = &c2
	}

	start := time.Now()
	resp, err := client.Do(httpReq)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, e.opt.MaxRespBytes))
	elapsed := time.Since(start)

	snapshot := &Response{
		URL:      target,
		Status:   resp.StatusCode,
		Headers:  resp.Header,
		Body:     body,
		Title:    extractTitle(body),
		Duration: elapsed,
	}
	return snapshot, dumpRequest(method, target, httpReq.Header, bodyText), nil
}

func (e *Engine) baseVars(t Target) Vars {
	path := t.Path
	if path == "" {
		path = "/"
	}
	return Vars{
		"BaseURL":   t.BaseURL(),
		"RootURL":   t.RootURL(),
		"Hostname":  t.Host,
		"Host":      t.Host,
		"Port":      itoa(t.Port),
		"Scheme":    t.Scheme,
		"Path":      path,
		"IP":        t.IP,
		"File":      lastPathSegment(path),
		"randstr":   RandStr(12),
		"randstr_1": RandStr(12),
		"randstr_2": RandStr(12),
		"randstr_3": RandStr(12),
	}
}

func lastPathSegment(p string) string {
	p = strings.TrimRight(p, "/")
	if i := strings.LastIndex(p, "/"); i >= 0 {
		return p[i+1:]
	}
	return p
}

func defaultSeverity(s string) string {
	if strings.TrimSpace(s) == "" {
		return SeverityInfo
	}
	return strings.ToLower(strings.TrimSpace(s))
}

func defaultConfidence(c string) string {
	if strings.TrimSpace(c) == "" {
		return "medium"
	}
	return strings.ToLower(strings.TrimSpace(c))
}

func usesOOB(tpl *Template) bool {
	for _, r := range tpl.HTTP {
		for _, p := range r.Path {
			if strings.Contains(p, "{{oob") {
				return true
			}
		}
		if strings.Contains(r.Body, "{{oob") {
			return true
		}
		for _, v := range r.Headers {
			if strings.Contains(v, "{{oob") {
				return true
			}
		}
	}
	return false
}

var rePOCTitle = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)

func extractTitle(body []byte) string {
	m := rePOCTitle.FindSubmatch(body)
	if len(m) != 2 {
		return ""
	}
	return strings.Join(strings.Fields(string(m[1])), " ")
}

// ---------------- 证据留存（可复现是漏洞报告的生命线） ----------------

const evidenceMaxBody = 800

func dumpRequest(method, target string, headers http.Header, body string) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "%s %s\n", method, target)
	for _, k := range []string{"User-Agent", "Accept", "Origin", "Content-Type", "Cookie", "Authorization"} {
		if v := headers.Get(k); v != "" {
			fmt.Fprintf(&sb, "%s: %s\n", k, v)
		}
	}
	if body != "" {
		sb.WriteString("\n")
		sb.WriteString(truncateEvidence(body))
	}
	return maskEvidence(sb.String())
}

func dumpResponse(r *Response) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "HTTP %d（%s）\n", r.Status, r.Duration.Round(time.Millisecond))
	for _, k := range []string{"Content-Type", "Server", "Location", "Access-Control-Allow-Origin", "Access-Control-Allow-Credentials"} {
		if v := r.Headers.Get(k); v != "" {
			fmt.Fprintf(&sb, "%s: %s\n", k, v)
		}
	}
	if len(r.Body) > 0 {
		sb.WriteString("\n")
		sb.WriteString(truncateEvidence(string(r.Body)))
	}
	return maskEvidence(sb.String())
}

func truncateEvidence(s string) string {
	if len(s) <= evidenceMaxBody {
		return s
	}
	return s[:evidenceMaxBody] + "…（已截断）"
}

// 证据里出现的疑似凭据必须掩码：报告会流转、归档，不该携带可直接使用的口令。
//
// 两个容易踩的点：
//  1. key 用 \b 边界会漏掉 DB_PASSWORD 这类下划线前缀（_ 属于单词字符），因此不锚定词首；
//  2. Bearer 必须**先**替换，否则 Authorization 的值先被掩码成 *** 后就找不到 bearer 关键字了。
var (
	reBearer    = regexp.MustCompile(`(?i)(bearer\s+)([A-Za-z0-9\-_.=]{8,})`)
	reSecretKV  = regexp.MustCompile(`(?i)(password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|authorization)(\s*[:=]\s*)([^\s"'&;]{6,})`)
	reAKIA      = regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`)
	reJWTInline = regexp.MustCompile(`\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\b`)
)

func maskEvidence(s string) string {
	s = reJWTInline.ReplaceAllString(s, "eyJ***.***.***")
	s = reBearer.ReplaceAllString(s, "$1***")
	s = reSecretKV.ReplaceAllString(s, "$1$2***")
	s = reAKIA.ReplaceAllString(s, "AKIA****************")
	return s
}

// TargetFromURL 从 Web 资产派生验证目标。
func TargetFromURL(raw, ip string) (Target, bool) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" {
		return Target{}, false
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return Target{}, false
	}
	port := 0
	if p := u.Port(); p != "" {
		port, _ = strconv.Atoi(p)
	}
	if port == 0 {
		if u.Scheme == "https" {
			port = 443
		} else {
			port = 80
		}
	}
	path := u.Path
	if path == "" {
		path = "/"
	}
	return Target{
		Input:  raw,
		Scheme: u.Scheme,
		Host:   u.Hostname(),
		Port:   port,
		IP:     ip,
		Path:   path,
	}, true
}

// DedupFindings 按 (模板, 命中地址) 去重，保留先出现的。
func DedupFindings(in []Finding) []Finding {
	seen := map[string]bool{}
	var out []Finding
	for _, f := range in {
		key := f.TemplateID + "|" + f.MatchedAt
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, f)
	}
	return out
}

// FindingsBySeverity 按严重级别从高到低排序（报告可读性）。
func FindingsBySeverity(in []Finding) []Finding {
	out := append([]Finding(nil), in...)
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && severityRank(out[j].Severity) > severityRank(out[j-1].Severity); j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}
