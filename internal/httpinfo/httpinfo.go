// Package httpinfo 负责 Web 层探测：存活、状态码、标题、关键响应头、证书信息。
//
// 它只产出"事实"，不做漏洞判定 —— 判定交给 fingerprint 规则引擎与后续的 POC 引擎。
package httpinfo

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
	"time"

	"westy_scan/internal/favhash"
	"westy_scan/internal/model"
	"westy_scan/internal/textutil"
)

var (
	reTitle    = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)
	reSpace    = regexp.MustCompile(`\s+`)
	reMetaName = regexp.MustCompile(`(?is)<meta[^>]+name=["']([^"']+)["'][^>]+content=["']([^"']*)["']`)
	// favicon 声明：<link rel="shortcut icon" href="/static/icon.png">
	// 注意整体要加捕获组，否则 FindSubmatch 拿不到标签内容
	reIconLink = regexp.MustCompile(`(?is)(<link[^>]+rel\s*=\s*["']?[^"'>]*icon[^>]*>)`)
	reHrefAttr = regexp.MustCompile(`(?is)href\s*=\s*["']([^"']+)["']`)
)

// Result 是单次探测的完整结果，Body/Headers 交给指纹引擎使用后即可丢弃。
type Result struct {
	Asset   model.Asset
	Headers http.Header
	Body    []byte
}

// Prober 是复用了连接池的 HTTP 探测器。
type Prober struct {
	Client     *http.Client
	MaxBody    int64
	MaxFavicon int64
	UserAgent  string
}

// New 构造探测器。TLS 证书校验刻意关闭：授权测试中自签名证书是常态，
// 而证书信息本身就是要收集的资产（见 Asset.TLS）。
func New(timeout time.Duration, userAgent string) *Prober {
	if timeout <= 0 {
		timeout = 8 * time.Second
	}
	if userAgent == "" {
		userAgent = "Mozilla/5.0 (compatible; westy-scan/0.1; authorized-testing)"
	}
	transport := &http.Transport{
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // 授权测试场景刻意为之
		DialContext:           (&net.Dialer{Timeout: timeout}).DialContext,
		MaxIdleConns:          200,
		MaxIdleConnsPerHost:   4,
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   timeout,
		ExpectContinueTimeout: time.Second,
		ForceAttemptHTTP2:     true,
	}
	return &Prober{
		Client: &http.Client{
			Transport: transport,
			Timeout:   timeout,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 5 {
					return http.ErrUseLastResponse
				}
				return nil
			},
		},
		MaxBody:   1 << 20, // 1MB
		UserAgent: userAgent,
	}
}

// BuildURL 根据主机、端口、协议拼出 URL，默认端口会省略。
func BuildURL(host string, port int, scheme string) string {
	if scheme == "" {
		scheme = GuessScheme(port)
	}
	if port <= 0 || (scheme == "http" && port == 80) || (scheme == "https" && port == 443) {
		return scheme + "://" + host
	}
	return scheme + "://" + net.JoinHostPort(host, strconv.Itoa(port))
}

// GuessScheme 依据端口猜协议。
func GuessScheme(port int) string {
	switch port {
	case 443, 4443, 8443, 9443, 10443:
		return "https"
	default:
		return "http"
	}
}

// Probe 对 host:port 发起一次 GET，返回完整结果。
func (p *Prober) Probe(ctx context.Context, host, ip string, port int, scheme string) (*Result, error) {
	url := BuildURL(host, port, scheme)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", p.UserAgent)
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Accept-Language", "zh-CN,zh;q=0.9,en;q=0.8")
	req.Header.Set("Connection", "close")

	resp, err := p.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, p.MaxBody))

	a := model.Asset{
		Host:       host,
		IP:         ip,
		Port:       port,
		Scheme:     scheme,
		URL:        url,
		StatusCode: resp.StatusCode,
		Server:     resp.Header.Get("Server"),
		Source:     "http",
		FoundAt:    time.Now(),
	}
	if m := reTitle.FindSubmatch(body); len(m) == 2 {
		a.Title = Truncate(CleanText(string(m[1])), 200)
	}
	for _, m := range reMetaName.FindAllSubmatch(body, 8) {
		if len(m) == 3 {
			name := strings.ToLower(strings.TrimSpace(string(m[1])))
			switch name {
			case "generator", "application-name", "description", "keywords":
				a.SetMeta("meta."+name, Truncate(CleanText(string(m[2])), 200))
			}
		}
	}
	for _, h := range []string{"X-Powered-By", "X-Generator", "X-Jenkins", "X-AspNet-Version", "WWW-Authenticate", "Location", "Set-Cookie", "Content-Type"} {
		if v := resp.Header.Get(h); v != "" {
			a.SetMeta("header."+strings.ToLower(h), Truncate(CleanText(v), 300))
		}
	}
	if resp.TLS != nil {
		a.TLS = TLSInfo(resp.TLS)
	}
	a.SetMeta("body_len", strconv.Itoa(len(body)))
	// 拿到结构化 HTTP 响应本身就是"该端口确实是 Web 服务"的实证
	a.RaiseConfidence(model.ConfidenceHigh)
	a.AddEvidence("http:status=" + strconv.Itoa(resp.StatusCode))

	// favicon 指纹：只在 HTML 页面上取，避免对每个静态资源都发额外请求。
	// favicon 是社区通行的资产关联手段（Shodan/FOFA/hunter），也是弱识别场景
	// 下少数能跨域名串联同一套系统的线索。
	if IsHTMLLike(resp.Header.Get("Content-Type"), body) {
		if fav, favURL := p.fetchFavicon(ctx, url, body); len(fav) > 0 {
			a.FaviconHash = favhash.ShodanHash(fav)
			a.SetMeta("favicon.url", favURL)
			a.SetMeta("favicon.mmh3", strconv.FormatInt(int64(a.FaviconHash), 10))
			a.SetMeta("favicon.mmh3_raw", strconv.FormatInt(int64(favhash.RawHash(fav)), 10))
			a.SetMeta("favicon.size", strconv.Itoa(len(fav)))
			a.AddEvidence("favicon:mmh3=" + strconv.FormatInt(int64(a.FaviconHash), 10))
		}
	}

	return &Result{Asset: a, Headers: resp.Header, Body: body}, nil
}

// IsHTMLLike 判断响应是不是 HTML（决定要不要去取 favicon）。
func IsHTMLLike(contentType string, body []byte) bool {
	if strings.Contains(strings.ToLower(contentType), "html") {
		return true
	}
	head := strings.ToLower(strings.TrimSpace(string(TruncateBytes(body, 256))))
	return strings.HasPrefix(head, "<!doctype html") || strings.HasPrefix(head, "<html")
}

// fetchFavicon 取 favicon：优先 HTML 里声明的 <link rel="icon">，否则回落到 /favicon.ico。
// 返回内容与来源 URL；取不到返回 nil。
func (p *Prober) fetchFavicon(ctx context.Context, pageURL string, body []byte) ([]byte, string) {
	base, err := url.Parse(pageURL)
	if err != nil {
		return nil, ""
	}
	var candidates []string
	if tag := reIconLink.FindSubmatch(body); len(tag) == 2 {
		if href := reHrefAttr.FindSubmatch(tag[1]); len(href) == 2 {
			if u, err := base.Parse(strings.TrimSpace(string(href[1]))); err == nil {
				candidates = append(candidates, u.String())
			}
		}
	}
	root := *base
	root.Path = "/favicon.ico"
	root.RawQuery = ""
	root.Fragment = ""
	candidates = append(candidates, root.String())

	for _, u := range candidates {
		if ctx.Err() != nil {
			return nil, ""
		}
		data, err := p.getBody(ctx, u)
		if err != nil || len(data) == 0 {
			continue
		}
		// 不少站点对 /favicon.ico 返回 200 + 一张 HTML 404 页面，必须排除
		if IsHTMLLike("", data) {
			continue
		}
		return data, u
	}
	return nil, ""
}

// getBody 取一个小体积资源（favicon），只接受 200。
func (p *Prober) getBody(ctx context.Context, u string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", p.UserAgent)
	req.Header.Set("Accept", "image/*,*/*;q=0.8")
	resp, err := p.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("favicon 返回状态 %d", resp.StatusCode)
	}
	limit := p.MaxFavicon
	if limit <= 0 {
		limit = 512 << 10
	}
	return io.ReadAll(io.LimitReader(resp.Body, limit))
}

// TruncateBytes 按字节截断（**刻意不保证 UTF-8 边界**：调用方只用它做特征匹配，
// 例如取响应体前缀做小写比较，切坏一个字符不影响 Contains 判定）。
func TruncateBytes(b []byte, max int) []byte {
	if max <= 0 || len(b) <= max {
		return b
	}
	return b[:max]
}

// TLSInfo 把连接状态里的证书信息转成资产模型。
func TLSInfo(state *tls.ConnectionState) *model.TLSInfo {
	if state == nil || len(state.PeerCertificates) == 0 {
		return nil
	}
	cert := state.PeerCertificates[0]
	return &model.TLSInfo{
		Subject:   cert.Subject.CommonName,
		Issuer:    cert.Issuer.CommonName,
		NotBefore: cert.NotBefore,
		NotAfter:  cert.NotAfter,
		DNSNames:  cert.DNSNames,
		Serial:    cert.SerialNumber.String(),
		Expired:   time.Now().After(cert.NotAfter),
	}
}

// CleanText 压缩空白，便于存进 JSONL 与报告。
func CleanText(s string) string {
	return strings.TrimSpace(reSpace.ReplaceAllString(s, " "))
}

// Truncate 按字节上限截断（避免把巨型响应塞进结果文件），并保证不切坏多字节字符 ——
// 标题、响应头、meta 里出现中文是常态，切出半个汉字会直接进报告。
func Truncate(s string, max int) string {
	return textutil.Truncate(s, max)
}
