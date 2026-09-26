// Package seed 从 robots.txt 与 sitemap.xml 里发现"站点自己声明的入口"。
//
// 为什么值得单独做：这两个文件是**站点主动公开**的路径清单，
// 比盲目目录爆破噪声低得多，而且经常直接暴露后台、接口与文档路径。
// 其中 Disallow 项尤其有价值 —— 它是管理员"不想被搜索引擎收录"的路径，
// 往往正是 /admin、/backup、/api/internal 这类地方。
//
// 合规提醒：Disallow 只作为**提示**记录，默认不主动请求这些路径；
// 要请求必须显式打开 UseDisallow，且仍然受全局限速与授权范围约束。
package seed

import (
	"compress/gzip"
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"westy_scan/internal/ratelimit"
)

// Options 控制入口发现行为。
type Options struct {
	Timeout     time.Duration
	UserAgent   string
	MaxSitemaps int  // 最多跟进多少个 sitemap（含索引里的嵌套项）
	MaxURLs     int  // 最多返回多少个候选 URL
	UseDisallow bool // 是否把 Disallow 前缀也作为候请求路径（默认 false，仅记录）
	Limiter     *ratelimit.Limiter
}

func (o Options) withDefaults() Options {
	if o.Timeout <= 0 {
		o.Timeout = 8 * time.Second
	}
	if o.UserAgent == "" {
		o.UserAgent = "Mozilla/5.0 (compatible; westy-scan/0.1; authorized-testing)"
	}
	if o.MaxSitemaps <= 0 {
		o.MaxSitemaps = 5
	}
	if o.MaxURLs <= 0 {
		o.MaxURLs = 500
	}
	return o
}

// Result 是一次入口发现的结果。
type Result struct {
	RobotsURL  string
	URLs       []string // 来自 sitemap 的候选 URL
	Disallow   []string // robots 里的 Disallow 前缀（敏感路径提示）
	Allow      []string
	Sitemaps   []string // 实际使用的 sitemap 地址
	CrawlDelay string
	Notes      []string // 过程中的异常说明（便于排查"为什么没发现东西"）
}

// Empty 表示什么都没发现。
func (r *Result) Empty() bool {
	return r == nil || (len(r.URLs) == 0 && len(r.Disallow) == 0 && len(r.Sitemaps) == 0)
}

// Discover 对站点做一次入口发现。base 可以是 http(s)://host[:port][/path]。
// 任何一步失败都不会中断整体流程，只会写进 Notes。
func Discover(ctx context.Context, base string, opt Options) *Result {
	opt = opt.withDefaults()
	res := &Result{}

	root, err := rootURL(base)
	if err != nil {
		res.Notes = append(res.Notes, "基础地址非法: "+err.Error())
		return res
	}
	client := &http.Client{Timeout: opt.Timeout}

	// 1) robots.txt
	robotsURL := root + "/robots.txt"
	if body, ok := fetch(ctx, client, robotsURL, opt); ok {
		res.RobotsURL = robotsURL
		parseRobots(string(body), res)
	} else {
		res.Notes = append(res.Notes, "robots.txt 不可用")
	}

	// 2) sitemap：robots 里声明的优先，否则按惯例探测
	candidates := make([]string, 0, 4)
	seen := map[string]bool{}
	for _, sm := range res.Sitemaps {
		if !seen[sm] {
			seen[sm] = true
			candidates = append(candidates, sm)
		}
	}
	for _, guess := range []string{root + "/sitemap.xml", root + "/sitemap_index.xml"} {
		if !seen[guess] {
			seen[guess] = true
			candidates = append(candidates, guess)
		}
	}

	visited := map[string]bool{}
	for len(candidates) > 0 && len(visited) < opt.MaxSitemaps && len(res.URLs) < opt.MaxURLs {
		sm := candidates[0]
		candidates = candidates[1:]
		if visited[sm] {
			continue
		}
		visited[sm] = true

		body, ok := fetchSitemap(ctx, client, sm, opt)
		if !ok {
			continue
		}
		urls, nested, err := parseSitemap(body)
		if err != nil {
			res.Notes = append(res.Notes, "解析 sitemap 失败 "+sm+": "+err.Error())
			continue
		}
		res.Sitemaps = append(res.Sitemaps, sm)
		for _, n := range nested {
			abs, err := normalizeSitemapURL(n, sm) // 嵌套索引同样可能是相对地址
			if err != nil {
				continue
			}
			if !visited[abs] && len(visited)+len(candidates) < opt.MaxSitemaps {
				candidates = append(candidates, abs)
			}
		}
		for _, u := range urls {
			if len(res.URLs) >= opt.MaxURLs {
				break
			}
			// 规范要求 loc 是绝对 URL，但真实站点常写相对路径，
			// 这里统一按 sitemap 自身地址解析，避免整份地图被丢弃。
			abs, err := normalizeSitemapURL(u, sm)
			if err != nil {
				res.Notes = append(res.Notes, "跳过非法 loc: "+u)
				continue
			}
			if !contains(res.URLs, abs) {
				res.URLs = append(res.URLs, abs)
			}
		}
	}

	if opt.UseDisallow {
		for _, d := range res.Disallow {
			if u := joinPath(root, d); u != "" && !contains(res.URLs, u) && len(res.URLs) < opt.MaxURLs {
				res.URLs = append(res.URLs, u)
			}
		}
	}
	return res
}

// parseRobots 解析 robots.txt。多个 User-agent 组会被合并处理（保守且简单）。
func parseRobots(text string, res *Result) {
	for _, rawLine := range strings.Split(text, "\n") {
		line := strings.TrimSpace(rawLine)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		key, value, ok := splitDirective(line)
		if !ok {
			continue
		}
		switch key {
		case "disallow":
			if value != "" {
				res.Disallow = appendUnique(res.Disallow, value)
			}
		case "allow":
			if value != "" {
				res.Allow = appendUnique(res.Allow, value)
			}
		case "sitemap":
			if abs, err := normalizeSitemapURL(value, res.RobotsURL); err == nil {
				res.Sitemaps = appendUnique(res.Sitemaps, abs)
			} else {
				res.Notes = append(res.Notes, "robots 里的 sitemap 地址非法: "+value)
			}
		case "crawl-delay":
			res.CrawlDelay = value
		}
	}
}

func splitDirective(line string) (key, value string, ok bool) {
	i := strings.IndexByte(line, ':')
	if i <= 0 {
		return "", "", false
	}
	key = strings.ToLower(strings.TrimSpace(line[:i]))
	value = strings.TrimSpace(line[i+1:])
	return key, value, value != "" || key == "disallow"
}

// sitemapDoc 同时兼容 <urlset> 与 <sitemapindex> 两种根节点。
type sitemapDoc struct {
	XMLName  xml.Name
	URLs     []locEntry `xml:"url"`
	Sitemaps []locEntry `xml:"sitemap"`
}

type locEntry struct {
	Loc string `xml:"loc"`
}

// parseSitemap 返回 (页面 URL, 嵌套 sitemap)。两种根节点都能处理。
func parseSitemap(body []byte) (urls []string, nested []string, err error) {
	dec := xml.NewDecoder(strings.NewReader(string(body)))
	dec.Strict = false
	var doc sitemapDoc
	if err := dec.Decode(&doc); err != nil {
		return nil, nil, err
	}
	for _, e := range doc.URLs {
		if v := strings.TrimSpace(e.Loc); v != "" {
			urls = append(urls, v)
		}
	}
	for _, e := range doc.Sitemaps {
		if v := strings.TrimSpace(e.Loc); v != "" {
			nested = append(nested, v)
		}
	}
	return urls, nested, nil
}

func fetchSitemap(ctx context.Context, client *http.Client, raw string, opt Options) ([]byte, bool) {
	data, ok := fetch(ctx, client, raw, opt)
	if !ok {
		return nil, false
	}
	// .xml.gz 需要解压（不少站点默认这么发）
	if strings.HasSuffix(strings.ToLower(raw), ".gz") {
		zr, err := gzip.NewReader(strings.NewReader(string(data)))
		if err != nil {
			return nil, false
		}
		defer zr.Close()
		plain, err := io.ReadAll(io.LimitReader(zr, 4<<20))
		if err != nil {
			return nil, false
		}
		return plain, true
	}
	return data, true
}

func fetch(ctx context.Context, client *http.Client, raw string, opt Options) ([]byte, bool) {
	if err := opt.Limiter.Wait(ctx); err != nil {
		return nil, false
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, raw, nil)
	if err != nil {
		return nil, false
	}
	req.Header.Set("User-Agent", opt.UserAgent)
	req.Header.Set("Accept", "*/*")
	resp, err := client.Do(req)
	if err != nil {
		return nil, false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, false
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if err != nil || len(body) == 0 {
		return nil, false
	}
	return body, true
}

// rootURL 取 scheme://host[:port]，丢掉路径部分。
func rootURL(base string) (string, error) {
	raw := strings.TrimSpace(base)
	if raw == "" {
		return "", fmt.Errorf("空地址")
	}
	if !strings.Contains(raw, "://") {
		raw = "http://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", err
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", fmt.Errorf("不支持的协议 %q", u.Scheme)
	}
	if u.Host == "" {
		return "", fmt.Errorf("缺少主机名")
	}
	return u.Scheme + "://" + u.Host, nil
}

func normalizeSitemapURL(value, base string) (string, error) {
	raw := strings.TrimSpace(value)
	if raw == "" {
		return "", fmt.Errorf("空 sitemap 地址")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", err
	}
	if !u.IsAbs() {
		if base == "" {
			return "", fmt.Errorf("相对 sitemap 地址缺少基准")
		}
		b, err := url.Parse(base)
		if err != nil {
			return "", err
		}
		u = b.ResolveReference(u)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", fmt.Errorf("不支持的协议 %q", u.Scheme)
	}
	return u.String(), nil
}

func joinPath(root, path string) string {
	if path == "" {
		return ""
	}
	if strings.HasPrefix(path, "http://") || strings.HasPrefix(path, "https://") {
		return path
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return root + path
}

func appendUnique(list []string, v string) []string {
	if v == "" || contains(list, v) {
		return list
	}
	return append(list, v)
}

func contains(list []string, v string) bool {
	for _, s := range list {
		if s == v {
			return true
		}
	}
	return false
}

// Note 方便调用方拼装说明文本。
func (r *Result) Note() string {
	if r == nil {
		return ""
	}
	parts := []string{
		"robots=" + strconv.FormatBool(r.RobotsURL != ""),
		"sitemap=" + strconv.Itoa(len(r.Sitemaps)),
		"urls=" + strconv.Itoa(len(r.URLs)),
		"disallow=" + strconv.Itoa(len(r.Disallow)),
	}
	if r.CrawlDelay != "" {
		parts = append(parts, "crawl-delay="+r.CrawlDelay)
	}
	return strings.Join(parts, " ")
}
