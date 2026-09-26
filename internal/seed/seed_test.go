package seed

import (
	"compress/gzip"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func testOptions() Options {
	return Options{Timeout: 3 * time.Second, MaxSitemaps: 5, MaxURLs: 100}
}

func TestDiscoverRobotsAndSitemap(t *testing.T) {
	var base string
	mux := http.NewServeMux()
	mux.HandleFunc("/robots.txt", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `# 注释行
User-agent: *
Disallow: /admin/
Disallow: /backup
Allow: /public/
Crawl-delay: 5
Sitemap: %s/sitemap.xml
Sitemap: /sitemap_index.xml
`, base)
	})
	mux.HandleFunc("/sitemap.xml", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		fmt.Fprint(w, `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url><loc>http://example.test/a</loc></url>
  <url><loc>http://example.test/b</loc></url>
</urlset>`)
	})
	mux.HandleFunc("/sitemap_index.xml", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `<?xml version="1.0"?>
<sitemapindex xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <sitemap><loc>%s/nested.xml</loc></sitemap>
</sitemapindex>`, base)
	})
	mux.HandleFunc("/nested.xml", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `<urlset><url><loc>http://example.test/nested-page</loc></url></urlset>`)
	})

	srv := httptest.NewServer(mux)
	defer srv.Close()
	base = srv.URL

	res := Discover(context.Background(), srv.URL, testOptions())
	if res.RobotsURL == "" {
		t.Fatal("未识别 robots.txt")
	}
	if res.CrawlDelay != "5" {
		t.Errorf("Crawl-delay = %q", res.CrawlDelay)
	}
	for _, want := range []string{"/admin/", "/backup"} {
		if !contains(res.Disallow, want) {
			t.Errorf("缺少 Disallow %q: %v", want, res.Disallow)
		}
	}
	if !contains(res.Allow, "/public/") {
		t.Errorf("缺少 Allow: %v", res.Allow)
	}
	// 相对 sitemap 地址必须解析成绝对地址
	if len(res.Sitemaps) < 2 {
		t.Fatalf("应发现 2 个 sitemap，实际 %v", res.Sitemaps)
	}
	for _, sm := range res.Sitemaps {
		if !strings.HasPrefix(sm, "http://") {
			t.Errorf("sitemap 地址未绝对化: %q", sm)
		}
	}
	// 嵌套索引里的页面也要被收进来
	for _, want := range []string{"http://example.test/a", "http://example.test/b", "http://example.test/nested-page"} {
		if !contains(res.URLs, want) {
			t.Errorf("缺少 URL %q，实际 %v", want, res.URLs)
		}
	}
}

func TestDiscoverWithoutRobotsFallback(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/sitemap.xml", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `<urlset><url><loc>http://example.test/only</loc></url></urlset>`)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	res := Discover(context.Background(), srv.URL, testOptions())
	if !contains(res.URLs, "http://example.test/only") {
		t.Errorf("robots 缺失时应回落到 /sitemap.xml，实际 %v", res.URLs)
	}
	if len(res.Notes) == 0 {
		t.Error("robots 缺失应记入 Notes，便于排查")
	}
}

func TestDiscoverGzippedSitemap(t *testing.T) {
	var base string
	mux := http.NewServeMux()
	mux.HandleFunc("/robots.txt", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "User-agent: *\nSitemap: %s/sitemap.xml.gz\n", base)
	})
	mux.HandleFunc("/sitemap.xml.gz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/x-gzip")
		zw := gzip.NewWriter(w)
		defer zw.Close()
		_, _ = zw.Write([]byte(`<urlset><url><loc>http://example.test/gz</loc></url></urlset>`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	base = srv.URL

	res := Discover(context.Background(), srv.URL, testOptions())
	if !contains(res.URLs, "http://example.test/gz") {
		t.Errorf("gzip sitemap 未解析: %v（notes=%v）", res.URLs, res.Notes)
	}
}

func TestDiscoverUseDisallowAsCandidates(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/robots.txt", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "User-agent: *\nDisallow: /admin/\nDisallow: /api/internal\n")
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	opt := testOptions()
	opt.UseDisallow = true
	res := Discover(context.Background(), srv.URL, opt)
	if !contains(res.URLs, srv.URL+"/admin/") {
		t.Errorf("UseDisallow=true 时应把 Disallow 作为候选: %v", res.URLs)
	}
	// 默认行为：只记录不请求
	res2 := Discover(context.Background(), srv.URL, testOptions())
	for _, u := range res2.URLs {
		if strings.Contains(u, "/admin/") {
			t.Errorf("默认不应把 Disallow 当候选: %v", res2.URLs)
		}
	}
}

func TestDiscoverMalformedInputs(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/robots.txt", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "这不是 robots 格式\n::::::::\nDisallow:\n")
	})
	mux.HandleFunc("/sitemap.xml", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "<urlset><url><loc>未闭合")
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	res := Discover(context.Background(), srv.URL, testOptions())
	if res == nil {
		t.Fatal("畸形输入不应返回 nil")
	}
	if len(res.URLs) != 0 {
		t.Errorf("畸形 sitemap 不应产出 URL: %v", res.URLs)
	}

	// 非法基础地址
	if r := Discover(context.Background(), "ftp://example.com", testOptions()); len(r.Notes) == 0 {
		t.Error("非法协议应记入 Notes")
	}
	if r := Discover(context.Background(), "   ", testOptions()); len(r.Notes) == 0 {
		t.Error("空地址应记入 Notes")
	}
}

func TestParseSitemapVariants(t *testing.T) {
	urls, nested, err := parseSitemap([]byte(`<?xml version="1.0"?>
<sitemapindex><sitemap><loc>http://a/1.xml</loc></sitemap><sitemap><loc>http://a/2.xml</loc></sitemap></sitemapindex>`))
	if err != nil {
		t.Fatalf("解析 sitemapindex 失败: %v", err)
	}
	if len(nested) != 2 || len(urls) != 0 {
		t.Errorf("索引解析错误: urls=%v nested=%v", urls, nested)
	}

	urls, nested, err = parseSitemap([]byte(`<urlset><url><loc> http://a/x </loc></url></urlset>`))
	if err != nil {
		t.Fatalf("解析 urlset 失败: %v", err)
	}
	if len(urls) != 1 || urls[0] != "http://a/x" {
		t.Errorf("loc 未去空白: %v", urls)
	}
	if len(nested) != 0 {
		t.Errorf("urlset 不应产出嵌套 sitemap: %v", nested)
	}
}

func TestDiscoverRelativeLocsResolved(t *testing.T) {
	var base string
	mux := http.NewServeMux()
	mux.HandleFunc("/sitemap.xml", func(w http.ResponseWriter, r *http.Request) {
		// 真实世界里确实存在写相对路径的 sitemap
		fmt.Fprint(w, `<urlset><url><loc>/rel-page</loc></url><url><loc>https://abs.example.com/p</loc></url></urlset>`)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	base = srv.URL
	_ = base

	res := Discover(context.Background(), srv.URL, testOptions())
	if !contains(res.URLs, srv.URL+"/rel-page") {
		t.Errorf("相对 loc 应解析为绝对地址: %v", res.URLs)
	}
	if !contains(res.URLs, "https://abs.example.com/p") {
		t.Errorf("绝对 loc 应原样保留: %v", res.URLs)
	}
}

func TestRootURL(t *testing.T) {
	cases := map[string]string{
		"http://example.com/path?a=1":  "http://example.com",
		"https://example.com:8443/x/y": "https://example.com:8443",
		"example.com":                  "http://example.com",
	}
	for in, want := range cases {
		got, err := rootURL(in)
		if err != nil || got != want {
			t.Errorf("rootURL(%q) = %q, %v；期望 %q", in, got, err, want)
		}
	}
	if _, err := rootURL(""); err == nil {
		t.Error("空地址应报错")
	}
}
