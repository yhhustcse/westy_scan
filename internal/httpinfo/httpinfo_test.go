package httpinfo

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"westy_scan/internal/favhash"
)

// faviconBytes 是任意二进制内容（真实 png 的字节对哈希逻辑没有影响）
var faviconBytes = []byte{0x89, 'P', 'N', 'G', 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x00, 0x00, 0x0d}

func probeTestServer(t *testing.T, mux *http.ServeMux) (host string, port int) {
	t.Helper()
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("解析测试服务地址失败: %v", err)
	}
	p, _ := strconv.Atoi(u.Port())
	return u.Hostname(), p
}

func newProber() *Prober { return New(3*time.Second, "westy-test") }

func TestProbeFetchesFaviconFromIconLink(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><head><title>Demo</title>
			<link rel="shortcut icon" href="/static/icon.png"></head><body>x</body></html>`)
	})
	mux.HandleFunc("/static/icon.png", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/png")
		_, _ = w.Write(faviconBytes)
	})
	host, port := probeTestServer(t, mux)

	res, err := newProber().Probe(context.Background(), host, host, port, "http")
	if err != nil {
		t.Fatalf("Probe 失败: %v", err)
	}
	want := favhash.ShodanHash(faviconBytes)
	if res.Asset.FaviconHash != want {
		t.Errorf("favicon 哈希 = %d，期望 %d", res.Asset.FaviconHash, want)
	}
	if !strings.HasSuffix(res.Asset.MetaValue("favicon.url"), "/static/icon.png") {
		t.Errorf("favicon 来源 URL 错误: %q", res.Asset.MetaValue("favicon.url"))
	}
	if res.Asset.MetaValue("favicon.mmh3") != strconv.FormatInt(int64(want), 10) {
		t.Errorf("meta favicon.mmh3 与字段不一致: %q", res.Asset.MetaValue("favicon.mmh3"))
	}
	// 两种社区约定都要记录：Shodan（base64 后 mmh3）与 FOFA（原始字节 mmh3）
	if got, want := res.Asset.MetaValue("favicon.mmh3_raw"), strconv.FormatInt(int64(favhash.RawHash(faviconBytes)), 10); got != want {
		t.Errorf("favicon.mmh3_raw = %q，期望 %q", got, want)
	}
	if res.Asset.MetaValue("favicon.size") != strconv.Itoa(len(faviconBytes)) {
		t.Errorf("favicon.size = %q", res.Asset.MetaValue("favicon.size"))
	}
}

func TestProbeFallsBackToRootFavicon(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><head><title>No icon link</title></head></html>`)
	})
	mux.HandleFunc("/favicon.ico", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/x-icon")
		_, _ = w.Write(faviconBytes)
	})
	host, port := probeTestServer(t, mux)

	res, err := newProber().Probe(context.Background(), host, host, port, "http")
	if err != nil {
		t.Fatalf("Probe 失败: %v", err)
	}
	if res.Asset.FaviconHash != favhash.ShodanHash(faviconBytes) {
		t.Errorf("未回落到根目录 favicon: %d", res.Asset.FaviconHash)
	}
	if !strings.HasSuffix(res.Asset.MetaValue("favicon.url"), "/favicon.ico") {
		t.Errorf("favicon 来源应为根目录: %q", res.Asset.MetaValue("favicon.url"))
	}
}

// 站点对 /favicon.ico 返回 200 + HTML 404 页面时，不能把 HTML 当成 favicon
func TestProbeSkipsHTMLFavicon(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><head><title>Demo</title></head></html>`)
	})
	mux.HandleFunc("/favicon.ico", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><body>404 Not Found</body></html>`)
	})
	host, port := probeTestServer(t, mux)

	res, err := newProber().Probe(context.Background(), host, host, port, "http")
	if err != nil {
		t.Fatalf("Probe 失败: %v", err)
	}
	if res.Asset.FaviconHash != 0 {
		t.Errorf("HTML 404 页面不应被当作 favicon: %d", res.Asset.FaviconHash)
	}
}

func TestProbeNoFaviconWhenMissing(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><head><title>Demo</title></head></html>`)
	})
	mux.HandleFunc("/favicon.ico", func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	})
	host, port := probeTestServer(t, mux)

	res, err := newProber().Probe(context.Background(), host, host, port, "http")
	if err != nil {
		t.Fatalf("favicon 缺失不应让 Probe 失败: %v", err)
	}
	if res.Asset.FaviconHash != 0 {
		t.Errorf("没有 favicon 时哈希应为 0: %d", res.Asset.FaviconHash)
	}
	if res.Asset.Title != "" && res.Asset.Title != "Demo" {
		t.Errorf("标题解析异常: %q", res.Asset.Title)
	}
}

// 非 HTML 响应（如 JSON API）不应触发 favicon 抓取
func TestProbeSkipsFaviconForNonHTML(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"ok":true}`)
	})
	mux.HandleFunc("/favicon.ico", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(faviconBytes)
	})
	host, port := probeTestServer(t, mux)

	res, err := newProber().Probe(context.Background(), host, host, port, "http")
	if err != nil {
		t.Fatalf("Probe 失败: %v", err)
	}
	if res.Asset.FaviconHash != 0 {
		t.Errorf("非 HTML 响应不应抓 favicon: %d", res.Asset.FaviconHash)
	}
}

func TestIsHTMLLike(t *testing.T) {
	cases := []struct {
		ct   string
		body string
		want bool
	}{
		{"text/html; charset=utf-8", "", true},
		{"", "<!DOCTYPE html><html>", true},
		{"", "  <html><body>", true},
		{"application/json", `{"a":1}`, false},
		{"image/png", string(faviconBytes), false},
		{"", "", false},
	}
	for _, c := range cases {
		if got := IsHTMLLike(c.ct, []byte(c.body)); got != c.want {
			t.Errorf("IsHTMLLike(%q, %q) = %v，期望 %v", c.ct, c.body, got, c.want)
		}
	}
}

func TestBuildURLAndGuessScheme(t *testing.T) {
	if got := BuildURL("example.com", 443, "https"); got != "https://example.com" {
		t.Errorf("默认端口应省略: %q", got)
	}
	if got := BuildURL("example.com", 8443, "https"); got != "https://example.com:8443" {
		t.Errorf("非默认端口应保留: %q", got)
	}
	if got := GuessScheme(8443); got != "https" {
		t.Errorf("8443 应为 https: %q", got)
	}
	if got := GuessScheme(18080); got != "http" {
		t.Errorf("18080 应为 http: %q", got)
	}
}
