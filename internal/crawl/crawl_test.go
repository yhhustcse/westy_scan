package crawl

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestCrawlerRun(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><head><title>首页</title></head><body>
			<a href="/a">a</a><a href="/b.html">b</a>
			<a href="https://evil.example.com/out">外站</a>
			<form action="/login"><input name="u"></form>
			</body></html>`)
	})
	mux.HandleFunc("/a", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `<html><title>A</title><a href="/deep">deep</a></html>`)
	})
	mux.HandleFunc("/b.html", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `<html><title>B</title></html>`)
	})
	mux.HandleFunc("/deep", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `<html><title>DEEP</title></html>`)
	})

	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := New(Options{
		MaxDepth:    1,
		MaxPages:    10,
		Concurrency: 2,
		Timeout:     3 * time.Second,
		SameHost:    true,
	})

	titles := map[string]bool{}
	for page := range c.Run(context.Background(), []string{srv.URL}) {
		titles[page.Asset.Title] = true
		if page.Asset.Source != "crawl" {
			t.Errorf("资产来源应为 crawl，实际 %q", page.Asset.Source)
		}
	}

	// 深度 1：只应覆盖首页与它直接链接的两页，/deep 属于深度 2
	for _, want := range []string{"首页", "A", "B"} {
		if !titles[want] {
			t.Errorf("缺少页面 %q，实际收集到 %v", want, titles)
		}
	}
	if titles["DEEP"] {
		t.Error("MaxDepth=1 不应抓到深度 2 的页面")
	}
}

func TestExtractLinksFiltersSchemes(t *testing.T) {
	c := New(Options{MaxDepth: 1, MaxPages: 5, Concurrency: 1, Timeout: time.Second})
	body := []byte(`<a href="javascript:void(0)">x</a><a href="mailto:a@b.c">m</a>
		<a href="#top">t</a><a href="/real?a=1">r</a><img src="/logo.png">`)
	links := c.extractLinks("http://host/", body)
	found := false
	for _, l := range links {
		if l == "http://host/real?a=1" {
			found = true
		}
		if l == "http://host/logo.png" {
			t.Error("默认应过滤静态资源")
		}
	}
	if !found {
		t.Errorf("未抽出预期链接，实际 %v", links)
	}
}
