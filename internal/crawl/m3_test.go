package crawl

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestExtractJSEndpointsAndSecrets(t *testing.T) {
	js := `
	const r = await fetch("/api/v1/users?page=1");
	axios.post('/api/login', {user: u, pass: p});
	$.ajax({url: "/rest/internal/status", method: "GET"});
	const base = "https://other.example.com/v2/items";
	const cfg = {password: "hunter2secret", token: "changeme"};
	const aws = "AKIAIOSFODNN7EXAMPLE";
	const jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abcdefghijklmnop";
	const img = "/static/logo.png";
	`
	f := ExtractJS(js, "https://t.example.com/app.js")

	for _, want := range []string{"/api/v1/users?page=1", "/api/login", "/rest/internal/status", "https://other.example.com/v2/items"} {
		if !containsString(f.Endpoints, want) {
			t.Errorf("缺少接口 %q，实际 %v", want, f.Endpoints)
		}
	}
	if containsString(f.Endpoints, "/static/logo.png") {
		t.Errorf("静态资源不应算接口: %v", f.Endpoints)
	}
	if len(f.Calls) < 3 {
		t.Errorf("fetch/axios/ajax 调用应被记录: %v", f.Calls)
	}

	var hasAWS, hasJWT, hasPassword bool
	for _, s := range f.Secrets {
		switch {
		case strings.Contains(s, "AWS Access Key ID"):
			hasAWS = true
			if strings.Contains(s, "AKIAIOSFODNN7EXAMPLE") {
				t.Errorf("凭据不得明文写入结果: %s", s)
			}
			if !strings.Contains(s, "@https://t.example.com/app.js") {
				t.Errorf("凭据应标注来源: %s", s)
			}
		case strings.Contains(s, "JWT"):
			hasJWT = true
		case strings.Contains(s, "口令"):
			hasPassword = true
		}
	}
	if !hasAWS || !hasJWT || !hasPassword {
		t.Errorf("凭据类型识别不全（aws=%v jwt=%v pwd=%v）: %v", hasAWS, hasJWT, hasPassword, f.Secrets)
	}
	// 占位符不算凭据
	for _, s := range f.Secrets {
		if strings.Contains(s, "changeme") {
			t.Errorf("占位符不应上报: %s", s)
		}
	}
}

func TestMaskSecret(t *testing.T) {
	cases := []struct {
		in     string
		expect func(string) bool
		desc   string
	}{
		{"short", func(s string) bool { return s == "*****" }, "极短全部打码"},
		{"abcdefghijklmnop", func(s string) bool {
			return strings.HasPrefix(s, "abc") && strings.HasSuffix(s, "op") && !strings.Contains(s, "defghijklmn")
		}, "中等长度保留首尾"},
		{"AKIAIOSFODNN7EXAMPLE", func(s string) bool {
			return strings.HasPrefix(s, "AKIA") && strings.HasSuffix(s, "MPLE(20字符)") && !strings.Contains(s, "IOSFODNN7EXA")
		}, "长串保留首尾并给出长度"},
	}
	for _, c := range cases {
		got := MaskSecret(c.in)
		if !c.expect(got) {
			t.Errorf("%s: MaskSecret(%q) = %q", c.desc, c.in, got)
		}
	}
	if MaskSecret("") != "" {
		t.Error("空串应返回空串")
	}
}

func TestExtractForms(t *testing.T) {
	html := []byte(`<html><body>
		<form action="/login" method="post">
			<input type="text" name="username">
			<input type="password" name="password">
			<input type="submit" value="登录">
		</form>
		<form action="https://other.example.com/search">
			<input name="q">
			<select name="scope"><option>all</option></select>
		</form>
	</body></html>`)

	forms := ExtractForms("https://t.example.com/page", html)
	if len(forms) != 2 {
		t.Fatalf("应抽出 2 个表单，实际 %d", len(forms))
	}
	if forms[0].Action != "https://t.example.com/login" {
		t.Errorf("相对 action 未绝对化: %q", forms[0].Action)
	}
	if forms[0].Method != "POST" {
		t.Errorf("method 应为 POST: %q", forms[0].Method)
	}
	if strings.Join(forms[0].Fields, ",") != "password,username" {
		t.Errorf("字段解析错误: %v", forms[0].Fields)
	}
	if forms[1].Method != "GET" {
		t.Errorf("缺省 method 应为 GET: %q", forms[1].Method)
	}
	if strings.Join(forms[1].Fields, ",") != "q,scope" {
		t.Errorf("第二个表单字段错误: %v", forms[1].Fields)
	}

	if got := ExtractForms("https://t.example.com/", []byte("<html>no form</html>")); got != nil {
		t.Errorf("没有表单时应返回 nil: %v", got)
	}
}

func TestExtractQueryParams(t *testing.T) {
	got := ExtractQueryParams("https://t.example.com/a?x=1&y=2&x=3&arr%5B%5D=1")
	if strings.Join(got, ",") != "arr[],x,y" {
		t.Errorf("参数解析错误: %v", got)
	}
	if ExtractQueryParams("https://t.example.com/a") != nil {
		t.Error("无查询串应返回 nil")
	}
}

// HTML 实体必须还原：真实站点用 &amp; 分隔查询参数是常态
func TestExtractLinksUnescapesHTMLEntities(t *testing.T) {
	c := New(Options{MaxDepth: 1, MaxPages: 5, Concurrency: 1, Timeout: time.Second})
	body := []byte(`<a href="/list?cat=1&amp;page=2&x=3">a</a>
		<a href="/q?a=1&#38;b=2">b</a>
		<form action="/post?u=1&amp;t=2"></form>`)
	links := c.extractLinks("http://host/", body)
	var hasCat, hasAB bool
	for _, l := range links {
		if l == "http://host/list?cat=1&page=2&x=3" {
			hasCat = true
		}
		if l == "http://host/q?a=1&b=2" {
			hasAB = true
		}
		if strings.Contains(l, "amp;") {
			t.Errorf("实体未还原: %q", l)
		}
	}
	if !hasCat || !hasAB {
		t.Errorf("实体还原后的链接缺失: %v", links)
	}

	forms := ExtractForms("http://host/", body)
	if len(forms) != 1 || forms[0].Action != "http://host/post?u=1&t=2" {
		t.Errorf("表单 action 未还原实体: %+v", forms)
	}
	// 参数名不能被实体污染
	if params := ExtractQueryParams("http://host/list?cat=1&page=2"); strings.Join(params, ",") != "cat,page" {
		t.Errorf("参数名解析错误: %v", params)
	}
}

// 端到端：内联脚本 + 外链 JS + 表单参数 + 近似重复
func TestCrawlerM3EndToEnd(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><head><title>首页</title>
			<script>fetch("/api/inline-endpoint");</script>
			<script src="/app.js"></script></head>
			<body>
			<form action="/login" method="post"><input name="username"><input name="password"></form>
			<a href="/list?cat=1&page=2">列表</a>
			<a href="/dup1">dup1</a><a href="/dup2">dup2</a>
			</body></html>`)
	})
	mux.HandleFunc("/app.js", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		fmt.Fprint(w, `fetch("/api/js-endpoint"); const k="AKIAIOSFODNN7EXAMPLE";`)
	})
	dupBody := `<html><head><title>模板页</title></head><body>` +
		strings.Repeat("这是一段很长的模板正文 内容 基本 一致 ", 40) + `</body></html>`
	mux.HandleFunc("/dup1", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, dupBody)
	})
	mux.HandleFunc("/dup2", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, dupBody)
	})
	mux.HandleFunc("/list", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><title>列表</title><body>list</body></html>`)
	})

	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := New(Options{
		MaxDepth:    2,
		MaxPages:    50,
		Concurrency: 4,
		Timeout:     3 * time.Second,
		SameHost:    true,
	})

	pages := map[string]bool{}
	var jsAsset, home, dup2 bool
	var dupMarked int
	var dupRef string
	endpointsOf := func(a interface{ MetaValue(string) string }) string { return "" }
	_ = endpointsOf

	for page := range c.Run(context.Background(), []string{srv.URL + "/"}) {
		a := page.Asset
		pages[a.URL] = true
		if a.Source == "crawl-js" {
			jsAsset = true
			if !strings.Contains(a.MetaValue("js.endpoints"), "/api/js-endpoint") {
				t.Errorf("外链 JS 未抽出接口: %v", a.Meta)
			}
			if a.MetaValue("js.secret_count") == "" {
				t.Errorf("外链 JS 未识别硬编码凭据: %v", a.Meta)
			}
			if strings.Contains(a.MetaValue("js.secrets"), "AKIAIOSFODNN7EXAMPLE") {
				t.Errorf("凭据不得明文落盘: %v", a.MetaValue("js.secrets"))
			}
		}
		if a.URL == srv.URL+"/" {
			home = true
			if len(a.Forms) != 1 || a.Forms[0].Method != "POST" {
				t.Errorf("首页表单未记录: %+v", a.Forms)
			}
			if !containsString(a.Params, "username") || !containsString(a.Params, "password") {
				t.Errorf("表单字段未进入参数清单: %v", a.Params)
			}
			if !strings.Contains(a.MetaValue("js.endpoints"), "/api/inline-endpoint") {
				t.Errorf("内联脚本未抽出接口: %v", a.Meta)
			}
			if a.MetaValue("content.simhash") == "" {
				t.Errorf("缺少内容指纹: %v", a.Meta)
			}
		}
		if a.URL == srv.URL+"/list" {
			if !containsString(a.Params, "cat") || !containsString(a.Params, "page") {
				t.Errorf("查询参数未进入清单: %v", a.Params)
			}
		}
		if a.URL == srv.URL+"/dup2" {
			dup2 = true
		}
		// 近重复判定的正确属性是"两个近似相同的页面里，**恰好有一个**被标为 duplicate_of"，
		// 而不是"必须是 /dup2 被标"：爬虫是并发的，谁先被处理不确定，
		// 断言具体某一个页面会让测试随调度/负载随机失败（-race 下尤其明显）。
		if a.URL == srv.URL+"/dup1" || a.URL == srv.URL+"/dup2" {
			if a.MetaValue("duplicate_of") != "" {
				dupMarked++
				dupRef = a.MetaValue("duplicate_of")
			}
		}
	}
	if !home || !jsAsset || !dup2 {
		t.Fatalf("抓取不完整（home=%v js=%v dup2=%v）: %v", home, jsAsset, dup2, pages)
	}
	if dupMarked != 1 {
		t.Errorf("两个内容一致的页面应恰好有一个被标记 duplicate_of，实际 %d 个（ref=%q）", dupMarked, dupRef)
	}
}

// 关闭 JS 抽取后不应抓取外链 JS
func TestCrawlerDisableJS(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><script src="/app.js"></script><body>x</body></html>`)
	})
	// handler 在 http 服务的协程里执行，测试协程随后读取 —— 必须用 atomic，
	// 裸 bool 是真实的 data race（本地常常侥幸不触发，CI 上 -race 会红）。
	var fetchedJS atomic.Bool
	mux.HandleFunc("/app.js", func(w http.ResponseWriter, r *http.Request) {
		fetchedJS.Store(true)
		fmt.Fprint(w, `fetch("/api/x");`)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := New(Options{MaxDepth: 2, MaxPages: 10, Concurrency: 2, Timeout: 3 * time.Second, DisableJS: true})
	for range c.Run(context.Background(), []string{srv.URL + "/"}) {
	}
	if fetchedJS.Load() {
		t.Error("DisableJS=true 时不应抓取外链 JS")
	}
}
