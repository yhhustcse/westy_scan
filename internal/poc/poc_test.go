package poc

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func testEngine(t *testing.T, tpls []*Template, opt Options) *Engine {
	t.Helper()
	if opt.Timeout == 0 {
		opt.Timeout = 3 * time.Second
	}
	opt.Concurrency = 4
	return NewEngine(tpls, opt)
}

func targetFor(t *testing.T, srv *httptest.Server) Target {
	t.Helper()
	tgt, ok := TargetFromURL(srv.URL, "127.0.0.1")
	if !ok {
		t.Fatalf("无法从 %s 构造目标", srv.URL)
	}
	return tgt
}

// ---------------- 变量渲染 ----------------

func TestRenderVariables(t *testing.T) {
	tgt := Target{Scheme: "https", Host: "example.com", Port: 8443, IP: "1.2.3.4", Path: "/a/b.html"}
	vars := NewEngine(nil, Options{}).baseVars(tgt)

	cases := map[string]string{
		"{{BaseURL}}/x":         "https://example.com:8443/x",
		"{{RootURL}}/x":         "https://example.com/x",
		"{{Hostname}}:{{Port}}": "example.com:8443",
		"{{Scheme}}://{{Host}}": "https://example.com",
		"{{File}}":              "b.html",
		"{{Path}}":              "/a/b.html",
	}
	for in, want := range cases {
		if got := Render(in, vars); got != want {
			t.Errorf("Render(%q) = %q，期望 %q", in, got, want)
		}
	}
	// 未知变量保持原样（避免误替换模板里的其它 {{}}）
	if got := Render("{{NotAVar}}", vars); got != "{{NotAVar}}" {
		t.Errorf("未知变量不应被替换: %q", got)
	}
	// randstr 每次调用都不同
	if vars["randstr"] == vars["randstr_1"] {
		t.Error("randstr 与 randstr_1 应相互独立")
	}
	// 默认端口应省略
	if got := (Target{Scheme: "http", Host: "a.com", Port: 80}).BaseURL(); got != "http://a.com" {
		t.Errorf("默认端口应省略: %q", got)
	}
}

func TestUnknownVars(t *testing.T) {
	vars := NewEngine(nil, Options{}).baseVars(Target{Scheme: "http", Host: "a.com", Port: 80})
	got := UnknownVars("{{BaseURL}}/x?y={{oob}}&z={{Weird}}", vars)
	if len(got) != 2 || got[0] != "oob" || got[1] != "Weird" {
		t.Errorf("未知变量检测错误: %v", got)
	}
}

// ---------------- 匹配器 ----------------

func TestMatchers(t *testing.T) {
	resp := &Response{
		URL:     "http://t/",
		Status:  200,
		Headers: http.Header{"Content-Type": []string{"application/json"}, "Server": []string{"nginx/1.25"}},
		Body:    []byte(`{"cluster_name":"es","lucene_version":"9.0","items":[{"name":"a"}]}`),
		Title:   "Index of /data",
	}
	vars := Vars{"randstr": "abc123"}

	cases := []struct {
		name string
		m    Matcher
		want bool
	}{
		{"status 命中", Matcher{Type: "status", Status: []int{200, 201}}, true},
		{"status 未命中", Matcher{Type: "status", Status: []int{404}}, false},
		{"word 命中", Matcher{Type: "word", Words: []string{"cluster_name"}}, true},
		{"word 大小写", Matcher{Type: "word", Words: []string{"CLUSTER_NAME"}, CaseInsensitive: true}, true},
		{"word part=header", Matcher{Type: "word", Part: "header", Words: []string{"nginx"}}, true},
		{"word and 缺一", Matcher{Type: "word", Words: []string{"cluster_name", "not-there"}, Condition: "and"}, false},
		{"word or 命中其一", Matcher{Type: "word", Words: []string{"not-there", "lucene_version"}, Condition: "or"}, true},
		{"regex 命中", Matcher{Type: "regex", Regex: []string{`"lucene_version"\s*:\s*"9`}}, true},
		{"regex 未命中", Matcher{Type: "regex", Regex: []string{`"postgres"`}}, false},
		{"size 命中", Matcher{Type: "size", Size: []int{len(resp.Body)}}, true},
		{"size 未命中", Matcher{Type: "size", Size: []int{1}}, false},
		{"header 命中", Matcher{Type: "header", Headers: map[string]string{"content-type": "(?i)json"}}, true},
		{"header 缺失", Matcher{Type: "header", Headers: map[string]string{"x-absent": ".*"}}, false},
		{"header 只判存在", Matcher{Type: "header", Headers: map[string]string{"server": ""}}, true},
		{"title 命中", Matcher{Type: "title", Regex: []string{"^Index of "}}, true},
		{"negative 取反", Matcher{Type: "status", Status: []int{404}, Negative: true}, true},
		{"变量渲染进 word", Matcher{Type: "word", Words: []string{"{{randstr}}"}}, false},
	}
	for _, c := range cases {
		got := EvaluateMatcher(c.m, resp, vars)
		if got.Hit != c.want {
			t.Errorf("%s: Hit=%v(%s)，期望 %v", c.name, got.Hit, got.Why, c.want)
		}
		if got.Why == "" {
			t.Errorf("%s: 缺少可解释的理由", c.name)
		}
	}

	// matchers-condition
	if r := EvaluateMatchers([]Matcher{{Type: "status", Status: []int{200}}, {Type: "word", Words: []string{"nope"}}}, "and", resp, vars); r.Hit {
		t.Error("and 语义下有一个不通过就不应命中")
	}
	if r := EvaluateMatchers([]Matcher{{Type: "status", Status: []int{500}}, {Type: "word", Words: []string{"cluster_name"}}}, "or", resp, vars); !r.Hit {
		t.Error("or 语义下任一通过即应命中")
	}
}

// ---------------- 提取器 ----------------

func TestExtractors(t *testing.T) {
	resp := &Response{
		Status:  200,
		Headers: http.Header{"Content-Type": []string{"application/json"}, "X-Powered-By": []string{"PHP/8.2"}},
		Body:    []byte(`{"users":[{"name":"admin"},{"name":"guest"}],"version":"1.2.3"}`),
	}
	vars := Vars{}

	got := Extract(Extractor{Type: "regex", Regex: []string{`"name":"([^"]+)"`}, Group: 1}, resp, vars)
	if strings.Join(got, ",") != "admin,guest" {
		t.Errorf("regex 提取错误: %v", got)
	}
	if got := Extract(Extractor{Type: "kval", KVal: []string{"X-Powered-By"}}, resp, vars); len(got) != 1 || !strings.Contains(got[0], "PHP/8.2") {
		t.Errorf("kval 提取错误: %v", got)
	}
	if got := Extract(Extractor{Type: "json", JSON: []string{"version", "users.0.name"}}, resp, vars); strings.Join(got, ",") != "1.2.3,admin" {
		t.Errorf("json 提取错误: %v", got)
	}
	if got := Extract(Extractor{Type: "json", JSON: []string{"not.there"}}, resp, vars); len(got) != 0 {
		t.Errorf("不存在的路径不应提取: %v", got)
	}
	// 非法正则不应 panic
	if got := Extract(Extractor{Type: "regex", Regex: []string{"([unclosed"}}, resp, vars); len(got) != 0 {
		t.Errorf("非法正则应返回空: %v", got)
	}
}

// ---------------- YAML 子集适配器 ----------------

const nucleiStyleTemplate = `
id: nacos-auth-bypass
info:
  name: Nacos 未授权访问
  severity: high
  tags: [nacos, unauthorized]
  description: |
    多行描述
    第二行
http:
  - method: GET
    path:
      - "{{BaseURL}}/nacos/v1/auth/users?pageNo=1&pageSize=1"
    matchers-condition: and
    matchers:
      - type: status
        status: [200]
      - type: word
        part: body
        words: ['"username"', '"pageItems"']
        condition: and
      - type: regex
        part: header
        regex: ['application/json']
    extractors:
      - type: regex
        part: body
        regex: ['"username":"([^"]+)"']
        group: 1
        name: usernames
`

func TestParseYAMLSubsetNucleiStyle(t *testing.T) {
	doc, err := ParseYAMLSubset(nucleiStyleTemplate)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	m, ok := doc.(map[string]any)
	if !ok {
		t.Fatalf("根节点应为映射，实际 %T", doc)
	}
	if m["id"] != "nacos-auth-bypass" {
		t.Errorf("id 解析错误: %v", m["id"])
	}
	info, _ := m["info"].(map[string]any)
	if info == nil || info["name"] != "Nacos 未授权访问" {
		t.Fatalf("info 解析错误: %#v", m["info"])
	}
	if !strings.Contains(fmt.Sprint(info["description"]), "第二行") {
		t.Errorf("块标量未保留多行: %v", info["description"])
	}
	tags, _ := info["tags"].([]any)
	if len(tags) != 2 || tags[0] != "nacos" {
		t.Errorf("内联序列解析错误: %#v", info["tags"])
	}
	httpSec, _ := m["http"].([]any)
	if len(httpSec) != 1 {
		t.Fatalf("http 段解析错误: %#v", m["http"])
	}
	req, _ := httpSec[0].(map[string]any)
	if req["method"] != "GET" {
		t.Errorf("method 解析错误: %v", req["method"])
	}
	paths, _ := req["path"].([]any)
	if len(paths) != 1 || !strings.Contains(paths[0].(string), "{{BaseURL}}/nacos") {
		t.Errorf("path 解析错误: %#v", req["path"])
	}
	matchers, _ := req["matchers"].([]any)
	if len(matchers) != 3 {
		t.Fatalf("matchers 解析错误: %#v", req["matchers"])
	}
	second, _ := matchers[1].(map[string]any)
	if second["type"] != "word" || second["condition"] != "and" {
		t.Errorf("第二个匹配器解析错误: %#v", second)
	}
	words, _ := second["words"].([]any)
	if len(words) != 2 || words[0] != `"username"` {
		t.Errorf("内联引号序列解析错误: %#v", second["words"])
	}
	// 数字应转成数值而不是字符串
	first, _ := matchers[0].(map[string]any)
	status, _ := first["status"].([]any)
	if len(status) != 1 {
		t.Fatalf("status 解析错误: %#v", first["status"])
	}
	if v, ok := status[0].(float64); !ok || v != 200 {
		t.Errorf("status 应为数值 200: %#v", status[0])
	}

	// 端到端：解析出的文档必须能变成合法 Template
	tpl, err := parseYAMLTemplate([]byte(nucleiStyleTemplate))
	if err != nil {
		t.Fatalf("转成 Template 失败: %v", err)
	}
	if err := Validate(tpl); err != nil {
		t.Fatalf("校验失败: %v", err)
	}
	if tpl.HTTP[0].Matchers[1].Condition != "and" {
		t.Errorf("条件字段丢失: %+v", tpl.HTTP[0].Matchers[1])
	}
}

func TestParseYAMLSubsetRejections(t *testing.T) {
	cases := []struct {
		name string
		src  string
	}{
		{"多文档", "---\nid: a\n"},
		{"锚点", "id: &x a\n"},
		{"别名", "id: *x\n"},
		{"tab 缩进", "id: a\n\tname: b\n"},
		{"类型标签", "!!str id: a\n"},
	}
	for _, c := range cases {
		if _, err := ParseYAMLSubset(c.src); err == nil {
			t.Errorf("%s: 应返回错误", c.name)
		} else if !strings.Contains(err.Error(), "第") && c.name != "tab 缩进" {
			t.Errorf("%s: 错误信息应带行号: %v", c.name, err)
		}
	}
}

// ---------------- 编译期校验 ----------------

func TestValidateRejectsBadTemplates(t *testing.T) {
	base := func() *Template {
		return &Template{
			ID:   "t1",
			Info: Info{Name: "t", Severity: "high"},
			HTTP: []HTTPRequest{{
				Method:   "GET",
				Path:     []string{"{{BaseURL}}/x"},
				Matchers: []Matcher{{Type: "status", Status: []int{200}}},
			}},
		}
	}
	cases := []struct {
		name   string
		mutate func(*Template)
		want   string
	}{
		{"缺少 id", func(t *Template) { t.ID = "" }, "缺少 id"},
		{"缺少 http", func(t *Template) { t.HTTP = nil }, "缺少 http"},
		{"缺少 path", func(t *Template) { t.HTTP[0].Path = nil }, "缺少 path"},
		{"缺少 matchers", func(t *Template) { t.HTTP[0].Matchers = nil }, "缺少 matchers"},
		{"未知匹配器类型", func(t *Template) { t.HTTP[0].Matchers[0].Type = "dsl" }, "不支持的匹配器类型"},
		{"非法正则", func(t *Template) {
			t.HTTP[0].Matchers = []Matcher{{Type: "regex", Regex: []string{"([bad"}}}
		}, "正则非法"},
		{"非法状态码", func(t *Template) { t.HTTP[0].Matchers[0].Status = []int{999} }, "非法状态码"},
		{"未知变量", func(t *Template) { t.HTTP[0].Path = []string{"{{BaseURL}}/{{Nope}}"} }, "未知变量"},
		{"非法 severity", func(t *Template) { t.Info.Severity = "super" }, "非法 severity"},
		{"写方法未声明侵入性", func(t *Template) { t.HTTP[0].Method = "POST" }, "intrusive"},
		{"破坏性关键字", func(t *Template) { t.HTTP[0].Body = "DROP TABLE users" }, "破坏性关键字"},
		{"非法 matchers-condition", func(t *Template) { t.HTTP[0].MatchersCondition = "xor" }, "matchers-condition"},
	}
	for _, c := range cases {
		tpl := base()
		c.mutate(tpl)
		err := Validate(tpl)
		if err == nil {
			t.Errorf("%s: 应校验失败", c.name)
			continue
		}
		if !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: 错误信息应包含 %q，实际 %v", c.name, c.want, err)
		}
	}
	// 声明了 intrusive 之后 POST 应放行
	tpl := base()
	tpl.Intrusive = true
	tpl.HTTP[0].Method = "POST"
	if err := Validate(tpl); err != nil {
		t.Errorf("声明 intrusive 后 POST 应通过校验: %v", err)
	}
}

func TestLoadBuiltinTemplates(t *testing.T) {
	tpls, err := Load(LoadOptions{IncludeBuiltin: true})
	if err != nil {
		t.Fatalf("加载内置模板失败: %v", err)
	}
	if len(tpls) < 10 {
		t.Errorf("内置模板过少: %d", len(tpls))
	}
	ids := map[string]bool{}
	for _, tpl := range tpls {
		if ids[tpl.ID] {
			t.Errorf("模板 id 重复: %s", tpl.ID)
		}
		ids[tpl.ID] = true
		if tpl.Source == "" {
			t.Errorf("模板 %s 缺少来源标记", tpl.ID)
		}
	}
	// 标签与级别过滤
	only, err := Load(LoadOptions{IncludeBuiltin: true, Tags: []string{"nacos"}})
	if err != nil {
		t.Fatalf("按标签过滤失败: %v", err)
	}
	if len(only) != 1 || !strings.Contains(only[0].ID, "nacos") {
		t.Errorf("标签过滤错误: %v", only)
	}
	high, err := Load(LoadOptions{IncludeBuiltin: true, Severity: "high"})
	if err != nil {
		t.Fatalf("按级别过滤失败: %v", err)
	}
	for _, tpl := range high {
		if severityRank(tpl.Info.Severity) < severityRank("high") {
			t.Errorf("级别过滤错误: %s=%s", tpl.ID, tpl.Info.Severity)
		}
	}
	// 空结果要报错，而不是静默返回空集
	if _, err := Load(LoadOptions{IncludeBuiltin: true, Tags: []string{"no-such-tag"}}); err == nil {
		t.Error("过滤后为空应报错")
	}
}

// ---------------- 引擎端到端 ----------------

// 关键用例：正常站点上跑全部内置模板，必须**零命中**（误报零容忍）
func TestEngineZeroFalsePositiveOnNormalSite(t *testing.T) {
	mux := http.NewServeMux()
	// 内容丰富的正常页面：含近似词（open/paths/status UP）但都不该触发模板
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Server", "nginx/1.25.3")
		fmt.Fprint(w, `<html><head><title>企业门户 - 首页</title></head><body>
			<h1>欢迎</h1>
			<p>我们提供 open 的技术服务，文档 paths 见下。</p>
			<form action="/search" method="get"><input name="q"></form>
			<a href="/about">关于我们</a>
			<script>var cfg = {status: "UP", version: "1.2.3"};</script>
			</body></html>`)
	})
	// JSON 接口：含 status UP 与 version，但不在模板检查的路径上
	mux.HandleFunc("/api/status", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"status":"UP","version":"1.2.3","items":[]}`)
	})
	mux.HandleFunc("/about", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><head><title>关于我们</title></head><body>about</body></html>`)
	})
	// 404 页面里刻意放一些"看起来像证据"的字样
	mux.HandleFunc("/missing", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(404)
		fmt.Fprint(w, `<html><head><title>404</title></head><body>Not Found: [core] index of nothing</body></html>`)
	})

	srv := httptest.NewServer(mux)
	defer srv.Close()

	tpls, err := Load(LoadOptions{IncludeBuiltin: true})
	if err != nil {
		t.Fatalf("加载模板失败: %v", err)
	}
	eng := testEngine(t, tpls, Options{Verify: true})
	findings := eng.ScanOne(context.Background(), targetFor(t, srv))
	if len(findings) != 0 {
		for _, f := range findings {
			t.Errorf("正常站点出现误报: 模板=%s 命中=%s 理由=%s", f.TemplateID, f.MatchedAt, f.Evidence.Matcher)
		}
		t.Fatalf("误报数 = %d，要求为 0", len(findings))
	}
}

// 靶机：逐一提供模板对应的暴露点，必须全部命中
func TestEngineDetectsExposedEndpoints(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/.git/config", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n[remote \"origin\"]\n\turl = https://git.example.com/app.git\n")
	})
	mux.HandleFunc("/.env", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "APP_ENV=production\nDB_PASSWORD=Sup3rSecretValue\nAPI_KEY=abcdef1234567890\n")
	})
	mux.HandleFunc("/actuator/env", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"activeProfiles":[],"propertySources":[{"name":"systemProperties"}]}`)
	})
	mux.HandleFunc("/nacos/v1/auth/users", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"totalCount":2,"pageItems":[{"username":"nacos","password":"$2a$10$xxx"}]}`)
	})
	mux.HandleFunc("/_cat/indices", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "green open users  1 0 10 0 10kb 10kb\nyellow open logs 1 0 5 0 5kb 5kb\n")
	})
	mux.HandleFunc("/version", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"Platform":{"Name":""},"Version":"20.10.21","ApiVersion":"1.41","MinAPIVersion":"1.12","Os":"linux"}`)
	})
	mux.HandleFunc("/phpinfo.php", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `<html><head><title>phpinfo()</title></head><body><h1>PHP Version 8.2.1</h1><p>Loaded Configuration File /etc/php.ini</p></body></html>`)
	})
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "# HELP go_gc_duration_seconds A summary of the GC invocation durations.\n# TYPE go_gc_duration_seconds summary\ngo_gc_duration_seconds{quantile=\"0\"} 1e-05\n")
	})
	mux.HandleFunc("/swagger-ui.html", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `<html><head><title>Swagger UI</title></head><body><div id="swagger-ui"></div></body></html>`)
	})
	mux.HandleFunc("/api/json", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"_class":"hudson.model.Hudson","jobs":[]}`)
	})
	// CORS 反射任意来源且允许凭据
	mux.HandleFunc("/cors/", func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin != "" {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Credentials", "true")
		}
		fmt.Fprint(w, "ok")
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	tpls, err := Load(LoadOptions{IncludeBuiltin: true})
	if err != nil {
		t.Fatalf("加载模板失败: %v", err)
	}
	eng := testEngine(t, tpls, Options{Timeout: 3 * time.Second})
	findings := eng.ScanOne(context.Background(), targetFor(t, srv))

	want := []string{
		"git-config-exposure", "env-file-exposure", "springboot-actuator-env",
		"nacos-unauthorized-user-list", "elasticsearch-unauthorized-cat",
		"docker-api-unauthorized-version", "phpinfo-exposure",
		"prometheus-metrics-exposure", "swagger-ui-exposure", "jenkins-unauthorized-api",
	}
	got := map[string]bool{}
	for _, f := range findings {
		got[f.TemplateID] = true
	}
	for _, id := range want {
		if !got[id] {
			t.Errorf("漏报: %s（命中 %v）", id, keys(got))
		}
	}
	// 每条命中都必须带可复现证据
	for _, f := range findings {
		if f.Evidence.Request == "" || f.Evidence.Response == "" {
			t.Errorf("%s 缺少证据: %+v", f.TemplateID, f.Evidence)
		}
		if f.MatchedAt == "" || f.Severity == "" {
			t.Errorf("%s 缺少命中地址或级别", f.TemplateID)
		}
	}
	// 提取器应拿到关键字段
	for _, f := range findings {
		if f.TemplateID == "docker-api-unauthorized-version" {
			if joined := strings.Join(f.Extracted["docker_version"], ","); !strings.Contains(joined, "20.10.21") {
				t.Errorf("docker 版本提取失败: %v", f.Extracted)
			}
		}
	}
}

func keys(m map[string]bool) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}

// 二次确认必须能压制"偶发命中"
func TestEngineVerifySuppressesFlakyMatch(t *testing.T) {
	var count int32
	mux := http.NewServeMux()
	mux.HandleFunc("/flaky", func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&count, 1)%2 == 1 {
			fmt.Fprint(w, "MARKER-PRESENT")
			return
		}
		fmt.Fprint(w, "marker-absent")
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	tpls := []*Template{{
		ID:   "flaky",
		Info: Info{Name: "flaky", Severity: "low"},
		HTTP: []HTTPRequest{{
			Path:     []string{"{{BaseURL}}/flaky"},
			Matchers: []Matcher{{Type: "word", Words: []string{"MARKER-PRESENT"}}},
		}},
	}}
	// 不开 verify：命中
	eng := testEngine(t, tpls, Options{})
	if got := eng.ScanOne(context.Background(), targetFor(t, srv)); len(got) != 1 {
		t.Fatalf("未开启 verify 时应命中一次，实际 %d", len(got))
	}
	// 开 verify：两次结果不一致，必须丢弃
	atomic.StoreInt32(&count, 0)
	eng2 := testEngine(t, tpls, Options{Verify: true})
	if got := eng2.ScanOne(context.Background(), targetFor(t, srv)); len(got) != 0 {
		t.Fatalf("verify 应压制偶发命中，实际 %d 条", len(got))
	}
}

// 侵入性模板默认不执行
func TestEngineIntrusiveGated(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "INTRUSIVE-MARKER")
	}))
	defer srv.Close()

	tpls := []*Template{{
		ID:        "intrusive",
		Info:      Info{Name: "写操作模板", Severity: "high"},
		Intrusive: true,
		HTTP: []HTTPRequest{{
			Method:   "POST",
			Path:     []string{"{{BaseURL}}/x"},
			Matchers: []Matcher{{Type: "word", Words: []string{"INTRUSIVE-MARKER"}}},
		}},
	}}
	eng := testEngine(t, tpls, Options{})
	if got := eng.ScanOne(context.Background(), targetFor(t, srv)); len(got) != 0 {
		t.Fatalf("未授权侵入性模板不应执行，实际命中 %d", len(got))
	}
	eng2 := testEngine(t, tpls, Options{AllowIntrusive: true})
	if got := eng2.ScanOne(context.Background(), targetFor(t, srv)); len(got) != 1 {
		t.Fatalf("显式放行后应命中，实际 %d", len(got))
	}
}

// 证据里的凭据必须掩码
func TestEvidenceMasksSecrets(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "DB_PASSWORD=Sup3rSecretValue\nAKIAIOSFODNN7EXAMPLE\nAuthorization: Bearer abcdefghijklmnopqrst\n")
	}))
	defer srv.Close()

	tpls := []*Template{{
		ID:   "leak",
		Info: Info{Name: "leak", Severity: "high"},
		HTTP: []HTTPRequest{{
			Path:     []string{"{{BaseURL}}/leak"},
			Matchers: []Matcher{{Type: "word", Words: []string{"DB_PASSWORD"}}},
		}},
	}}
	eng := testEngine(t, tpls, Options{})
	got := eng.ScanOne(context.Background(), targetFor(t, srv))
	if len(got) != 1 {
		t.Fatalf("应命中 1 条，实际 %d", len(got))
	}
	ev := got[0].Evidence.Response
	for _, secret := range []string{"Sup3rSecretValue", "AKIAIOSFODNN7EXAMPLE", "abcdefghijklmnopqrst"} {
		if strings.Contains(ev, secret) {
			t.Errorf("证据泄露明文凭据 %q:\n%s", secret, ev)
		}
	}
}

// OOB 外带验证：假靶机收到请求后回连监听器
func TestEngineOOBCallback(t *testing.T) {
	oob, err := NewOOB("127.0.0.1:0", "")
	if err != nil {
		t.Fatalf("创建 OOB 失败: %v", err)
	}
	oob.Start()
	defer oob.Stop()

	// 模拟"无回显"漏洞：靶机把 payload 当 URL 请求出去（SSRF/盲打）
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw := r.URL.Query().Get("url")
		if raw != "" {
			if u, err := url.Parse(raw); err == nil {
				client := &http.Client{Timeout: 2 * time.Second}
				if resp, err := client.Get(u.String()); err == nil {
					resp.Body.Close()
				}
			}
		}
		fmt.Fprint(w, "accepted") // 页面本身没有任何回显
	}))
	defer srv.Close()

	tpls := []*Template{{
		ID:   "blind-ssrf",
		Info: Info{Name: "盲 SSRF", Severity: "high", Confidence: "high"},
		HTTP: []HTTPRequest{{
			Path: []string{"{{BaseURL}}/fetch?url={{oob_url}}"},
			Matchers: []Matcher{
				{Type: "word", Words: []string{"accepted"}},
			},
		}},
	}}
	eng := testEngine(t, tpls, Options{OOB: oob, Timeout: 3 * time.Second})
	got := eng.ScanOne(context.Background(), targetFor(t, srv))
	if len(got) != 1 {
		t.Fatalf("应命中 1 条，实际 %d", len(got))
	}
	if !got[0].Verified {
		t.Errorf("OOB 回连后应标记为已验证: %+v", got[0])
	}
	if !strings.Contains(got[0].Evidence.Matcher, "OOB 回连") {
		t.Errorf("证据应记录 OOB 回连: %s", got[0].Evidence.Matcher)
	}
}

func TestTargetFromURL(t *testing.T) {
	cases := []struct {
		raw    string
		scheme string
		host   string
		port   int
		ok     bool
	}{
		{"https://a.example.com/x/y", "https", "a.example.com", 443, true},
		{"http://a.example.com:8080/", "http", "a.example.com", 8080, true},
		{"ftp://a.example.com", "", "", 0, false},
		{"", "", "", 0, false},
	}
	for _, c := range cases {
		got, ok := TargetFromURL(c.raw, "1.2.3.4")
		if ok != c.ok {
			t.Errorf("TargetFromURL(%q) ok=%v，期望 %v", c.raw, ok, c.ok)
			continue
		}
		if !ok {
			continue
		}
		if got.Scheme != c.scheme || got.Host != c.host || got.Port != c.port {
			t.Errorf("TargetFromURL(%q) = %+v", c.raw, got)
		}
	}
}

func TestSeverityAtLeast(t *testing.T) {
	if !SeverityAtLeast("critical", "high") {
		t.Error("critical 应 >= high")
	}
	if SeverityAtLeast("low", "high") {
		t.Error("low 不应 >= high")
	}
	if !SeverityAtLeast("info", "") {
		t.Error("空阈值表示不限制")
	}
}
