package poc

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// 规则库金丝雀门禁（M7）。
//
// 模板库最危险的失效模式不是"报错"，而是**写了却永远不命中**：路径写错、匹配器太严、
// 正则用了 RE2 不支持的语法、变量名拼错。加载期校验只能挡住"格式非法"，
// 挡不住"语法正确但逻辑是死的"。所以每条模板都必须有一份金丝雀夹具
// （scripts/rules-fixtures/*.json），声明"命中它时长什么样"，
// 本测试用真实的匹配器把它跑一遍 —— 死模板在这里就会被抓出来。
//
// 同时做反向检查：这些匹配器打在**干净页面**上必须一条都不命中（误报门禁）。

// fixture 是金丝雀夹具的 schema，与 scripts/fake-services.py 的金丝雀站点共用。
type fixture struct {
	TemplateID  string            `json:"template_id"`
	Path        string            `json:"path"`
	Status      int               `json:"status"`
	ContentType string            `json:"content_type"`
	Headers     map[string]string `json:"headers"`
	Body        string            `json:"body"`
	AlsoServes  []string          `json:"also_serves"`
	// Expect 为空表示"这个响应应当命中"；填 "no-match" 表示"这个响应**不该**命中"。
	//
	// 为什么需要负样本：很多设备的真实行为是先 302 跳到登录页。
	// 如果模板只认 200，那它在真机上永远不会命中 —— 而"302 页面的空 body"
	// 又绝不能算命中（否则任何跳转都成了漏洞）。两种情况都必须被固化下来测。
	Expect string `json:"expect"`
}

// canaryVars 是金丝雀测试用的变量集合。
//
// 为什么固定 randstr：CORS 类模板用 `wor-{{randstr}}.example.com` 做回显验证，
// 夹具里必须写死一个具体值才能断言；真机上由引擎注入随机值、由靶站回显 Origin。
var canaryVars = Vars{"randstr": "canary", "randstr_1": "canary1", "randstr_2": "canary2"}
var libraryGroups = []string{
	"builtin-exposure.json",
	"builtin-exposure-web.json",
	"builtin-exposure-cn.json",
}

func loadFixtures(t *testing.T) []fixture {
	t.Helper()
	dir := filepath.Join("..", "..", "scripts", "rules-fixtures")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("读取夹具目录失败（%s）: %v", dir, err)
	}
	var out []fixture
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatalf("读取夹具 %s 失败: %v", e.Name(), err)
		}
		var items []fixture
		if err := json.Unmarshal(raw, &items); err != nil {
			t.Fatalf("夹具 %s 不是合法 JSON 数组: %v", e.Name(), err)
		}
		for i := range items {
			if items[i].TemplateID == "" || items[i].Path == "" {
				t.Errorf("夹具 %s 第 %d 条缺少 template_id 或 path", e.Name(), i+1)
			}
		}
		out = append(out, items...)
	}
	return out
}

// templateIDsIn 解析指定内置模板文件里声明的 id（用于"模板↔夹具一一对应"检查）。
func templateIDsIn(t *testing.T, name string) []string {
	t.Helper()
	raw, err := builtinFS.ReadFile("templates/" + name)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		t.Fatalf("读取内置模板 %s 失败: %v", name, err)
	}
	var items []struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(raw, &items); err != nil {
		t.Fatalf("内置模板 %s 解析失败: %v", name, err)
	}
	ids := make([]string, 0, len(items))
	for _, it := range items {
		ids = append(ids, it.ID)
	}
	return ids
}

// responseFrom 把夹具还原成一次"响应快照"，交给真实匹配器判定。
func responseFrom(f fixture) *Response {
	h := http.Header{}
	for k, v := range f.Headers {
		h.Set(k, v)
	}
	if f.ContentType != "" && h.Get("Content-Type") == "" {
		h.Set("Content-Type", f.ContentType)
	}
	status := f.Status
	if status == 0 {
		status = 200
	}
	return &Response{
		URL:     "http://canary.local" + f.Path,
		Status:  status,
		Headers: h,
		Body:    []byte(f.Body),
		Title:   extractTitle([]byte(f.Body)),
	}
}

func templateByID(t *testing.T, templates []*Template, id string) *Template {
	t.Helper()
	for _, tpl := range templates {
		if tpl.ID == id {
			return tpl
		}
	}
	return nil
}

// TestLibraryFixturesMatchTheirTemplates 是"每条模板都必须能命中自己的金丝雀"的门禁。
func TestLibraryFixturesMatchTheirTemplates(t *testing.T) {
	templates, err := Load(LoadOptions{IncludeBuiltin: true})
	if err != nil {
		t.Fatalf("加载内置模板失败: %v", err)
	}
	fixtures := loadFixtures(t)
	if len(fixtures) == 0 {
		t.Fatal("没有读到任何金丝雀夹具，规则库门禁形同虚设")
	}

	seenPath := map[string]string{}
	for _, f := range fixtures {
		if prev, dup := seenPath[f.Path]; dup {
			t.Errorf("夹具路径重复 %s：%s 与 %s（金丝雀站点按精确路径返回，重复会导致其中一条永远测不到）",
				f.Path, prev, f.TemplateID)
		}
		seenPath[f.Path] = f.TemplateID

		tpl := templateByID(t, templates, f.TemplateID)
		if tpl == nil {
			t.Errorf("夹具 %s 指向的模板 %q 不存在（拼错 id 或模板未加载）", f.Path, f.TemplateID)
			continue
		}
		resp := responseFrom(f)
		hit := false
		var whys []string
		for i := range tpl.HTTP {
			req := &tpl.HTTP[i]
			// 夹具按路径精确匹配，所以只要求"命中该路径的那个请求"匹配成功；
			// 多请求模板（例如先探测再验证）只要有一个请求命中即视为模板可命中。
			if !requestCoversPath(req, f.Path) {
				continue
			}
			mr := EvaluateMatchers(req.Matchers, req.MatchersCondition, resp, canaryVars)
			whys = append(whys, mr.Why)
			if mr.Hit {
				hit = true
				break
			}
		}
		if strings.EqualFold(f.Expect, "no-match") {
			// 负样本：这个响应**不该**被判成命中（例如 302 跳转的空页面）
			if hit {
				t.Errorf("夹具 %s（%s）声明为 no-match，但模板 %s 却命中了：%s",
					f.Path, f.TemplateID, f.TemplateID, strings.Join(whys, " | "))
			}
			continue
		}
		if !hit {
			t.Errorf("模板 %s 在它自己的金丝雀夹具（%s）上**没有命中** —— 这是一条死模板；匹配理由: %s",
				f.TemplateID, f.Path, strings.Join(whys, " | "))
		}
		// also_serves：同一条夹具声明还能喂给别的模板
		for _, extra := range f.AlsoServes {
			other := templateByID(t, templates, extra)
			if other == nil {
				t.Errorf("夹具 %s 的 also_serves 指向不存在的模板 %q", f.Path, extra)
				continue
			}
			ok := false
			for i := range other.HTTP {
				req := &other.HTTP[i]
				if !requestCoversPath(req, f.Path) {
					continue
				}
				if EvaluateMatchers(req.Matchers, req.MatchersCondition, resp, canaryVars).Hit {
					ok = true
					break
				}
			}
			if !ok {
				t.Errorf("模板 %s 在共享夹具（%s）上没有命中", extra, f.Path)
			}
		}
	}
}

// TestTemplateIDCollisionPolicy 锁定"同 id 覆盖"的允许范围。
//
// 为什么值得一条测试：规则库分成多批文件后，"两个内置文件撞 id"是最隐蔽的错误——
// 两条模板都在库里、只有一条生效，没有任何提示。外置覆盖内置是合法用法，必须继续允许。
func TestTemplateIDCollisionPolicy(t *testing.T) {
	builtinA := &Template{ID: "x", Source: "builtin:a.json"}
	builtinB := &Template{ID: "x", Source: "builtin:b.json"}
	if err := checkIDCollision(builtinA, builtinB); err == nil {
		t.Error("两个内置文件定义同一个 id 必须报错（否则其中一条永远不生效）")
	}
	external := &Template{ID: "x", Source: "/tmp/my.json"}
	if err := checkIDCollision(builtinA, external); err != nil {
		t.Errorf("外置覆盖内置是合法用法，不应报错: %v", err)
	}
	if err := checkIDCollision(external, &Template{ID: "x", Source: "/tmp/other.json"}); err != nil {
		t.Errorf("外置之间后者覆盖前者是合法用法，不应报错: %v", err)
	}
}

// TestLibraryEveryTemplateHasFixture 保证 M7 规则批次里"每条模板都有金丝雀"，
// 避免有人加了模板却忘了夹具（那样这条模板就永远没被真跑验证过）。
func TestLibraryEveryTemplateHasFixture(t *testing.T) {
	fixtures := loadFixtures(t)
	covered := map[string]bool{}
	for _, f := range fixtures {
		// 只有"正向夹具"才算覆盖：no-match 只说明某个响应不该命中，
		// 不能证明这条模板打得中（否则一条死模板配一个负样本就能骗过门禁）。
		if strings.EqualFold(f.Expect, "no-match") {
			continue
		}
		covered[f.TemplateID] = true
		for _, extra := range f.AlsoServes {
			covered[extra] = true
		}
	}
	var missing []string
	for _, group := range libraryGroups {
		for _, id := range templateIDsIn(t, group) {
			if !covered[id] {
				missing = append(missing, id)
			}
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Errorf("以下 %d 条模板没有金丝雀夹具（等于从未被真跑验证过）: %s",
			len(missing), strings.Join(missing, ", "))
	}
}

// cleanPage 是"干净站点"的响应：正常业务页面 + 一点容易误伤的文案
// （open/paths/status UP），与 scripts/demo-m4.ps1 里的干净站点保持一致。
const cleanPage = `<html><head><title>Clean Site</title></head><body>
<h1>正常站点</h1>
<p>open 的服务说明、paths 目录、status UP 的文案都在这里。</p>
<form action="/login" method="get"><input name="q"></form>
</body></html>`

// TestLibraryNoFalsePositiveOnCleanPage 是误报门禁：所有规则库模板打在干净页面上必须 0 命中。
//
// 注意这里用的是"根路径响应"——真实扫描里每条模板都会打自己的路径，
// 干净站点对未知路径返回 404，这正是最容易出现"404 页面被误判为漏洞"的场景。
func TestLibraryNoFalsePositiveOnCleanPage(t *testing.T) {
	templates, err := Load(LoadOptions{IncludeBuiltin: true})
	if err != nil {
		t.Fatalf("加载内置模板失败: %v", err)
	}
	// 两个场景：200 的正常首页；未知路径的 404（内容为站点自己的 404 页）。
	scenarios := map[string]*Response{
		"clean-200": {
			URL: "http://clean.local/", Status: 200,
			Headers: http.Header{"Content-Type": []string{"text/html; charset=utf-8"}},
			Body:    []byte(cleanPage), Title: "Clean Site",
		},
		"clean-404": {
			URL: "http://clean.local/whatever", Status: 404,
			Headers: http.Header{"Content-Type": []string{"text/html; charset=utf-8"}},
			Body:    []byte("<html><head><title>404 Not Found</title></head><body><h1>404</h1><p>The requested URL was not found.</p></body></html>"),
			Title:   "404 Not Found",
		},
	}
	for name, resp := range scenarios {
		for _, tpl := range templates {
			for i := range tpl.HTTP {
				req := &tpl.HTTP[i]
				if mr := EvaluateMatchers(req.Matchers, req.MatchersCondition, resp, nil); mr.Hit {
					t.Errorf("[%s] 模板 %s 在干净响应上误报命中: %s", name, tpl.ID, mr.Why)
				}
			}
		}
	}
}

// TestLibraryNoEmptyMatchingRegex 拦住模板里"能在空串上命中"的正则。
//
// 一条匹配空串的 body 正则 + 一个 status:200 匹配器 = 在任何站点上都命中。
// 这类模板是误报的主要来源，必须在加载测试里就拦下。
func TestLibraryNoEmptyMatchingRegex(t *testing.T) {
	templates, err := Load(LoadOptions{IncludeBuiltin: true})
	if err != nil {
		t.Fatalf("加载内置模板失败: %v", err)
	}
	for _, tpl := range templates {
		for i := range tpl.HTTP {
			req := &tpl.HTTP[i]
			for _, m := range req.Matchers {
				for _, p := range m.Regex {
					re, err := regexp.Compile(p)
					if err != nil {
						t.Errorf("模板 %s 的正则 %q 非法: %v", tpl.ID, p, err)
						continue
					}
					if re.MatchString("") {
						t.Errorf("模板 %s 的正则 %q 能匹配空串 —— 配上状态码匹配器就会在任何目标上命中（误报源）",
							tpl.ID, p)
					}
				}
			}
		}
	}
}

// requestCoversPath 判断该请求是否就是打夹具那个路径的请求。
// 路径可能带变量（{{BaseURL}}/x）和查询串（?a=1），这里只比对静态路径部分。
func requestCoversPath(req *HTTPRequest, fixturePath string) bool {
	want := strings.TrimSuffix(fixturePath, "/")
	for _, p := range req.Path {
		got := strings.TrimPrefix(strings.TrimPrefix(p, "{{BaseURL}}"), "{{RootURL}}")
		if i := strings.Index(got, "?"); i >= 0 {
			got = got[:i]
		}
		got = strings.TrimSuffix(got, "/")
		if got == "" {
			got = "/"
		}
		if got == want || (want == "" && got == "/") {
			return true
		}
	}
	return false
}
