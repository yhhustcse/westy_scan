package poc

// 本文件只做**加载校验与夹具自检**，不修改任何引擎代码。
//
// 覆盖三件事：
//  1. 新增的国产暴露面模板文件能被内置加载器接受（编译期校验全过）；
//  2. scripts/rules-fixtures/cn.json 里每条夹具都能命中它声明的模板（防止"模板写了但永远不命中"）；
//  3. 同一条夹具不会意外命中别的模板（防止夹具之间互相污染，掩盖真实匹配条件）。
//
// 关于夹具格式：与验收靶站一致（template_id/path/status/content_type/headers/body），
// 可选字段 also_serves（同路径多模板）、redirects="跟随跳转后才拿到的响应"。

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// cnTemplateIDs 是本次新增模板的全部 id。夹具与模板必须严格一一对应。
var cnTemplateIDs = []string{
	// 国产 OA / 协同
	"weaver-ecology-wui-exposure",
	"weaver-eoffice-panel-exposure",
	"seeyon-oa-panel-exposure",
	"landray-ekp-panel-exposure",
	"tongda-oa-login-code-exposure",
	"huatian-oa-panel-exposure",
	// 国产 ERP / 财务
	"yonyou-nc-portal-exposure",
	"yonyou-yonsuite-panel-exposure",
	"kingdee-eas-panel-exposure",
	"kingdee-k3cloud-panel-exposure",
	"inspur-gs-panel-exposure",
	"sap-netweaver-portal-exposure",
	// 国产数据库 / 中间件管理端
	"dameng-dmweb-console-exposure",
	"kingbase-web-console-exposure",
	"oceanbase-ocp-console-exposure",
	"tidb-dashboard-exposure",
	"tongweb-console-exposure",
	"bes-console-exposure",
	"inforSuite-console-exposure",
	// 网管 / 运维平台
	"huawei-esight-panel-exposure",
	"h3c-imc-panel-exposure",
	"ruijie-riil-panel-exposure",
	"sangfor-ac-panel-exposure",
	"sangfor-af-panel-exposure",
	"manageengine-opmanager-api-exposure",
	"solarwinds-orion-login-exposure",
	"prtg-web-panel-exposure",
	"jumpserver-panel-exposure",
	"shterm-bastion-panel-exposure",
	"cloudbility-bastion-panel-exposure",
	// 安防 / 物联网设备
	"hikvision-device-login-exposure",
	"hikvision-isapi-devinfo-exposure",
	"dahua-current-config-exposure",
	"dahua-rpc2-login-exposure",
	"uniview-device-login-exposure",
	"axis-cgi-panel-exposure",
	"dvr-nvr-web-panel-exposure",
	// 网络 / 安全设备
	"fortinet-fortigate-panel-exposure",
	"paloalto-globalprotect-panel-exposure",
	"sonicwall-auth-panel-exposure",
	"cisco-asa-login-exposure",
	"f5-bigip-tmui-exposure",
	"citrix-netscaler-vpn-exposure",
	"sangfor-ssl-vpn-panel-exposure",
	"array-networks-sslvpn-exposure",
	"hillstone-panel-exposure",
	// 存储 / 打印机管理口
	"synology-dsm-panel-exposure",
	"qnap-qts-panel-exposure",
	"hp-printer-ews-exposure",
	"truenas-webui-exposure",
}

// cnFixture 与靶站夹具文件同构；body 用 any 以兼容字符串或对象两种写法。
type cnFixture struct {
	TemplateID  string            `json:"template_id"`
	AlsoServes  []string          `json:"also_serves,omitempty"`
	Path        string            `json:"path"`
	Status      int               `json:"status,omitempty"`
	ContentType string            `json:"content_type,omitempty"`
	Headers     map[string]string `json:"headers,omitempty"`
	Body        any               `json:"body,omitempty"`
	Redirects   bool              `json:"redirects,omitempty"`
	Note        string            `json:"note,omitempty"`
}

func (f cnFixture) status() int {
	if f.Status == 0 {
		return 200
	}
	return f.Status
}

func (f cnFixture) bodyBytes() []byte {
	switch v := f.Body.(type) {
	case nil:
		return nil
	case string:
		return []byte(v)
	default:
		// 允许 body 写成 JSON 对象（接口类夹具更自然）
		b, err := json.Marshal(v)
		if err != nil {
			return nil
		}
		return b
	}
}

// loadCNFixtures 读取 scripts/rules-fixtures/cn.json。
func loadCNFixtures(t *testing.T) []cnFixture {
	t.Helper()
	path := filepath.Join("..", "..", "scripts", "rules-fixtures", "cn.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("读取夹具文件失败（%s）: %v", path, err)
	}
	var list []cnFixture
	if err := json.Unmarshal(raw, &list); err != nil {
		t.Fatalf("解析夹具文件失败: %v", err)
	}
	if len(list) == 0 {
		t.Fatal("夹具文件为空")
	}
	return list
}

// loadCNTemplates 只取新增模板，按 id 建索引。
func loadCNTemplates(t *testing.T) map[string]*Template {
	t.Helper()
	tpls, err := Load(LoadOptions{IncludeBuiltin: true})
	if err != nil {
		t.Fatalf("加载内置模板失败: %v", err)
	}
	want := map[string]bool{}
	for _, id := range cnTemplateIDs {
		want[id] = true
	}
	out := map[string]*Template{}
	for _, tpl := range tpls {
		if want[tpl.ID] {
			out[tpl.ID] = tpl
		}
	}
	return out
}

// stripQuery 去掉 scheme://host 前缀、查询串与锚点，与靶站"按去掉查询串后的精确路径返回"保持一致。
func stripQuery(u string) string {
	if i := strings.IndexAny(u, "?#"); i >= 0 {
		u = u[:i]
	}
	if i := strings.Index(u, "://"); i >= 0 {
		rest := u[i+3:]
		if j := strings.Index(rest, "/"); j >= 0 {
			u = rest[j:]
		} else {
			u = "/"
		}
	}
	if u == "" {
		u = "/"
	}
	return u
}

// cnVars 用固定的合成目标渲染变量，保证夹具路径比较是确定性的。
func cnVars(t *testing.T) Vars {
	t.Helper()
	return NewEngine(nil, Options{}).baseVars(Target{Scheme: "http", Host: "127.0.0.1", Port: 8080, Path: "/"})
}

// requestPaths 返回模板里所有请求路径渲染后的结果（与 target 无关的确定性比较用）。
func requestPaths(tpl *Template, vars Vars) []string {
	var out []string
	for _, req := range tpl.HTTP {
		for _, raw := range req.Path {
			out = append(out, stripQuery(Render(raw, vars)))
		}
	}
	return out
}

// resolveFixture 沿夹具里的 3xx + Location 往下走，返回模板"最终看到"的那份响应。
// 引擎在模板声明 redirects:true 时会跟随跳转，合成校验也必须跟随，否则会把
// "登录页可达" 误判成漏报。
func resolveFixture(t *testing.T, fx cnFixture, routes map[string]cnFixture) (cnFixture, string) {
	t.Helper()
	cur := fx
	for hop := 0; hop < 3; hop++ {
		if cur.status() < 300 || cur.status() >= 400 {
			break
		}
		loc := stripQuery(cur.Headers["Location"])
		if loc == "" {
			break
		}
		next, ok := routes[loc]
		if !ok {
			t.Logf("夹具 %s 的跳转目标 %s 没有夹具，按跳转响应本身判定", cur.TemplateID, loc)
			break
		}
		cur = next
	}
	return cur, stripQuery(cur.Path)
}

// fireCNFixture 用夹具（含跳转链）构造合成响应，把模板里路径对得上的请求逐个试一遍。
// 命中要求：渲染后的路径（去查询串）与该夹具 path 完全一致，且该请求的匹配器全部通过。
func fireCNFixture(t *testing.T, tpl *Template, fx cnFixture, why string, routes map[string]cnFixture) bool {
	t.Helper()
	final, finalPath := resolveFixture(t, fx, routes)
	body := final.bodyBytes()
	hdr := http.Header{}
	for k, v := range final.Headers {
		hdr.Set(k, v)
	}
	if final.ContentType != "" {
		hdr.Set("Content-Type", final.ContentType)
	}
	resp := &Response{
		URL:     "http://127.0.0.1:8080" + finalPath,
		Status:  final.status(),
		Headers: hdr,
		Body:    body,
		Title:   extractTitle(body),
	}
	vars := cnVars(t)

	skipped := map[string]bool{}
	for _, req := range tpl.HTTP {
		for _, raw := range req.Path {
			got := stripQuery(Render(raw, vars))
			if got != stripQuery(fx.Path) {
				if !skipped[got] {
					skipped[got] = true
					t.Logf("夹具 %s（%s）与模板 %s 的路径 %s 不一致，跳过该路径",
						fx.TemplateID, fx.Path, tpl.ID, got)
				}
				continue
			}
			if mr := EvaluateMatchers(req.Matchers, req.MatchersCondition, resp, vars); mr.Hit {
				t.Logf("命中 %s <- 夹具 %s（%s，最终 %s）: %s", tpl.ID, fx.TemplateID, why, finalPath, mr.Why)
				return true
			} else {
				t.Logf("夹具 %s 路径命中但匹配器未通过（模板 %s）: %s", fx.TemplateID, tpl.ID, mr.Why)
			}
		}
	}
	return false
}

// newFixtureServer 按夹具文件起一个"金丝雀靶站"：只认精确路径，未知路径一律 404。
func newFixtureServer(t *testing.T, routes map[string]cnFixture) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fx, ok := routes[r.URL.Path]
		if !ok {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprint(w, "404 page not found")
			return
		}
		for k, v := range fx.Headers {
			w.Header().Set(k, v)
		}
		if fx.ContentType != "" {
			w.Header().Set("Content-Type", fx.ContentType)
		}
		w.WriteHeader(fx.status())
		w.Write(fx.bodyBytes())
	}))
}

// ---------------- 1. 加载期校验 ----------------

func TestCNTemplatesLoad(t *testing.T) {
	tpls, err := Load(LoadOptions{IncludeBuiltin: true})
	if err != nil {
		t.Fatalf("加载内置模板失败: %v", err)
	}
	t.Logf("内置模板总数 = %d（其中本次新增 %d 条）", len(tpls), len(cnTemplateIDs))

	byID := map[string]*Template{}
	for _, tpl := range tpls {
		byID[tpl.ID] = tpl
	}
	for _, id := range cnTemplateIDs {
		tpl, ok := byID[id]
		if !ok {
			t.Errorf("新增模板未加载: %s", id)
			continue
		}
		if tpl.Source != "builtin:builtin-exposure-cn.json" {
			t.Errorf("%s 来源不符: %s", id, tpl.Source)
		}
		// 只读约束：非 intrusive 模板不得出现写方法
		for i, req := range tpl.HTTP {
			if !readOnlyMethods[req.Method] {
				t.Errorf("%s 第 %d 个请求用了 %s，只读暴露面模板不允许", id, i+1, req.Method)
			}
			if len(req.Matchers) < 2 {
				t.Errorf("%s 第 %d 个请求只有一个匹配器：状态码 + 产品专有特征是最低要求", id, i+1)
			}
			hasStatus, hasFeature := false, false
			for _, m := range req.Matchers {
				if strings.EqualFold(m.Type, "status") {
					hasStatus = true
					continue
				}
				hasFeature = true
			}
			if !hasStatus || !hasFeature {
				t.Errorf("%s 第 %d 个请求缺少 status 或专有特征匹配器（status=%v feature=%v）", id, i+1, hasStatus, hasFeature)
			}
		}
		if len(tpl.Info.Tags) == 0 {
			t.Errorf("%s 缺少 tags", id)
			continue
		}
		okTag := false
		for _, tag := range tpl.Info.Tags {
			switch strings.ToLower(tag) {
			case "exposure", "unauthorized", "cn-app":
				okTag = true
			}
		}
		if !okTag {
			t.Errorf("%s 的 tags 必须含 exposure/unauthorized/cn-app 之一: %v", id, tpl.Info.Tags)
		}
		if severityRank(tpl.Info.Severity) == 0 {
			t.Errorf("%s 缺少合法 severity", id)
		}
	}
	// 内置模板 id 不应重复（Load 内部按 id 去重，这里再兜一层）
	seen := map[string]bool{}
	for _, tpl := range tpls {
		if seen[tpl.ID] {
			t.Errorf("模板 id 重复: %s", tpl.ID)
		}
		seen[tpl.ID] = true
	}
}

// ---------------- 2/3. 夹具自检 ----------------

func TestCNFixturesMatchTheirTemplates(t *testing.T) {
	fixtures := loadCNFixtures(t)
	byID := loadCNTemplates(t)

	t.Logf("夹具条目 = %d 条，覆盖模板 %d 个", len(fixtures), len(cnTemplateIDs))

	// 夹具自身的结构性约束
	pathOwner := map[string][]string{}
	for i, fx := range fixtures {
		if fx.TemplateID == "" {
			t.Errorf("第 %d 条夹具缺少 template_id", i+1)
			continue
		}
		if !strings.HasPrefix(fx.Path, "/") {
			t.Errorf("夹具 %s 的 path 必须以 / 开头: %q", fx.TemplateID, fx.Path)
		}
		for _, id := range append([]string{fx.TemplateID}, fx.AlsoServes...) {
			if _, ok := byID[id]; !ok {
				t.Errorf("夹具引用了不存在的模板 id: %s", id)
			}
			pathOwner[id] = append(pathOwner[id], stripQuery(fx.Path))
		}
	}
	// 每个模板只允许一条夹具；唯一的例外是"跳转链"：第二条夹具是第一条 Location 的目标，
	// 即模板声明了 redirects:true、靶站跳转后才会返回的那一页。
	for id, paths := range pathOwner {
		if len(paths) <= 1 {
			continue
		}
		redirectChain := false
		for _, fx := range fixtures {
			if fx.TemplateID != id || fx.status() < 300 || fx.status() >= 400 {
				continue
			}
			target := stripQuery(fx.Headers["Location"])
			for _, p := range paths {
				if p != stripQuery(fx.Path) && p == target {
					redirectChain = true
				}
			}
		}
		if !redirectChain {
			t.Errorf("模板 %s 有 %d 条夹具且不是跳转链（%v）：每个模板只允许一条", id, len(paths), paths)
		}
	}
	// 同一路径被不同模板使用必须显式 also_serves（302 链是同模板，允许）
	byPath := map[string][]cnFixture{}
	for _, fx := range fixtures {
		p := stripQuery(fx.Path)
		byPath[p] = append(byPath[p], fx)
	}
	for p, group := range byPath {
		for i := 0; i < len(group); i++ {
			for j := i + 1; j < len(group); j++ {
				if group[i].TemplateID != group[j].TemplateID {
					t.Errorf("路径 %s 被 %s 与 %s 共用，但没有用 also_serves 合并",
						p, group[i].TemplateID, group[j].TemplateID)
				}
			}
		}
	}

	// 每条夹具都必须命中它声明的模板
	routes := map[string]cnFixture{}
	for _, fx := range fixtures {
		routes[stripQuery(fx.Path)] = fx
	}
	covered := map[string]bool{}
	for _, fx := range fixtures {
		if tpl, ok := byID[fx.TemplateID]; ok {
			if fireCNFixture(t, tpl, fx, "主模板", routes) {
				covered[fx.TemplateID] = true
			}
		}
		for _, alt := range fx.AlsoServes {
			atpl, ok := byID[alt]
			if !ok {
				continue
			}
			if fireCNFixture(t, atpl, fx, "also_serves", routes) {
				covered[alt] = true
			}
		}
	}
	for _, id := range cnTemplateIDs {
		if !covered[id] {
			t.Errorf("夹具未命中模板 %s（模板可能永远不命中）", id)
		}
	}
}

// 夹具之间不得互相污染：一条夹具若命中别的模板，说明匹配条件太宽。
func TestCNFixturesDoNotCrossMatch(t *testing.T) {
	fixtures := loadCNFixtures(t)
	byID := loadCNTemplates(t)
	vars := cnVars(t)

	routes := map[string]cnFixture{}
	for _, fx := range fixtures {
		routes[stripQuery(fx.Path)] = fx
	}
	for _, fx := range fixtures {
		served := map[string]bool{fx.TemplateID: true}
		for _, alt := range fx.AlsoServes {
			served[alt] = true
		}
		for id, tpl := range byID {
			if served[id] {
				continue
			}
			samePath := false
			for _, p := range requestPaths(tpl, vars) {
				if p == stripQuery(fx.Path) {
					samePath = true
					break
				}
			}
			if !samePath {
				continue
			}
			if fireCNFixture(t, tpl, fx, "越界命中", routes) {
				t.Errorf("夹具 %s（path=%s）意外命中模板 %s：专有特征不够专有", fx.TemplateID, fx.Path, id)
			}
		}
	}
}

// ---------------- 4. 端到端：把夹具当靶站跑一遍 ----------------

// TestCNFixtureServerEndToEnd 用夹具文件起一个"金丝雀靶站"，
// 跑真实 Engine，确认所有新增模板都能命中、且都命中在自己声明的路径上。
func TestCNFixtureServerEndToEnd(t *testing.T) {
	fixtures := loadCNFixtures(t)

	routes := map[string]cnFixture{}
	for _, fx := range fixtures {
		routes[stripQuery(fx.Path)] = fx
	}
	pathOf := map[string]string{}
	for _, fx := range fixtures {
		_, finalPath := resolveFixture(t, fx, routes)
		pathOf[fx.TemplateID] = finalPath
		for _, alt := range fx.AlsoServes {
			pathOf[alt] = finalPath
		}
	}
	srv := newFixtureServer(t, routes)
	defer srv.Close()

	tpls, err := Load(LoadOptions{IncludeBuiltin: true})
	if err != nil {
		t.Fatalf("加载模板失败: %v", err)
	}
	want := map[string]bool{}
	for _, id := range cnTemplateIDs {
		want[id] = true
	}
	var cnTpls []*Template
	for _, tpl := range tpls {
		if want[tpl.ID] {
			cnTpls = append(cnTpls, tpl)
		}
	}
	if len(cnTpls) != len(cnTemplateIDs) {
		t.Fatalf("新增模板数量不符：加载到 %d，期望 %d", len(cnTpls), len(cnTemplateIDs))
	}

	eng := testEngine(t, cnTpls, Options{Timeout: 5 * time.Second})
	findings := eng.ScanOne(context.Background(), targetFor(t, srv))

	got := map[string]bool{}
	for _, f := range findings {
		got[f.TemplateID] = true
		t.Logf("命中: %s @ %s", f.TemplateID, f.MatchedAt)
	}
	for _, id := range cnTemplateIDs {
		if !got[id] {
			t.Errorf("靶站已按夹具响应，但模板未命中: %s", id)
		}
	}
	for _, f := range findings {
		wantPath, ok := pathOf[f.TemplateID]
		if !ok {
			t.Errorf("出现未预期的模板命中: %s", f.TemplateID)
			continue
		}
		if gotPath := stripQuery(strings.TrimPrefix(f.MatchedAt, srv.URL)); gotPath != wantPath {
			t.Errorf("%s 命中在 %s，期望 %s", f.TemplateID, gotPath, wantPath)
		}
	}
}
