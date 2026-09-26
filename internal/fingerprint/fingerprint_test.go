package fingerprint

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"westy_scan/internal/model"
)

func contains(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}

// 回归用例：缺失响应头时不得命中任何 header 规则。
// 历史缺陷：x-application-context: ".*" 之类的规则会对空串命中，
// 导致 Python SimpleHTTP 站点被误报成 Spring Boot / WebLogic / GitLab。
func TestHeaderMatcherIgnoresEmptyValue(t *testing.T) {
	e, err := New([]Rule{{Name: "Fake", Service: "http", Header: map[string]string{"x-absent": ".*"}}})
	if err != nil {
		t.Fatalf("构造规则失败: %v", err)
	}
	a := &model.Asset{Host: "h", Port: 80}
	svc, products := e.MatchHTTP(a, http.Header{}, []byte("<html>hello</html>"))
	if len(products) != 0 {
		t.Fatalf("缺失响应头时不应命中，实际 service=%q products=%v", svc, products)
	}
}

// 内置规则不得对"普通静态站点"产生中间件误报，且存活 Web 资产必须有服务标签。
func TestDefaultRulesNoFalsePositiveOnPlainSite(t *testing.T) {
	e := Default()
	a := &model.Asset{Host: "h", Port: 18080, Scheme: "http", URL: "http://h:18080/"}
	h := http.Header{}
	h.Set("Server", "SimpleHTTP/0.6 Python/3.13.13")
	h.Set("Content-Type", "text/html")
	body := []byte(`<html><head><title>Westy Demo</title></head><body><a href="/admin.html">admin</a></body></html>`)

	e.Apply(a, h, body)

	if a.Service != "http" {
		t.Errorf("存活 Web 资产的 service 应为 http，实际 %q", a.Service)
	}
	for _, bad := range []string{"Spring Boot", "WebLogic", "GitLab", "Nacos", "Consul", "Solr"} {
		if contains(a.Products, bad) {
			t.Errorf("误报: 普通静态站点被识别为 %s（products=%v）", bad, a.Products)
		}
	}
}

func TestMatchRealHeaders(t *testing.T) {
	e := Default()
	a := &model.Asset{Host: "h", Port: 80}

	h := http.Header{}
	h.Set("Server", "nginx/1.25.3")
	_, products := e.MatchHTTP(a, h, []byte("<html><title>Welcome to nginx</title></html>"))
	if !contains(products, "Nginx") {
		t.Fatalf("nginx 应被识别，实际 %v", products)
	}

	h2 := http.Header{}
	h2.Set("X-Powered-By", "PHP/8.2.1")
	if _, p2 := e.MatchHTTP(a, h2, nil); !contains(p2, "PHP") {
		t.Fatalf("PHP 应被识别，实际 %v", p2)
	}
}

func TestMatchBanner(t *testing.T) {
	e := Default()
	svc, products := e.MatchTCP(22, "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13")
	if svc != "ssh" || !contains(products, "OpenSSH") {
		t.Fatalf("SSH Banner 指纹失败: service=%q products=%v", svc, products)
	}

	svc2, p2 := e.MatchTCP(6379, "-DENIED Redis is running in protected mode")
	if svc2 != "redis" || !contains(p2, "Redis") {
		t.Fatalf("Redis Banner 指纹失败: service=%q products=%v", svc2, p2)
	}
}

// 纯端口规则（无任何特征串）必须只在自己声明的端口上生效。
func TestPortOnlyRule(t *testing.T) {
	e := Default()
	svc, products := e.MatchTCP(3389, "")
	if svc != "rdp" || !contains(products, "RDP") {
		t.Fatalf("纯端口规则失效: service=%q products=%v", svc, products)
	}
	if svc, products := e.MatchTCP(65500, ""); len(products) != 0 {
		t.Fatalf("未声明端口不应命中任何纯端口规则: service=%q products=%v", svc, products)
	}
}

func TestRulePortConstraint(t *testing.T) {
	e := Default()
	// 9200 是 Elasticsearch 规则声明的端口，6379 不是
	if _, products := e.MatchHTTP(&model.Asset{Port: 6379}, nil, []byte(`{"cluster_name":"x"}`)); contains(products, "Elasticsearch") {
		t.Errorf("带端口约束的规则不应在 6379 上命中: %v", products)
	}
	if _, products := e.MatchHTTP(&model.Asset{Port: 9200}, nil, []byte(`{"cluster_name":"x"}`)); !contains(products, "Elasticsearch") {
		t.Errorf("Elasticsearch 规则应在 9200 上命中: %v", products)
	}
}

func TestInvalidRegexRejected(t *testing.T) {
	if _, err := New([]Rule{{Name: "Bad", Body: []string{"([unclosed"}}}); err == nil {
		t.Fatal("非法正则必须在加载时报错，而不是运行时静默失效")
	}
}

// ---------------- M2：规则合并 / enabled / 置信度 / favicon ----------------

func writeRules(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "rules.json")
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatalf("写临时规则失败: %v", err)
	}
	return path
}

func TestMergeRulesOverridesByName(t *testing.T) {
	base := []Rule{
		{Name: "Nginx", Service: "http", Header: map[string]string{"server": `(?i)nginx`}},
		{Name: "OnlyBase", Service: "http", Body: []string{"base-only"}},
	}
	external := []Rule{
		{Name: "nginx", Service: "http", Header: map[string]string{"server": `(?i)nginx/(\d+)`}}, // 大小写不同也算同名
		{Name: "OnlyExternal", Service: "http", Body: []string{"ext-only"}},
	}
	merged := MergeRules(base, external)
	if len(merged) != 3 {
		t.Fatalf("合并后应有 3 条（覆盖 1 + 保留 1 + 新增 1），实际 %d", len(merged))
	}
	for _, r := range merged {
		if strings.EqualFold(r.Name, "Nginx") {
			if r.Header["server"] != `(?i)nginx/(\d+)` {
				t.Errorf("同名规则未被外置规则覆盖: %+v", r)
			}
		}
	}
}

func TestLoadMergedAndLoadOnly(t *testing.T) {
	path := writeRules(t, `[{"name":"MyProduct","service":"http","body_regex":["my-marker"]}]`)

	merged, err := Load(path) // 默认合并内置规则
	if err != nil {
		t.Fatalf("Load 失败: %v", err)
	}
	if merged.Count() <= 1 {
		t.Errorf("合并模式应包含内置规则，实际只有 %d 条", merged.Count())
	}
	if _, products := merged.MatchHTTP(&model.Asset{Port: 80}, nil, []byte("my-marker")); !contains(products, "MyProduct") {
		t.Errorf("外置规则未生效: %v", products)
	}
	if _, products := merged.MatchHTTP(&model.Asset{Port: 80}, http.Header{"Server": []string{"nginx"}}, nil); !contains(products, "Nginx") {
		t.Errorf("合并模式下内置规则应仍然生效: %v", products)
	}

	only, err := LoadOnly(path)
	if err != nil {
		t.Fatalf("LoadOnly 失败: %v", err)
	}
	if only.Count() != 1 {
		t.Errorf("-no-default-rules 时只应有 1 条规则，实际 %d", only.Count())
	}
	if _, products := only.MatchHTTP(&model.Asset{Port: 80}, http.Header{"Server": []string{"nginx"}}, nil); len(products) != 0 {
		t.Errorf("只用外置规则时不应命中内置的 Nginx: %v", products)
	}
}

func TestLoadOnlyWithoutFileFails(t *testing.T) {
	if _, err := LoadOnly(""); err == nil {
		t.Fatal("禁用内置规则又没给外置规则时必须报错，而不是静默返回空规则集")
	}
}

func TestDisabledRuleSkipped(t *testing.T) {
	no := false
	e, err := New([]Rule{{Name: "Off", Body: []string{"x"}, Enabled: &no}})
	if err != nil {
		t.Fatalf("New 失败: %v", err)
	}
	if e.Count() != 0 {
		t.Errorf("enabled:false 的规则不应生效，实际 %d 条", e.Count())
	}
}

func TestPortOnlyRuleIsLowConfidence(t *testing.T) {
	e := Default()
	matches := e.MatchTCPAll(3389, "")
	if len(matches) == 0 {
		t.Fatal("3389 应命中 RDP 纯端口规则")
	}
	if matches[0].Confidence != model.ConfidenceLow {
		t.Errorf("纯端口规则应为 low，实际 %q", matches[0].Confidence)
	}
	// 纯端口规则不能覆盖握手实证
	a := &model.Asset{Host: "h", Port: 3389, Service: "ssh", Confidence: model.ConfidenceHigh}
	e.Apply(a, nil, nil)
	if a.Confidence != model.ConfidenceHigh {
		t.Errorf("置信度只升不降，实际 %q", a.Confidence)
	}
	if a.Service != "ssh" {
		t.Errorf("已有服务名不应被端口猜测覆盖，实际 %q", a.Service)
	}
}

func TestRuleConfidenceOverride(t *testing.T) {
	e, err := New([]Rule{{
		Name:       "Certain",
		Service:    "http",
		Header:     map[string]string{"server": `(?i)certain`},
		Confidence: "high",
	}})
	if err != nil {
		t.Fatalf("New 失败: %v", err)
	}
	a := &model.Asset{Host: "h", Port: 80}
	e.Apply(a, http.Header{"Server": []string{"Certain/1.0"}}, nil)
	if a.Confidence != model.ConfidenceHigh {
		t.Errorf("规则显式 high 未生效: %q", a.Confidence)
	}
	if !contains(a.Evidence, "rule:Certain") {
		t.Errorf("缺少规则判据: %v", a.Evidence)
	}
	if a.Product != "Certain" {
		t.Errorf("主产品名未设置: %q", a.Product)
	}
}

func TestFaviconHashMatch(t *testing.T) {
	e, err := New([]Rule{{
		Name:        "CommunityIcon",
		Service:     "http",
		FaviconHash: []int32{-247388890, 116323288},
	}})
	if err != nil {
		t.Fatalf("New 失败: %v", err)
	}
	matches := e.MatchFavicon(-247388890)
	if len(matches) != 1 || matches[0].Product != "CommunityIcon" {
		t.Fatalf("favicon 哈希未命中: %+v", matches)
	}
	if matches[0].Confidence != model.ConfidenceMedium {
		t.Errorf("favicon 哈希存在碰撞可能，默认应为 medium，实际 %q", matches[0].Confidence)
	}
	if got := e.MatchFavicon(999999); len(got) != 0 {
		t.Errorf("未声明的哈希不应命中: %+v", got)
	}
	if got := e.MatchFavicon(0); got != nil {
		t.Errorf("hash=0 视为无 favicon，应返回 nil: %+v", got)
	}

	a := &model.Asset{Host: "h", Port: 443, FaviconHash: 116323288}
	e.Apply(a, nil, nil)
	if a.Product != "CommunityIcon" {
		t.Errorf("Apply 未应用 favicon 指纹: %+v", a)
	}
	if !contains(a.Evidence, "rule:CommunityIcon") {
		t.Errorf("缺少 favicon 判据: %v", a.Evidence)
	}
}

// favicon 规则不应被当成"纯端口规则"，也不应在端口不匹配时命中
func TestFaviconRuleRespectsPorts(t *testing.T) {
	e, err := New([]Rule{{
		Name:        "IconOn8080",
		Service:     "http",
		Ports:       []int{8080},
		FaviconHash: []int32{42},
	}})
	if err != nil {
		t.Fatalf("New 失败: %v", err)
	}
	if len(e.MatchTCPAll(8080, "")) != 0 {
		t.Error("带 favicon 的规则不应被当作纯端口规则命中")
	}
	if len(e.MatchFavicon(42)) != 1 {
		t.Error("favicon 匹配不应受端口约束（端口信息不在哈希里）")
	}
}
