package poc

import (
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// 本文件是"只读暴露面模板扩充"（builtin-exposure-web.json）的验收测试：
//
//  1. 新增模板必须能被 Load 正常加载（加载期会做方法/变量/正则等全部校验）；
//  2. 新增模板 id 必须都在加载结果里（防止写错文件名或 id）；
//  3. 每条模板必须能在自己的金丝雀夹具上命中（防止"写了却永远不命中"的死模板）；
//  4. 夹具与模板必须一一对应（防止改路径忘了改夹具、或两条模板共用同一路径）。
//
// 金丝雀夹具（scripts/rules-fixtures/web.json）是靶站的契约文件：
// 靶站对夹具里声明的路径严格按声明的状态码/响应头/响应体回包，其它路径一律 404。

// webTemplateIDs 是 builtin-exposure-web.json 里的模板 id 清单。
// 这里显式列出而不是从模板文件反读：模板被误删或改名时测试要立刻失败。
var webTemplateIDs = []string{
	"actuator-heapdump-exposure",
	"actuator-mappings-exposure",
	"actuator-beans-exposure",
	"actuator-configprops-exposure",
	"actuator-threaddump-exposure",
	"spring-cloud-gateway-routes-exposure",
	"jolokia-list-exposure",
	"druid-monitor-index-exposure",
	"druid-sql-monitor-exposure",
	"springfox-v2-api-docs-exposure",
	"springdoc-v3-api-docs-exposure",
	"swagger-ui-index-exposure",
	"graphql-introspection-exposure",
	"elasticsearch-cluster-health-exposure",
	"elasticsearch-nodes-info-exposure",
	"elasticsearch-search-api-exposure",
	"solr-admin-cores-exposure",
	"hadoop-namenode-jmx-exposure",
	"yarn-resourcemanager-info-exposure",
	"spark-master-applications-exposure",
	"flink-dashboard-overview-exposure",
	"hive-server2-cliservice-exposure",
	"jenkins-script-console-anonymous-exposure",
	"sonarqube-server-version-exposure",
	"nexus-repository-status-exposure",
	"artifactory-system-ping-exposure",
	"harbor-systeminfo-exposure",
	"docker-registry-catalog-unauthorized",
	"prometheus-status-config-exposure",
	"prometheus-targets-exposure",
	"alertmanager-status-exposure",
	"grafana-health-exposure",
	"grafana-datasources-unauthorized",
	"netdata-api-info-exposure",
	"graylog-api-system-exposure",
	"kibana-api-status-exposure",
	"zabbix-api-jsonrpc-exposure",
	"cacti-console-exposure",
	"nagios-status-cgi-exposure",
	"kubernetes-namespaces-unauthorized",
	"kubelet-pods-unauthorized",
	"consul-agent-self-unauthorized",
	"consul-catalog-services-unauthorized",
	"etcd-v2-keys-unauthorized",
	"nomad-agent-members-unauthorized",
	"rancher-public-settings-exposure",
	"svn-entries-exposure",
	"hg-requires-exposure",
	"ds-store-exposure",
	"web-inf-web-xml-exposure",
	"meta-inf-manifest-exposure",
	"crossdomain-xml-exposure",
	"apache-server-status-exposure",
	"apache-server-info-exposure",
	"aspnet-trace-axd-exposure",
	"aspnet-elmah-axd-exposure",
	"web-config-exposure",
	"composer-json-exposure",
	"sql-dump-file-exposure",
	"www-zip-exposure",
	"phpmyadmin-panel-exposure",
	"adminer-panel-exposure",
	"clickhouse-http-interface-exposure",
	"influxdb-health-exposure",
	"couchdb-all-dbs-unauthorized",
	"neo4j-browser-exposure",
	"minio-health-live-exposure",
}

// webFixturePath 是金丝雀夹具文件（相对本包目录：internal/poc）。
const webFixturePath = "../../scripts/rules-fixtures/web.json"

type webFixture struct {
	TemplateID  string            `json:"template_id"`
	Path        string            `json:"path"`
	Status      int               `json:"status"`
	ContentType string            `json:"content_type"`
	Headers     map[string]string `json:"headers"`
	Body        string            `json:"body"`
	// AlsoServes 用于"两条模板确实必须打同一路径"的场景；
	// 本文件目前没有任何一条使用它（每条模板各有独立路径）。
	AlsoServes []string `json:"also_serves"`
}

func loadWebFixtures(t *testing.T) []webFixture {
	t.Helper()
	data, err := os.ReadFile(filepath.FromSlash(webFixturePath))
	if err != nil {
		t.Fatalf("读取金丝雀夹具失败: %v", err)
	}
	var out []webFixture
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatalf("金丝雀夹具 JSON 非法: %v", err)
	}
	if len(out) == 0 {
		t.Fatal("金丝雀夹具为空")
	}
	return out
}

func loadBuiltinByID(t *testing.T) map[string]*Template {
	t.Helper()
	tpls, err := Load(LoadOptions{IncludeBuiltin: true})
	if err != nil {
		t.Fatalf("加载内置模板失败: %v", err)
	}
	byID := make(map[string]*Template, len(tpls))
	for _, tpl := range tpls {
		byID[tpl.ID] = tpl
	}
	return byID
}

// 加载期校验：任何一条新模板非法（写方法、未知变量、PCRE 正则……）都会在这里失败。
func TestLoadWebBuiltinTemplates(t *testing.T) {
	tpls, err := Load(LoadOptions{IncludeBuiltin: true})
	if err != nil {
		t.Fatalf("加载内置模板失败: %v", err)
	}
	t.Logf("内置模板总数: %d（本轮新增 %d 条）", len(tpls), len(webTemplateIDs))

	ids := make(map[string]bool, len(tpls))
	for _, tpl := range tpls {
		ids[tpl.ID] = true
	}
	for _, id := range webTemplateIDs {
		if !ids[id] {
			t.Errorf("新增模板未出现在加载结果中: %s", id)
		}
	}
}

// fixtureResponse 按夹具合成一次响应快照：金丝雀靶站就是这样回包的。
func fixtureResponse(fx webFixture) *Response {
	status := fx.Status
	if status == 0 {
		status = 200
	}
	ct := fx.ContentType
	if strings.TrimSpace(ct) == "" {
		ct = "text/html; charset=utf-8"
	}
	h := http.Header{}
	h.Set("Content-Type", ct)
	for k, v := range fx.Headers {
		h.Set(k, v)
	}
	body := []byte(fx.Body)
	return &Response{
		URL:     "http://canary.local" + fx.Path,
		Status:  status,
		Headers: h,
		Body:    body,
		Title:   extractTitle(body),
	}
}

// fixtureRequest 找出模板里"会打到该夹具路径"的那个请求（渲染变量后按路径比对）。
func fixtureRequest(t *testing.T, tpl *Template, path string) *HTTPRequest {
	t.Helper()
	vars := NewEngine(nil, Options{}).baseVars(Target{Scheme: "http", Host: "canary.local", Port: 80})
	for i := range tpl.HTTP {
		req := &tpl.HTTP[i]
		for _, raw := range req.Path {
			rendered := Render(raw, vars)
			u, err := url.Parse(rendered)
			if err != nil {
				t.Fatalf("模板 %s 的 path %q 无法解析: %v", tpl.ID, raw, err)
			}
			if u.Path == path {
				return req
			}
		}
	}
	return nil
}

// 每条模板都必须能在自己的夹具响应上命中（这是本轮最有价值的测试）。
func TestWebFixturesMatchTheirTemplates(t *testing.T) {
	fixtures := loadWebFixtures(t)
	byID := loadBuiltinByID(t)

	for _, fx := range fixtures {
		tpl := byID[fx.TemplateID]
		if tpl == nil {
			t.Errorf("夹具 %s 指向不存在的模板: %s", fx.Path, fx.TemplateID)
			continue
		}
		req := fixtureRequest(t, tpl, fx.Path)
		if req == nil {
			t.Errorf("模板 %s 没有任何请求会打到夹具路径 %s（模板与夹具已失配）", tpl.ID, fx.Path)
			continue
		}
		resp := fixtureResponse(fx)
		if res := EvaluateMatchers(req.Matchers, req.MatchersCondition, resp, Vars{}); !res.Hit {
			t.Errorf("漏报: 模板 %s 在夹具 %s 上未命中: %s", tpl.ID, fx.Path, res.Why)
		}
		// 同一个响应不能顺带命中它不该命中的模板？—— 靶站按路径分发，
		// 这里只显式校验 also_serves 里声明的共享关系。
		for _, other := range fx.AlsoServes {
			otpl := byID[other]
			if otpl == nil {
				t.Errorf("夹具 %s 的 also_serves 指向不存在的模板: %s", fx.Path, other)
				continue
			}
			oreq := fixtureRequest(t, otpl, fx.Path)
			if oreq == nil {
				t.Errorf("also_serves 模板 %s 不会打到夹具路径 %s", other, fx.Path)
				continue
			}
			if res := EvaluateMatchers(oreq.Matchers, oreq.MatchersCondition, resp, Vars{}); !res.Hit {
				t.Errorf("also_serves 漏报: 模板 %s 在夹具 %s 上未命中: %s", other, fx.Path, res.Why)
			}
		}
	}
}

// 夹具必须与新增模板一一对应：路径唯一、id 不重复、无遗漏、无多余。
func TestWebFixturesAreOneToOne(t *testing.T) {
	fixtures := loadWebFixtures(t)
	byID := loadBuiltinByID(t)

	seenPath := map[string]string{}
	countByID := map[string]int{}
	for _, fx := range fixtures {
		if fx.TemplateID == "" || fx.Path == "" {
			t.Fatalf("夹具缺少 template_id 或 path: %+v", fx)
		}
		if prev, ok := seenPath[fx.Path]; ok {
			t.Errorf("夹具路径重复: %s（%s 与 %s）", fx.Path, prev, fx.TemplateID)
		}
		seenPath[fx.Path] = fx.TemplateID
		countByID[fx.TemplateID]++
	}
	for _, id := range webTemplateIDs {
		if byID[id] == nil {
			t.Errorf("新增模板未加载: %s", id)
			continue
		}
		switch countByID[id] {
		case 1:
		case 0:
			t.Errorf("新增模板缺少夹具: %s", id)
		default:
			t.Errorf("新增模板有多条夹具（要求恰好一条）: %s（%d 条）", id, countByID[id])
		}
	}
	known := map[string]bool{}
	for _, id := range webTemplateIDs {
		known[id] = true
	}
	for _, fx := range fixtures {
		if !known[fx.TemplateID] {
			t.Errorf("夹具 %s 的 template_id 不是本轮新增模板: %s", fx.Path, fx.TemplateID)
		}
	}
	if len(seenPath) != len(webTemplateIDs) {
		t.Errorf("夹具条数 %d 与新增模板条数 %d 不一致", len(seenPath), len(webTemplateIDs))
	}
}
