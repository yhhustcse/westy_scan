// Package fingerprint 是一个声明式指纹规则引擎。
//
// 设计取舍：指纹不写死在代码里，而是先用内置规则保证开箱即用，
// 再允许用 JSON 规则文件**合并/覆盖**。这样：
//   - 指纹更新不需要重新编译；
//   - 后续 POC 引擎可以复用同一套规则加载与匹配逻辑（漏洞模板 = 指纹 + 验证请求）。
//
// M2 增强：
//   - 规则可与内置规则**合并**（同名覆盖），用 -no-default-rules 关闭内置规则；
//   - 每条规则带 confidence（high/medium/low），结果写进资产，纯端口规则默认 low；
//   - 支持 favicon_hash 匹配（Shodan 约定的 mmh3），把 Web 资产和社区指纹库打通；
//   - 规则可 enabled:false 临时停用，不用删掉整条规则。
package fingerprint

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"strings"
	"westy_scan/internal/jsonutil"

	"westy_scan/internal/model"
)

// Rule 是一条指纹规则。
type Rule struct {
	Name    string            `json:"name"`                   // 产品名，如 nginx
	Service string            `json:"service,omitempty"`      // 服务/协议名，如 http、ssh、redis
	Ports   []int             `json:"ports,omitempty"`        // 仅在这些端口生效；为空表示不限
	Banner  []string          `json:"banner_regex,omitempty"` // 匹配 TCP Banner
	Title   []string          `json:"title_regex,omitempty"`  // 匹配页面标题
	Header  map[string]string `json:"header_regex,omitempty"` // 响应头名 -> 正则
	Body    []string          `json:"body_regex,omitempty"`   // 匹配响应体
	// FaviconHash 是 favicon 的 mmh3 哈希（Shodan 约定，见 internal/favhash）。
	// 命中即认为产品匹配 —— 注意哈希存在碰撞可能，因此默认给 medium 置信度。
	FaviconHash []int32 `json:"favicon_hash,omitempty"`
	// Confidence 为 high/medium/low；留空时：特征串规则 medium、纯端口规则 low。
	Confidence string `json:"confidence,omitempty"`
	// Enabled 为 nil 或 true 时启用；显式 false 可临时停用规则。
	Enabled *bool `json:"enabled,omitempty"`
}

type compiledRule struct {
	rule       Rule
	ports      map[int]bool
	favicon    map[int32]bool
	banner     []*regexp.Regexp
	title      []*regexp.Regexp
	header     map[string]*regexp.Regexp
	body       []*regexp.Regexp
	confidence string
}

// Match 是一条命中的规则。
type Match struct {
	Rule       string
	Service    string
	Product    string
	Confidence string
}

// Engine 是线程安全的只读规则集。
type Engine struct {
	rules []compiledRule
}

// New 编译规则集。任何非法正则都会在这里报错，避免运行时静默失效。
func New(rules []Rule) (*Engine, error) {
	e := &Engine{}
	for i, r := range rules {
		if strings.TrimSpace(r.Name) == "" {
			return nil, fmt.Errorf("第 %d 条指纹规则缺少 name", i+1)
		}
		if r.Enabled != nil && !*r.Enabled {
			continue // 显式停用
		}
		c := compiledRule{rule: r}
		if len(r.Ports) > 0 {
			c.ports = make(map[int]bool, len(r.Ports))
			for _, p := range r.Ports {
				c.ports[p] = true
			}
		}
		if len(r.FaviconHash) > 0 {
			c.favicon = make(map[int32]bool, len(r.FaviconHash))
			for _, h := range r.FaviconHash {
				c.favicon[h] = true
			}
		}
		var err error
		if c.banner, err = compileAll(r.Banner); err != nil {
			return nil, fmt.Errorf("规则 %s 的 banner_regex 非法: %w", r.Name, err)
		}
		if c.title, err = compileAll(r.Title); err != nil {
			return nil, fmt.Errorf("规则 %s 的 title_regex 非法: %w", r.Name, err)
		}
		if c.body, err = compileAll(r.Body); err != nil {
			return nil, fmt.Errorf("规则 %s 的 body_regex 非法: %w", r.Name, err)
		}
		if len(r.Header) > 0 {
			c.header = make(map[string]*regexp.Regexp, len(r.Header))
			for k, v := range r.Header {
				re, err := regexp.Compile(v)
				if err != nil {
					return nil, fmt.Errorf("规则 %s 的 header_regex[%s] 非法: %w", r.Name, k, err)
				}
				c.header[strings.ToLower(k)] = re
			}
		}
		c.confidence = normalizeConfidence(r.Confidence)
		if c.confidence == "" {
			if c.portOnly() {
				c.confidence = model.ConfidenceLow // 仅凭端口推断，天然弱
			} else {
				c.confidence = model.ConfidenceMedium
			}
		}
		e.rules = append(e.rules, c)
	}
	return e, nil
}

func normalizeConfidence(v string) string {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case model.ConfidenceHigh:
		return model.ConfidenceHigh
	case model.ConfidenceMedium:
		return model.ConfidenceMedium
	case model.ConfidenceLow:
		return model.ConfidenceLow
	default:
		return ""
	}
}

func compileAll(patterns []string) ([]*regexp.Regexp, error) {
	if len(patterns) == 0 {
		return nil, nil
	}
	out := make([]*regexp.Regexp, 0, len(patterns))
	for _, p := range patterns {
		re, err := regexp.Compile(p)
		if err != nil {
			return nil, err
		}
		out = append(out, re)
	}
	return out, nil
}

// Load 加载规则文件并与内置规则**合并**（同名覆盖）；文件不存在时只用内置规则。
func Load(path string) (*Engine, error) {
	return LoadMerged(path, true)
}

// LoadOnly 只使用外置规则（对应命令行 -no-default-rules）。
func LoadOnly(path string) (*Engine, error) {
	return LoadMerged(path, false)
}

// LoadMerged 是统一入口：
//
//	includeDefaults=true  → 内置规则 + 外置规则（同名覆盖内置）
//	includeDefaults=false → 只用外置规则
func LoadMerged(path string, includeDefaults bool) (*Engine, error) {
	var rules []Rule
	if includeDefaults {
		rules = append(rules, DefaultRules()...)
	}
	if strings.TrimSpace(path) == "" {
		if len(rules) == 0 {
			return nil, errors.New("未提供外置规则且已禁用内置规则，规则集为空")
		}
		return New(rules)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) && includeDefaults {
			return Default(), nil
		}
		return nil, err
	}
	var external []Rule
	if err := jsonutil.Unmarshal(data, &external); err != nil {
		return nil, fmt.Errorf("解析指纹规则 %s 失败: %w", path, err)
	}
	rules = MergeRules(rules, external)
	if len(rules) == 0 {
		return nil, fmt.Errorf("规则文件 %s 没有可用规则", path)
	}
	return New(rules)
}

// MergeRules 按 Name 合并：外置规则与已有规则同名则替换，否则追加。
// 大小写不敏感，便于"用外置规则修正内置规则"。
func MergeRules(base, external []Rule) []Rule {
	out := make([]Rule, 0, len(base)+len(external))
	out = append(out, base...)
	for _, r := range external {
		replaced := false
		for i := range out {
			if strings.EqualFold(out[i].Name, r.Name) {
				out[i] = r
				replaced = true
				break
			}
		}
		if !replaced {
			out = append(out, r)
		}
	}
	return out
}

// Default 返回内置规则引擎（不会失败）。
func Default() *Engine {
	e, err := New(DefaultRules())
	if err != nil {
		// 内置规则是常量，编译失败属于代码缺陷，直接 panic 让它尽早暴露
		panic("内置指纹规则非法: " + err.Error())
	}
	return e
}

// Rules 返回规则快照，供 --list-rules 使用。
func (e *Engine) Rules() []Rule {
	out := make([]Rule, 0, len(e.rules))
	for _, c := range e.rules {
		out = append(out, c.rule)
	}
	return out
}

// Count 返回生效的规则条数（已排除 enabled:false）。
func (e *Engine) Count() int { return len(e.rules) }

// Apply 一站式给资产打指纹：Banner → HTTP 响应 → favicon。
// 命中的规则会同时写入产品、置信度与判据（evidence）。
func (e *Engine) Apply(a *model.Asset, headers http.Header, body []byte) {
	if a == nil {
		return
	}
	if a.Banner != "" {
		e.applyMatches(a, e.MatchTCPAll(a.Port, a.Banner))
	}
	if headers != nil || len(body) > 0 {
		e.applyMatches(a, e.MatchHTTPAll(a, headers, body))
	}
	if a.FaviconHash != 0 {
		e.applyMatches(a, e.MatchFavicon(a.FaviconHash))
	}
	// 兜底：能响应 HTTP(S) 的资产至少要有服务标签。
	// 否则一个没有命中任何产品指纹的普通站点，报告里 service 会留空。
	if a.Service == "" && (a.URL != "" || a.Scheme != "") {
		if a.Scheme != "" {
			a.Service = a.Scheme
		} else {
			a.Service = "http"
		}
	}
}

func (e *Engine) applyMatches(a *model.Asset, matches []Match) {
	for _, m := range matches {
		if a.Service == "" && m.Service != "" {
			a.Service = m.Service
		}
		if m.Product != "" {
			a.AddProduct(m.Product)
			if a.Product == "" {
				a.Product = m.Product
			}
		}
		a.RaiseConfidence(m.Confidence)
		a.AddEvidence("rule:" + m.Rule)
	}
}

// MatchTCPAll 匹配 Banner，返回全部命中（含置信度）。
func (e *Engine) MatchTCPAll(port int, banner string) []Match {
	var out []Match
	for _, c := range e.rules {
		if !c.matchPort(port) {
			continue
		}
		// 纯端口规则（如 RDP 3389）：没有可匹配的特征，仅凭端口定服务
		if c.portOnly() {
			out = append(out, c.match())
			continue
		}
		if len(c.banner) == 0 || !anyMatch(c.banner, banner) {
			continue
		}
		out = append(out, c.match())
	}
	return out
}

// MatchHTTPAll 匹配标题 / 响应头 / 响应体。
func (e *Engine) MatchHTTPAll(a *model.Asset, headers http.Header, body []byte) []Match {
	if a == nil {
		return nil
	}
	bodyStr := string(body)
	title := a.Title
	var out []Match
	for _, c := range e.rules {
		if !c.matchPort(a.Port) {
			continue
		}
		if c.portOnly() {
			out = append(out, c.match())
			continue
		}
		hit := false
		if len(c.title) > 0 && title != "" && anyMatch(c.title, title) {
			hit = true
		}
		if !hit && len(c.header) > 0 && headers != nil {
			for name, re := range c.header {
				v := headers.Get(name)
				// 关键：缺失的响应头取到空串，而 ".*" 能匹配空串；
				// 若不判空，任何声明 ".*" 的规则都会命中所有目标（典型误报来源）。
				if v != "" && re.MatchString(v) {
					hit = true
					break
				}
			}
		}
		if !hit && len(c.body) > 0 && bodyStr != "" && anyMatch(c.body, bodyStr) {
			hit = true
		}
		if hit {
			out = append(out, c.match())
		}
	}
	return out
}

// MatchFavicon 按 favicon 的 mmh3 哈希匹配规则。
func (e *Engine) MatchFavicon(hash int32) []Match {
	if hash == 0 {
		return nil
	}
	var out []Match
	for _, c := range e.rules {
		if len(c.favicon) > 0 && c.favicon[hash] {
			out = append(out, c.match())
		}
	}
	return out
}

// MatchTCP 是兼容入口：只返回服务名与产品名。
func (e *Engine) MatchTCP(port int, banner string) (service string, products []string) {
	return flatten(e.MatchTCPAll(port, banner))
}

// MatchHTTP 是兼容入口：只返回服务名与产品名。
func (e *Engine) MatchHTTP(a *model.Asset, headers http.Header, body []byte) (service string, products []string) {
	return flatten(e.MatchHTTPAll(a, headers, body))
}

func flatten(matches []Match) (service string, products []string) {
	for _, m := range matches {
		if m.Service != "" {
			service = m.Service
		}
		if m.Product != "" {
			products = append(products, m.Product)
		}
	}
	return service, products
}

func (c compiledRule) match() Match {
	return Match{
		Rule:       c.rule.Name,
		Service:    serviceOf(c.rule),
		Product:    c.rule.Name,
		Confidence: c.confidence,
	}
}

func serviceOf(r Rule) string {
	if r.Service != "" {
		return r.Service
	}
	return strings.ToLower(r.Name)
}

func (c compiledRule) matchPort(port int) bool {
	if len(c.ports) == 0 {
		return true
	}
	return c.ports[port]
}

// portOnly 表示该规则没有任何特征串，只靠端口判定（必须显式声明 ports）。
func (c compiledRule) portOnly() bool {
	return len(c.ports) > 0 &&
		len(c.banner) == 0 && len(c.title) == 0 && len(c.header) == 0 &&
		len(c.body) == 0 && len(c.favicon) == 0
}

func anyMatch(res []*regexp.Regexp, s string) bool {
	for _, re := range res {
		if re.MatchString(s) {
			return true
		}
	}
	return false
}

// DefaultRules 是内置指纹规则集，覆盖授权测试中最常见的服务与中间件。
//
// confidence 留空时自动判定（特征串 medium / 纯端口 low）；
// 需要外部 favicon 指纹时，把 mmh3 值填进 favicon_hash 即可。
func DefaultRules() []Rule {
	return append([]Rule{
		{Name: "OpenSSH", Service: "ssh", Banner: []string{`^SSH-[12]\.\d+-OpenSSH`, `OpenSSH[_-][\d.p]+`}},
		{Name: "SSH", Service: "ssh", Banner: []string{`^SSH-[12]\.\d+`}},
		{Name: "vsftpd", Service: "ftp", Banner: []string{`vsFTPd`, `220.*vsFTPd`}},
		{Name: "ProFTPD", Service: "ftp", Banner: []string{`ProFTPD`}},
		{Name: "Pure-FTPd", Service: "ftp", Banner: []string{`Pure-FTPd`}},
		{Name: "Microsoft FTP", Service: "ftp", Banner: []string{`Microsoft FTP Service`}},
		{Name: "Postfix", Service: "smtp", Banner: []string{`220.*Postfix`, `Postfix`}},
		{Name: "Exim", Service: "smtp", Banner: []string{`220.*Exim`}},
		{Name: "Sendmail", Service: "smtp", Banner: []string{`220.*Sendmail`}},
		{Name: "MySQL", Service: "mysql", Ports: []int{3306, 3307}, Banner: []string{`mysql_native_password`, `\d+\.\d+\.\d+.*MariaDB`, `caching_sha2_password`}},
		{Name: "MariaDB", Service: "mysql", Ports: []int{3306, 3307}, Banner: []string{`MariaDB`}},
		{Name: "PostgreSQL", Service: "postgres", Ports: []int{5432, 5433}, Banner: []string{`PostgreSQL`, `FATAL`, `invalid startup packet`}},
		{Name: "Redis", Service: "redis", Ports: []int{6379, 6380}, Banner: []string{`(?i)redis`, `-ERR unknown command`, `-DENIED`}},
		{Name: "Memcached", Service: "memcached", Ports: []int{11211}, Banner: []string{`(?i)memcached`, `ERROR`}},
		{Name: "MongoDB", Service: "mongodb", Ports: []int{27017, 27018}, Banner: []string{`(?i)mongodb`, `ismaster`, `MongoDB`}},
		{Name: "RDP", Service: "rdp", Ports: []int{3389}}, // 纯端口规则 → 自动 low
		{Name: "VNC", Service: "vnc", Ports: []int{5900, 5901}, Banner: []string{`^RFB \d{3}\.\d{3}`}},
		{Name: "Docker API", Service: "docker", Ports: []int{2375, 2376}, Header: map[string]string{"server": `(?i)docker`}, Body: []string{`ApiVersion`, `"Version"`}},
		{Name: "Kubernetes API", Service: "kubernetes", Ports: []int{6443, 8443, 10250}, Body: []string{`"kind":\s*"APIVersions"`, `"versions":\s*\[`}},
		{Name: "Elasticsearch", Service: "elasticsearch", Ports: []int{9200, 9201}, Body: []string{`"cluster_name"`, `"lucene_version"`, `"tagline"\s*:\s*"You Know, for Search"`}},
		{Name: "Kibana", Service: "kibana", Ports: []int{5601}, Title: []string{`(?i)kibana`}, Body: []string{`kbn-injected-metadata`}},
		{Name: "RabbitMQ", Service: "rabbitmq", Ports: []int{15672, 5672}, Body: []string{`RabbitMQ Management`}, Title: []string{`(?i)rabbitmq`}},
		{Name: "Nginx", Service: "http", Header: map[string]string{"server": `(?i)nginx`}},
		{Name: "Apache httpd", Service: "http", Header: map[string]string{"server": `(?i)apache`}},
		{Name: "Microsoft IIS", Service: "http", Header: map[string]string{"server": `(?i)microsoft-iis`}},
		{Name: "Apache Tomcat", Service: "http", Title: []string{`(?i)apache tomcat`}, Body: []string{`Apache Tomcat/\d`}},
		{Name: "Jenkins", Service: "http", Header: map[string]string{"x-jenkins": `\d`}, Title: []string{`(?i)jenkins`}},
		{Name: "Spring Boot", Service: "http", Body: []string{`Whitelabel Error Page`}, Header: map[string]string{"x-application-context": `.+`}},
		{Name: "Nacos", Service: "http", Title: []string{`(?i)nacos`}, Body: []string{`console-ui`, `nacos`}},
		{Name: "WebLogic", Service: "http", Body: []string{`WebLogic`, `console/login/LoginForm.jsp`}, Header: map[string]string{"x-weblogic": `.+`}},
		{Name: "Grafana", Service: "http", Title: []string{`(?i)grafana`}, Body: []string{`grafana-app`}},
		{Name: "GitLab", Service: "http", Title: []string{`(?i)gitlab`}, Body: []string{`GitLab`}, Header: map[string]string{"x-gitlab-meta": `.+`}},
		{Name: "phpMyAdmin", Service: "http", Title: []string{`(?i)phpmyadmin`}, Header: map[string]string{"set-cookie": `phpMyAdmin`}},
		{Name: "Zabbix", Service: "http", Title: []string{`(?i)zabbix`}, Header: map[string]string{"set-cookie": `zbx_session`}},
		{Name: "MinIO", Service: "http", Header: map[string]string{"server": `(?i)minio`}},
		{Name: "Consul", Service: "http", Title: []string{`(?i)consul`}, Body: []string{`consul-ui`, `"Config":`}},
		{Name: "Harbor", Service: "http", Title: []string{`(?i)harbor`}, Body: []string{`harbor-logo`}},
		{Name: "Solr", Service: "http", Title: []string{`(?i)solr`}, Body: []string{`solr`}},
		{Name: "PHP", Service: "http", Header: map[string]string{"x-powered-by": `(?i)php`}},
		{Name: "ASP.NET", Service: "http", Header: map[string]string{"x-aspnet-version": `\d`, "x-powered-by": `(?i)asp\.net`}},
		{Name: "ThinkPHP", Service: "http", Header: map[string]string{"x-powered-by": `(?i)thinkphp`}},
	}, libraryRules()...)
}
