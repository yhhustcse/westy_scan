package crawl

import (
	"regexp"
	"sort"
	"strings"
)

// 本文件做**纯文本**的 JS 抽取：不执行脚本、不做 AST 解析，
// 只用正则把"前端代码里明面写着的东西"捞出来。成本极低、收益很高：
//   - SPA 站点的真实接口往往只出现在 JS 里，HTML 里一个链接都没有；
//   - 前端硬编码的 token / AK 是真实且高危的发现。
//
// 明确的局限：不做混淆还原、不做动态拼接（`"/api/" + v` 这类拼不出来）。
// 要覆盖这些场景需要无头浏览器 + 运行时 hook，属于后续阶段。

var (
	// 引号字符串里看起来像接口路径的内容
	reJSPath = regexp.MustCompile(`["'` + "`" + `](/[A-Za-z0-9_\-./{}$:]{2,120})["'` + "`" + `]`)
	// 绝对 URL
	reJSURL = regexp.MustCompile(`["'` + "`" + `](https?://[A-Za-z0-9_\-.:]{4,200}(?:/[A-Za-z0-9_\-./{}$:?=&%]*)?)["'` + "`" + `]`)
	// fetch("...") / axios.get("...") / axios.post("...") / $.ajax({url:"..."})
	reJSFetch = regexp.MustCompile(`(?i)\b(?:fetch|axios\.(?:get|post|put|delete|patch|head|options)|open)\s*\(\s*["'` + "`" + `]([^"'` + "`" + `\s]{2,200})["'` + "`" + `]`)
	reJSAjax  = regexp.MustCompile(`(?i)\burl\s*:\s*["'` + "`" + `]([^"'` + "`" + `\s]{2,200})["'` + "`" + `]`)
)

// secretRule 描述一类疑似凭据。
type secretRule struct {
	Name    string
	Pattern *regexp.Regexp
}

// 只收录"误报率足够低"的模式：宁可少报，也不要用一堆猜测淹没真正的泄露。
var secretRules = []secretRule{
	{"AWS Access Key ID", regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`)},
	{"Google API Key", regexp.MustCompile(`\bAIza[0-9A-Za-z\-_]{35}\b`)},
	{"GitHub Token", regexp.MustCompile(`\bgh[pousr]_[0-9A-Za-z]{36,}\b`)},
	{"Slack Token", regexp.MustCompile(`\bxox[abprs]-[0-9A-Za-z\-]{10,}\b`)},
	{"JWT", regexp.MustCompile(`\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b`)},
	{"Private Key Block", regexp.MustCompile(`-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----`)},
	{"Bearer Token 字面量", regexp.MustCompile(`(?i)["']?authorization["']?\s*[:=]\s*["']bearer\s+([A-Za-z0-9\-_.=]{16,})["']`)},
	{"硬编码口令字段", regexp.MustCompile(`(?i)\b(?:password|passwd|pwd|secret|api_?key|access_?key|token)\b\s*[:=]\s*["']([^"'\s]{8,80})["']`)},
}

// 明显的占位符/示例值不值得上报
var placeholderValues = map[string]bool{
	"password": true, "passwd": true, "secret": true, "token": true, "apikey": true,
	"api_key": true, "your_password": true, "changeme": true, "xxxxxx": true,
	"12345678": true, "undefined": true, "null": true, "example": true,
	"test": true, "demo": true, "placeholder": true, "todo": true,
}

// JSFinding 是一条 JS 抽取结果。
type JSFinding struct {
	Endpoints []string // 疑似接口路径或绝对 URL
	Secrets   []string // 已掩码的疑似凭据（含类型标签与来源）
	Calls     []string // fetch/axios/ajax 里出现的目标（原始字面量）
}

// ExtractJS 从一段 JS 内容里抽取接口与疑似凭据。
//
// source 用于标注凭据的出处（如页面 URL 或 JS 文件 URL），便于人工复核。
func ExtractJS(content, source string) JSFinding {
	var f JSFinding
	seen := map[string]bool{}
	addEndpoint := func(v string) {
		v = strings.TrimSpace(v)
		if v == "" || seen[v] || !interestingPath(v) {
			return
		}
		seen[v] = true
		f.Endpoints = append(f.Endpoints, v)
	}

	for _, m := range reJSFetch.FindAllStringSubmatch(content, 200) {
		if m[1] != "" {
			f.Calls = append(f.Calls, m[1])
			addEndpoint(m[1])
		}
	}
	for _, m := range reJSAjax.FindAllStringSubmatch(content, 200) {
		if m[1] != "" {
			f.Calls = append(f.Calls, m[1])
			addEndpoint(m[1])
		}
	}
	for _, m := range reJSURL.FindAllStringSubmatch(content, 200) {
		addEndpoint(m[1])
	}
	for _, m := range reJSPath.FindAllStringSubmatch(content, 500) {
		addEndpoint(m[1])
	}

	secretSeen := map[string]bool{}
	for _, rule := range secretRules {
		for _, m := range rule.Pattern.FindAllStringSubmatch(content, 20) {
			raw := m[0]
			if len(m) > 1 && m[1] != "" {
				raw = m[1]
			}
			if placeholderValues[strings.ToLower(strings.TrimSpace(raw))] {
				continue
			}
			masked := MaskSecret(raw)
			key := rule.Name + "|" + masked
			if secretSeen[key] {
				continue
			}
			secretSeen[key] = true
			entry := rule.Name + "=" + masked
			if source != "" {
				entry += " @" + source
			}
			f.Secrets = append(f.Secrets, entry)
		}
	}

	sort.Strings(f.Endpoints)
	f.Endpoints = dedupStrings(f.Endpoints, 200)
	f.Secrets = dedupStrings(f.Secrets, 50)
	f.Calls = dedupStrings(f.Calls, 100)
	return f
}

// MaskSecret 只保留凭据的首尾少量字符，避免把可用的活凭据写进报告。
//
// 这是刻意的数据处理决策：报告会流转、会被归档、可能被无关人员看到，
// 而"确认为真实凭据"只需要看到类型、位置与指纹，不需要完整明文。
func MaskSecret(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	r := []rune(s)
	switch {
	case len(r) <= 8:
		return strings.Repeat("*", len(r))
	case len(r) <= 16:
		return string(r[:3]) + strings.Repeat("*", len(r)-5) + string(r[len(r)-2:])
	default:
		return string(r[:4]) + strings.Repeat("*", 8) + string(r[len(r)-4:]) + "(" + itoa(len(r)) + "字符)"
	}
}

// interestingPath 过滤掉明显是静态资源的路径，只留下可能藏接口的路径。
func interestingPath(p string) bool {
	lower := strings.ToLower(p)
	if strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://") {
		return true
	}
	if !strings.HasPrefix(lower, "/") {
		return false
	}
	if strings.Contains(lower, " ") || strings.Contains(lower, "\\") {
		return false
	}
	for _, ext := range []string{".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".css",
		".woff", ".woff2", ".ttf", ".eot", ".map", ".mp4", ".webp"} {
		if strings.HasSuffix(lower, ext) {
			return false
		}
	}
	// 只保留"像接口"的：带 api/rest/graphql/v1 等关键字、带扩展名、带参数、带路径参数
	for _, kw := range []string{"/api", "/rest", "/graphql", "/v1/", "/v2/", "/v3/", "/rpc", "/json", "/data"} {
		if strings.Contains(lower, kw) {
			return true
		}
	}
	if strings.ContainsAny(p, "?&={}") {
		return true
	}
	return strings.Count(p, "/") >= 2
}

func dedupStrings(in []string, limit int) []string {
	if len(in) == 0 {
		return nil
	}
	out := make([]string, 0, len(in))
	seen := map[string]bool{}
	for _, s := range in {
		if seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
		if limit > 0 && len(out) >= limit {
			break
		}
	}
	return out
}
