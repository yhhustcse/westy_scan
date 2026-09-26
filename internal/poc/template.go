// Package poc 是一个**验证型**漏洞模板引擎（M4）。
//
// 定位：只做"发现并验证"，不做"利用"。
// 模板模型里**根本没有**执行命令、写文件、删数据的字段 —— 破坏性动作用结构禁止，
// 而不是靠"请大家不要这么写"的约定。
//
// 原生格式是 JSON（编译期校验、零依赖）；同时提供 nuclei YAML 的**子集**适配器
// （见 yamlmin.go），以便复用社区模板。不支持的语法会明确报错，不会静默忽略。
package poc

import (
	"strings"
	"time"
)

// 严重级别。
const (
	SeverityInfo     = "info"
	SeverityLow      = "low"
	SeverityMedium   = "medium"
	SeverityHigh     = "high"
	SeverityCritical = "critical"
)

// Template 是一个漏洞模板。
type Template struct {
	ID   string `json:"id"`
	Info Info   `json:"info"`
	// HTTP 段：一组请求。模板命中要求满足 MatchersCondition（默认 or，与 nuclei 一致）。
	HTTP              []HTTPRequest `json:"http"`
	MatchersCondition string        `json:"matchers-condition,omitempty"` // and | or
	// Intrusive 标记"有副作用/高噪声"的模板：必须显式 -allow-intrusive 才会执行。
	Intrusive bool `json:"intrusive,omitempty"`
	// Source 是模板来源（文件路径或 "builtin"），用于审计与排障。
	Source string `json:"-"`
}

// Info 是模板元信息。
type Info struct {
	Name        string   `json:"name"`
	Severity    string   `json:"severity,omitempty"`
	Description string   `json:"description,omitempty"`
	Tags        []string `json:"tags,omitempty"`
	Reference   []string `json:"reference,omitempty"`
	// Confidence 表达"这个模板本身有多容易误报"（high/medium/low），
	// 与"资产识别置信度"是同一套语义，便于统一排序与展示。
	Confidence string `json:"confidence,omitempty"`
}

// HTTPRequest 是一次验证请求。
type HTTPRequest struct {
	Method            string            `json:"method,omitempty"` // 默认 GET
	Path              []string          `json:"path"`
	Headers           map[string]string `json:"headers,omitempty"`
	Body              string            `json:"body,omitempty"`
	MatchersCondition string            `json:"matchers-condition,omitempty"` // and | or（默认 and）
	Matchers          []Matcher         `json:"matchers"`
	Extractors        []Extractor       `json:"extractors,omitempty"`
	Redirects         bool              `json:"redirects,omitempty"`
	MaxRedirects      int               `json:"max-redirects,omitempty"`
}

// Matcher 是匹配器。
type Matcher struct {
	Type   string   `json:"type"`           // status | word | regex | size | header | title
	Part   string   `json:"part,omitempty"` // body | header | all | title
	Words  []string `json:"words,omitempty"`
	Regex  []string `json:"regex,omitempty"`
	Status []int    `json:"status,omitempty"`
	Size   []int    `json:"size,omitempty"`
	// Headers 用于 type=header，元素形如 "Content-Type: application/json"（值为正则）
	Headers map[string]string `json:"headers,omitempty"`
	// Condition 控制列表内部的关系：and 要求全部命中，or 命中一个即可（默认 or）。
	Condition       string `json:"condition,omitempty"`
	Negative        bool   `json:"negative,omitempty"`
	CaseInsensitive bool   `json:"case-insensitive,omitempty"`
}

// Extractor 是结果提取器。
type Extractor struct {
	Type  string   `json:"type"`           // regex | kval | json
	Part  string   `json:"part,omitempty"` // body | header
	Regex []string `json:"regex,omitempty"`
	Group int      `json:"group,omitempty"`
	KVal  []string `json:"kval,omitempty"`
	JSON  []string `json:"json,omitempty"`
	Name  string   `json:"name,omitempty"`
}

// Target 是一次漏洞验证的目标（由已发现的 Web 资产派生）。
type Target struct {
	Input  string // 原始输入值
	Scheme string
	Host   string // 主机名（域名或 IP）
	Port   int
	IP     string
	Path   string // 资产已知的路径（可能为空）
}

// BaseURL 返回 scheme://host[:port]，与 nuclei 的 {{BaseURL}} 语义一致。
func (t Target) BaseURL() string {
	if t.Host == "" {
		return ""
	}
	if t.Port <= 0 || (t.Scheme == "http" && t.Port == 80) || (t.Scheme == "https" && t.Port == 443) {
		return t.Scheme + "://" + t.Host
	}
	return t.Scheme + "://" + t.Host + ":" + itoa(t.Port)
}

// RootURL 返回 scheme://host（始终省略端口），便于构造跨端口/标准端口的 URL。
func (t Target) RootURL() string {
	if t.Host == "" {
		return ""
	}
	return t.Scheme + "://" + t.Host
}

// Finding 是一条验证结论。
type Finding struct {
	TemplateID  string              `json:"template_id"`
	Name        string              `json:"name"`
	Severity    string              `json:"severity"`
	Tags        []string            `json:"tags,omitempty"`
	Target      string              `json:"target"`     // 被检目标（BaseURL）
	MatchedAt   string              `json:"matched_at"` // 实际命中的 URL
	Confidence  string              `json:"confidence,omitempty"`
	Verified    bool                `json:"verified"` // 是否通过二次确认
	Intrusive   bool                `json:"intrusive,omitempty"`
	Extracted   map[string][]string `json:"extracted,omitempty"`
	Evidence    Evidence            `json:"evidence"`
	Description string              `json:"description,omitempty"`
	Reference   []string            `json:"reference,omitempty"`
	FoundAt     time.Time           `json:"found_at"`
	// 分布式场景（M5）：结果归属，便于按 scan_id 对齐完整证据链
	ScanID  string `json:"scan_id,omitempty"`
	AgentID string `json:"agent_id,omitempty"`
}

// Evidence 是可复现证据：没有它，漏洞报告就只是一句断言。
type Evidence struct {
	Request  string `json:"request"`
	Response string `json:"response"`
	Matcher  string `json:"matcher,omitempty"` // 命中的匹配器说明
}

// severityRank 用于比较与阈值判断。
func severityRank(s string) int {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case SeverityCritical:
		return 5
	case SeverityHigh:
		return 4
	case SeverityMedium:
		return 3
	case SeverityLow:
		return 2
	case SeverityInfo:
		return 1
	default:
		return 0
	}
}

// SeverityAtLeast 判断 sev 是否不低于阈值（threshold 为空表示不限制）。
func SeverityAtLeast(sev, threshold string) bool {
	if strings.TrimSpace(threshold) == "" {
		return true
	}
	return severityRank(sev) >= severityRank(threshold)
}
