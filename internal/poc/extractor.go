package poc

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"westy_scan/internal/textutil"
)

// 提取器负责把"命中的证据"从响应里取出来。
// 它的价值不在"发现漏洞"，而在让复核者一眼看到关键字段（版本号、用户名、路径…）。

// Extract 执行全部提取器，返回 name -> values。
// 未显式命名的提取器用 "extract_1"、"extract_2" 占位。
func ExtractAll(extractors []Extractor, r *Response, vars Vars) map[string][]string {
	if len(extractors) == 0 || r == nil {
		return nil
	}
	out := map[string][]string{}
	for i, e := range extractors {
		name := strings.TrimSpace(e.Name)
		if name == "" {
			name = fmt.Sprintf("extract_%d", i+1)
		}
		vals := Extract(e, r, vars)
		if len(vals) == 0 {
			continue
		}
		out[name] = append(out[name], vals...)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// Extract 执行单个提取器。
func Extract(e Extractor, r *Response, vars Vars) []string {
	if r == nil {
		return nil
	}
	switch strings.ToLower(strings.TrimSpace(e.Type)) {
	case "regex":
		return extractRegex(e, r, vars)
	case "kval":
		return extractKVal(e, r)
	case "json":
		return extractJSON(e, r)
	default:
		return nil
	}
}

func extractRegex(e Extractor, r *Response, vars Vars) []string {
	text := partText(e.Part, r)
	var out []string
	for _, pattern := range e.Regex {
		re, err := compileCached(Render(pattern, vars))
		if err != nil {
			continue
		}
		for _, m := range re.FindAllStringSubmatch(text, 20) {
			group := e.Group
			if group < 0 || group >= len(m) {
				group = 0
			}
			if v := strings.TrimSpace(m[group]); v != "" {
				out = append(out, truncateValue(v, 300))
			}
		}
	}
	return dedup(out)
}

func extractKVal(e Extractor, r *Response) []string {
	if r.Headers == nil {
		return nil
	}
	var out []string
	for _, name := range e.KVal {
		if v := strings.TrimSpace(r.Headers.Get(name)); v != "" {
			out = append(out, truncateValue(name+": "+v, 300))
		}
	}
	return dedup(out)
}

// extractJSON 支持简单的点路径（a.b.c）与数组下标（a.items.0.name）。
func extractJSON(e Extractor, r *Response) []string {
	if len(r.Body) == 0 {
		return nil
	}
	var doc any
	if err := json.Unmarshal(r.Body, &doc); err != nil {
		return nil
	}
	var out []string
	for _, path := range e.JSON {
		v, ok := jsonPath(doc, path)
		if !ok {
			continue
		}
		out = append(out, truncateValue(jsonValueString(v), 300))
	}
	return dedup(out)
}

func jsonPath(doc any, path string) (any, bool) {
	cur := doc
	for _, seg := range strings.Split(strings.TrimSpace(path), ".") {
		if seg == "" {
			continue
		}
		switch node := cur.(type) {
		case map[string]any:
			v, ok := node[seg]
			if !ok {
				return nil, false
			}
			cur = v
		case []any:
			idx, err := strconv.Atoi(seg)
			if err != nil || idx < 0 || idx >= len(node) {
				return nil, false
			}
			cur = node[idx]
		default:
			return nil, false
		}
	}
	return cur, true
}

func jsonValueString(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64)
	case bool:
		return strconv.FormatBool(t)
	case nil:
		return "null"
	default:
		b, err := json.Marshal(t)
		if err != nil {
			return fmt.Sprintf("%v", t)
		}
		return string(b)
	}
}

// truncateValue 截断抽取到的证据值，保证不切坏多字节字符。
// 证据会被写进报告给人看，切出半个汉字比截短更糟，所以统一走 textutil。
func truncateValue(s string, max int) string {
	return textutil.TruncateEllipsis(strings.TrimSpace(s), max)
}

func dedup(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, s := range in {
		if seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}
