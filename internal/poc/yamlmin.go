package poc

import (
	"fmt"
	"strconv"
	"strings"
)

// ParseYAMLSubset 解析 nuclei 模板常用的 YAML **子集**，返回 map[string]any / []any / 标量。
//
// 支持（覆盖社区模板的绝大多数写法）：
//   - 注释（#）、空行
//   - 块映射（空格缩进；禁止 tab）
//   - 块序列（"- "），含 "- key: value" 后跟同项其它键
//   - 标量：裸字符串、单/双引号、整数、浮点、true/false/null
//   - 内联序列 [a, b] 与内联映射 {k: v}
//   - 块标量 | 与 >（含 |- / >- 去尾变体）
//
// 明确**不支持**：锚点/别名（&/*）、多文档（---）、显式类型标签（!!）、复杂 flow 嵌套。
// 遇到这些返回带行号的错误 —— 宁可拒绝，也不要解析出一份"看起来对"的错误结构：
// 模板解析错误如果被静默容忍，表现出来就是"漏洞扫不出来"。
func ParseYAMLSubset(src string) (any, error) {
	lines, err := lexYAML(src)
	if err != nil {
		return nil, err
	}
	if len(lines) == 0 {
		return map[string]any{}, nil
	}
	value, next, err := parseBlock(lines, 0, lines[0].indent)
	if err != nil {
		return nil, err
	}
	if next < len(lines) {
		return nil, fmt.Errorf("第 %d 行: 缩进不一致或存在无法解析的内容: %q", lines[next].num, lines[next].text)
	}
	return value, nil
}

type yamlLine struct {
	indent int
	text   string
	num    int
}

func lexYAML(src string) ([]yamlLine, error) {
	src = strings.ReplaceAll(src, "\r\n", "\n")
	var out []yamlLine
	for i, raw := range strings.Split(src, "\n") {
		num := i + 1
		line := strings.TrimRight(raw, " \t")
		if strings.TrimSpace(line) == "" {
			continue
		}
		indent := 0
		for indent < len(line) && line[indent] == ' ' {
			indent++
		}
		if indent < len(line) && line[indent] == '\t' {
			return nil, fmt.Errorf("第 %d 行: YAML 缩进不允许使用 tab", num)
		}
		text := strings.TrimRight(stripYAMLComment(line[indent:]), " ")
		if strings.TrimSpace(text) == "" {
			continue
		}
		trimmed := strings.TrimSpace(text)
		switch {
		case trimmed == "---" || trimmed == "...":
			return nil, fmt.Errorf("第 %d 行: 不支持多文档 YAML（---）", num)
		case strings.HasPrefix(trimmed, "!!"):
			return nil, fmt.Errorf("第 %d 行: 不支持显式类型标签（!!）", num)
		}
		// 锚点/别名可能出现在行首，也可能出现在 "key: &anchor" 或 "- *alias" 里
		if probe := yamlValueProbe(trimmed); strings.HasPrefix(probe, "&") || strings.HasPrefix(probe, "*") {
			return nil, fmt.Errorf("第 %d 行: 不支持锚点/别名（& / *）", num)
		}
		out = append(out, yamlLine{indent: indent, text: text, num: num})
	}
	return out, nil
}

// yamlValueProbe 取出"值"的位置用于检测锚点/别名。
func yamlValueProbe(trimmed string) string {
	probe := trimmed
	if strings.HasPrefix(probe, "-") {
		probe = strings.TrimSpace(strings.TrimPrefix(probe, "-"))
	}
	if _, v, ok := splitKeyValue(probe); ok {
		return v
	}
	return probe
}

// stripYAMLComment 去掉行内注释（# 必须前面有空白，且不在引号内）。
func stripYAMLComment(s string) string {
	inSingle, inDouble := false, false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '\'' && !inDouble:
			inSingle = !inSingle
		case c == '"' && !inSingle:
			inDouble = !inDouble
		case c == '#' && !inSingle && !inDouble:
			if i == 0 || s[i-1] == ' ' || s[i-1] == '\t' {
				return s[:i]
			}
		}
	}
	return s
}

func parseBlock(lines []yamlLine, idx, indent int) (any, int, error) {
	if idx >= len(lines) {
		return nil, idx, nil
	}
	if lines[idx].indent < indent {
		return nil, idx, nil
	}
	if isSeqItem(lines[idx].text) {
		return parseSeq(lines, idx, lines[idx].indent)
	}
	return parseMap(lines, idx, lines[idx].indent)
}

func isSeqItem(text string) bool {
	t := strings.TrimSpace(text)
	return t == "-" || strings.HasPrefix(t, "- ")
}

func parseSeq(lines []yamlLine, idx, indent int) (any, int, error) {
	out := []any{}
	for idx < len(lines) {
		line := lines[idx]
		if line.indent != indent || !isSeqItem(line.text) {
			break
		}
		rest := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line.text), "-"))
		if rest == "" {
			idx++
			if idx < len(lines) && lines[idx].indent > indent {
				v, next, err := parseBlock(lines, idx, lines[idx].indent)
				if err != nil {
					return nil, idx, err
				}
				out = append(out, v)
				idx = next
			} else {
				out = append(out, nil)
			}
			continue
		}
		if _, _, ok := splitKeyValue(rest); ok {
			// "- key: value"：把这一行改写成同缩进的映射行，让 parseMap 继续吃同项的后续行
			orig := lines[idx]
			lines[idx] = yamlLine{indent: indent + 2, text: rest, num: orig.num}
			mv, next, err := parseMap(lines, idx, indent+2)
			lines[idx] = orig
			if err != nil {
				return nil, idx, err
			}
			out = append(out, mv)
			idx = next
			continue
		}
		out = append(out, parseScalar(rest))
		idx++
	}
	return out, idx, nil
}

func parseMap(lines []yamlLine, idx, indent int) (any, int, error) {
	out := map[string]any{}
	for idx < len(lines) {
		line := lines[idx]
		if line.indent != indent || isSeqItem(line.text) {
			break
		}
		key, value, ok := splitKeyValue(line.text)
		if !ok {
			return nil, idx, fmt.Errorf("第 %d 行: 不是合法的 key: value: %q", line.num, line.text)
		}
		if key == "" {
			return nil, idx, fmt.Errorf("第 %d 行: 空键名", line.num)
		}
		if value == "" {
			idx++
			if idx < len(lines) && lines[idx].indent > indent {
				v, next, err := parseBlock(lines, idx, lines[idx].indent)
				if err != nil {
					return nil, idx, err
				}
				out[key] = v
				idx = next
				continue
			}
			out[key] = nil
			continue
		}
		if isBlockScalar(value) {
			idx++
			var parts []string
			for idx < len(lines) && lines[idx].indent > indent {
				parts = append(parts, lines[idx].text)
				idx++
			}
			text := strings.Join(parts, "\n")
			if strings.HasPrefix(value, ">") {
				text = strings.Join(parts, " ")
			}
			if !strings.HasSuffix(value, "-") {
				text += "\n"
			}
			out[key] = text
			continue
		}
		out[key] = parseScalar(value)
		idx++
	}
	return out, idx, nil
}

// splitKeyValue 在 depth 0 且不在引号内的 ":" 处切分；要求冒号后是空白或行尾，
// 这样 http:// 这类 URL 不会被误切。
func splitKeyValue(s string) (key, value string, ok bool) {
	inSingle, inDouble := false, false
	depth := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '\'' && !inDouble:
			inSingle = !inSingle
		case c == '"' && !inSingle:
			inDouble = !inDouble
		case (c == '[' || c == '{') && !inSingle && !inDouble:
			depth++
		case (c == ']' || c == '}') && !inSingle && !inDouble:
			depth--
		case c == ':' && !inSingle && !inDouble && depth == 0:
			if i+1 >= len(s) || s[i+1] == ' ' {
				return strings.TrimSpace(s[:i]), strings.TrimSpace(s[i+1:]), true
			}
		}
	}
	return "", "", false
}

func isBlockScalar(v string) bool {
	switch v {
	case "|", "|-", "|+", ">", ">-", ">+":
		return true
	}
	return false
}

func parseScalar(s string) any {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	switch s {
	case "null", "Null", "NULL", "~":
		return nil
	case "true", "True", "TRUE", "yes", "Yes":
		return true
	case "false", "False", "FALSE", "no", "No":
		return false
	}
	if len(s) >= 2 {
		if (s[0] == '"' && s[len(s)-1] == '"') || (s[0] == '\'' && s[len(s)-1] == '\'') {
			return unquoteYAML(s)
		}
	}
	if strings.HasPrefix(s, "[") && strings.HasSuffix(s, "]") {
		return parseFlowSeq(s[1 : len(s)-1])
	}
	if strings.HasPrefix(s, "{") && strings.HasSuffix(s, "}") {
		return parseFlowMap(s[1 : len(s)-1])
	}
	if i, err := strconv.Atoi(s); err == nil {
		return float64(i)
	}
	if f, err := strconv.ParseFloat(s, 64); err == nil {
		return f
	}
	return s
}

func unquoteYAML(s string) string {
	if len(s) < 2 {
		return s
	}
	inner := s[1 : len(s)-1]
	if s[0] == '\'' {
		return strings.ReplaceAll(inner, "''", "'")
	}
	// 双引号：处理常见转义
	replacer := strings.NewReplacer(
		`\"`, `"`, `\\`, `\`, `\n`, "\n", `\t`, "\t", `\r`, "\r",
	)
	return replacer.Replace(inner)
}

func parseFlowSeq(inner string) []any {
	parts := splitFlow(inner)
	out := make([]any, 0, len(parts))
	for _, p := range parts {
		if strings.TrimSpace(p) == "" {
			continue
		}
		out = append(out, parseScalar(p))
	}
	return out
}

func parseFlowMap(inner string) map[string]any {
	out := map[string]any{}
	for _, p := range splitFlow(inner) {
		k, v, ok := splitKeyValue(strings.TrimSpace(p))
		if !ok {
			continue
		}
		out[unquoteYAML(k)] = parseScalar(v)
	}
	return out
}

// splitFlow 按 depth 0 的逗号切分（尊重引号与嵌套括号）。
func splitFlow(s string) []string {
	var out []string
	inSingle, inDouble := false, false
	depth := 0
	start := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '\'' && !inDouble:
			inSingle = !inSingle
		case c == '"' && !inSingle:
			inDouble = !inDouble
		case (c == '[' || c == '{') && !inSingle && !inDouble:
			depth++
		case (c == ']' || c == '}') && !inSingle && !inDouble:
			depth--
		case c == ',' && !inSingle && !inDouble && depth == 0:
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	out = append(out, s[start:])
	return out
}
