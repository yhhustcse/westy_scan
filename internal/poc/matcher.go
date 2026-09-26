package poc

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"
)

// 匹配器是误报控制的第一道闸门：单个匹配器必须"可解释"，
// 命中时要能说清"凭什么命中"，否则证据链就断了。

// Response 是一次验证请求的响应快照。
type Response struct {
	URL      string
	Status   int
	Headers  http.Header
	Body     []byte
	Title    string
	Duration time.Duration
}

// MatchResult 是匹配结果。
type MatchResult struct {
	Hit bool
	Why string // 人类可读的命中/未命中理由
}

// regexCache 让同一个模板跑多个目标时不必重复编译正则。
var regexCache sync.Map // pattern -> *regexp.Regexp（编译失败的存 false）

func compileCached(pattern string) (*regexp.Regexp, error) {
	if v, ok := regexCache.Load(pattern); ok {
		if re, ok := v.(*regexp.Regexp); ok {
			return re, nil
		}
		return nil, fmt.Errorf("正则 %q 之前编译失败", pattern)
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		regexCache.Store(pattern, false)
		return nil, err
	}
	regexCache.Store(pattern, re)
	return re, nil
}

// EvaluateMatcher 计算单个匹配器。vars 用于渲染 words/regex 里的变量。
func EvaluateMatcher(m Matcher, r *Response, vars Vars) MatchResult {
	if r == nil {
		return MatchResult{Hit: false, Why: "无响应"}
	}
	var res MatchResult
	switch strings.ToLower(strings.TrimSpace(m.Type)) {
	case "status":
		res = matchStatus(m, r)
	case "word":
		res = matchWord(m, r, vars)
	case "regex":
		res = matchRegex(m, r, vars)
	case "size":
		res = matchSize(m, r)
	case "header":
		res = matchHeader(m, r, vars)
	case "title":
		res = matchTitle(m, r, vars)
	default:
		res = MatchResult{Hit: false, Why: "未知匹配器类型 " + m.Type}
	}
	if m.Negative {
		res.Hit = !res.Hit
		if res.Hit {
			res.Why = "negative 取反后命中：" + res.Why
		} else {
			res.Why = "negative 取反后未命中：" + res.Why
		}
	}
	return res
}

// EvaluateMatchers 按 condition（默认 and）组合多个匹配器。
func EvaluateMatchers(matchers []Matcher, condition string, r *Response, vars Vars) MatchResult {
	if len(matchers) == 0 {
		return MatchResult{Hit: false, Why: "模板没有匹配器"}
	}
	cond := normalizeCondition(condition, "and")
	var whys []string
	if cond == "or" {
		for _, m := range matchers {
			res := EvaluateMatcher(m, r, vars)
			whys = append(whys, res.Why)
			if res.Hit {
				return MatchResult{Hit: true, Why: "or: " + res.Why}
			}
		}
		return MatchResult{Hit: false, Why: "or 全部未命中: " + strings.Join(whys, " | ")}
	}
	for _, m := range matchers {
		res := EvaluateMatcher(m, r, vars)
		whys = append(whys, res.Why)
		if !res.Hit {
			return MatchResult{Hit: false, Why: "and 未通过: " + res.Why}
		}
	}
	return MatchResult{Hit: true, Why: "and 全部通过: " + strings.Join(whys, " | ")}
}

func normalizeCondition(v, def string) string {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "and":
		return "and"
	case "or":
		return "or"
	default:
		return def
	}
}

func matchStatus(m Matcher, r *Response) MatchResult {
	for _, code := range m.Status {
		if code == r.Status {
			return MatchResult{Hit: true, Why: fmt.Sprintf("status=%d 命中", r.Status)}
		}
	}
	return MatchResult{Hit: false, Why: fmt.Sprintf("status=%d 不在 %v 中", r.Status, m.Status)}
}

func partText(part string, r *Response) string {
	switch strings.ToLower(strings.TrimSpace(part)) {
	case "header", "headers":
		return headerText(r.Headers)
	case "all":
		return headerText(r.Headers) + "\n" + string(r.Body)
	case "title":
		return r.Title
	default: // body
		return string(r.Body)
	}
}

func headerText(h http.Header) string {
	if h == nil {
		return ""
	}
	var sb strings.Builder
	for k, vals := range h {
		for _, v := range vals {
			sb.WriteString(k)
			sb.WriteString(": ")
			sb.WriteString(v)
			sb.WriteString("\n")
		}
	}
	return sb.String()
}

func matchWord(m Matcher, r *Response, vars Vars) MatchResult {
	if len(m.Words) == 0 {
		return MatchResult{Hit: false, Why: "word 匹配器没有 words"}
	}
	text := partText(m.Part, r)
	if m.CaseInsensitive {
		text = strings.ToLower(text)
	}
	cond := normalizeCondition(m.Condition, "or")
	var missing []string
	var found []string
	for _, w := range m.Words {
		needle := Render(w, vars)
		if needle == "" {
			continue
		}
		if m.CaseInsensitive {
			needle = strings.ToLower(needle)
		}
		if strings.Contains(text, needle) {
			found = append(found, needle)
			if cond == "or" {
				return MatchResult{Hit: true, Why: "包含 " + strconvQuote(needle)}
			}
			continue
		}
		missing = append(missing, needle)
		if cond == "and" {
			return MatchResult{Hit: false, Why: "缺少 " + strconvQuote(needle)}
		}
	}
	if cond == "and" && len(missing) == 0 && len(found) > 0 {
		return MatchResult{Hit: true, Why: "全部包含: " + strings.Join(found, ",")}
	}
	if cond == "or" {
		return MatchResult{Hit: false, Why: "未包含任一关键词 " + strings.Join(missing, ",")}
	}
	return MatchResult{Hit: false, Why: "未包含关键词"}
}

func matchRegex(m Matcher, r *Response, vars Vars) MatchResult {
	if len(m.Regex) == 0 {
		return MatchResult{Hit: false, Why: "regex 匹配器没有 regex"}
	}
	text := partText(m.Part, r)
	cond := normalizeCondition(m.Condition, "or")
	var whys []string
	for _, pattern := range m.Regex {
		re, err := compileCached(Render(pattern, vars))
		if err != nil {
			whys = append(whys, "正则非法: "+err.Error())
			if cond == "and" {
				return MatchResult{Hit: false, Why: whys[len(whys)-1]}
			}
			continue
		}
		if loc := re.FindString(text); loc != "" {
			whys = append(whys, "匹配 /"+pattern+"/")
			if cond == "or" {
				return MatchResult{Hit: true, Why: "regex 命中 /" + pattern + "/"}
			}
			continue
		}
		whys = append(whys, "未匹配 /"+pattern+"/")
		if cond == "and" {
			return MatchResult{Hit: false, Why: "regex 未匹配 /" + pattern + "/"}
		}
	}
	if cond == "and" {
		return MatchResult{Hit: true, Why: "regex 全部命中: " + strings.Join(whys, " | ")}
	}
	return MatchResult{Hit: false, Why: "regex 均未命中: " + strings.Join(whys, " | ")}
}

func matchSize(m Matcher, r *Response) MatchResult {
	size := len(r.Body)
	for _, want := range m.Size {
		if want == size {
			return MatchResult{Hit: true, Why: fmt.Sprintf("body 长度=%d 命中", size)}
		}
	}
	return MatchResult{Hit: false, Why: fmt.Sprintf("body 长度=%d 不在 %v 中", size, m.Size)}
}

func matchHeader(m Matcher, r *Response, vars Vars) MatchResult {
	if len(m.Headers) == 0 {
		return MatchResult{Hit: false, Why: "header 匹配器没有 headers"}
	}
	cond := normalizeCondition(m.Condition, "and")
	var whys []string
	for name, pattern := range m.Headers {
		value := ""
		if r.Headers != nil {
			value = r.Headers.Get(name)
		}
		if value == "" {
			whys = append(whys, "缺少响应头 "+name)
			if cond == "and" {
				return MatchResult{Hit: false, Why: "缺少响应头 " + name}
			}
			continue
		}
		// 空正则视为"头存在即可"；否则按正则匹配（缺失值不参与，避免 ".*" 误报）
		if strings.TrimSpace(pattern) == "" {
			whys = append(whys, "存在响应头 "+name)
			if cond == "or" {
				return MatchResult{Hit: true, Why: "存在响应头 " + name}
			}
			continue
		}
		re, err := compileCached(Render(pattern, vars))
		if err != nil {
			whys = append(whys, "正则非法: "+err.Error())
			if cond == "and" {
				return MatchResult{Hit: false, Why: "header 正则非法: " + err.Error()}
			}
			continue
		}
		if re.MatchString(value) {
			whys = append(whys, fmt.Sprintf("%s 匹配 /%s/", name, pattern))
			if cond == "or" {
				return MatchResult{Hit: true, Why: fmt.Sprintf("响应头 %s 匹配 /%s/", name, pattern)}
			}
			continue
		}
		whys = append(whys, fmt.Sprintf("%s 未匹配 /%s/", name, pattern))
		if cond == "and" {
			return MatchResult{Hit: false, Why: fmt.Sprintf("响应头 %s 未匹配 /%s/", name, pattern)}
		}
	}
	if cond == "and" {
		return MatchResult{Hit: true, Why: "header 全部通过: " + strings.Join(whys, " | ")}
	}
	return MatchResult{Hit: false, Why: "header 均未命中: " + strings.Join(whys, " | ")}
}

func matchTitle(m Matcher, r *Response, vars Vars) MatchResult {
	re := Matcher{Type: "regex", Part: "title", Regex: m.Regex, Condition: m.Condition}
	if len(m.Words) > 0 {
		return matchWord(Matcher{Type: "word", Part: "title", Words: m.Words, Condition: m.Condition, CaseInsensitive: true}, r, vars)
	}
	return matchRegex(re, r, vars)
}

func strconvQuote(s string) string { return "\"" + s + "\"" }
