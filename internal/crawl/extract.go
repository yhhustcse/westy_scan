package crawl

import (
	"net/url"
	"regexp"
	"sort"
	"strings"

	"westy_scan/internal/model"
)

// 本文件抽取"可攻击的输入面"：表单结构、查询参数名。
//
// 这些信息的价值在 M4：注入类/越权类模板需要一个明确的输入点
// （哪个 URL、哪个参数、什么方法），而不是盲目地把 payload 打到首页。

var (
	reFormBlock  = regexp.MustCompile(`(?is)<form[^>]*>.*?</form>`)
	reFormOpen   = regexp.MustCompile(`(?is)<form[^>]*>`)
	reFormAction = regexp.MustCompile(`(?is)action\s*=\s*["']([^"']*)["']`)
	reFormMethod = regexp.MustCompile(`(?is)method\s*=\s*["']([^"']*)["']`)
	reFieldTag   = regexp.MustCompile(`(?is)<(?:input|select|textarea|button)[^>]*>`)
	reFieldName  = regexp.MustCompile(`(?is)name\s*=\s*["']([^"']+)["']`)
	reQueryKey   = regexp.MustCompile(`(?:^|[?&])([A-Za-z0-9_\-\.\[\]]{1,64})=`)
)

// ExtractForms 抽取页面里的表单：action（解析为绝对地址）、method、字段名。
func ExtractForms(base string, body []byte) []model.Form {
	blocks := reFormBlock.FindAll(body, 20)
	if len(blocks) == 0 {
		return nil
	}
	out := make([]model.Form, 0, len(blocks))
	for _, block := range blocks {
		open := reFormOpen.Find(block)
		if open == nil {
			continue
		}
		f := model.Form{Method: "GET"}
		if m := reFormAction.FindSubmatch(open); len(m) == 2 {
			f.Action = resolve(base, unescapeHTMLAttr(strings.TrimSpace(string(m[1]))))
		}
		if m := reFormMethod.FindSubmatch(open); len(m) == 2 {
			if v := strings.ToUpper(strings.TrimSpace(string(m[1]))); v != "" {
				f.Method = v
			}
		}
		for _, tag := range reFieldTag.FindAll(block, 50) {
			if m := reFieldName.FindSubmatch(tag); len(m) == 2 {
				name := strings.TrimSpace(string(m[1]))
				if name != "" && !containsString(f.Fields, name) {
					f.Fields = append(f.Fields, name)
				}
			}
		}
		sort.Strings(f.Fields)
		out = append(out, f)
	}
	return out
}

// ExtractQueryParams 抽取 URL 查询串里的参数名（会做 URL 解码，arr%5B%5D → arr[]）。
func ExtractQueryParams(rawURL string) []string {
	u, err := url.Parse(rawURL)
	if err != nil || u.RawQuery == "" {
		return nil
	}
	// 标准解析：能正确处理百分号编码与重复键；遇到畸形 query 时尽力而为。
	values, _ := url.ParseQuery(u.RawQuery)
	out := make([]string, 0, len(values))
	for k := range values {
		if k != "" {
			out = append(out, k)
		}
	}
	if len(out) == 0 {
		// 退化路径：query 完全无法解析时用正则兜底，至少拿到形如 name= 的片段
		seen := map[string]bool{}
		for _, m := range reQueryKey.FindAllStringSubmatch(u.RawQuery, 50) {
			name := m[1]
			if name == "" || seen[name] {
				continue
			}
			seen[name] = true
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}

// MergeParams 去重合并多组参数名（结果有序，便于报告稳定输出）。
func MergeParams(lists ...[]string) []string {
	seen := map[string]bool{}
	var out []string
	for _, list := range lists {
		for _, p := range list {
			p = strings.TrimSpace(p)
			if p == "" || seen[p] {
				continue
			}
			seen[p] = true
			out = append(out, p)
		}
	}
	sort.Strings(out)
	return out
}

// FormFieldNames 把表单字段拍平成参数名列表。
func FormFieldNames(forms []model.Form) []string {
	var lists [][]string
	for _, f := range forms {
		lists = append(lists, f.Fields)
	}
	return MergeParams(lists...)
}

func containsString(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}
