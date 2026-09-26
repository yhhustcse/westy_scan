package fingerprint

import (
	"regexp"
	"strings"
	"testing"
)

// 规则库质量门禁（M7）。
//
// 指纹库最贵的错误是**误报**：一条 `.*` 规则能在任何站点的空响应头上命中，
// 于是整份报告的可信度就没了（M2 真踩过这个坑）。
// 这些门禁把"写规则时容易犯的错"变成构建期就能拦住的红线。

// minLibraryRules 是内置规则数的下限。
// 这个数字不是 KPI，而是防回归：规则库被误删/合并出错时会立刻失败。
const minLibraryRules = 150

func TestDefaultRulesCompileAndCount(t *testing.T) {
	rules := DefaultRules()
	if _, err := New(rules); err != nil {
		t.Fatalf("内置规则编译失败: %v", err)
	}
	if len(rules) < minLibraryRules {
		t.Errorf("内置规则只有 %d 条，低于下限 %d（规则库被误删？）", len(rules), minLibraryRules)
	}
	t.Logf("内置指纹规则共 %d 条", len(rules))
}

func TestDefaultRulesNoDuplicateNames(t *testing.T) {
	// 注意必须**大小写不敏感**：合并外置规则时是按大小写不敏感去重的，
	// 所以 `Cacti` 与 `cacti` 在真实合并语义下就是同一条，这里也要按同一标准查。
	seen := map[string][]string{}
	for _, r := range DefaultRules() {
		key := strings.ToLower(strings.TrimSpace(r.Name))
		seen[key] = append(seen[key], r.Name)
	}
	for key, names := range seen {
		if len(names) > 1 {
			t.Errorf("规则名重复 %q（%d 次：%s）：同名规则会让「命中哪个产品」变得不确定",
				key, len(names), strings.Join(names, ", "))
		}
	}
}

// TestDefaultRulesNoEmptyMatchingRegex 拦住"能在空串上命中"的正则。
//
// 为什么这条最重要：HTTP 响应头为空、body 为空都很常见。
// 一条能匹配空串的正则 = 在任何目标上都命中 = 满屏误报。
func TestDefaultRulesNoEmptyMatchingRegex(t *testing.T) {
	check := func(rule, field, pattern string) {
		re, err := regexp.Compile(pattern)
		if err != nil {
			t.Errorf("规则 %s 的 %s 正则非法: %v", rule, field, err)
			return
		}
		if re.MatchString("") {
			t.Errorf("规则 %s 的 %s 正则 %q 能匹配空串 —— 空响应头/空响应体会让它到处命中（误报源）",
				rule, field, pattern)
		}
	}
	for _, r := range DefaultRules() {
		for _, p := range r.Banner {
			check(r.Name, "banner_regex", p)
		}
		for _, p := range r.Title {
			check(r.Name, "title_regex", p)
		}
		for _, p := range r.Body {
			check(r.Name, "body_regex", p)
		}
		for name, p := range r.Header {
			check(r.Name, "header_regex["+name+"]", p)
		}
	}
}

// TestDefaultRulesHaveEvidence 要求"特征串规则得有真特征"。
//
// 只有端口、没有任何特征串的规则只能给 low 置信度（纯端口推断本来就不可靠）；
// 反过来，声明了 high 的规则必须有实打实的特征串，不能靠猜。
func TestDefaultRulesHaveEvidence(t *testing.T) {
	for _, r := range DefaultRules() {
		hasEvidence := len(r.Banner)+len(r.Title)+len(r.Body)+len(r.Header)+len(r.FaviconHash) > 0
		if !hasEvidence && r.Confidence == "high" {
			t.Errorf("规则 %s 没有任何特征串却声明 high 置信度", r.Name)
		}
	}
}
