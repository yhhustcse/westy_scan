package textutil

import (
	"strings"
	"testing"
	"unicode/utf8"
)

// 这个包的测试存在的唯一理由：项目里曾经有 4 份各自实现的按字节截断（crawl/httpinfo/poc/report），
// 每一份都能把多字节字符切成半个，让中文标题、中文 banner、中文证据在报告里变成乱码。
// 现在只有一份实现，于是只需要在这里把边界钉死。

func TestTruncateBoundaries(t *testing.T) {
	cn := "漏洞扫描器" // 5 个汉字 = 15 字节
	cases := []struct {
		name     string
		in       string
		max      int
		want     string
		wantSame bool // true 表示应与输入完全相同
	}{
		{name: "不超预算原样返回", in: cn, max: 15, want: cn, wantSame: true},
		{name: "预算更大原样返回", in: cn, max: 999, want: cn, wantSame: true},
		{name: "max=0 视为不限", in: cn, max: 0, want: cn, wantSame: true},
		{name: "max 为负数视为不限", in: cn, max: -5, want: cn, wantSame: true},
		{name: "整字边界(3 字节=1 字)", in: cn, max: 3, want: "漏"},
		{name: "整字边界(9 字节=3 字)", in: cn, max: 9, want: "漏洞扫"},
		{name: "切在汉字中间要回退", in: cn, max: 4, want: "漏"},
		{name: "切在汉字中间要回退(5)", in: cn, max: 5, want: "漏"},
		{name: "上限小于单个汉字", in: cn, max: 2, want: ""},
		{name: "上限为 1", in: cn, max: 1, want: ""},
		{name: "纯 ASCII 按字节切", in: "abcdef", max: 4, want: "abcd"},
		{name: "空串", in: "", max: 10, want: ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := Truncate(c.in, c.max)
			if got != c.want {
				t.Fatalf("Truncate(%q, %d) = %q，期望 %q", c.in, c.max, got, c.want)
			}
			if !utf8.ValidString(got) {
				t.Fatalf("结果不是合法 UTF-8: %q", got)
			}
			if c.max > 0 && len(got) > c.max {
				t.Fatalf("结果超预算: %d > %d", len(got), c.max)
			}
			if c.wantSame && got != c.in {
				t.Fatalf("应原样返回，实际被改动: %q", got)
			}
		})
	}
}

// emoji 是 4 字节字符，混排时最容易暴露"按字节切"的缺陷。
func TestTruncateMixedWidthRunes(t *testing.T) {
	in := strings.Repeat("洞", 3) + "🔴" + "abc" // 9 + 4 + 3 = 16 字节
	for max := 1; max <= len(in); max++ {
		got := Truncate(in, max)
		if !utf8.ValidString(got) {
			t.Fatalf("max=%d 时产生非法 UTF-8: %q", max, got)
		}
		if len(got) > max {
			t.Fatalf("max=%d 时超预算: %d 字节", max, len(got))
		}
		if !strings.HasPrefix(in, got) {
			t.Fatalf("截断结果必须是原串的前缀：%q 不是 %q 的前缀", got, in)
		}
	}
}

func TestTruncateEllipsis(t *testing.T) {
	cn := strings.Repeat("洞", 10) // 30 字节

	// 未截断：不加省略号
	if got := TruncateEllipsis(cn, 30); got != cn {
		t.Fatalf("未截断时不应加省略号: %q", got)
	}
	if got := TruncateEllipsis(cn, 100); got != cn {
		t.Fatalf("未截断时不应加省略号: %q", got)
	}
	if got := TruncateEllipsis(cn, 0); got != cn {
		t.Fatalf("max<=0 时不应加省略号: %q", got)
	}

	// 截断：必须加省略号，且截断部分本身是合法 UTF-8
	got := TruncateEllipsis(cn, 10) // 10 字节 -> 回退到 9 字节（3 个汉字）
	if !strings.HasSuffix(got, "…") {
		t.Fatalf("截断后应带省略号: %q", got)
	}
	if got != "洞洞洞…" {
		t.Fatalf("截断结果 = %q，期望 %q", got, "洞洞洞…")
	}
	// 省略号本身占 3 字节，所以总长允许超过预算 3 字节——这是刻意的（省略号要能显示出来）
	if len(got) > 10+3 {
		t.Fatalf("含省略号后超预算过多: %d 字节", len(got))
	}
}

// 真实调用点回归：这些上限来自各包的既有代码，确保边界上不再产生乱码。
func TestTruncateRealCallSiteBudgets(t *testing.T) {
	budgets := []struct {
		what string
		max  int
	}{
		{"报告表格 Host", 40},
		{"报告表格 Product", 24},
		{"报告表格 Version", 16},
		{"报告表格 Banner", 44},
		{"报告 Markdown 单元格", 120},
		{"HTML 标题", 80},
		{"httpinfo 标题", 200},
		{"crawl 标题", 200},
		{"crawl JS 接口清单", 1500},
		{"poc 抽取证据", 300},
	}
	// 用 3 字节汉字 + 4 字节 emoji 混排，逐个预算验证
	in := strings.Repeat("洞漏", 200) + strings.Repeat("🔴", 50)
	for _, b := range budgets {
		got := Truncate(in, b.max)
		if !utf8.ValidString(got) {
			t.Errorf("%s（上限 %d 字节）产生了非法 UTF-8", b.what, b.max)
		}
		if len(got) > b.max {
			t.Errorf("%s（上限 %d 字节）超预算: %d", b.what, b.max, len(got))
		}
	}
}
