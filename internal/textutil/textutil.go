// Package textutil 提供跨包共用的字符串处理工具。
//
// 为什么单独建一个包：项目里一度存在 **4 份各自实现的"按字节截断"**
// （crawl / httpinfo / poc / report），它们都能把一个多字节字符切成半个，
// 于是中文标题、中文 banner、从中文页面里抽出的证据在报告里会显示成乱码（U+FFFD）。
// 这类 bug 不会报错、不会 panic，只会悄悄损坏交付物 —— 所以统一收口到这里，
// 由一处实现 + 一处测试守住。
package textutil

import "unicode/utf8"

// Truncate 把字符串截断到不超过 maxBytes 字节，并保证结果仍是**合法 UTF-8**。
//
// 语义：
//   - 长度不超过 maxBytes：原样返回；
//   - 超出：在**字符边界**上向前回退，宁可少几个字节也不切坏字符；
//   - maxBytes <= 0：视为不限制，原样返回。
//
// 注意：这是"按字节预算截断"，不是"按字符数截断"——
// 调用方（报告表格、元数据上限）关心的是别把交付物撑爆，用字节预算更合适。
func Truncate(s string, maxBytes int) string {
	if maxBytes <= 0 || len(s) <= maxBytes {
		return s
	}
	end := maxBytes
	// 从 maxBytes 往回退到最近的字符起始位置。
	// s[end] 是续字节（0b10xxxxxx）时说明这里正好切在一个字符中间。
	for end > 0 && !utf8.RuneStart(s[end]) {
		end--
	}
	return s[:end]
}

// TruncateEllipsis 与 Truncate 相同，但在**发生截断**时追加省略号「…」。
//
// 因此结果可能比 maxBytes 多 3 个字节（省略号本身），这是刻意的：
// 省略号的作用就是告诉读者"这里被截断了"，把它算进预算反而会让它自己被切掉。
func TruncateEllipsis(s string, maxBytes int) string {
	if maxBytes <= 0 || len(s) <= maxBytes {
		return s
	}
	return Truncate(s, maxBytes) + "…"
}
