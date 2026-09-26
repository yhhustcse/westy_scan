package simhash

import (
	"regexp"
	"strings"
)

var (
	reScript  = regexp.MustCompile(`(?is)<script[^>]*>.*?</script>`)
	reStyle   = regexp.MustCompile(`(?is)<style[^>]*>.*?</style>`)
	reComment = regexp.MustCompile(`(?s)<!--.*?-->`)
	reTag     = regexp.MustCompile(`(?s)<[^>]*>`)
)

// RePlainTextTags 暴露给测试，确认常用的标签剥离规则没被改坏。
func RePlainTextTags() []*regexp.Regexp { return []*regexp.Regexp{reScript, reStyle, reComment, reTag} }

// plainTextReference 是一个简单的参考实现，测试里用来做交叉校验。
// 注意实体解码要与 PlainText 保持一致，否则比较的是两件不同的事。
func plainTextReference(html string) string {
	for _, re := range RePlainTextTags() {
		html = re.ReplaceAllString(html, " ")
	}
	html = strings.ReplaceAll(html, "&nbsp;", " ")
	html = strings.ReplaceAll(html, "&amp;", "&")
	html = strings.ReplaceAll(html, "&lt;", "<")
	html = strings.ReplaceAll(html, "&gt;", ">")
	return strings.Join(strings.Fields(html), " ")
}
