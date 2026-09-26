package simhash

import (
	"strings"
	"testing"
)

func TestHashStableAndEmpty(t *testing.T) {
	if got := Hash(""); got != 0 {
		t.Errorf("空文本应返回 0，实际 %d", got)
	}
	if got := Hash("   \n\t "); got != 0 {
		t.Errorf("纯空白应返回 0，实际 %d", got)
	}
	text := "the quick brown fox jumps over the lazy dog"
	first := Hash(text)
	for i := 0; i < 5; i++ {
		if got := Hash(text); got != first {
			t.Fatalf("同一文本哈希不稳定: %d != %d", got, first)
		}
	}
}

func TestIdenticalTextDistanceZero(t *testing.T) {
	text := strings.Repeat("登录 系统 管理 后台 用户 列表 ", 30)
	if d := Distance(Hash(text), Hash(text)); d != 0 {
		t.Errorf("相同文本距离应为 0，实际 %d", d)
	}
}

// 模板化页面的典型场景：95% 相同，只有一小段不同
func TestTemplatePagesAreSimilar(t *testing.T) {
	header := "欢迎光临 本站 商品 列表 分页 上一页 下一页 版权所有 联系我们 关于我们 "
	page1 := header + "商品A 价格 100 元 库存 5 件 加入购物车"
	page2 := header + "商品B 价格 200 元 库存 3 件 加入购物车"

	d := Distance(Hash(page1), Hash(page2))
	if d > 6 {
		t.Errorf("模板化页面距离应较小，实际 %d", d)
	}
	if !Similar(Hash(page1), Hash(page2), 6) {
		t.Errorf("模板化页面应判定为近似重复（距离 %d）", d)
	}
}

func TestDifferentPagesAreNotSimilar(t *testing.T) {
	a := "用户登录 用户名 密码 验证码 记住我 忘记密码"
	b := "应用程序接口文档 请求参数 返回示例 错误码 限流策略 鉴权方式"
	d := Distance(Hash(a), Hash(b))
	if Similar(Hash(a), Hash(b), 3) {
		t.Errorf("完全不同的页面不应判定为重复（距离 %d）", d)
	}
}

func TestDistanceBounds(t *testing.T) {
	var zero, all uint64
	all = ^uint64(0)
	if d := Distance(zero, all); d != 64 {
		t.Errorf("全 0 与全 1 的距离应为 64，实际 %d", d)
	}
	if d := Distance(zero, zero); d != 0 {
		t.Errorf("自身距离应为 0，实际 %d", d)
	}
	if d := Distance(0b1010, 0b1000); d != 1 {
		t.Errorf("距离应为 1，实际 %d", d)
	}
}

func TestTokenize(t *testing.T) {
	toks := Tokenize("Hello, World! 你好世界 42")
	joined := strings.Join(toks, "|")
	for _, want := range []string{"hello", "world", "42", "你", "好", "世", "界"} {
		if !strings.Contains(joined, want) {
			t.Errorf("缺少 token %q：%s", want, joined)
		}
	}
	if len(Tokenize("")) != 0 {
		t.Error("空文本不应产生 token")
	}
}

func TestPlainText(t *testing.T) {
	html := []byte(`<html><head><title>T</title>
		<script>var secret = "should-be-removed";</script>
		<style>.a{color:red}</style></head>
		<body><!-- 注释 --><h1>标题</h1><p>正文 &amp; 内容</p></body></html>`)
	got := PlainText(html)
	if strings.Contains(got, "should-be-removed") {
		t.Errorf("script 内容应被剥离: %q", got)
	}
	if strings.Contains(got, "color:red") {
		t.Errorf("style 内容应被剥离: %q", got)
	}
	if strings.Contains(got, "注释") {
		t.Errorf("注释应被剥离: %q", got)
	}
	for _, want := range []string{"标题", "正文", "内容"} {
		if !strings.Contains(got, want) {
			t.Errorf("缺少正文 %q: %q", want, got)
		}
	}
	if got != plainTextReference(string(html)) {
		t.Errorf("PlainText 与参考实现不一致:\n%q\n%q", got, plainTextReference(string(html)))
	}
}

// 相似度必须对"正文相同、导航不同"这种真实情况稳健
func TestSimilarIgnoresBoilerplateDrift(t *testing.T) {
	body := strings.Repeat("这是一段很长的正文内容 用于模拟真实文章 ", 40)
	a := body + " 导航 首页 产品 服务 支持 联系我们"
	b := body + " 导航 首页 解决方案 案例 关于 招聘"
	if !Similar(Hash(a), Hash(b), 8) {
		t.Errorf("正文相同的页面应判定为近似重复（距离 %d）", Distance(Hash(a), Hash(b)))
	}
}
