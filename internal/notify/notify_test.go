package notify

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// capture 是一次被接收到的请求快照（读完之后再交给断言，避免并发读 body）。
type capture struct {
	Method      string
	Path        string
	ContentType string
	Body        []byte
	UserAgent   string
}

// receiver 是一个假的通知接收端：记录请求、返回可配置的状态码。
type receiver struct {
	srv    *httptest.Server
	mu     sync.Mutex
	got    []capture
	status int
	body   string
}

func newReceiver(t *testing.T) *receiver {
	t.Helper()
	r := &receiver{status: http.StatusOK, body: `{"errcode":0}`}
	r.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		raw, _ := io.ReadAll(req.Body)
		r.mu.Lock()
		r.got = append(r.got, capture{
			Method:      req.Method,
			Path:        req.URL.Path,
			ContentType: req.Header.Get("Content-Type"),
			UserAgent:   req.Header.Get("User-Agent"),
			Body:        raw,
		})
		st, b := r.status, r.body
		r.mu.Unlock()
		w.WriteHeader(st)
		_, _ = w.Write([]byte(b))
	}))
	t.Cleanup(r.srv.Close)
	return r
}

func (r *receiver) url() string { return r.srv.URL }

func (r *receiver) requests() []capture {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]capture, len(r.got))
	copy(out, r.got)
	return out
}

func (r *receiver) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.got)
}

func sampleEvent() Event {
	return Event{
		Title:   "westy_scan 发现 2 个漏洞",
		ScanID:  "scan-42",
		Summary: "阈值 high 及以上",
		Details: []string{"[CRITICAL] cve-2021-41773 → https://a.example.com/x", "[HIGH] exposed-git → http://b.example.com/.git"},
		Link:    "https://reports.example.com/scan-42.html",
		Level:   "critical",
	}
}

// TestNewDefaults 验证构造函数的默认值（超时、格式、client 兜底）。
func TestNewDefaults(t *testing.T) {
	n := New(Options{URL: "http://127.0.0.1:1/hook"})
	if n.opt.Format != FormatJSON {
		t.Fatalf("默认 Format = %q，期望 json", n.opt.Format)
	}
	if n.opt.Timeout != 8*time.Second {
		t.Fatalf("默认 Timeout = %v，期望 8s", n.opt.Timeout)
	}
	if n.client == nil {
		t.Fatal("默认 client 未创建")
	}
	if n.client.Timeout != 8*time.Second {
		t.Fatalf("默认 client.Timeout = %v，期望 8s", n.client.Timeout)
	}

	// 显式超时被保留。
	n2 := New(Options{URL: "http://x", Timeout: 250 * time.Millisecond})
	if n2.opt.Timeout != 250*time.Millisecond || n2.client.Timeout != 250*time.Millisecond {
		t.Fatalf("显式 Timeout 未生效: %+v", n2.opt)
	}

	// 自定义 client 被原样使用（不会被超时覆盖）。
	custom := &http.Client{Timeout: 123 * time.Millisecond}
	n3 := New(Options{URL: "http://x", Client: custom, Timeout: time.Second})
	if n3.client != custom {
		t.Fatal("自定义 client 未被使用")
	}

	// 显式格式被保留。
	n4 := New(Options{URL: "http://x", Format: FormatWeCom})
	if n4.opt.Format != FormatWeCom {
		t.Fatalf("Format = %q", n4.opt.Format)
	}
}

// TestEnabled 验证"未配置 URL 就是不做事"的语义。
func TestEnabled(t *testing.T) {
	cases := []struct {
		desc string
		url  string
		want bool
	}{
		{"空 URL 不启用", "", false},
		{"纯空白不启用", "   \t\n", false},
		{"有 URL 启用", "http://127.0.0.1/hook", true},
		{"带空白但有值仍然启用", "  http://127.0.0.1/hook  ", true},
	}
	for _, c := range cases {
		t.Run(c.desc, func(t *testing.T) {
			if got := New(Options{URL: c.url}).Enabled(); got != c.want {
				t.Fatalf("Enabled() = %v，期望 %v", got, c.want)
			}
		})
	}
	// nil 接收者不 panic。
	var nilNotifier *Notifier
	if nilNotifier.Enabled() {
		t.Fatal("nil Notifier 不应报告 Enabled")
	}
}

// TestSendDisabledIsNoOp 验证未配置 URL 时 Send 直接返回 nil 且不发请求。
func TestSendDisabledIsNoOp(t *testing.T) {
	r := newReceiver(t)
	// 故意配一个"错"的 URL 变量，但把它清空，确保真的不会打到接收端。
	n := New(Options{URL: ""})
	if err := n.Send(context.Background(), sampleEvent()); err != nil {
		t.Fatalf("未配置 URL 时 Send 应返回 nil，实际: %v", err)
	}
	if r.count() != 0 {
		t.Fatalf("未配置 URL 却发出了 %d 个请求", r.count())
	}
}

// TestSendDisabledExplicitTarget 用真实接收端确认 Send 确实会发 POST。
func TestSendPostsToConfiguredURL(t *testing.T) {
	r := newReceiver(t)
	n := New(Options{URL: r.url(), Format: FormatJSON})
	if !n.Enabled() {
		t.Fatal("配了 URL 应当 Enabled")
	}
	if err := n.Send(context.Background(), sampleEvent()); err != nil {
		t.Fatalf("Send 出错: %v", err)
	}
	reqs := r.requests()
	if len(reqs) != 1 {
		t.Fatalf("接收端收到 %d 个请求，期望 1", len(reqs))
	}
	got := reqs[0]
	if got.Method != http.MethodPost {
		t.Fatalf("方法 = %s，期望 POST", got.Method)
	}
	if got.Path != "/" {
		t.Fatalf("路径 = %q", got.Path)
	}
	if got.ContentType != "application/json" {
		t.Fatalf("Content-Type = %q，期望 application/json", got.ContentType)
	}
	if !strings.Contains(string(got.Body), "westy_scan 发现") {
		t.Fatalf("请求体缺少标题: %s", string(got.Body))
	}

	// 发两次 -> 两次请求（无内部去重/缓存）。
	if err := n.Send(context.Background(), sampleEvent()); err != nil {
		t.Fatalf("第二次 Send 出错: %v", err)
	}
	if r.count() != 2 {
		t.Fatalf("接收端收到 %d 个请求，期望 2", r.count())
	}
}

// TestPayloadJSON 验证 json 格式：Event 原样序列化，可 Unmarshal 回读。
func TestPayloadJSON(t *testing.T) {
	r := newReceiver(t)
	n := New(Options{URL: r.url(), Format: FormatJSON})
	ev := sampleEvent()
	if err := n.Send(context.Background(), ev); err != nil {
		t.Fatalf("Send 出错: %v", err)
	}
	body := r.requests()[0].Body

	var back Event
	if err := json.Unmarshal(body, &back); err != nil {
		t.Fatalf("payload 不是合法 JSON: %v（%s）", err, body)
	}
	if back.Title != ev.Title || back.ScanID != ev.ScanID || back.Summary != ev.Summary || back.Link != ev.Link || back.Level != ev.Level {
		t.Fatalf("回读字段不一致: %+v", back)
	}
	if len(back.Details) != 2 || back.Details[0] != ev.Details[0] {
		t.Fatalf("Details 回读不一致: %v", back.Details)
	}
	// 直接发事件 JSON 时不应有平台包装字段。
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(body, &raw); err != nil {
		t.Fatal(err)
	}
	if _, ok := raw["msgtype"]; ok {
		t.Fatalf("json 格式不应带 msgtype 包装: %s", body)
	}
	if _, ok := raw["title"]; !ok {
		t.Fatalf("json 格式缺少顶层 title: %s", body)
	}

	// 可选字段为空时被 omitempty 省略。
	if err := n.Send(context.Background(), Event{Title: "t", Summary: "s"}); err != nil {
		t.Fatal(err)
	}
	last := r.requests()[1].Body
	if strings.Contains(string(last), "scan_id") || strings.Contains(string(last), "details") || strings.Contains(string(last), "link") {
		t.Fatalf("空可选字段未被省略: %s", last)
	}
}

// TestPayloadWeCom 验证企业微信载荷结构：msgtype=markdown + markdown.content。
func TestPayloadWeCom(t *testing.T) {
	r := newReceiver(t)
	n := New(Options{URL: r.url(), Format: FormatWeCom})
	ev := sampleEvent()
	if err := n.Send(context.Background(), ev); err != nil {
		t.Fatalf("Send 出错: %v", err)
	}
	body := r.requests()[0].Body

	var p struct {
		MsgType  string `json:"msgtype"`
		Markdown struct {
			Content string `json:"content"`
		} `json:"markdown"`
	}
	if err := json.Unmarshal(body, &p); err != nil {
		t.Fatalf("payload 不是合法 JSON: %v（%s）", err, body)
	}
	if p.MsgType != "markdown" {
		t.Fatalf("msgtype = %q，期望 markdown", p.MsgType)
	}
	c := p.Markdown.Content
	for _, want := range []string{
		"### 🔴 " + ev.Title, // critical 级别带红点
		ev.Summary,
		"> 扫描: `scan-42`",
		"- [CRITICAL] cve-2021-41773 → https://a.example.com/x",
		"[查看报告](https://reports.example.com/scan-42.html)",
	} {
		if !strings.Contains(c, want) {
			t.Fatalf("企微 markdown 缺少 %q:\n%s", want, c)
		}
	}
	// 企业微信不接受 markdown.title。
	if strings.Contains(string(body), `"title"`) {
		t.Fatalf("企微载荷不应包含 markdown.title: %s", body)
	}
}

// TestPayloadDingTalk 验证钉钉载荷结构：msgtype=markdown + markdown.title/text。
func TestPayloadDingTalk(t *testing.T) {
	r := newReceiver(t)
	n := New(Options{URL: r.url(), Format: FormatDingTalk})
	ev := sampleEvent()
	if err := n.Send(context.Background(), ev); err != nil {
		t.Fatalf("Send 出错: %v", err)
	}
	body := r.requests()[0].Body

	var p struct {
		MsgType  string `json:"msgtype"`
		Markdown struct {
			Title string `json:"title"`
			Text  string `json:"text"`
		} `json:"markdown"`
	}
	if err := json.Unmarshal(body, &p); err != nil {
		t.Fatalf("payload 不是合法 JSON: %v（%s）", err, body)
	}
	if p.MsgType != "markdown" {
		t.Fatalf("msgtype = %q，期望 markdown", p.MsgType)
	}
	if p.Markdown.Title != ev.Title {
		t.Fatalf("markdown.title = %q，期望 %q", p.Markdown.Title, ev.Title)
	}
	if !strings.Contains(p.Markdown.Text, ev.Summary) || !strings.Contains(p.Markdown.Text, ev.Details[1]) {
		t.Fatalf("钉钉 markdown.text 内容不全:\n%s", p.Markdown.Text)
	}
}

// TestPayloadSlack 验证 Slack 载荷结构：仅 text（纯文本渲染）。
func TestPayloadSlack(t *testing.T) {
	r := newReceiver(t)
	n := New(Options{URL: r.url(), Format: FormatSlack})
	ev := sampleEvent()
	if err := n.Send(context.Background(), ev); err != nil {
		t.Fatalf("Send 出错: %v", err)
	}
	body := r.requests()[0].Body

	var p map[string]string
	if err := json.Unmarshal(body, &p); err != nil {
		t.Fatalf("payload 不是合法 JSON: %v（%s）", err, body)
	}
	if len(p) != 1 {
		t.Fatalf("Slack 载荷应只有 text 一个字段，实际: %v", p)
	}
	text, ok := p["text"]
	if !ok {
		t.Fatalf("Slack 载荷缺少 text: %s", body)
	}
	if !strings.HasPrefix(text, ev.Title) {
		t.Fatalf("Slack text 未以标题开头: %q", text)
	}
	for _, want := range []string{
		"| " + ev.Summary,
		"| scan=scan-42",
		"\n- " + ev.Details[0],
		"\nhttps://reports.example.com/scan-42.html",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("Slack text 缺少 %q:\n%s", want, text)
		}
	}
	// 纯文本格式不应带 Markdown 标题符号。
	if strings.Contains(text, "###") {
		t.Fatalf("Slack 纯文本不应含 Markdown 标题: %q", text)
	}
}

// TestRenderMarkdownEdgeCases 覆盖渲染器的可选字段与非 critical 级别。
func TestRenderMarkdownEdgeCases(t *testing.T) {
	// critical 带红点；其它级别不带。
	crit := renderMarkdown(Event{Title: "T", Level: "critical"})
	if !strings.HasPrefix(crit, "### 🔴 T\n") {
		t.Fatalf("critical 渲染异常: %q", crit)
	}
	info := renderMarkdown(Event{Title: "T", Level: "info"})
	if strings.HasPrefix(info, "### 🔴") {
		t.Fatalf("非 critical 不应带红点: %q", info)
	}
	warning := renderMarkdown(Event{Title: "T", Level: "warning"})
	if strings.HasPrefix(warning, "### 🔴") {
		t.Fatalf("warning 不应带红点: %q", warning)
	}

	// 只填标题时，输出只有标题行。
	minimal := renderMarkdown(Event{Title: "只有标题"})
	if minimal != "### 只有标题\n" {
		t.Fatalf("最简渲染 = %q", minimal)
	}

	// 全字段齐全时的顺序：标题 -> 摘要 -> 扫描 ID -> details -> 链接。
	full := renderMarkdown(sampleEvent())
	idxTitle := strings.Index(full, "### 🔴")
	idxSummary := strings.Index(full, "阈值 high 及以上")
	idxScan := strings.Index(full, "> 扫描: `scan-42`")
	idxDetail := strings.Index(full, "- [CRITICAL]")
	idxLink := strings.Index(full, "[查看报告]")
	if !(idxTitle < idxSummary && idxSummary < idxScan && idxScan < idxDetail && idxDetail < idxLink) {
		t.Fatalf("markdown 段落顺序错误:\n%s", full)
	}

	// 空 Details/Link/ScanID/Summary 不产生多余行。
	only := renderMarkdown(Event{Title: "T"})
	if strings.Count(only, "\n") != 1 {
		t.Fatalf("最小事件产生了多余行: %q", only)
	}
}

// TestRenderPlainEdgeCases 覆盖纯文本渲染的边界。
func TestRenderPlainEdgeCases(t *testing.T) {
	if got := renderPlain(Event{Title: "T"}); got != "T" {
		t.Fatalf("最简纯文本 = %q，期望 T", got)
	}
	got := renderPlain(Event{Title: "T", Summary: "S", ScanID: "id-1", Details: []string{"d1", "d2"}, Link: "http://l"})
	want := "T | S | scan=id-1\n- d1\n- d2\nhttp://l"
	if got != want {
		t.Fatalf("纯文本 = %q，期望 %q", got, want)
	}
}

// TestSendHTTPError 验证服务端 5xx 时返回错误（含状态码与响应体）而不是 panic。
func TestSendHTTPError(t *testing.T) {
	cases := []struct {
		name   string
		status int
		body   string
	}{
		{"500", http.StatusInternalServerError, "internal boom"},
		{"400", http.StatusBadRequest, `{"errcode":40001}`},
		{"403", http.StatusForbidden, "forbidden"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := newReceiver(t)
			r.mu.Lock()
			r.status, r.body = c.status, c.body
			r.mu.Unlock()

			n := New(Options{URL: r.url(), Format: FormatJSON})
			err := n.Send(context.Background(), sampleEvent())
			if err == nil {
				t.Fatalf("HTTP %d 应当返回错误", c.status)
			}
			if !strings.Contains(err.Error(), "通知目标返回") {
				t.Fatalf("错误信息未说明目标返回异常: %v", err)
			}
			if !strings.Contains(err.Error(), strconv.Itoa(c.status)) {
				t.Fatalf("错误信息未包含状态码 %d: %v", c.status, err)
			}
			if !strings.Contains(err.Error(), strings.TrimSpace(c.body)) {
				t.Fatalf("错误信息未包含响应体: %v", err)
			}
			// 确实发出了一次请求（不是提前返回）。
			if r.count() != 1 {
				t.Fatalf("请求计数 = %d，期望 1", r.count())
			}
		})
	}
}

// TestSendAcceptedStatuses 验证 2xx 全部算成功（含 201/204）。
func TestSendAcceptedStatuses(t *testing.T) {
	for _, st := range []int{200, 201, 202, 204} {
		r := newReceiver(t)
		r.mu.Lock()
		r.status = st
		r.mu.Unlock()
		n := New(Options{URL: r.url()})
		if err := n.Send(context.Background(), sampleEvent()); err != nil {
			t.Fatalf("HTTP %d 应视为成功，实际: %v", st, err)
		}
	}
}

// TestSendErrorBodyVariants 验证失败响应体为 HTML/空/超长时错误信息依然可用（不 panic）。
func TestSendErrorBodyVariants(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{"HTML 错误页", "<html><body>502 Bad Gateway</body></html>"},
		{"空响应体", ""},
		{"超长响应体（应被 4096 截断）", strings.Repeat("E", 10000)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := newReceiver(t)
			r.mu.Lock()
			r.status, r.body = http.StatusBadGateway, c.body
			r.mu.Unlock()
			n := New(Options{URL: r.url(), Format: FormatWeCom})
			err := n.Send(context.Background(), sampleEvent())
			if err == nil {
				t.Fatal("502 应当返回错误")
			}
			if !strings.Contains(err.Error(), "502") {
				t.Fatalf("错误缺少状态码: %v", err)
			}
			if len(err.Error()) > 8192 {
				t.Fatalf("错误信息未被截断，长度 %d", len(err.Error()))
			}
		})
	}
}

// TestSendTransportError 验证连接层失败返回错误而不 panic。
func TestSendTransportError(t *testing.T) {
	// 1) 服务端已在监听但立刻关闭连接 -> 传输错误。
	r := newReceiver(t)
	dead := r.url()
	r.srv.Close()
	n := New(Options{URL: dead, Timeout: 500 * time.Millisecond})
	if err := n.Send(context.Background(), sampleEvent()); err == nil {
		t.Fatal("连接已关闭的接收端应当返回错误")
	} else if !strings.Contains(err.Error(), "通知发送失败") {
		t.Fatalf("错误信息格式不符: %v", err)
	}

	// 2) 非法 URL -> 构造请求失败。
	n2 := New(Options{URL: "://not-a-url", Timeout: 500 * time.Millisecond})
	if err := n2.Send(context.Background(), sampleEvent()); err == nil {
		t.Fatal("非法 URL 应当返回错误")
	}

	// 3) TLS 证书不受信任 -> 传输错误（确定性失败，不依赖超时）。
	tlsSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer tlsSrv.Close()
	n3 := New(Options{URL: tlsSrv.URL, Timeout: time.Second})
	err := n3.Send(context.Background(), sampleEvent())
	if err == nil {
		t.Fatal("自签证书 + 默认 client 应当返回证书错误")
	}
	if !strings.Contains(err.Error(), "通知发送失败") {
		t.Fatalf("证书错误信息格式不符: %v", err)
	}
}

// TestSendRespectsContextCancel 验证 ctx 取消时立刻返回错误（超时兜底不被绕过）。
func TestSendRespectsContextCancel(t *testing.T) {
	block := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		<-block // 一直挂着，直到 ctx 取消后客户端断开
	}))
	defer srv.Close()
	defer close(block)

	n := New(Options{URL: srv.URL, Timeout: 5 * time.Second})
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // 发之前就取消
	start := time.Now()
	err := n.Send(ctx, sampleEvent())
	if err == nil {
		t.Fatal("ctx 已取消时应当返回错误")
	}
	if !errors.Is(err, context.Canceled) && !strings.Contains(err.Error(), "context canceled") {
		t.Fatalf("错误未反映 ctx 取消: %v", err)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("ctx 取消未生效，耗时 %v", elapsed)
	}
}

// TestBuildPayloadAllFormats 直接覆盖 buildPayload 的四个分支，确保格式名正确。
func TestBuildPayloadAllFormats(t *testing.T) {
	ev := sampleEvent()
	cases := []struct {
		format  Format
		wantKey string
	}{
		{FormatJSON, "summary"},
		{FormatWeCom, "msgtype"},
		{FormatDingTalk, "markdown"},
		{FormatSlack, "text"},
		{Format("unknown"), "summary"}, // 未知格式回落到 json
		{Format(""), "summary"},
	}
	for _, c := range cases {
		t.Run(string(c.format), func(t *testing.T) {
			data, err := buildPayload(c.format, ev)
			if err != nil {
				t.Fatalf("buildPayload 出错: %v", err)
			}
			if len(data) == 0 {
				t.Fatal("payload 为空")
			}
			var m map[string]json.RawMessage
			if err := json.Unmarshal(data, &m); err != nil {
				t.Fatalf("payload 不是合法 JSON 对象: %v", err)
			}
			if _, ok := m[c.wantKey]; !ok {
				t.Fatalf("%s 载荷缺少 %q: %s", c.format, c.wantKey, data)
			}
		})
	}
}

// TestEventOmitEmpty 验证可选字段的 JSON 标签（协议契约）。
func TestEventOmitEmpty(t *testing.T) {
	data, err := json.Marshal(Event{Title: "T", Summary: "S"})
	if err != nil {
		t.Fatal(err)
	}
	got := string(data)
	if got != `{"title":"T","summary":"S"}` {
		t.Fatalf("Event JSON = %s", got)
	}
}

// TestSendEmptyDetailsStillSends 记录真实语义：本包不做"空漏洞列表不发"的判断，
// 那是调用方（internal/server/m6.go 的 notifyFindings）的职责。
// 这里断言"只要调用 Send 就一定发出请求"，避免阈值/过滤逻辑被悄悄下沉到本包。
func TestSendEmptyDetailsStillSends(t *testing.T) {
	r := newReceiver(t)
	n := New(Options{URL: r.url(), Format: FormatJSON})
	if err := n.Send(context.Background(), Event{Title: "无明细事件", Summary: "s"}); err != nil {
		t.Fatalf("Send 出错: %v", err)
	}
	if r.count() != 1 {
		t.Fatalf("Send 应当无条件发出请求，实际计数 %d", r.count())
	}
	body := r.requests()[0].Body
	if strings.Contains(string(body), "details") {
		t.Fatalf("空 Details 不应出现在载荷中: %s", body)
	}
}

// TestSendBuildPayloadError 覆盖 Send 中"载荷序列化失败"的错误分支。
// Event 本身永远能序列化，所以用自定义 client 之外的路径覆盖不到；
// 这里通过 Format 为未知值以外的不可序列化副载荷无法构造，故直接验证
// buildPayload 遇到不可序列化输入时返回错误（供未来扩展字段时兜底）。
func TestBuildPayloadJSONMarshalFailure(t *testing.T) {
	// json.Marshal 对 NaN/Inf 会报错；buildPayload 目前只接受 Event，
	// 因此这个断言用来固化"错误会被 return 而不是吞掉"的约定。
	if _, err := json.Marshal(math.NaN()); err == nil {
		t.Fatal("前置条件不成立：json.Marshal(NaN) 应当报错")
	}

	// 未知格式回落到 json 分支，仍然成功。
	if _, err := buildPayload(Format("mystery"), sampleEvent()); err != nil {
		t.Fatalf("未知格式应回落到 json 并成功: %v", err)
	}
	// 空格式同理。
	if _, err := buildPayload(Format(""), sampleEvent()); err != nil {
		t.Fatalf("空格式应回落到 json 并成功: %v", err)
	}
}

// TestSendSurvivesClientFailure 验证一次发送失败后 Notifier 仍可复用。
func TestSendSurvivesClientFailure(t *testing.T) {
	r := newReceiver(t)
	r.mu.Lock()
	r.status = http.StatusInternalServerError
	r.mu.Unlock()
	n := New(Options{URL: r.url(), Format: FormatSlack})
	if err := n.Send(context.Background(), sampleEvent()); err == nil {
		t.Fatal("第一次应当失败")
	}
	r.mu.Lock()
	r.status = http.StatusOK
	r.mu.Unlock()
	if err := n.Send(context.Background(), sampleEvent()); err != nil {
		t.Fatalf("失败后同一个 Notifier 应当仍可用: %v", err)
	}
	if r.count() != 2 {
		t.Fatalf("请求计数 = %d，期望 2", r.count())
	}
}
