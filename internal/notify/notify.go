// Package notify 负责把扫描结果推给外部（M6）。
//
// 设计约束：只用标准库、只发一种东西 —— **HTTP POST 一个 JSON**。
// 企业微信/钉钉/Slack 的机器人 API 都是这个形状，所以一个通用 webhook 就能覆盖，
// 不需要为每个平台引入 SDK（也就不需要联网拉依赖）。
package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Format 是 payload 的形态。
type Format string

const (
	FormatJSON     Format = "json"     // 直接发事件 JSON（自建网关/SIEM 用）
	FormatWeCom    Format = "wecom"    // 企业微信群机器人
	FormatDingTalk Format = "dingtalk" // 钉钉群机器人
	FormatSlack    Format = "slack"    // Slack Incoming Webhook
)

// Options 是通知器参数。
type Options struct {
	URL     string
	Format  Format
	Timeout time.Duration
	Client  *http.Client
}

// Event 是一次通知事件。
type Event struct {
	Title   string   `json:"title"`
	ScanID  string   `json:"scan_id,omitempty"`
	Summary string   `json:"summary"`
	Details []string `json:"details,omitempty"`
	Link    string   `json:"link,omitempty"`
	Level   string   `json:"level,omitempty"` // info / warning / critical
}

// Notifier 是通知器。
type Notifier struct {
	opt    Options
	client *http.Client
}

// New 构造通知器；URL 为空时返回一个"不做事"的通知器（Enabled()=false）。
func New(opt Options) *Notifier {
	if opt.Timeout <= 0 {
		opt.Timeout = 8 * time.Second
	}
	if opt.Format == "" {
		opt.Format = FormatJSON
	}
	client := opt.Client
	if client == nil {
		client = &http.Client{Timeout: opt.Timeout}
	}
	return &Notifier{opt: opt, client: client}
}

// Enabled 表示是否配置了通知目标。
func (n *Notifier) Enabled() bool { return n != nil && strings.TrimSpace(n.opt.URL) != "" }

// Send 发送通知。未配置 URL 时直接返回 nil（不算错误）。
func (n *Notifier) Send(ctx context.Context, ev Event) error {
	if !n.Enabled() {
		return nil
	}
	payload, err := buildPayload(n.opt.Format, ev)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, n.opt.URL, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := n.client.Do(req)
	if err != nil {
		return fmt.Errorf("通知发送失败: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("通知目标返回 %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return nil
}

func buildPayload(format Format, ev Event) ([]byte, error) {
	switch format {
	case FormatWeCom:
		return json.Marshal(map[string]any{
			"msgtype":  "markdown",
			"markdown": map[string]string{"content": renderMarkdown(ev)},
		})
	case FormatDingTalk:
		return json.Marshal(map[string]any{
			"msgtype":  "markdown",
			"markdown": map[string]string{"title": ev.Title, "text": renderMarkdown(ev)},
		})
	case FormatSlack:
		return json.Marshal(map[string]string{"text": renderPlain(ev)})
	default:
		return json.Marshal(ev)
	}
}

// renderMarkdown 生成群机器人可读的消息体（企业微信/钉钉都支持 markdown）。
func renderMarkdown(ev Event) string {
	var b strings.Builder
	if ev.Level == "critical" {
		b.WriteString("### 🔴 " + ev.Title + "\n")
	} else {
		b.WriteString("### " + ev.Title + "\n")
	}
	if ev.Summary != "" {
		b.WriteString(ev.Summary + "\n")
	}
	if ev.ScanID != "" {
		b.WriteString("> 扫描: `" + ev.ScanID + "`\n")
	}
	for _, d := range ev.Details {
		b.WriteString("- " + d + "\n")
	}
	if ev.Link != "" {
		b.WriteString("\n[查看报告](" + ev.Link + ")\n")
	}
	return b.String()
}

func renderPlain(ev Event) string {
	var b strings.Builder
	b.WriteString(ev.Title)
	if ev.Summary != "" {
		b.WriteString(" | " + ev.Summary)
	}
	if ev.ScanID != "" {
		b.WriteString(" | scan=" + ev.ScanID)
	}
	for _, d := range ev.Details {
		b.WriteString("\n- " + d)
	}
	if ev.Link != "" {
		b.WriteString("\n" + ev.Link)
	}
	return b.String()
}
