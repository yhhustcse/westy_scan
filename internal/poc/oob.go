package poc

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// OOBCallback 是一次外带回连记录。
type OOBCallback struct {
	Token      string    `json:"token"`
	Method     string    `json:"method"`
	Path       string    `json:"path"`
	RemoteAddr string    `json:"remote_addr"`
	UserAgent  string    `json:"user_agent,omitempty"`
	At         time.Time `json:"at"`
}

// OOB 是自建的 HTTP 回调监听器，用于验证"无回显"类漏洞（盲注、SSRF、命令注入）。
//
// 为什么不用第三方 DNSLog 平台：
//  1. 不该把授权测试的流量与目标信息交给外部平台（数据合规）；
//  2. 内网/隔离环境根本访问不到外网。
//
// DNS 型外带需要自建权威 DNS，属于后续阶段；HTTP 型回调覆盖了绝大多数场景，
// 而且能在本地端到端验证（假靶机收到 payload 后回连监听器即可）。
type OOB struct {
	ln      net.Listener
	srv     *http.Server
	domain  string
	urlBase string

	mu     sync.Mutex
	tokens map[string]string // token -> 备注（目标/模板）
	hits   map[string][]OOBCallback

	Logf func(format string, args ...any)
}

// NewOOB 在 listen 地址上监听；domain 是"目标机器能访问到的地址"，为空时用监听地址。
// listen 传 "127.0.0.1:0" 可让系统分配端口（测试用）。
func NewOOB(listen, domain string) (*OOB, error) {
	if strings.TrimSpace(listen) == "" {
		listen = "127.0.0.1:0"
	}
	ln, err := net.Listen("tcp", listen)
	if err != nil {
		return nil, fmt.Errorf("OOB 监听失败 %s: %w", listen, err)
	}
	domain = strings.TrimSpace(domain)
	domain = strings.TrimPrefix(strings.TrimPrefix(domain, "http://"), "https://")
	domain = strings.TrimSuffix(domain, "/")
	if domain == "" {
		domain = ln.Addr().String()
	}
	o := &OOB{
		ln:      ln,
		domain:  domain,
		urlBase: "http://" + domain,
		tokens:  make(map[string]string),
		hits:    make(map[string][]OOBCallback),
	}
	o.srv = &http.Server{
		Handler:           http.HandlerFunc(o.handle),
		ReadHeaderTimeout: 5 * time.Second,
	}
	return o, nil
}

// Start 启动监听（非阻塞）。
func (o *OOB) Start() {
	go func() {
		if err := o.srv.Serve(o.ln); err != nil && err != http.ErrServerClosed {
			o.logf("OOB 监听退出: %v", err)
		}
	}()
}

// Stop 关闭监听。
func (o *OOB) Stop() error {
	return o.srv.Close()
}

// Host 返回回调域名（写进模板变量 {{oob_host}}）。
func (o *OOB) Host() string { return o.domain }

// Addr 返回实际监听地址（便于日志确认）。
func (o *OOB) Addr() string { return o.ln.Addr().String() }

// URL 返回某个 token 对应的回调地址（{{oob_url}}）。
func (o *OOB) URL(token string) string { return o.urlBase + "/" + token }

// NewToken 登记一个新的回调 token。
func (o *OOB) NewToken(target, templateID string) string {
	token := "ws" + RandStr(16)
	o.mu.Lock()
	o.tokens[token] = target + "|" + templateID
	o.mu.Unlock()
	return token
}

// Wait 等待某个 token 的回连，直到超时或 ctx 结束。
func (o *OOB) Wait(ctx context.Context, token string, timeout time.Duration) *OOBCallback {
	if token == "" {
		return nil
	}
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	deadline := time.Now().Add(timeout)
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		if cb := o.Take(token); cb != nil {
			return cb
		}
		if time.Now().After(deadline) {
			return nil
		}
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}

// Take 取出（并消费）某个 token 的首条回连记录。
func (o *OOB) Take(token string) *OOBCallback {
	o.mu.Lock()
	defer o.mu.Unlock()
	list := o.hits[token]
	if len(list) == 0 {
		return nil
	}
	cb := list[0]
	o.hits[token] = list[1:]
	return &cb
}

// Hits 返回某个 token 的全部回连记录。
func (o *OOB) Hits(token string) []OOBCallback {
	o.mu.Lock()
	defer o.mu.Unlock()
	return append([]OOBCallback(nil), o.hits[token]...)
}

// AllHits 返回全部回连记录（报告用）。
func (o *OOB) AllHits() map[string][]OOBCallback {
	o.mu.Lock()
	defer o.mu.Unlock()
	out := make(map[string][]OOBCallback, len(o.hits))
	for k, v := range o.hits {
		out[k] = append([]OOBCallback(nil), v...)
	}
	return out
}

func (o *OOB) handle(w http.ResponseWriter, r *http.Request) {
	path := strings.Trim(r.URL.Path, "/")
	token := path
	if i := strings.IndexByte(path, '/'); i >= 0 {
		token = path[:i]
	}
	cb := OOBCallback{
		Token:      token,
		Method:     r.Method,
		Path:       r.URL.Path,
		RemoteAddr: r.RemoteAddr,
		UserAgent:  r.Header.Get("User-Agent"),
		At:         time.Now(),
	}
	o.mu.Lock()
	if _, known := o.tokens[token]; known {
		o.hits[token] = append(o.hits[token], cb)
	}
	o.mu.Unlock()

	o.logf("OOB 收到回连: token=%s 来自 %s %s %s", token, cb.RemoteAddr, cb.Method, cb.Path)
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}

func (o *OOB) logf(format string, args ...any) {
	if o.Logf != nil {
		o.Logf(format, args...)
	}
}
