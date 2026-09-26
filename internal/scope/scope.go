// Package scope 实现"授权范围闸门"（Scope Gate）。
//
// 这是整个框架唯一的合规出口：任何对外发包的动作（端口扫描 / HTTP 探测 / 爬虫）
// 都必须先经过 Scope。设计要点：
//
//  1. 未显式声明"已获得授权"直接拒绝启动，杜绝误用；
//  2. deny 优先于 allow；
//  3. 支持 CIDR、单 IP、域名后缀（含 *.example.com）；
//  4. 域名解析集中在这里做并缓存，避免重复 DNS 查询；
//  5. 域名解析出的 IP 会再过一遍 deny 规则，防止"外网域名指向内网"绕过范围限制。
package scope

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
)

// Rule 是一条范围规则，要么是网段，要么是域名。
type Rule struct {
	Raw     string
	IsCIDR  bool
	Network *net.IPNet
	Domain  string // 已去掉 "*." / "." 前缀，做后缀匹配
}

// MatchIP 判断 IP 是否落在该网段内。
func (r Rule) MatchIP(ip net.IP) bool {
	if !r.IsCIDR || r.Network == nil || ip == nil {
		return false
	}
	return r.Network.Contains(ip)
}

// MatchDomain 判断主机名是否命中该域名规则（自身或子域）。
func (r Rule) MatchDomain(host string) bool {
	if r.IsCIDR || r.Domain == "" {
		return false
	}
	h := strings.ToLower(strings.TrimSuffix(host, "."))
	if h == r.Domain {
		return true
	}
	return strings.HasSuffix(h, "."+r.Domain)
}

// Scope 是授权范围本身。
type Scope struct {
	Allow      []Rule
	Deny       []Rule
	MaxHosts   int
	Strict     bool
	Authorized bool

	mu       sync.Mutex
	resolved map[string]string
}

// New 构造 Scope。authorized 为 false 时直接报错，这是刻意设计的"合规开关"。
func New(allow, deny []string, maxHosts int, strict, authorized bool) (*Scope, error) {
	if !authorized {
		return nil, errors.New("拒绝启动: 未声明已获得目标书面授权（配置 authorized=true 或命令行 --i-have-authorization）")
	}
	if maxHosts <= 0 {
		maxHosts = 4096
	}
	s := &Scope{
		MaxHosts:   maxHosts,
		Strict:     strict,
		Authorized: authorized,
		resolved:   make(map[string]string),
	}
	for _, raw := range allow {
		r, err := ParseRule(raw)
		if err != nil {
			return nil, err
		}
		s.Allow = append(s.Allow, r)
	}
	for _, raw := range deny {
		r, err := ParseRule(raw)
		if err != nil {
			return nil, err
		}
		s.Deny = append(s.Deny, r)
	}
	if strict && len(s.Allow) == 0 {
		return nil, errors.New("严格模式下必须至少配置一条 allow 规则（例如 10.0.0.0/24）")
	}
	return s, nil
}

// ParseRule 解析一条范围规则。
//
//	10.0.0.0/24      -> 网段
//	10.0.0.7         -> 单 IP（内部转成 /32）
//	example.com      -> 域名及其子域
//	*.example.com    -> 同上
func ParseRule(raw string) (Rule, error) {
	s := strings.ToLower(strings.TrimSpace(raw))
	if s == "" {
		return Rule{}, errors.New("范围规则为空")
	}
	r := Rule{Raw: raw}
	if strings.Contains(s, "/") {
		_, n, err := net.ParseCIDR(s)
		if err != nil {
			return r, fmt.Errorf("非法的 CIDR 规则 %q: %w", raw, err)
		}
		r.IsCIDR = true
		r.Network = n
		return r, nil
	}
	if ip := net.ParseIP(s); ip != nil {
		bits := 32
		if ip.To4() == nil {
			bits = 128
		}
		_, n, err := net.ParseCIDR(fmt.Sprintf("%s/%d", ip.String(), bits))
		if err != nil {
			return r, fmt.Errorf("非法的 IP 规则 %q: %w", raw, err)
		}
		r.IsCIDR = true
		r.Network = n
		return r, nil
	}
	if strings.Contains(s, " ") {
		return r, fmt.Errorf("非法的范围规则 %q", raw)
	}
	d := strings.TrimPrefix(s, "*.")
	d = strings.TrimPrefix(d, ".")
	if d == "" {
		return r, fmt.Errorf("非法的域名规则 %q", raw)
	}
	r.Domain = d
	return r, nil
}

// NormalizeHost 去掉 scheme / 路径 / 端口 / IPv6 方括号，返回小写主机名。
func NormalizeHost(raw string) string {
	h := strings.TrimSpace(raw)
	if i := strings.Index(h, "://"); i >= 0 {
		h = h[i+3:]
	}
	if i := strings.IndexAny(h, "/?#"); i >= 0 {
		h = h[:i]
	}
	switch {
	case strings.HasPrefix(h, "["):
		// IPv6 字面量：[::1]:8080 或 [::1]
		if j := strings.Index(h, "]"); j > 0 {
			h = h[1:j]
		}
	case strings.Contains(h, ":"):
		// host:port 形式；裸 IPv6（2001:db8::1）解析失败时保持原样
		if host, _, err := net.SplitHostPort(h); err == nil {
			h = host
		}
	}
	return strings.ToLower(strings.TrimSuffix(h, "."))
}

// Check 只做范围判定，不解析 DNS。
// 返回的 reason 为空字符串表示通过。
func (s *Scope) Check(raw string) (host string, ok bool, reason string) {
	host = NormalizeHost(raw)
	if host == "" {
		return "", false, "空目标"
	}
	ip := net.ParseIP(host)
	for _, r := range s.Deny {
		if ip != nil && r.MatchIP(ip) {
			return host, false, fmt.Sprintf("命中 deny 规则 %s", r.Raw)
		}
		if r.MatchDomain(host) {
			return host, false, fmt.Sprintf("命中 deny 规则 %s", r.Raw)
		}
	}
	if len(s.Allow) == 0 {
		return host, true, ""
	}
	for _, r := range s.Allow {
		if ip != nil && r.MatchIP(ip) {
			return host, true, ""
		}
		if r.MatchDomain(host) {
			return host, true, ""
		}
	}
	return host, false, "不在 allow 授权范围内"
}

// Resolve 解析主机名（带缓存）。IP 字面量直接返回。
func (s *Scope) Resolve(ctx context.Context, host string) (string, error) {
	if ip := net.ParseIP(host); ip != nil {
		return ip.String(), nil
	}
	s.mu.Lock()
	if v, ok := s.resolved[host]; ok {
		s.mu.Unlock()
		return v, nil
	}
	s.mu.Unlock()

	addrs, err := net.DefaultResolver.LookupIP(ctx, "ip4", host)
	if err != nil {
		return "", fmt.Errorf("%w: DNS 查询 %s 出错: %w", ErrResolveFailed, host, err)
	}
	if len(addrs) == 0 {
		return "", fmt.Errorf("%w: %s 无 A 记录", ErrResolveFailed, host)
	}
	ipStr := addrs[0].String()
	s.mu.Lock()
	s.resolved[host] = ipStr
	s.mu.Unlock()
	return ipStr, nil
}

// PreResolve 并发预热 DNS 缓存。
//
// 大规模扫描时串行解析会成为吞吐瓶颈（扫描本身高并发，DNS 却是串行的）。
// 这里只做"解析 + deny 复检"，不做 allow 的最终判定 ——
// 真正的发包前判定仍然由 Guard 完成，合规闸门没有被绕过。
func (s *Scope) PreResolve(ctx context.Context, hosts []string, concurrency int) {
	if concurrency <= 0 {
		concurrency = 32
	}
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup
	for _, h := range hosts {
		if ctx.Err() != nil {
			break
		}
		host, ok, _ := s.Check(h)
		if !ok || host == "" {
			continue
		}
		s.mu.Lock()
		_, cached := s.resolved[host]
		s.mu.Unlock()
		if cached {
			continue
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(host string) {
			defer wg.Done()
			defer func() { <-sem }()
			_, _ = s.Resolve(ctx, host)
		}(host)
	}
	wg.Wait()
}

// ErrOutOfScope 表示目标被授权范围拦截。
//
// 为什么要有这个哨兵错误：调用方（Agent 的本地闸门、审计、被拒统计）需要判断
// "这次失败是不是因为越界"。以前是靠 `strings.Contains(err.Error(), "授权范围")` 匹配文案——
// 文案一改判定就静默失效，而且 DNS 解析失败等其它拒绝原因会被漏掉。
// 判定要走 errors.Is，错误文案只给人看。
var ErrOutOfScope = errors.New("目标被授权范围拦截")

// ErrResolveFailed 表示目标解析失败（DNS 无记录/解析服务不可用）。
//
// 它与 ErrOutOfScope 是两类拒绝：一个"不允许扫"，一个"扫不了"。
// 但两者都必须让审计看得见 —— 否则服务端只会看到"这个任务没结果"，不知道原因。
var ErrResolveFailed = errors.New("目标解析失败")

// Guard 是扫描模块唯一应该调用的入口：范围检查 + 解析 + 解析后再检查。
func (s *Scope) Guard(ctx context.Context, raw string) (host, ip string, err error) {
	host, ok, reason := s.Check(raw)
	if !ok {
		return host, "", fmt.Errorf("%w: %s (%s)", ErrOutOfScope, host, reason)
	}
	ip, err = s.Resolve(ctx, host)
	if err != nil {
		return host, "", err
	}
	if parsed := net.ParseIP(ip); parsed != nil {
		for _, r := range s.Deny {
			if r.MatchIP(parsed) {
				return host, "", fmt.Errorf("%w: %s 解析到 %s（命中 deny 规则 %s）", ErrOutOfScope, host, ip, r.Raw)
			}
		}
	}
	return host, ip, nil
}

// Describe 返回人类可读的范围描述，用于启动横幅与审计日志。
func (s *Scope) Describe() string {
	parts := make([]string, 0, 4)
	if len(s.Allow) > 0 {
		items := make([]string, 0, len(s.Allow))
		for _, r := range s.Allow {
			items = append(items, r.Raw)
		}
		parts = append(parts, "allow=["+strings.Join(items, ",")+"]")
	} else {
		parts = append(parts, "allow=[* 未配置，全放行，风险自负]")
	}
	if len(s.Deny) > 0 {
		items := make([]string, 0, len(s.Deny))
		for _, r := range s.Deny {
			items = append(items, r.Raw)
		}
		parts = append(parts, "deny=["+strings.Join(items, ",")+"]")
	}
	parts = append(parts, fmt.Sprintf("max_hosts=%d", s.MaxHosts))
	if s.Strict {
		parts = append(parts, "strict=true")
	}
	return strings.Join(parts, " ")
}
