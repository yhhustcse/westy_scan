// Package portscan 实现 TCP connect 端口扫描 + Banner 抓取。
//
// 为什么先用 connect 扫描而不是 SYN 半开扫描：
//   - connect 扫描只用标准库，跨平台可用，无需 raw socket 与管理员权限；
//   - 在授权测试场景下，隐蔽性不是首要目标，"稳定、可解释、可审计"才是；
//   - 需要更隐蔽时可以把 probe 换成 SYN 实现，接口保持不变（后续可插拔）。
package portscan

import (
	"context"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"westy_scan/internal/model"
	"westy_scan/internal/ratelimit"
	"westy_scan/internal/scope"
)

// Options 是端口扫描参数。
type Options struct {
	Timeout       time.Duration // 建连超时
	Concurrency   int           // 并发协程数
	Banner        bool          // 是否抓取 Banner
	BannerTimeout time.Duration // Banner 读取超时
	Limiter       *ratelimit.Limiter
	OnError       func(target string, err error) // 目标被拦截/DNS 失败等回调，用于审计
}

func (o Options) withDefaults() Options {
	if o.Timeout <= 0 {
		o.Timeout = 3 * time.Second
	}
	if o.Concurrency <= 0 {
		o.Concurrency = 200
	}
	if o.BannerTimeout <= 0 {
		o.BannerTimeout = 2 * time.Second
	}
	return o
}

type job struct {
	host string
	ip   string
	port int
}

// ConnectScanner 是默认的 TCP connect 扫描器：
// 用标准库完成三次握手，无需特权，跨平台可用，但会在目标侧留下完整连接记录。
type ConnectScanner struct{}

// Name 实现 Scanner。
func (ConnectScanner) Name() string { return ModeConnect }

// Scan 对 hosts × ports 做扫描，返回开放端口的资产流。
//
// 调用方 range 该 channel 即可，ctx 取消会尽快收敛并关闭 channel。
func (ConnectScanner) Scan(ctx context.Context, sc *scope.Scope, hosts []string, ports []int, opt Options) <-chan model.Asset {
	opt = opt.withDefaults()
	out := make(chan model.Asset, 256)

	go func() {
		defer close(out)

		jobs := make(chan job, opt.Concurrency*2)
		var wg sync.WaitGroup
		for i := 0; i < opt.Concurrency; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for j := range jobs {
					select {
					case <-ctx.Done():
						return
					default:
					}
					a, ok := probe(ctx, j, opt)
					if !ok {
						continue
					}
					select {
					case out <- a:
					case <-ctx.Done():
						return
					}
				}
			}()
		}

	feed:
		for _, h := range hosts {
			host, ip, err := sc.Guard(ctx, h)
			if err != nil {
				if opt.OnError != nil {
					opt.OnError(h, err)
				}
				continue
			}
			for _, p := range ports {
				select {
				case <-ctx.Done():
					break feed
				case jobs <- job{host: host, ip: ip, port: p}:
				}
			}
		}
		close(jobs)
		wg.Wait()
	}()

	return out
}

func probe(ctx context.Context, j job, opt Options) (model.Asset, bool) {
	if err := opt.Limiter.Wait(ctx); err != nil {
		return model.Asset{}, false
	}
	addr := net.JoinHostPort(j.ip, strconv.Itoa(j.port))
	dialer := net.Dialer{Timeout: opt.Timeout}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return model.Asset{}, false
	}
	defer conn.Close()

	banner := ""
	if opt.Banner {
		banner = grabBanner(conn, j.port, opt.BannerTimeout)
	}
	return model.Asset{
		Host:    j.host,
		IP:      j.ip,
		Port:    j.port,
		Banner:  banner,
		Source:  "portscan",
		FoundAt: time.Now(),
	}, true
}

// grabBanner 先尝试被动读取，读不到再按协议发送探测载荷。
func grabBanner(conn net.Conn, port int, timeout time.Duration) string {
	deadline := time.Now().Add(timeout)
	if err := conn.SetReadDeadline(deadline); err != nil {
		return ""
	}
	buf := make([]byte, 1024)
	if n, _ := conn.Read(buf); n > 0 {
		return sanitize(string(buf[:n]))
	}

	// 被动读取失败：按端口猜测协议主动问一句
	payload := probePayload(port)
	if payload == "" {
		return ""
	}
	if err := conn.SetWriteDeadline(deadline); err != nil {
		return ""
	}
	if _, err := conn.Write([]byte(payload)); err != nil {
		return ""
	}
	if err := conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		return ""
	}
	if n, _ := conn.Read(buf); n > 0 {
		return sanitize(string(buf[:n]))
	}
	return ""
}

func probePayload(port int) string {
	switch port {
	case 80, 8000, 8008, 8080, 8081, 8088, 8090, 8888, 9000, 9090, 10000:
		return "GET / HTTP/1.0\r\nHost: probe\r\nUser-Agent: westy-scan\r\nAccept: */*\r\n\r\n"
	case 443, 8443, 9443:
		// TLS 端口不主动搞乱握手，交给 httpinfo 模块处理
		return ""
	case 21, 22, 25, 110, 143, 587, 993, 995:
		return "\r\n"
	case 3306, 5432, 6379, 11211, 27017:
		return "\r\n"
	case 2375, 2376, 9200, 5601:
		return "GET / HTTP/1.0\r\nHost: probe\r\n\r\n"
	default:
		return ""
	}
}

// sanitize 把 Banner 压成单行可读文本，避免污染 JSONL 输出。
func sanitize(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch {
		case r == '\r' || r == '\n' || r == '\t':
			b.WriteByte(' ')
		case r < 0x20 || r == 0x7f:
			// 丢弃二进制控制字符
		default:
			b.WriteRune(r)
		}
	}
	out := strings.Join(strings.Fields(b.String()), " ")
	if len(out) > 512 {
		out = out[:512]
	}
	return out
}
