//go:build linux

package portscan

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"syscall"
	"time"

	"westy_scan/internal/model"
	"westy_scan/internal/scope"
)

// inflightJob 记录一条已发出、等待回包的 SYN 探测。
type inflightJob struct {
	host     string
	ip       string
	port     int
	deadline time.Time
}

const (
	srcPortMin = 40000
	srcPortMax = 60000
)

// SynScanner 是 Linux 上的 TCP SYN 半开扫描器（实验性）。
//
// 需要 root 或 CAP_NET_RAW。工作方式：
//  1. AF_INET + SOCK_RAW + IPPROTO_TCP + IP_HDRINCL，自己构造并发送 SYN；
//  2. 同一个原始套接字收包，按 (本机源端口, 目标 IP, 目标端口) 匹配 SYN+ACK / RST；
//  3. 只上报"开放"，其余超时按 filtered 处理（与 connect 扫描语义一致，避免过度断言）。
//
// 已知副作用：内核会对不属于任何连接的 SYN+ACK 回 RST，目标侧可能因此看到异常连接记录。
// 需要完全无痕请自行在防火墙丢弃出站 RST —— 这不在本工具职责范围内。
type SynScanner struct {
	portCursor uint32
}

// NewSynScanner 创建 SYN 扫描器。
func NewSynScanner() (Scanner, error) {
	return &SynScanner{portCursor: srcPortMin}, nil
}

// Name 实现 Scanner。
func (s *SynScanner) Name() string { return ModeSYN }

// Scan 实现 Scanner。
func (s *SynScanner) Scan(ctx context.Context, sc *scope.Scope, hosts []string, ports []int, opt Options) <-chan model.Asset {
	opt = opt.withDefaults()
	out := make(chan model.Asset, 256)

	go func() {
		defer close(out)

		fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_TCP)
		if err != nil {
			reportErr(opt, "", fmt.Errorf("创建原始套接字失败（SYN 扫描需要 root 或 CAP_NET_RAW）: %w", err))
			return
		}
		defer syscall.Close(fd)

		if err := syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_HDRINCL, 1); err != nil {
			reportErr(opt, "", fmt.Errorf("设置 IP_HDRINCL 失败: %w", err))
			return
		}
		// 收包超时设短一点，便于周期性检查 ctx 取消
		tv := syscall.NsecToTimeval((200 * time.Millisecond).Nanoseconds())
		if err := syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv); err != nil {
			reportErr(opt, "", fmt.Errorf("设置收包超时失败: %w", err))
			return
		}

		var mu sync.Mutex
		pending := make(map[uint16]inflightJob) // key = 本机源端口

		// ---- 收包协程 ----
		recvStop := make(chan struct{})
		var recvWG sync.WaitGroup
		recvWG.Add(1)
		go func() {
			defer recvWG.Done()
			buf := make([]byte, 65536)
			for {
				select {
				case <-recvStop:
					return
				case <-ctx.Done():
					return
				default:
				}
				n, _, rerr := syscall.Recvfrom(fd, buf, 0)
				if rerr != nil {
					if rerr == syscall.EAGAIN || rerr == syscall.EWOULDBLOCK || rerr == syscall.EINTR {
						continue // 收包超时，回去检查 ctx
					}
					return
				}
				if n <= 0 {
					continue
				}
				resp, perr := parseIPv4TCP(buf[:n])
				if perr != nil {
					continue
				}

				var hit inflightJob
				var matched bool
				mu.Lock()
				j, ok := pending[resp.DstPort]
				if ok && int(resp.SrcPort) == j.port && resp.SrcIP.String() == j.ip {
					if resp.IsSYNACK() {
						delete(pending, resp.DstPort)
						hit, matched = j, true
					} else if resp.IsRST() {
						delete(pending, resp.DstPort) // 端口关闭：不上报
					}
				}
				mu.Unlock()

				if matched {
					asset := model.Asset{
						Host:    hit.host,
						IP:      hit.ip,
						Port:    hit.port,
						Source:  "synscan",
						FoundAt: time.Now(),
					}
					asset.AddEvidence("syn-ack")
					select {
					case out <- asset:
					case <-ctx.Done():
						return
					}
				}
			}
		}()

		// ---- 发包 ----
	feed:
		for _, h := range hosts {
			host, ip, gerr := sc.Guard(ctx, h)
			if gerr != nil {
				reportErr(opt, h, gerr)
				continue
			}
			dst := net.ParseIP(ip)
			if dst == nil || dst.To4() == nil {
				reportErr(opt, h, fmt.Errorf("SYN 扫描仅支持 IPv4，跳过 %s", ip))
				continue
			}
			srcIP, lerr := localIPFor(dst)
			if lerr != nil {
				reportErr(opt, h, fmt.Errorf("无法确定到 %s 的本机源地址: %w", ip, lerr))
				continue
			}
			var addr [4]byte
			copy(addr[:], dst.To4())

			for _, p := range ports {
				select {
				case <-ctx.Done():
					break feed
				default:
				}
				if err := opt.Limiter.Wait(ctx); err != nil {
					break feed
				}
				if p < 1 || p > 65535 {
					continue
				}
				srcPort := s.reserveSourcePort(&mu, pending)
				pkt, berr := buildSYNPacket(srcIP, dst, srcPort, uint16(p), randSeq())
				if berr != nil {
					reportErr(opt, host, berr)
					continue
				}
				mu.Lock()
				pending[srcPort] = inflightJob{host: host, ip: ip, port: p, deadline: time.Now().Add(opt.Timeout)}
				mu.Unlock()

				if serr := syscall.Sendto(fd, pkt, 0, &syscall.SockaddrInet4{Addr: addr}); serr != nil {
					mu.Lock()
					delete(pending, srcPort)
					mu.Unlock()
					reportErr(opt, host, fmt.Errorf("发送 SYN 失败: %w", serr))
				}
			}
		}

		// ---- 等待在途探测结束或超时 ----
		ticker := time.NewTicker(50 * time.Millisecond)
		defer ticker.Stop()
		for ctx.Err() == nil {
			mu.Lock()
			now := time.Now()
			for k, j := range pending {
				if now.After(j.deadline) {
					delete(pending, k)
				}
			}
			remaining := len(pending)
			mu.Unlock()
			if remaining == 0 {
				break
			}
			<-ticker.C
		}

		close(recvStop)
		recvWG.Wait()
	}()

	return out
}

// reserveSourcePort 在 [srcPortMin, srcPortMax] 上轮转，挑一个未被占用的源端口。
func (s *SynScanner) reserveSourcePort(mu *sync.Mutex, pending map[uint16]inflightJob) uint16 {
	for i := 0; i <= srcPortMax-srcPortMin; i++ {
		s.portCursor++
		if s.portCursor > srcPortMax {
			s.portCursor = srcPortMin
		}
		p := uint16(s.portCursor)
		mu.Lock()
		_, used := pending[p]
		mu.Unlock()
		if !used {
			return p
		}
	}
	return uint16(srcPortMin)
}

func randSeq() uint32 {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		return uint32(time.Now().UnixNano())
	}
	return binary.BigEndian.Uint32(b[:])
}

// localIPFor 用一次 UDP connect 让内核告诉我们到该目的地址会用哪个源 IP（不会真的发包）。
func localIPFor(dst net.IP) (net.IP, error) {
	c, err := net.Dial("udp", net.JoinHostPort(dst.String(), "9"))
	if err != nil {
		return nil, err
	}
	defer c.Close()
	ua, ok := c.LocalAddr().(*net.UDPAddr)
	if !ok {
		return nil, fmt.Errorf("无法确定本机源地址")
	}
	return ua.IP, nil
}

func reportErr(opt Options, target string, err error) {
	if opt.OnError != nil {
		opt.OnError(target, err)
	}
}
