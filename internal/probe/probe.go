// Package probe 实现"协议握手识别"：对开放端口主动发起一次协议级交互，
// 从响应报文的**结构化字段**里解析出服务、产品与版本。
//
// 与 fingerprint 包的分工（两者互补，结果写进同一个 model.Asset）：
//
//	probe       —— 结构化证据（握手包字段），置信度 high
//	fingerprint —— 特征串匹配（banner / 标题 / 响应头），置信度 medium/low
//
// 设计约束：只依赖标准库；每个探针必须对截断/畸形数据返回错误而不是 panic；
// 除被动读取外，只发送"只读型"请求（INFO/VERSION/NEGOTIATE 这类不改变服务状态的命令）。
package probe

import (
	"context"
	"fmt"
	"io"
	"net"
	"sort"
	"strconv"
	"time"

	"westy_scan/internal/model"
)

// Result 是一次协议识别的结论。
type Result struct {
	Service    string
	Product    string
	Version    string
	Confidence string
	Evidence   string
	Extra      map[string]string
	Banner     string // 可读摘要，用于补充/美化 Asset.Banner
}

// Apply 把识别结论写入资产。置信度只升不降，已有结论不被覆盖。
func (r *Result) Apply(a *model.Asset) {
	if r == nil || a == nil {
		return
	}
	a.Identify(r.Service, r.Product, r.Version, r.Confidence, r.Evidence)
	if r.Banner != "" && a.Banner == "" {
		a.Banner = r.Banner
	}
	for k, v := range r.Extra {
		if v != "" {
			a.SetMeta(k, v)
		}
	}
}

// Options 控制探测行为。
type Options struct {
	Timeout   time.Duration // 单次读写超时
	MaxProbes int           // 每个端口最多尝试的探针数（防止对未知端口乱打）
}

func (o Options) withDefaults() Options {
	if o.Timeout <= 0 {
		o.Timeout = 2 * time.Second
	}
	if o.MaxProbes <= 0 {
		o.MaxProbes = 3
	}
	return o
}

// Probe 是一个协议探针。
type Probe struct {
	Name    string
	Ports   []int // 适用端口
	Generic bool  // 是否可用于未知端口（如 TLS：任何端口都可能是 TLS）
	// Run 在一条已建立的连接上完成一次协议交互。
	// 返回 (nil, err) 表示"这个端口不是该协议"。
	Run func(ctx context.Context, cn *Conn, host string, port int) (*Result, error)
}

// Conn 封装一次探测的连接，统一超时与读取上限。
type Conn struct {
	c       net.Conn
	timeout time.Duration
	maxRead int
}

// NetConn 暴露底层连接（TLS 探针需要用它包装 tls.Client）。
func (c *Conn) NetConn() net.Conn { return c.c }

// Close 关闭连接。
func (c *Conn) Close() error { return c.c.Close() }

// Write 带超时地发送载荷。
func (c *Conn) Write(b []byte) error {
	if err := c.c.SetWriteDeadline(time.Now().Add(c.timeout)); err != nil {
		return err
	}
	_, err := c.c.Write(b)
	return err
}

// ReadSome 读取一次响应（服务端先说话的协议：SSH/FTP/SMTP/MySQL/VNC）。
func (c *Conn) ReadSome() ([]byte, error) {
	if err := c.c.SetReadDeadline(time.Now().Add(c.timeout)); err != nil {
		return nil, err
	}
	buf := make([]byte, c.maxRead)
	n, err := c.c.Read(buf)
	if n > 0 {
		return buf[:n], nil
	}
	return nil, err
}

// ReadFull 读取恰好 n 字节（定长响应，如 NetBIOS/TPKT 头）。
func (c *Conn) ReadFull(n int) ([]byte, error) {
	if n <= 0 {
		return nil, fmt.Errorf("非法读取长度 %d", n)
	}
	if n > c.maxRead {
		return nil, fmt.Errorf("响应长度 %d 超过上限 %d", n, c.maxRead)
	}
	if err := c.c.SetReadDeadline(time.Now().Add(c.timeout)); err != nil {
		return nil, err
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(c.c, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

// ReadLine 读到换行为止（文本协议的 Banner，避免 TCP 分片把一行截断）。
func (c *Conn) ReadLine() ([]byte, error) {
	if err := c.c.SetReadDeadline(time.Now().Add(c.timeout)); err != nil {
		return nil, err
	}
	var out []byte
	buf := make([]byte, 1)
	for len(out) < c.maxRead {
		n, err := c.c.Read(buf)
		if n > 0 {
			out = append(out, buf[0])
			if buf[0] == '\n' {
				return out, nil
			}
		}
		if err != nil {
			if len(out) > 0 {
				return out, nil // 读到一半也返回，交给解析器判断
			}
			return nil, err
		}
	}
	return out, nil
}

func dial(ctx context.Context, ip string, port int, timeout time.Duration) (*Conn, error) {
	d := net.Dialer{Timeout: timeout}
	c, err := d.DialContext(ctx, "tcp", net.JoinHostPort(ip, strconv.Itoa(port)))
	if err != nil {
		return nil, err
	}
	return &Conn{c: c, timeout: timeout, maxRead: 8192}, nil
}

// ProbesForPort 返回该端口的候选探针（含通用探针）。
func ProbesForPort(port int) []Probe {
	var out []Probe
	for _, p := range registry {
		for _, pp := range p.Ports {
			if pp == port {
				out = append(out, p)
				break
			}
		}
	}
	// 常见 TLS 端口补一个 TLS 探针（如 465/993/995 这类隐式 TLS 服务）
	if isTLSPort(port) && !containsName(out, "tls") {
		out = append(out, tlsProbe)
	}
	if len(out) == 0 {
		// 未知端口：只做一次 TLS 判断，避免对陌生服务乱发包
		out = append(out, tlsProbe)
	}
	return out
}

// HasSpecificProbe 表示该端口有专门的协议探针（区别于"未知端口只试 TLS"的通用探测）。
// 流水线用它决定：是直接在扫描阶段做协议识别，还是先让 Web 探测路径去试 HTTP。
func HasSpecificProbe(port int) bool {
	for _, p := range registry {
		for _, pp := range p.Ports {
			if pp == port {
				return true
			}
		}
	}
	return false
}

// SupportedPorts 返回内置探针覆盖的 TCP 端口（升序去重），用于文档与自检。
func SupportedPorts() []int {
	set := make(map[int]bool)
	for _, p := range registry {
		for _, pp := range p.Ports {
			set[pp] = true
		}
	}
	for _, pp := range tlsPorts {
		set[pp] = true
	}
	out := make([]int, 0, len(set))
	for p := range set {
		out = append(out, p)
	}
	sort.Ints(out)
	return out
}

func containsName(list []Probe, name string) bool {
	for _, p := range list {
		if p.Name == name {
			return true
		}
	}
	return false
}

// Detect 对已确认开放的 TCP 端口做协议识别，返回置信度最高的结论（无结论返回 nil）。
//
// banner 是端口扫描阶段抓到的文本 Banner：文本协议（SSH/FTP/SMTP/VNC）可以直接
// 复用它得出结论，省掉一次往返。
func Detect(ctx context.Context, host, ip string, port int, banner string, opt Options) *Result {
	opt = opt.withDefaults()
	cands := ProbesForPort(port)
	if len(cands) == 0 {
		return nil
	}

	// 1) 先用已有 Banner 做零成本解析
	if banner != "" {
		if r := parseBannerText(cands, banner); r != nil {
			return r
		}
	}

	// 2) 建立连接逐个体试
	tried := 0
	for _, p := range cands {
		if ctx.Err() != nil || tried >= opt.MaxProbes {
			break
		}
		tried++
		cn, err := dial(ctx, ip, port, opt.Timeout)
		if err != nil {
			continue
		}
		res, err := p.Run(ctx, cn, host, port)
		_ = cn.Close()
		if err == nil && res != nil {
			return res
		}
	}
	return nil
}

// parseBannerText 用纯文本解析器直接吃已有 Banner，覆盖"服务端先说话"的协议。
func parseBannerText(cands []Probe, banner string) *Result {
	for _, p := range cands {
		switch p.Name {
		case "ssh":
			if r := parseSSH(banner); r != nil {
				return r
			}
		case "ftp":
			if r := parseFTP(banner); r != nil {
				return r
			}
		case "smtp":
			if r := parseSMTP(banner); r != nil {
				return r
			}
		case "vnc":
			if r := parseVNCServer(banner); r != nil {
				return r
			}
		}
	}
	return nil
}
