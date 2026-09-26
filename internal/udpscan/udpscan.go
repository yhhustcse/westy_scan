// Package udpscan 实现自包含的 UDP 协议探测（DNS / NTP / SNMP / NetBIOS）。
//
// # 为什么"UDP 开放"只能是启发式结论
//
// UDP 是无连接协议，没有 TCP SYN/ACK 那样明确的握手语义：
//
//   - 目标回包       => 端口上确实有服务在监听（本包据此产出资产）；
//   - 目标回 ICMP 端口不可达 => 端口关闭（Windows 上表现为连接型 socket 的
//     read 返回 WSAECONNRESET，本包按"无响应"处理，不产出资产）；
//   - 什么都不回     => 无法区分 filtered（被防火墙静默丢弃）与
//     open|filtered（服务存在但不回应这个载荷）。
//
// 因此本模块只把"收到响应"当作命中依据，且每条资产都在 Evidence 里写明判据
// （形如 udp:dns-rcode=0、udp:ntp-mode=4）、在 Meta 里写 probe 与
// confidence_reason，便于人工复核与后续降噪；"没响应"一律不产出资产。
//
// 另一个刻意的设计是：解析失败 ≠ 未命中。能从 UDP 收到任何字节就说明该端口
// 背后有东西，所以"有响应但内容不符"仍然记录为资产，只是置信度从 high 降到
// medium（典型例子：DNS 返回 REFUSED、SNMP 回 noSuchName/authorizationError、
// NTP 返回 kiss-o'-death）。
//
// # 使用方式
//
//	out := udpscan.Scan(ctx, sc, hosts, []int{53, 123, 161, 137}, udpscan.Options{
//		Timeout:     2 * time.Second,
//		Concurrency: 50,
//		Limiter:     limiter,
//		OnError:     func(target string, err error) { log.Printf("%s: %v", target, err) },
//	})
//	for asset := range out { ... }
//
// 所有目标都会先经过 scope.Scope.Guard 的授权闸门，被拦截的目标跳过并回调
// OnError；每个主机名只解析一次，Asset.Host 用主机名、Asset.IP 用解析结果。
package udpscan

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"io"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"westy_scan/internal/model"
	"westy_scan/internal/ratelimit"
	"westy_scan/internal/scope"
)

// SourceName 是本模块写入 Asset.Source 的标识。
const SourceName = "udpscan"

// maxResponseSize 是单个 UDP 响应的读取上限，超过部分丢弃。
// 4KB 足够容纳 SNMP 的 sysDescr，又不至于让恶意/错乱的响应撑爆内存。
const maxResponseSize = 4096

// Options UDP 扫描参数。
type Options struct {
	Timeout     time.Duration // 单个探测的等待超时，<=0 时默认 2s
	Concurrency int           // 并发数，<=0 时默认 50
	Limiter     *ratelimit.Limiter
	OnError     func(target string, err error) // 目标被拦截 / DNS 失败 等回调
}

func (o Options) withDefaults() Options {
	if o.Timeout <= 0 {
		o.Timeout = 2 * time.Second
	}
	if o.Concurrency <= 0 {
		o.Concurrency = 50
	}
	return o
}

// parseResult 是探针解析响应的统一输出：一个已被证明"有服务在监听"的候选。
//
// 解析函数只有在载荷短到无法构成任何合法响应时才返回 error；能解析出的字段
// 越少，Confidence 越低，但这个候选依然会被产出（有响应即命中）。
type parseResult struct {
	Service    string            // 归一化服务名，如 dns、ntp
	Banner     string            // 单行可读摘要，便于人眼扫
	Product    string            // 产品名（能提取时）
	Version    string            // 版本（能提取时）
	Products   []string          // 附加产品指纹
	Confidence string            // model.ConfidenceHigh / Medium
	Evidence   []string          // 判据，形如 udp:dns-rcode=0
	Meta       map[string]string // 协议细节
	Exact      bool              // true 表示严格符合该协议的应答特征
}

// probeFunc 是单个 UDP 探针：构造请求、发包、解析响应。
// 返回 (nil, nil) 表示"没响应"，不属于命中。
type probeFunc func(ctx context.Context, network, addr string, timeout time.Duration) (*parseResult, error)

// job 是一次"某主机 × 某端口"的探测任务，IP 已在投递前解析完成。
type job struct {
	host string
	ip   string
	port int
}

// SupportedPorts 返回内置探针覆盖的 UDP 端口（升序、去重）。
func SupportedPorts() []int {
	ports := make([]int, 0, len(probeTable))
	for p := range probeTable {
		ports = append(ports, p)
	}
	sort.Ints(ports)
	return ports
}

// Scan 对 hosts × ports 做 UDP 探测，返回"有应答"的资产流。
//
// hosts 是主机名或 IP 字面量；ports 是待探测的 UDP 端口列表。
// 只对内置探针支持的端口生效，其余端口直接忽略（不做无效发包，
// 避免把不确定的 open|filtered 噪声写进结果）。
//
// ctx 取消后 worker 会尽快收敛并关闭返回的 channel。
func Scan(ctx context.Context, sc *scope.Scope, hosts []string, ports []int, opt Options) <-chan model.Asset {
	opt = opt.withDefaults()
	out := make(chan model.Asset, 256)

	wanted := filterSupportedPorts(ports)
	if sc == nil || len(hosts) == 0 || len(wanted) == 0 {
		close(out)
		return out
	}

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
					a, ok := processJob(ctx, j, opt)
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
			// 授权闸门 + DNS 解析：每个目标只做一次。
			host, ip, err := sc.Guard(ctx, h)
			if err != nil {
				if opt.OnError != nil {
					opt.OnError(h, err)
				}
				continue
			}
			for _, p := range wanted {
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

// processJob 执行一次探测并把结果整理成资产。
func processJob(ctx context.Context, j job, opt Options) (model.Asset, bool) {
	if ctx.Err() != nil {
		return model.Asset{}, false
	}
	if err := opt.Limiter.Wait(ctx); err != nil {
		return model.Asset{}, false
	}
	if ctx.Err() != nil {
		return model.Asset{}, false
	}

	entry, ok := probeTable[j.port]
	if !ok {
		return model.Asset{}, false
	}

	// 实际发包端口来自探针端口映射：生产环境就是注册端口本身，
	// 测试里可以把它改写成临时端口，从而在不占用 53/161 等特权端口的前提下
	// 走完整的 Scan → 发包 → 解析 → 产出资产 链路。
	dialPort := resolveProbePort(entry.port)
	res, err := entry.fn(ctx, udpNetwork(j.ip, dialPort), net.JoinHostPort(j.ip, strconv.Itoa(dialPort)), opt.Timeout)
	if err != nil {
		// 协议格式非法（响应太短/畸形），或本地 socket 错误。
		// 这类噪声不上报，避免污染 OnError 审计流。
		return model.Asset{}, false
	}
	if res == nil {
		// 超时或 ICMP 端口不可达：无法区分 filtered 与 open|filtered，不算命中。
		return model.Asset{}, false
	}
	return finalize(ctx, j, dialPort, entry, res)
}

// 探针端口映射（默认恒等）。仅测试会替换它（改写为本地临时端口），生产代码不要修改。
//
// 为什么用锁而不是裸变量：这个函数是**扫描 worker 协程在读**、
// 测试在写（含 t.Cleanup 里的还原），裸变量就是一个真实的 data race ——
// 本地快机器上侥幸不触发，CI 上跑 -race 就会红。加锁后读写都有同步边。
var (
	portResolverMu sync.RWMutex
	portResolver   = func(port int) int { return port }
)

// resolveProbePort 读取当前映射并应用（持读锁取函数指针，再调用）。
func resolveProbePort(port int) int {
	portResolverMu.RLock()
	f := portResolver
	portResolverMu.RUnlock()
	return f(port)
}

// setPortResolver 替换映射，返回还原函数（测试用；生产代码不要调用）。
func setPortResolver(f func(int) int) (restore func()) {
	portResolverMu.Lock()
	old := portResolver
	if f == nil {
		f = func(p int) int { return p }
	}
	portResolver = f
	portResolverMu.Unlock()
	return func() {
		portResolverMu.Lock()
		portResolver = old
		portResolverMu.Unlock()
	}
}

// protocolEntropy 是随机 ID 的来源。默认 crypto/rand（报文 ID 可预测会带来
// 缓存投毒/响应伪造风险），仅测试会替换成确定性来源以便校验报文编码。
var protocolEntropy io.Reader = rand.Reader

// udpNetwork 选择 UDP 网络类型：IPv6 目标必须显式用 udp6，否则双栈机器上会发错族。
func udpNetwork(ip string, port int) string {
	if strings.Contains(ip, ":") {
		return "udp6"
	}
	return "udp4"
}

// probeTable 是端口 → 探针的静态注册表，键顺序无关，SupportedPorts 会排序。
var probeTable = map[int]probeEntry{
	53:  {port: 53, name: "dns", fn: probeDNS},
	123: {port: 123, name: "ntp", fn: probeNTP},
	137: {port: 137, name: "netbios", fn: probeNetBIOS},
	161: {port: 161, name: "snmp", fn: probeSNMP},
}

type probeEntry struct {
	port int
	name string
	fn   probeFunc
}

// filterSupportedPorts 保持调用方给的顺序，去重并丢掉没有探针的端口。
func filterSupportedPorts(ports []int) []int {
	seen := make(map[int]bool, len(ports))
	out := make([]int, 0, len(ports))
	for _, p := range ports {
		if p <= 0 || p > 65535 || seen[p] {
			continue
		}
		if _, ok := probeTable[p]; !ok {
			continue
		}
		seen[p] = true
		out = append(out, p)
	}
	return out
}

// exchange 完成一次 UDP 请求/响应交换。
//
// 返回值约定：
//   - (data, nil)：收到响应，data 长度 > 0；
//   - (nil, nil) ：没响应（超时 / ICMP 端口不可达 / ctx 取消），不属于命中；
//   - (nil, err) ：本地错误（发包失败、地址非法等）。
func exchange(ctx context.Context, network, addr string, req []byte, timeout time.Duration) ([]byte, error) {
	// 先看 ctx：已经被取消就不要再发包了。
	if err := ctx.Err(); err != nil {
		return nil, nil
	}
	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	// 连接型 UDP socket 的 Read 不会感知 ctx，只认 deadline；
	// 用一个小协程在 ctx 取消时关闭 socket 把它唤醒，保证 Scan 能立即收敛。
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			_ = conn.Close()
		case <-done:
		}
	}()

	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return nil, err
	}
	if _, err := conn.Write(req); err != nil {
		return nil, err
	}
	buf := make([]byte, maxResponseSize)
	n, err := conn.Read(buf)
	if err != nil {
		// 超时、connection refused（ICMP 端口不可达）、reset、ctx 取消：
		// 一律视为"没有可用响应"，交由上层判定为非命中。
		return nil, nil
	}
	if n == 0 {
		return nil, nil
	}
	return buf[:n], nil
}

// randomUint16 生成协议识别用的随机 ID（DNS 事务号 / SNMP request-id）。
func randomUint16() uint16 {
	var b [2]byte
	if _, err := protocolEntropy.Read(b[:]); err != nil {
		// 标准库 crypto/rand 在支持的平台上不会失败；兜底用时间低位。
		return uint16(time.Now().UnixNano())
	}
	return binary.BigEndian.Uint16(b[:])
}

// finalize 把探针解析结果整理为 model.Asset。
// dialPort 是真正发包用的端口（生产环境等于注册端口，测试中可能是临时端口），
// Asset.Port 必须记录实际探测的端口，否则结果与配置对不上。
func finalize(ctx context.Context, j job, dialPort int, entry probeEntry, res *parseResult) (model.Asset, bool) {
	if ctx.Err() != nil {
		return model.Asset{}, false
	}
	a := model.Asset{
		Host:    j.host,
		IP:      j.ip,
		Port:    dialPort,
		Service: res.Service,
		Source:  SourceName,
		FoundAt: time.Now(),
	}
	if a.Service == "" {
		a.Service = entry.name
	}
	a.Banner = res.Banner
	if res.Product != "" {
		a.Product = res.Product // 主产品名（报告与后续 POC 匹配都要用）
		a.AddProduct(res.Product)
	}
	a.AddProduct(res.Products...)
	a.Version = res.Version
	a.AddEvidence(res.Evidence...)

	a.SetMeta("probe", entry.name)
	a.SetMeta("transport", "udp")
	reason := "有响应但不符合 " + entry.name + " 应答特征（可能是其它服务占用该端口）"
	if res.Exact {
		reason = "收到符合 " + entry.name + " 特征的响应"
	}
	a.SetMeta("confidence_reason", reason)
	for k, v := range res.Meta {
		a.SetMeta(k, v)
	}

	// UDP 没有连接语义：置信度只表达"响应像不像这个协议"，不代表端口一定开放。
	conf := res.Confidence
	if conf == "" {
		conf = model.ConfidenceMedium
	}
	a.RaiseConfidence(conf)
	a.SetMeta("confidence", conf)
	return a, true
}

// joinNames 去重并压缩名称列表，用于 DNS 的 NS/SOA 名称。
func joinNames(names []string) string {
	out := make([]string, 0, len(names))
	for _, n := range names {
		n = strings.TrimSpace(n)
		if n == "" {
			continue
		}
		dup := false
		for _, old := range out {
			if old == n {
				dup = true
				break
			}
		}
		if !dup {
			out = append(out, n)
		}
		if len(out) >= 8 {
			break
		}
	}
	return strings.Join(out, ",")
}

// be16/be32 是大端读取小工具，避免各解析文件重复 binary.BigEndian 调用。
func be16(b []byte) uint16 { return binary.BigEndian.Uint16(b) }

func be32(b []byte) uint32 { return binary.BigEndian.Uint32(b) }

// sanitizeText 把原始字节/字符串压成单行安全文本，避免污染 JSONL 输出。
func sanitizeText(s string, max int) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch {
		case r == '\r' || r == '\n' || r == '\t':
			b.WriteByte(' ')
		case r < 0x20 || r == 0x7f:
			// 丢弃控制字符
		default:
			b.WriteRune(r)
		}
	}
	out := strings.Join(strings.Fields(b.String()), " ")
	if max > 0 && len(out) > max {
		out = out[:max]
	}
	return out
}
