// Package target 负责把用户输入变成结构化的目标列表。
//
// 支持的输入形态：
//
//	https://example.com/path     -> example.com
//	example.com:8443             -> example.com
//	10.0.0.0/24                  -> 展开为 254 个 Host（受 maxHosts 保护）
//	10.0.0.7                     -> 单个 Host
//	targets.txt                  -> 逐行读取，支持 # 注释
package target

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"

	"westy_scan/internal/model"
	"westy_scan/internal/scope"
)

// Parse 解析单条目标表达式。
func Parse(spec string, maxHosts int) ([]model.Host, error) {
	raw := strings.TrimSpace(spec)
	if raw == "" {
		return nil, nil
	}
	if maxHosts <= 0 {
		maxHosts = 4096
	}
	if strings.Contains(raw, "/") && !strings.Contains(raw, "://") {
		_, n, err := net.ParseCIDR(raw)
		if err != nil {
			return nil, fmt.Errorf("非法 CIDR %q: %w", raw, err)
		}
		ips, err := expandCIDR(n, maxHosts)
		if err != nil {
			return nil, err
		}
		out := make([]model.Host, 0, len(ips))
		for _, ip := range ips {
			out = append(out, model.Host{Input: raw, Host: ip, IP: ip})
		}
		return out, nil
	}
	host := scope.NormalizeHost(raw)
	if host == "" {
		return nil, fmt.Errorf("无法解析目标 %q", raw)
	}
	h := model.Host{Input: raw, Host: host}
	if ip := net.ParseIP(host); ip != nil {
		h.IP = ip.String()
	}
	return []model.Host{h}, nil
}

// ParseAll 解析多条表达式（支持逗号、空白、换行分隔），并去重。
func ParseAll(specs []string, maxHosts int) ([]model.Host, error) {
	seen := make(map[string]bool)
	var out []model.Host
	for _, spec := range specs {
		for _, part := range SplitList(spec) {
			hosts, err := Parse(part, maxHosts)
			if err != nil {
				return nil, err
			}
			for _, h := range hosts {
				if seen[h.Host] {
					continue
				}
				seen[h.Host] = true
				out = append(out, h)
			}
		}
	}
	return out, nil
}

// ParseFile 读取目标文件，跳过空行与 # 注释。
func ParseFile(path string, maxHosts int) ([]model.Host, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var specs []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		specs = append(specs, line)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return ParseAll(specs, maxHosts)
}

// SplitList 把一条输入拆成若干目标（逗号/空白/换行分隔）。
func SplitList(s string) []string {
	fields := strings.FieldsFunc(s, func(r rune) bool {
		return r == ',' || r == ';' || r == '\n' || r == '\r' || r == '\t' || r == ' '
	})
	var out []string
	for _, f := range fields {
		if f = strings.TrimSpace(f); f != "" {
			out = append(out, f)
		}
	}
	return out
}

// expandCIDR 展开网段。超过 maxHosts 时直接报错而不是把机器打爆。
func expandCIDR(n *net.IPNet, maxHosts int) ([]string, error) {
	ip := n.IP.Mask(n.Mask)
	ones, bits := n.Mask.Size()
	if bits == 0 {
		return nil, fmt.Errorf("非法网段掩码: %s", n.String())
	}
	// 预判规模，避免无谓循环
	size := 1 << uint(bits-ones)
	if size > maxHosts+2 {
		return nil, fmt.Errorf("网段 %s 展开为 %d 个地址，超过 max_hosts=%d；请拆分范围或显式调大上限", n.String(), size, maxHosts)
	}
	isV4 := ip.To4() != nil
	var out []string
	for n.Contains(ip) {
		cur := ip.String()
		// IPv4 常规网段跳过网络号与广播地址
		if isV4 && ones <= 30 {
			if cur != n.IP.Mask(n.Mask).String() && cur != lastIP(n).String() {
				out = append(out, cur)
			}
		} else {
			out = append(out, cur)
		}
		if len(out) > maxHosts {
			return nil, fmt.Errorf("网段 %s 展开超过 max_hosts=%d", n.String(), maxHosts)
		}
		ip = nextIP(ip)
		if ip == nil {
			break
		}
	}
	return out, nil
}

func nextIP(ip net.IP) net.IP {
	out := make(net.IP, len(ip))
	copy(out, ip)
	for i := len(out) - 1; i >= 0; i-- {
		out[i]++
		if out[i] != 0 {
			return out
		}
	}
	return nil
}

func lastIP(n *net.IPNet) net.IP {
	ip := make(net.IP, len(n.IP))
	copy(ip, n.IP)
	for i := range ip {
		ip[i] |= ^n.Mask[i]
	}
	return ip
}

// ---------------------------------------------------------------------------
// 端口集合
// ---------------------------------------------------------------------------

// commonPorts 是默认端口集合：覆盖远程管理、常见 Web、数据库与中间件。
var commonPorts = []int{
	21, 22, 23, 25, 53, 80, 81, 110, 111, 135, 139, 143, 161, 389, 443, 445,
	465, 512, 513, 514, 548, 554, 587, 631, 636, 873, 993, 995, 1080, 1099,
	1158, 1433, 1521, 1723, 1883, 2049, 2082, 2083, 2100, 2181, 2222, 2375,
	2376, 2379, 2480, 3000, 3128, 3260, 3306, 3389, 3690, 4000, 4369, 4443,
	4848, 5000, 5044, 5222, 5432, 5555, 5601, 5672, 5678, 5900, 5901, 5984,
	5985, 5986, 6000, 6379, 6443, 7001, 7002, 7077, 8000, 8008, 8009, 8080,
	8081, 8088, 8090, 8161, 8443, 8500, 8529, 8888, 8983, 9000, 9001, 9042,
	9060, 9090, 9092, 9200, 9300, 9418, 9443, 9999, 10000, 10250, 11211,
	15672, 27017, 27018, 50000, 50070, 50075, 61616,
}

// webPorts 是常见的 Web 端口，用于决定是否做 HTTP 探测。
var webPorts = []int{
	80, 81, 443, 591, 2082, 2087, 2095, 3000, 4000, 4443, 4848, 5000, 5601,
	7001, 7002, 8000, 8001, 8008, 8009, 8010, 8043, 8069, 8080, 8081, 8088,
	8090, 8161, 8180, 8443, 8500, 8888, 8983, 9000, 9001, 9043, 9060, 9080,
	9090, 9200, 9443, 10000, 10250, 15672,
}

var namedPortGroups = map[string][]int{
	"common": commonPorts,
	"top100": commonPorts,
	"web":    webPorts,
	"db":     {1433, 1521, 2181, 3306, 5432, 5672, 6379, 9042, 9200, 9300, 11211, 27017},
}

// DefaultPorts 返回默认端口集合的副本。
func DefaultPorts() []int {
	out := make([]int, len(commonPorts))
	copy(out, commonPorts)
	return out
}

// IsWebPort 判断端口是否值得做 HTTP 探测。
func IsWebPort(port int) bool {
	for _, p := range webPorts {
		if p == port {
			return true
		}
	}
	return false
}

// ParsePorts 解析端口表达式。
//
//	"80,443"            -> 指定端口
//	"1-1024"            -> 区间
//	"common"/"web"/"db" -> 内置端口组
//	"all"               -> 1-65535
//	""                  -> 默认端口组
func ParsePorts(spec string) ([]int, error) {
	s := strings.ToLower(strings.TrimSpace(spec))
	if s == "" {
		return DefaultPorts(), nil
	}
	if s == "all" || s == "full" {
		s = "1-65535"
	}
	if g, ok := namedPortGroups[s]; ok {
		out := make([]int, len(g))
		copy(out, g)
		sort.Ints(out)
		return out, nil
	}
	seen := make(map[int]bool)
	var out []int
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if strings.Contains(part, "-") {
			bounds := strings.SplitN(part, "-", 2)
			lo, err1 := strconv.Atoi(strings.TrimSpace(bounds[0]))
			hi, err2 := strconv.Atoi(strings.TrimSpace(bounds[1]))
			if err1 != nil || err2 != nil {
				return nil, fmt.Errorf("非法端口区间 %q", part)
			}
			if lo < 1 || hi > 65535 || lo > hi {
				return nil, fmt.Errorf("端口区间越界 %q（合法范围 1-65535）", part)
			}
			for p := lo; p <= hi; p++ {
				if !seen[p] {
					seen[p] = true
					out = append(out, p)
				}
			}
			continue
		}
		p, err := strconv.Atoi(part)
		if err != nil || p < 1 || p > 65535 {
			return nil, fmt.Errorf("非法端口 %q（合法范围 1-65535）", part)
		}
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	sort.Ints(out)
	return out, nil
}
