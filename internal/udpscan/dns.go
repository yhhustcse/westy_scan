package udpscan

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"time"

	"westy_scan/internal/model"
)

// DNS 报文常量（RFC 1035）。只实现探测所需的最小子集，不引入第三方库。
const (
	dnsHeaderLen = 12

	dnsTypeA     = 1
	dnsTypeNS    = 2
	dnsTypeSOA   = 6
	dnsTypeCNAME = 5

	dnsClassIN = 1

	dnsFlagQR = 0x8000 // 响应
	dnsFlagAA = 0x0400 // 权威应答
	dnsFlagTC = 0x0200 // 截断
	dnsFlagRD = 0x0100 // 期望递归
	dnsFlagRA = 0x0080 // 支持递归
)

// dnsRCodeText 是 RCODE 的可读文本，用于 meta 与 Evidence。
var dnsRCodeText = map[int]string{
	0: "NOERROR",
	1: "FORMERR",
	2: "SERVFAIL",
	3: "NXDOMAIN",
	4: "NOTIMP",
	5: "REFUSED",
}

// probeDNS 对 53/udp 发起一次递归的根域 NS 查询。
//
// 用根域 NS 而不是 MX/CH TXT 之类的原因：任何递归解析器都必须能回答根域，
// 不会因为域名不存在而给出无区分度的 NXDOMAIN。
func probeDNS(ctx context.Context, network, addr string, timeout time.Duration) (*parseResult, error) {
	resp, err := exchange(ctx, network, addr, buildDNSQuery(), timeout)
	if err != nil || len(resp) == 0 {
		return nil, err
	}
	return parseDNS(resp)
}

// buildDNSQuery 构造标准 DNS 查询：随机 ID，QR=0/Opcode=0/RD=1，
// QDCOUNT=1，QNAME="."，QTYPE=NS(2)，QCLASS=IN(1)。
func buildDNSQuery() []byte {
	b := make([]byte, 0, dnsHeaderLen+5)
	var hdr [dnsHeaderLen]byte
	binary.BigEndian.PutUint16(hdr[0:2], randomUint16()) // ID
	binary.BigEndian.PutUint16(hdr[2:4], dnsFlagRD)      // Flags: 标准查询 + 期望递归
	binary.BigEndian.PutUint16(hdr[4:6], 1)              // QDCOUNT
	// ANCOUNT / NSCOUNT / ARCOUNT 保持 0
	b = append(b, hdr[:]...)
	b = append(b, 0x00)                   // QNAME = 根域（单字节 0 长度标签）
	b = append(b, 0x00, byte(dnsTypeNS))  // QTYPE = NS
	b = append(b, 0x00, byte(dnsClassIN)) // QCLASS = IN
	return b
}

// dnsResp 是解析后的 DNS 响应关键字段。
type dnsResp struct {
	ID        uint16
	Flags     uint16
	QR        bool
	Opcode    int
	AA        bool
	TC        bool
	RD        bool
	RA        bool
	RCode     int
	Questions int
	Answers   int
	NS        []string // Answer/Authority 段里的 NS 目标名
	SOA       []string // Answer/Authority 段里的 SOA 主名
}

// parseDNS 解析 DNS 响应。任何越界/截断都返回 error 而不是 panic。
func parseDNS(pkt []byte) (*parseResult, error) {
	r, err := decodeDNS(pkt)
	if err != nil {
		return nil, err
	}

	rcodeText, ok := dnsRCodeText[r.RCode]
	if !ok {
		rcodeText = fmt.Sprintf("RCODE%d", r.RCode)
	}

	evidence := []string{fmt.Sprintf("udp:dns-rcode=%d", r.RCode)}
	meta := map[string]string{
		"dns.rcode":     fmt.Sprintf("%d(%s)", r.RCode, rcodeText),
		"dns.flags":     fmt.Sprintf("0x%04x", r.Flags),
		"dns.qr":        boolText(r.QR),
		"dns.aa":        boolText(r.AA),
		"dns.tc":        boolText(r.TC),
		"dns.rd":        boolText(r.RD),
		"dns.ra":        boolText(r.RA),
		"dns.opcode":    fmt.Sprint(r.Opcode),
		"dns.questions": fmt.Sprint(r.Questions),
		"dns.answers":   fmt.Sprint(r.Answers),
	}
	if ns := joinNames(r.NS); ns != "" {
		meta["dns.ns"] = ns
	}
	if soa := joinNames(r.SOA); soa != "" {
		meta["dns.soa"] = soa
	}

	res := &parseResult{
		Service: "dns",
		Banner: fmt.Sprintf("DNS %s qr=%d aa=%d ra=%d answers=%d %s",
			rcodeText, b2i(r.QR), b2i(r.AA), b2i(r.RA), r.Answers, dnsNamesSummary(r)),
		Meta: meta,
	}

	// 判定：QR=1 说明这是一个"应答"，是 DNS 服务最直接的证据；
	// RCODE=5(REFUSED) 同样证明端口后面是一个会解析报文的 DNS 实现。
	switch {
	case !r.QR:
		res.Evidence = append(evidence, "udp:dns-response-without-qr")
		res.Confidence = model.ConfidenceMedium
	case r.RCode == 0:
		res.Exact = true
		res.Evidence = append(evidence, "udp:dns-rcode=0")
		res.Confidence = model.ConfidenceHigh
	case r.RCode == 5:
		res.Exact = true
		res.Evidence = append(evidence, "udp:dns-refused")
		res.Confidence = model.ConfidenceHigh
	case r.RCode == 4:
		// NOTIMP：实现了 DNS 报文解析但不支持该查询类型，仍是 DNS 服务。
		res.Evidence = append(evidence, "udp:dns-notimp")
		res.Confidence = model.ConfidenceMedium
	default:
		// NXDOMAIN / SERVFAIL / FORMERR：能生成合法 RCODE 的基本都是 DNS。
		res.Evidence = append(evidence, fmt.Sprintf("udp:dns-rcode=%d", r.RCode))
		res.Confidence = model.ConfidenceMedium
	}
	if r.TC {
		res.Evidence = append(res.Evidence, "udp:dns-truncated")
	}
	return res, nil
}

// decodeDNS 拆解头部并遍历 Answer/Authority 段。
func decodeDNS(pkt []byte) (dnsResp, error) {
	var r dnsResp
	if len(pkt) < dnsHeaderLen {
		return r, fmt.Errorf("dns: 响应过短 %d 字节（头部需 %d 字节）", len(pkt), dnsHeaderLen)
	}
	r.ID = binary.BigEndian.Uint16(pkt[0:2])
	r.Flags = binary.BigEndian.Uint16(pkt[2:4])
	r.QR = r.Flags&dnsFlagQR != 0
	r.AA = r.Flags&dnsFlagAA != 0
	r.TC = r.Flags&dnsFlagTC != 0
	r.RD = r.Flags&dnsFlagRD != 0
	r.RA = r.Flags&dnsFlagRA != 0
	r.Opcode = int(r.Flags>>11) & 0x0f
	r.RCode = int(r.Flags & 0x0f)
	r.Questions = int(binary.BigEndian.Uint16(pkt[4:6]))
	r.Answers = int(binary.BigEndian.Uint16(pkt[6:8]))
	nsCount := int(binary.BigEndian.Uint16(pkt[8:10]))
	arCount := int(binary.BigEndian.Uint16(pkt[10:12]))

	// TC 表示报文被截断，段计数不可信，只保留头部信息。
	if r.TC {
		return r, nil
	}

	off := dnsHeaderLen
	for i := 0; i < r.Questions; i++ {
		_, next, err := dnsReadName(pkt, off)
		if err != nil {
			return r, fmt.Errorf("dns: 解析第 %d 个问题失败: %w", i+1, err)
		}
		if next+4 > len(pkt) {
			return r, fmt.Errorf("dns: 第 %d 个问题的 QTYPE/QCLASS 被截断", i+1)
		}
		off = next + 4
	}

	total := r.Answers + nsCount
	for i := 0; i < total; i++ {
		_, next, err := dnsReadName(pkt, off)
		if err != nil {
			return r, fmt.Errorf("dns: 解析第 %d 条记录名失败: %w", i+1, err)
		}
		if next+10 > len(pkt) {
			return r, fmt.Errorf("dns: 第 %d 条记录的 RR 头被截断", i+1)
		}
		rtype := binary.BigEndian.Uint16(pkt[next : next+2])
		rdlen := int(binary.BigEndian.Uint16(pkt[next+8 : next+10]))
		rdata := next + 10
		if rdata+rdlen > len(pkt) {
			return r, fmt.Errorf("dns: 第 %d 条记录的 RDATA 越界 (rdlen=%d)", i+1, rdlen)
		}
		switch rtype {
		case dnsTypeNS:
			if target, _, err := dnsReadName(pkt, rdata); err == nil && target != "" {
				r.NS = append(r.NS, target)
			}
		case dnsTypeSOA:
			if mname, _, err := dnsReadName(pkt, rdata); err == nil && mname != "" {
				r.SOA = append(r.SOA, mname)
			}
		}
		off = rdata + rdlen
	}
	// ARCOUNT 段（OPT 等）对本探测无价值，不再解析。
	_ = arCount
	return r, nil
}

// dnsReadName 在 off 处读取一个域名，支持 RFC 1035 的 0xC0 压缩指针。
// 返回解码后的名字与实际消费到的绝对偏移（指针只占 2 字节）。
func dnsReadName(pkt []byte, off int) (string, int, error) {
	if off < 0 || off >= len(pkt) {
		return "", 0, fmt.Errorf("dns: 名字偏移 %d 越界 (len=%d)", off, len(pkt))
	}
	var labels []string
	p, end, hops := off, -1, 0
	for {
		if p >= len(pkt) {
			return "", 0, errors.New("dns: 名字未以 0 结尾（数据截断）")
		}
		c := int(pkt[p])
		switch {
		case c == 0:
			p++
			if end < 0 {
				end = p
			}
			return strings.Join(labels, "."), end, nil
		case c&0xc0 == 0xc0:
			if p+2 > len(pkt) {
				return "", 0, errors.New("dns: 压缩指针被截断")
			}
			target := int(binary.BigEndian.Uint16(pkt[p:p+2]) & 0x3fff)
			if end < 0 {
				end = p + 2
			}
			hops++
			if hops > 16 {
				return "", 0, errors.New("dns: 压缩指针形成环或嵌套过深")
			}
			if target >= len(pkt) {
				return "", 0, fmt.Errorf("dns: 压缩指针目标 %d 越界 (len=%d)", target, len(pkt))
			}
			if target == p {
				return "", 0, errors.New("dns: 压缩指针自引用")
			}
			p = target
		case c&0xc0 != 0:
			return "", 0, fmt.Errorf("dns: 非法的标签长度字节 0x%02x", c)
		default:
			if p+1+c > len(pkt) {
				return "", 0, errors.New("dns: 标签内容被截断")
			}
			labels = append(labels, string(pkt[p+1:p+1+c]))
			p += 1 + c
		}
	}
}

// dnsNamesSummary 生成 Banner 里的 NS/SOA 摘要，两者都有时同时展示。
func dnsNamesSummary(r dnsResp) string {
	parts := make([]string, 0, 2)
	if ns := joinNames(r.NS); ns != "" {
		parts = append(parts, "ns="+ns)
	}
	if soa := joinNames(r.SOA); soa != "" {
		parts = append(parts, "soa="+soa)
	}
	if len(parts) == 0 {
		return "ns=-"
	}
	return strings.Join(parts, " ")
}

func boolText(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}
