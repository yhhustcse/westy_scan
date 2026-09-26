package udpscan

import (
	"context"
	"encoding/binary"
	"fmt"
	"strings"
	"time"

	"westy_scan/internal/model"
)

// NetBIOS 名称服务（RFC 1001/1002）常量。
const (
	nbNameLen = 16

	nbTypeNBSTAT = 0x0021 // Node Status Request

	nbFlagResponse = 0x8000 // QR
	nbFlagAA       = 0x0400 // 权威应答

	nbSuffixHost       = 0x00 // 第 16 字节后缀：工作站/主机名
	nbSuffixGroup      = 0x1e // 工作组 / 域
	nbSuffixDC         = 0x1c // 域控制器（此时第 0 个名字是域）
	nbSuffixMessenger  = 0x03
	nbSuffixFileServer = 0x20

	nbFlagGroupName = 0x8000 // 名字表中的 G 位

	// 线上名字编码 = 1 字节长度(通常 0x20) + 首层编码名字 + 1 字节结束符。
	// 解析侧按长度前缀动态读取，这里的常量只用于构造查询。
	nbEncodedNameLen = 1 + nbNameLen*2 + 1
	nbQuestionLen    = nbEncodedNameLen + 2 + 2
)

// probeNetBIOS 发送 NetBIOS 名称服务 NBSTAT（Node Status）查询并解析响应。
func probeNetBIOS(ctx context.Context, network, addr string, timeout time.Duration) (*parseResult, error) {
	resp, err := exchange(ctx, network, addr, buildNBSTATQuery(), timeout)
	if err != nil || len(resp) == 0 {
		return nil, err
	}
	return parseNetBIOS(resp)
}

// buildNBSTATQuery 构造 NBSTAT 查询：
//
//	Header: ID(随机) / Flags=0x0000 / QDCOUNT=1 / 其余计数 0
//	Question: 0x20 长度 + 32 字节首层编码("*") + 0x00 结束 + QTYPE=0x0021 + QCLASS=0x0001
func buildNBSTATQuery() []byte {
	q := make([]byte, 0, 12+nbQuestionLen)
	var hdr [12]byte
	binary.BigEndian.PutUint16(hdr[0:2], randomUint16()) // ID
	binary.BigEndian.PutUint16(hdr[4:6], 1)              // QDCOUNT
	q = append(q, hdr[:]...)
	q = append(q, nbQuestionName()...)
	q = append(q, 0x00, byte(nbTypeNBSTAT)) // QTYPE = NBSTAT
	q = append(q, 0x00, 0x01)               // QCLASS = IN
	return q
}

// nbQuestionName 返回线上格式的名字字段：1 字节长度 + 32 字节首层编码 + 结束符。
func nbQuestionName() []byte {
	var raw [nbNameLen]byte
	raw[0] = '*'
	out := make([]byte, 0, nbEncodedNameLen+1)
	out = append(out, byte(nbNameLen*2))
	out = append(out, nbFirstLevelEncode(raw)...)
	return append(out, 0x00)
}

// nbFirstLevelEncode 实现 NetBIOS 首层编码：16 字节 → 32 字节，
// 每个字节拆成两个半字节，各加 'A'（0x41）。
func nbFirstLevelEncode(raw [nbNameLen]byte) []byte {
	out := make([]byte, 0, nbNameLen*2)
	for _, b := range raw {
		out = append(out, 'A'+(b>>4), 'A'+(b&0x0f))
	}
	return out
}

// nbFirstLevelDecode 是 nbFirstLevelEncode 的逆操作。
func nbFirstLevelDecode(enc []byte) ([nbNameLen]byte, error) {
	var out [nbNameLen]byte
	if len(enc) < nbNameLen*2 {
		return out, fmt.Errorf("netbios: 首层编码名字过短 %d 字节（需 %d 字节）", len(enc), nbNameLen*2)
	}
	for i := 0; i < nbNameLen; i++ {
		hi, lo := enc[i*2], enc[i*2+1]
		if hi < 'A' || hi > 'P' || lo < 'A' || lo > 'P' {
			return out, fmt.Errorf("netbios: 非法首层编码字节 %c%c", hi, lo)
		}
		out[i] = (hi-'A')<<4 | (lo - 'A')
	}
	return out, nil
}

// nbName 是解码后的名字表条目。
type nbName struct {
	Name   string
	Suffix byte
	Flags  uint16
}

// parseNetBIOS 解析 NBSTAT 响应，提取主机名与工作组名。
func parseNetBIOS(pkt []byte) (*parseResult, error) {
	if len(pkt) < 12 {
		return nil, fmt.Errorf("netbios: 响应过短 %d 字节（头部需 12 字节）", len(pkt))
	}
	flags := binary.BigEndian.Uint16(pkt[2:4])
	qd := int(binary.BigEndian.Uint16(pkt[4:6]))
	an := int(binary.BigEndian.Uint16(pkt[6:8]))

	meta := map[string]string{
		"netbios.flags":     fmt.Sprintf("0x%04x", flags),
		"netbios.qr":        boolText(flags&nbFlagResponse != 0),
		"netbios.aa":        boolText(flags&nbFlagAA != 0),
		"netbios.answers":   fmt.Sprint(an),
		"netbios.questions": fmt.Sprint(qd),
	}
	// 有响应但没有名字表（ANCOUNT=0）：能响应 NetBIOS 报文的端口依然值得记录。
	res := &parseResult{Service: "netbios", Meta: meta}
	if an == 0 {
		res.Banner = fmt.Sprintf("NetBIOS NS flags=0x%04x answers=0", flags)
		res.Evidence = append(res.Evidence, "udp:netbios-no-answers")
		res.Confidence = model.ConfidenceMedium
		return res, nil
	}

	// 遍历问题段，跳过 QDCOUNT 个问题（名字 + QTYPE + QCLASS）。
	// 这里刻意不写死"NBSTAT 问题段固定 N 字节"：线上名字长度由长度前缀决定，
	// 允许 0x20/0x00 等变体，固定长度一遇到变体就会整体错位。
	off := 12
	for i := 0; i < qd; i++ {
		_, next, err := nbReadName(pkt, off)
		if err != nil {
			return nil, fmt.Errorf("netbios: 解析第 %d 个问题失败: %w", i+1, err)
		}
		if next+4 > len(pkt) {
			return nil, fmt.Errorf("netbios: 第 %d 个问题的 QTYPE/QCLASS 被截断", i+1)
		}
		off = next + 4
	}
	if off >= len(pkt) {
		return nil, fmt.Errorf("netbios: 问题段越界 (offset=%d, len=%d)", off, len(pkt))
	}
	name, next, err := nbReadName(pkt, off)
	if err != nil {
		return nil, err
	}
	if next+10 > len(pkt) {
		return nil, fmt.Errorf("netbios: 答案记录头被截断")
	}
	rtype := binary.BigEndian.Uint16(pkt[next : next+2])
	rdlen := int(binary.BigEndian.Uint16(pkt[next+8 : next+10]))
	rdata := next + 10
	if rtype != nbTypeNBSTAT || rdlen <= 0 {
		return nil, fmt.Errorf("netbios: 答案记录类型非法 0x%04x (rdlen=%d)", rtype, rdlen)
	}
	if rdata+rdlen > len(pkt) {
		return nil, fmt.Errorf("netbios: 答案记录 RDATA 越界 (rdlen=%d)", rdlen)
	}
	meta["netbios.query_name"] = name

	names, err := parseNBSTATNames(pkt[rdata : rdata+rdlen])
	if err != nil {
		return nil, err
	}
	host, group, dc := classifyNBNames(names)
	if host != "" {
		meta["netbios.hostname"] = host
	}
	if group != "" {
		meta["netbios.workgroup"] = group
	}
	if dc != "" {
		meta["netbios.domain"] = dc
	}

	suffixParts := make([]string, 0, len(names))
	for _, n := range names {
		suffixParts = append(suffixParts, fmt.Sprintf("%s<0x%02x>", n.Name, n.Suffix))
	}
	meta["netbios.names"] = sanitizeText(strings.Join(suffixParts, ","), 512)
	res.Banner = fmt.Sprintf("NetBIOS NS hostname=%s workgroup=%s names=%d", dash(host), dash(group), len(names))
	res.Evidence = append(res.Evidence,
		fmt.Sprintf("udp:netbios-names=%d", len(names)),
		"udp:netbios-nbstat-response")
	res.Product = "NetBIOS Name Service"
	res.Confidence = model.ConfidenceHigh
	res.Exact = true
	return res, nil
}

// parseNBSTATNames 解析 RDATA 里的名字表：1 字节条目数 + N × 18 字节。
func parseNBSTATNames(rdata []byte) ([]nbName, error) {
	if len(rdata) < 1 {
		return nil, fmt.Errorf("netbios: 名字表为空")
	}
	count := int(rdata[0])
	if count == 0 {
		return nil, fmt.Errorf("netbios: 名字表条目数为 0")
	}
	// RDATA 尾部允许有统计信息，因此只要求 count 条名字完整存在。
	if 1+count*nbNameLen+count*2 > len(rdata) {
		return nil, fmt.Errorf("netbios: 名字表被截断 (count=%d, len=%d)", count, len(rdata))
	}
	names := make([]nbName, 0, count)
	for i := 0; i < count; i++ {
		off := 1 + i*18
		raw := rdata[off : off+nbNameLen]
		flags := binary.BigEndian.Uint16(rdata[off+nbNameLen : off+nbNameLen+2])
		names = append(names, nbName{
			Name:   strings.TrimRight(string(raw[:nbNameLen-1]), " \x00"),
			Suffix: raw[nbNameLen-1],
			Flags:  flags,
		})
	}
	return names, nil
}

// classifyNBNames 按第 16 字节后缀区分主机名与工作组/域。
//
// 约定（Windows 实际行为）：
//   - 后缀 0x00 且 G 位为 0 → 主机名；
//   - 后缀 0x1e 且 G 位为 1 → 工作组 / 域；
//   - 后缀 0x1c 且 G 位为 1 → 域控制器场景，第 0 个名字是域、第 1 个是主机名。
func classifyNBNames(names []nbName) (host, group, dc string) {
	for _, n := range names {
		if n.Name == "" {
			continue
		}
		isGroup := n.Flags&nbFlagGroupName != 0
		switch n.Suffix {
		case nbSuffixHost:
			if isGroup {
				continue
			}
			if host == "" {
				host = n.Name
			}
		case nbSuffixGroup:
			if group == "" {
				group = n.Name
			}
		case nbSuffixDC:
			if dc == "" {
				dc = n.Name
			}
		}
	}
	if host == "" && dc != "" && len(names) > 1 {
		// 域控机器上主机名常出现在第 0 个名字（后缀 0x1c）之后。
		for i, n := range names {
			if i > 0 && n.Suffix == nbSuffixHost && n.Name != "" {
				host = n.Name
				break
			}
		}
	}
	if group == "" && dc != "" {
		group = dc
	}
	return host, group, dc
}

// nbReadName 读取一个 NetBIOS 线上名字：
//
//	[1 字节长度 0x20][32 字节首层编码][1 字节结束符 0x00]      —— 完整形式
//	[2 字节压缩指针 0xC0 xx]                                  —— 压缩形式（答案段常见）
//
// 返回的 next 指向"名字之后紧跟的字段"（问题段是 QTYPE，答案段是 TYPE），
// **不消费** QTYPE/TYPE 本身 —— 由调用方按 4/10 字节的固定结构继续解析。
func nbReadName(pkt []byte, off int) (string, int, error) {
	if off < 0 || off >= len(pkt) {
		return "", 0, fmt.Errorf("netbios: 名字偏移 %d 越界 (len=%d)", off, len(pkt))
	}
	// 压缩指针：高两位为 11
	if pkt[off]&0xC0 == 0xC0 {
		if off+2 > len(pkt) {
			return "", 0, fmt.Errorf("netbios: 压缩指针被截断")
		}
		ptr := int(pkt[off]&0x3F)<<8 | int(pkt[off+1])
		if ptr >= len(pkt) || ptr == off {
			return "", 0, fmt.Errorf("netbios: 压缩指针越界 %d", ptr)
		}
		name, _, err := nbReadName(pkt, ptr)
		if err != nil {
			return "", 0, err
		}
		return name, off + 2, nil
	}

	n := int(pkt[off])
	off++
	if n < 0 || n > 32 {
		return "", 0, fmt.Errorf("netbios: 非法名字长度 %d", n)
	}
	if off+n > len(pkt) {
		return "", 0, fmt.Errorf("netbios: 名字内容被截断 (len=%d)", n)
	}
	raw, err := nbFirstLevelDecode(pkt[off : off+n])
	if err != nil {
		return "", 0, err
	}
	off += n
	// 结束符：首层编码名之后必须有一个 0x00
	if off < len(pkt) && pkt[off] == 0x00 {
		off++
	}
	name := strings.TrimRight(string(raw[:]), " \x00")
	return name, off, nil
}

// dash 把空字符串替换成 "-"，只用于 Banner 展示。
func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
