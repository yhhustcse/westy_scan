package udpscan

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"westy_scan/internal/model"
	"westy_scan/internal/scope"
)

// ---------------------------------------------------------------------------
// 测试辅助
// ---------------------------------------------------------------------------

// withProbePorts 把探针注册端口临时改写到本地假服务端的临时端口。
// 这样端到端测试可以走完整的 Scan 链路，又不需要占用 53/123/137/161。
//
// 走 setPortResolver 而不是直接赋值：扫描 worker 协程会并发读这个映射，
// 裸赋值是一个真实的 data race（本地不触发、CI 上 -race 必红）。
func withProbePorts(t *testing.T, mapping map[int]int) {
	t.Helper()
	restore := setPortResolver(func(p int) int {
		if v, ok := mapping[p]; ok {
			return v
		}
		return p
	})
	t.Cleanup(restore)
}

// appendName 追加一个 DNS 名字（仅用于测试构造响应）。
func appendName(b []byte, name string) []byte {
	for _, label := range strings.Split(name, ".") {
		if label == "" {
			continue
		}
		b = append(b, byte(len(label)))
		b = append(b, label...)
	}
	return append(b, 0x00)
}

// appendRR 追加一条 DNS 资源记录。
func appendRR(b []byte, name string, rtype uint16, ttl uint32, rdata []byte) []byte {
	b = appendName(b, name)
	var hdr [10]byte
	binary.BigEndian.PutUint16(hdr[0:2], rtype)
	binary.BigEndian.PutUint16(hdr[2:4], dnsClassIN)
	binary.BigEndian.PutUint32(hdr[4:8], ttl)
	binary.BigEndian.PutUint16(hdr[8:10], uint16(len(rdata)))
	b = append(b, hdr[:]...)
	return append(b, rdata...)
}

// buildDNSHeader 构造 DNS 响应头。
func buildDNSHeader(id uint16, rcode, qd, an, ns, ar int) []byte {
	var hdr [dnsHeaderLen]byte
	binary.BigEndian.PutUint16(hdr[0:2], id)
	// QR=1 RD=1 RA=1，AA 位在需要时由调用方通过 buildDNSHeaderAA 显式打开
	binary.BigEndian.PutUint16(hdr[2:4], uint16(dnsFlagQR|dnsFlagRD|dnsFlagRA|rcode))
	binary.BigEndian.PutUint16(hdr[4:6], uint16(qd))
	binary.BigEndian.PutUint16(hdr[6:8], uint16(an))
	binary.BigEndian.PutUint16(hdr[8:10], uint16(ns))
	binary.BigEndian.PutUint16(hdr[10:12], uint16(ar))
	return hdr[:]
}

// buildDNSResponse 构造一个根域 NS 应答（Answer 段 n 条，Authority 段 n 条）。
func buildDNSResponse(id uint16, rcode int, nsNames ...string) []byte {
	b := append([]byte{}, buildDNSHeader(id, rcode, 1, len(nsNames), len(nsNames), 0)...)
	// 回显问题段：QNAME="." QTYPE=NS QCLASS=IN
	b = append(b, 0x00, 0x00, byte(dnsTypeNS), 0x00, byte(dnsClassIN))
	for _, n := range nsNames {
		b = appendRR(b, ".", dnsTypeNS, 518400, appendName(nil, n))
	}
	for _, n := range nsNames {
		b = appendRR(b, ".", dnsTypeNS, 518400, appendName(nil, n))
	}
	return b
}

// buildNTPResponse 构造一个 NTPv4 服务器应答。
func buildNTPResponse(stratum byte, refid string, txTime uint32) []byte {
	b := make([]byte, ntpPacketLen)
	b[0] = 0x24 // LI=0, VN=4, Mode=4（服务器）
	b[1] = stratum
	b[2] = 0x04 // poll = 4
	b[3] = 0xfa // precision = -6
	copy(b[12:16], refid)
	binary.BigEndian.PutUint32(b[16:20], 0xEE000000) // 参考时间戳
	binary.BigEndian.PutUint32(b[28:32], txTime)
	return b
}

// buildNTPKiss 构造 kiss-o'-death 包：stratum=0 + mode=4。
func buildNTPKiss(code string) []byte {
	b := make([]byte, ntpPacketLen)
	b[0] = 0x24
	b[1] = 0x00
	copy(b[12:16], code)
	return b
}

// nbQuestion 是 NBSTAT 查询的问题段（32 字节编码名 + 结束字节 + QTYPE + QCLASS）。
func nbQuestion() []byte {
	b := make([]byte, 0, 38)
	b = append(b, 0x20)
	b = append(b, []byte("CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")...)
	b = append(b, 0x00)
	b = append(b, 0x00, byte(nbTypeNBSTAT))
	b = append(b, 0x00, 0x01)
	return b
}

// buildNBSTATNamesTable 构造 NBSTAT 的 RDATA：1 字节条目数 + N × 18 字节。
func buildNBSTATNamesTable(hostSuffix byte, hostname, workgroup string) []byte {
	type entry struct {
		name   string
		suffix byte
		group  bool
	}
	entries := []entry{{hostname, hostSuffix, hostSuffix == nbSuffixDC}}
	if workgroup != "" {
		entries = append(entries, entry{workgroup, nbSuffixGroup, true})
	}

	table := []byte{byte(len(entries))}
	for _, e := range entries {
		raw := make([]byte, nbNameLen)
		copy(raw, e.name)
		raw[nbNameLen-1] = e.suffix // 第 16 字节是后缀，别漏
		table = append(table, raw...)
		var fl [2]byte
		if e.group {
			binary.BigEndian.PutUint16(fl[:], nbFlagGroupName)
		}
		table = append(table, fl[:]...)
	}
	return table
}

// buildNBSTATResponseWithNames 用显式的名字表构造 NBSTAT 应答（支持多条/自定义后缀）。
func buildNBSTATResponseWithNames(names []nbName) []byte {
	table := []byte{byte(len(names))}
	for _, n := range names {
		raw := make([]byte, nbNameLen)
		copy(raw, n.Name)
		raw[15] = n.Suffix
		table = append(table, raw...)
		var fl [2]byte
		binary.BigEndian.PutUint16(fl[:], n.Flags)
		table = append(table, fl[:]...)
	}
	return buildNBSTATPacket(table)
}

// buildNBSTATResponse 构造 NetBIOS 名称服务 NBSTAT 应答。
// hostSuffix 传 nbSuffixDC 可模拟域控场景（第 0 个名字后缀 0x1c）。
func buildNBSTATResponse(hostname, workgroup string, hostSuffix byte) []byte {
	table := buildNBSTATNamesTable(hostSuffix, hostname, workgroup)
	return buildNBSTATPacket(table)
}

// buildNBSTATPacket 把名字表 RDATA 包成完整的 NBSTAT 应答报文。
func buildNBSTATPacket(table []byte) []byte {
	b := make([]byte, 0, 256)
	var hdr [12]byte
	binary.BigEndian.PutUint16(hdr[0:2], 0x1234)
	binary.BigEndian.PutUint16(hdr[2:4], nbFlagResponse|nbFlagAA)
	binary.BigEndian.PutUint16(hdr[4:6], 1) // QDCOUNT
	binary.BigEndian.PutUint16(hdr[6:8], 1) // ANCOUNT
	b = append(b, hdr[:]...)
	b = append(b, nbQuestion()...)

	// 答案记录：名字 + TYPE + CLASS + TTL + RDLENGTH + RDATA
	b = append(b, 0x20)
	b = append(b, []byte("CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")...)
	b = append(b, 0x00)
	b = append(b, 0x00, byte(nbTypeNBSTAT))
	b = append(b, 0x00, 0x01)
	b = append(b, 0x00, 0x00, 0x00, 0x00) // TTL
	var rdlen [2]byte
	binary.BigEndian.PutUint16(rdlen[:], uint16(len(table)))
	b = append(b, rdlen[:]...)
	return append(b, table...)
}

// buildSNMPResponse 构造 SNMP 应答：value 为 nil 时回 NULL（模拟错误响应）。
func buildSNMPResponse(value []byte, errStatus, errIndex int) []byte {
	version := berTLV(asn1Integer, berUint(1))
	community := berTLV(asn1OctetStr, []byte("public"))

	var val []byte
	if value == nil {
		val = berTLV(asn1Null, nil)
	} else {
		val = berTLV(asn1OctetStr, value)
	}
	varbind := berTLV(asn1Sequence, append(berTLV(asn1ObjectID, sysDescrOID), val...))
	varbindList := berTLV(asn1Sequence, varbind)

	var pdu []byte
	pdu = append(pdu, berTLV(asn1Integer, berUint(4242))...)
	pdu = append(pdu, berTLV(asn1Integer, berUint(uint64(errStatus)))...)
	pdu = append(pdu, berTLV(asn1Integer, berUint(uint64(errIndex)))...)
	pdu = append(pdu, varbindList...)

	body := append(version, community...)
	body = append(body, berTLV(0xa2, pdu)...)
	return berTLV(asn1Sequence, body)
}

// fakeServer 是本地假 UDP 服务端。
type fakeServer struct {
	conn net.PacketConn
	port int
}

func startFakeServer(t *testing.T, handler func(req []byte) []byte) *fakeServer {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("监听本地 UDP 失败: %v", err)
	}
	port := conn.LocalAddr().(*net.UDPAddr).Port
	go func() {
		buf := make([]byte, maxResponseSize)
		for {
			n, addr, err := conn.ReadFrom(buf)
			if err != nil {
				return
			}
			req := make([]byte, n)
			copy(req, buf[:n])
			// 每个请求单独一个协程：真实 UDP 服务端是并发的，
			// 串行处理会让"客户端并发度"这类用例永远测不出来。
			go func(req []byte, addr net.Addr) {
				resp := handler(req)
				if resp == nil {
					return // 模拟"静默丢弃"
				}
				_, _ = conn.WriteTo(resp, addr)
			}(req, addr)
		}
	}()
	t.Cleanup(func() { _ = conn.Close() })
	return &fakeServer{conn: conn, port: port}
}

func testScope(t *testing.T) *scope.Scope {
	t.Helper()
	sc, err := scope.New([]string{"127.0.0.0/8", "localhost"}, nil, 4096, false, true)
	if err != nil {
		t.Fatalf("构造 Scope 失败: %v", err)
	}
	return sc
}

func collectAssets(t *testing.T, ch <-chan model.Asset) []model.Asset {
	t.Helper()
	var got []model.Asset
	timeout := time.After(15 * time.Second)
	for {
		select {
		case a, ok := <-ch:
			if !ok {
				return got
			}
			got = append(got, a)
		case <-timeout:
			t.Fatalf("等待资产流关闭超时，已收到 %d 条", len(got))
		}
	}
}

func hasEvidence(list []string, want string) bool {
	for _, e := range list {
		if e == want {
			return true
		}
	}
	return false
}

// assertNoPanic 断言解析函数面对畸形输入时返回 error 而不是 panic。
func assertNoPanic(t *testing.T, name string, fn func()) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("%s 触发 panic: %v", name, r)
		}
	}()
	fn()
}

// ---------------------------------------------------------------------------
// DNS 解析测试
// ---------------------------------------------------------------------------

func TestParseDNS_OK(t *testing.T) {
	pkt := buildDNSResponse(0x1234, 0,
		"a.root-servers.net", "b.root-servers.net", "a.root-servers.net")

	res, err := parseDNS(pkt)
	if err != nil {
		t.Fatalf("parseDNS 返回错误: %v", err)
	}
	if res.Service != "dns" {
		t.Errorf("service = %q, 期望 dns", res.Service)
	}
	if res.Confidence != model.ConfidenceHigh {
		t.Errorf("confidence = %q, 期望 %q", res.Confidence, model.ConfidenceHigh)
	}
	if !res.Exact {
		t.Errorf("RCODE=0 应标记为精确命中")
	}
	wantMeta := map[string]string{
		"dns.rcode":     "0(NOERROR)",
		"dns.qr":        "true",
		"dns.aa":        "false", // buildDNSResponse 默认不开 AA 位
		"dns.ra":        "true",
		"dns.rd":        "true",
		"dns.answers":   "3",
		"dns.questions": "1",
		"dns.ns":        "a.root-servers.net,b.root-servers.net", // 去重且保持顺序
	}
	for k, v := range wantMeta {
		if got := res.Meta[k]; got != v {
			t.Errorf("meta %s = %q, 期望 %q", k, got, v)
		}
	}
	if !hasEvidence(res.Evidence, "udp:dns-rcode=0") {
		t.Errorf("缺少判据 udp:dns-rcode=0, 实际 %v", res.Evidence)
	}
	if !strings.Contains(res.Banner, "NOERROR") || !strings.Contains(res.Banner, "a.root-servers.net") {
		t.Errorf("banner = %q", res.Banner)
	}
}

// TestParseDNS_CompressionPointer 用字节字面量构造带 0xC0 压缩指针与 SOA 的响应。
func TestParseDNS_CompressionPointer(t *testing.T) {
	// 1 个问题 + 2 条 Answer + 1 条 Authority + 0 条 Additional
	pkt := append([]byte{}, buildDNSHeader(0xbeef, 0, 1, 2, 1, 0)...)
	pkt = append(pkt, 0x00, 0x00, byte(dnsTypeNS), 0x00, byte(dnsClassIN)) // 问题段
	// AN：名字用压缩指针指回偏移 12 的根标签
	pkt = appendRR(pkt, ".", dnsTypeNS, 3600, []byte{0xc0, 0x0c})
	// AN：完整的根域 NS 名字
	pkt = appendRR(pkt, ".", dnsTypeNS, 3600, appendName(nil, "k.root-servers.net"))
	// NS：SOA，RDATA = MNAME + RNAME + 20 字节定长字段
	soa := appendName(nil, "a.root-servers.net")
	soa = appendName(soa, "nstld.verisign-grs.com")
	soa = append(soa, make([]byte, 20)...)
	pkt = appendRR(pkt, ".", dnsTypeSOA, 3600, soa)

	res, err := parseDNS(pkt)
	if err != nil {
		t.Fatalf("parseDNS 返回错误: %v", err)
	}
	if got := res.Meta["dns.ns"]; got != "k.root-servers.net" {
		t.Errorf("meta dns.ns = %q, 期望 k.root-servers.net（压缩指针应被正确解析）", got)
	}
	if got := res.Meta["dns.soa"]; got != "a.root-servers.net" {
		t.Errorf("meta dns.soa = %q, 期望 a.root-servers.net", got)
	}
	if !strings.Contains(res.Banner, "soa=") {
		t.Errorf("banner 应含 SOA 摘要: %q", res.Banner)
	}
}

func TestParseDNS_Refused(t *testing.T) {
	// RCODE=5(REFUSED)：解析器拒绝递归，但端口后面确实是 DNS 服务，算命中。
	pkt := buildDNSResponse(0x0102, 5)
	res, err := parseDNS(pkt)
	if err != nil {
		t.Fatalf("parseDNS 返回错误: %v", err)
	}
	if res.Confidence != model.ConfidenceHigh {
		t.Errorf("REFUSED 应为 %q，实际 %q", model.ConfidenceHigh, res.Confidence)
	}
	if got := res.Meta["dns.rcode"]; got != "5(REFUSED)" {
		t.Errorf("meta dns.rcode = %q, 期望 5(REFUSED)", got)
	}
	if !hasEvidence(res.Evidence, "udp:dns-refused") {
		t.Errorf("缺少判据 udp:dns-refused, 实际 %v", res.Evidence)
	}
}

func TestParseDNS_NXDOMAIN_Medium(t *testing.T) {
	res, err := parseDNS(buildDNSResponse(0x0103, 3))
	if err != nil {
		t.Fatalf("parseDNS 返回错误: %v", err)
	}
	if res.Confidence != model.ConfidenceMedium {
		t.Errorf("NXDOMAIN 置信度应为 %q，实际 %q", model.ConfidenceMedium, res.Confidence)
	}
	if res.Exact {
		t.Errorf("NXDOMAIN 不应标记为精确命中")
	}
}

func TestParseDNS_TruncatedAndMalformed(t *testing.T) {
	cases := []struct {
		name string
		pkt  []byte
	}{
		{"空报文", []byte{}},
		{"短于头部", []byte{0x12, 0x34, 0x81, 0x80}},
		{"压缩指针自引用", []byte{
			0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0xc0, 0x0c,
		}},
		{"压缩指针越界", []byte{
			0x12, 0x34, 0x81, 0x80, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
			0xc0, 0xff, 0x00, 0x02, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x04, 0xde, 0xad, 0xbe, 0xef,
		}},
		{"标签长度非法", []byte{
			0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x41, 0x41,
		}},
		{"RDATA 长度越界", []byte{
			0x12, 0x34, 0x81, 0x80, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x02, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0xff, 0xff, 0x01,
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			assertNoPanic(t, c.name, func() {
				res, err := parseDNS(c.pkt)
				if err == nil {
					t.Fatalf("期望返回 error，实际 res=%+v", res)
				}
				if res != nil {
					t.Errorf("出错时应返回 nil 结果")
				}
			})
		})
	}
}

// ---------------------------------------------------------------------------
// NTP 解析测试
// ---------------------------------------------------------------------------

func TestParseNTP_RealSample(t *testing.T) {
	// 真实形态的 NTPv4 服务器应答（48 字节字面量）。
	rx := []byte{
		0x24, 0x02, 0x04, 0xfa, 0x00, 0x00, 0x01, 0x2c,
		0x00, 0x00, 0x00, 0x40, 0xc0, 0xa8, 0x01, 0x01,
		0xee, 0x00, 0x00, 0x00, 0x11, 0x22, 0x33, 0x44,
		0xee, 0x00, 0x00, 0x10, 0xee, 0x00, 0x00, 0x20,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0xe8, 0xfe, 0x6f, 0x80, 0x00, 0x00, 0x00, 0x00,
	}
	res, err := parseNTP(rx)
	if err != nil {
		t.Fatalf("parseNTP 返回错误: %v", err)
	}
	if res.Service != "ntp" {
		t.Errorf("service = %q, 期望 ntp", res.Service)
	}
	if res.Confidence != model.ConfidenceHigh || !res.Exact {
		t.Errorf("mode=4 stratum=2 应为 high/Exact，实际 %q/%v", res.Confidence, res.Exact)
	}
	wantMeta := map[string]string{
		"ntp.leap":       "0(no-warning)",
		"ntp.version":    "4",
		"ntp.mode":       "4(server)",
		"ntp.stratum":    "2",
		"ntp.poll":       "4",
		"ntp.precision":  "-6",
		"ntp.ref_id":     "192.168.1.1",
		"ntp.root_delay": "0.005s",               // 0x12c = 300 / 65536 ≈ 0.0046s
		"ntp.tx_time":    "2023-11-14T22:13:20Z", // tx = 0xEE00_0000
	}
	for k, v := range wantMeta {
		if got := res.Meta[k]; got != v {
			t.Errorf("meta %s = %q, 期望 %q", k, got, v)
		}
	}
	if !hasEvidence(res.Evidence, "udp:ntp-mode=4") || !hasEvidence(res.Evidence, "udp:ntp-server-response") {
		t.Errorf("缺少 NTP 判据: %v", res.Evidence)
	}
	if !strings.Contains(res.Banner, "stratum=2") || !strings.Contains(res.Banner, "192.168.1.1") {
		t.Errorf("banner = %q", res.Banner)
	}
}

func TestParseNTP_KissOfDeath(t *testing.T) {
	res, err := parseNTP(buildNTPKiss("RATE"))
	if err != nil {
		t.Fatalf("parseNTP 返回错误: %v", err)
	}
	if res.Confidence != model.ConfidenceHigh {
		t.Errorf("kiss-o'-death 应算命中(high)，实际 %q", res.Confidence)
	}
	if got := res.Meta["ntp.kiss_code"]; got != "RATE" {
		t.Errorf("meta ntp.kiss_code = %q, 期望 RATE", got)
	}
	if got := res.Meta["ntp.stratum"]; got != "0" {
		t.Errorf("meta ntp.stratum = %q, 期望 0", got)
	}
	if got := res.Meta["ntp.mode"]; got != "4(server)" {
		t.Errorf("meta ntp.mode = %q", got)
	}
	if !hasEvidence(res.Evidence, "udp:ntp-kiss-o-death") {
		t.Errorf("缺少判据 udp:ntp-kiss-o-death: %v", res.Evidence)
	}
	if !strings.Contains(res.Banner, "RATE") {
		t.Errorf("banner = %q", res.Banner)
	}
}

func TestParseNTP_UnsynchronizedMedium(t *testing.T) {
	res, err := parseNTP(buildNTPResponse(16, "\x00\x00\x00\x00", 0))
	if err != nil {
		t.Fatalf("parseNTP 返回错误: %v", err)
	}
	if res.Confidence != model.ConfidenceMedium {
		t.Errorf("stratum=16 置信度应为 medium，实际 %q", res.Confidence)
	}
	if !hasEvidence(res.Evidence, "udp:ntp-unsynchronized-stratum=16") {
		t.Errorf("Evidence = %v", res.Evidence)
	}
}

func TestBuildNTPRequest(t *testing.T) {
	req := buildNTPRequest()
	if len(req) != ntpPacketLen {
		t.Fatalf("NTP 请求长度 = %d, 期望 %d", len(req), ntpPacketLen)
	}
	if req[0] != 0x23 {
		t.Errorf("首字节 = 0x%02x, 期望 0x23 (LI=0/VN=4/Mode=3)", req[0])
	}
	for i := 1; i < len(req); i++ {
		if req[i] != 0 {
			t.Fatalf("第 %d 字节 = 0x%02x, 期望 0（其余字节必须全 0）", i, req[i])
		}
	}
}

func TestParseNTP_Truncated(t *testing.T) {
	for _, n := range []int{0, 1, 12, 47} {
		pkt := make([]byte, n)
		if n >= 1 {
			pkt[0] = 0x24
		}
		assertNoPanic(t, fmt.Sprintf("长度%d", n), func() {
			res, err := parseNTP(pkt)
			if err == nil {
				t.Fatalf("长度 %d 应返回 error，实际 res=%+v", n, res)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// SNMP 解析测试
// ---------------------------------------------------------------------------

// TestBuildSNMPGetRequest 用字节字面量校验手工 BER 编码结果。
// 固定熵源让 request-id 变成确定的 2 字节 0x0521，从而可以逐字节比对整个报文。
func TestBuildSNMPGetRequest(t *testing.T) {
	old := protocolEntropy
	protocolEntropy = bytes.NewReader([]byte{0x05, 0x21})
	t.Cleanup(func() { protocolEntropy = old })
	want := []byte{
		0x30, 0x27,
		0x02, 0x01, 0x01, // version = v2c
		0x04, 0x06, 'p', 'u', 'b', 'l', 'i', 'c', // community = public
		0xa0, 0x1a, // GetRequest PDU，长度 26 = 3(rid) + 3 + 3 + 17(varbind-list)
		0x02, 0x02, 0x05, 0x21, // request-id = 1313
		0x02, 0x01, 0x00, // error-status = 0
		0x02, 0x01, 0x00, // error-index = 0
		0x30, 0x0e, // varbind-list，长度 14
		0x30, 0x0c, // varbind，长度 12
		0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00, // sysDescr OID
		0x05, 0x00, // NULL
	}
	got := buildSNMPGetRequest()
	if len(got) != len(want) {
		t.Fatalf("长度 = %d, 期望 %d\ngot  = % x\nwant = % x", len(got), len(want), got, want)
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("报文不一致\ngot  = % x\nwant = % x", got, want)
	}
	assertWellFormedBER(t, got)
}

// TestBuildSNMPGetRequest_RandomID 确认 request-id 来自随机熵源而不是常量。
func TestBuildSNMPGetRequest_RandomID(t *testing.T) {
	seen := map[uint16]bool{}
	for i := 0; i < 32; i++ {
		req := buildSNMPGetRequest()
		seen[binary.BigEndian.Uint16(req[17:19])] = true
	}
	if len(seen) < 2 {
		t.Errorf("request-id 似乎没有随机性: %v", seen)
	}
}

func TestParseSNMP_SysDescr(t *testing.T) {
	descr := "Cisco IOS Software, C2960 Software (C2960-LANBASEK9-M), Version 15.0(2)SE11"
	pkt := buildSNMPResponse([]byte(descr), 0, 0)
	assertWellFormedBER(t, pkt)

	res, err := parseSNMP(pkt)
	if err != nil {
		t.Fatalf("parseSNMP 返回错误: %v", err)
	}
	if res.Service != "snmp" {
		t.Errorf("service = %q, 期望 snmp", res.Service)
	}
	if res.Confidence != model.ConfidenceHigh || !res.Exact {
		t.Errorf("成功读取 sysDescr 应为 high/Exact，实际 %q/%v", res.Confidence, res.Exact)
	}
	wantMeta := map[string]string{
		"snmp.sys_descr":    descr,
		"snmp.community":    "public",
		"snmp.version":      "v2c",
		"snmp.request_id":   "4242",
		"snmp.error_status": "0(noError)",
	}
	for k, v := range wantMeta {
		if got := res.Meta[k]; got != v {
			t.Errorf("meta %s = %q, 期望 %q", k, got, v)
		}
	}
	if res.Product != "Cisco IOS" {
		t.Errorf("Product = %q, 期望 Cisco IOS", res.Product)
	}
	if res.Version != "15.0" {
		t.Errorf("Version = %q, 期望 15.0", res.Version)
	}
	if !hasEvidence(res.Evidence, "udp:snmp-sysdescr") {
		t.Errorf("缺少判据 udp:snmp-sysdescr: %v", res.Evidence)
	}
}

func TestParseSNMP_ErrorStatuses(t *testing.T) {
	cases := []struct {
		name     string
		status   int
		wantText string
		wantEvi  string
	}{
		{"noSuchName", 2, "2(noSuchName)", "udp:snmp-noSuchName"},
		{"authorizationError", 16, "16(authorizationError)", "udp:snmp-authorizationError"},
		{"noAccess", 6, "6(noAccess)", "udp:snmp-noAccess"},
		{"tooBig", 1, "1(tooBig)", "udp:snmp-error-status"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			pkt := buildSNMPResponse(nil, c.status, 1)
			res, err := parseSNMP(pkt)
			if err != nil {
				t.Fatalf("parseSNMP 返回错误: %v", err)
			}
			if res.Confidence != model.ConfidenceMedium {
				t.Errorf("error-status=%d 置信度应为 medium，实际 %q", c.status, res.Confidence)
			}
			if got := res.Meta["snmp.error_status"]; got != c.wantText {
				t.Errorf("meta snmp.error_status = %q, 期望 %q", got, c.wantText)
			}
			if !hasEvidence(res.Evidence, c.wantEvi) {
				t.Errorf("缺少判据 %s: %v", c.wantEvi, res.Evidence)
			}
			if res.Product != "" {
				t.Errorf("无 sysDescr 时不应猜产品: %q", res.Product)
			}
		})
	}
}

func TestSNMPFingerprint(t *testing.T) {
	cases := []struct {
		descr   string
		product string
		version string
	}{
		{"Cisco IOS Software, Version 15.2(4)M6", "Cisco IOS", "15.2"},
		{"MikroTik RouterOS 6.48.6 (stable)", "RouterOS", "6.48.6"},
		{"Microsoft Windows Server 2019 Version 10.0.17763", "Windows", "10.0.17763"},
		{"FreeBSD 13.2-RELEASE-p1", "FreeBSD", "13.2"},
		{"some unknown agent 1.0", "", ""},
	}
	for _, c := range cases {
		p, v := snmpFingerprint(c.descr)
		if p != c.product || v != c.version {
			t.Errorf("snmpFingerprint(%q) = (%q,%q), 期望 (%q,%q)", c.descr, p, v, c.product, c.version)
		}
	}
}

func TestParseSNMP_Malformed(t *testing.T) {
	valid := buildSNMPResponse([]byte("hello"), 0, 0)
	cases := []struct {
		name string
		pkt  []byte
	}{
		{"空报文", []byte{}},
		{"只有标签", []byte{0x30}},
		{"长度越界", []byte{0x30, 0x7f, 0x02, 0x01, 0x01}},
		{"不定长编码", []byte{0x30, 0x80, 0x02, 0x01, 0x01, 0x00, 0x00}},
		{"顶层不是 SEQUENCE", []byte{0x02, 0x03, 0x01, 0x02, 0x03}},
		{"version 后截断", valid[:4]},
		{"community 后截断", valid[:9]},
		{"PDU 截断一半", valid[:len(valid)/2]},
		{"varbind OID 标签错误", func() []byte {
			b := append([]byte{}, valid...)
			i := bytes.Index(b, sysDescrOID)
			if i < 2 {
				t.Fatalf("样本里找不到 sysDescr OID")
			}
			b[i-2] = 0x04 // 把 OID 的标签字节改成 OCTET STRING
			return b
		}()},
		{"varbind value 截断", func() []byte {
			return append([]byte{}, valid[:len(valid)-2]...)
		}()},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			assertNoPanic(t, c.name, func() {
				res, err := parseSNMP(c.pkt)
				if err == nil {
					t.Fatalf("期望返回 error，实际 res=%+v", res)
				}
			})
		})
	}
}

// ---------------------------------------------------------------------------
// NetBIOS 解析测试
// ---------------------------------------------------------------------------

func TestNBFirstLevelCodec(t *testing.T) {
	var raw [nbNameLen]byte
	copy(raw[:], "WESTY-PC")
	enc := nbFirstLevelEncode(raw)
	if len(enc) != 32 {
		t.Fatalf("首层编码长度 = %d, 期望 32", len(enc))
	}
	// 'W' = 0x57 -> 高半字节 5 -> 'F'，低半字节 7 -> 'H'
	if enc[0] != 'F' || enc[1] != 'H' {
		t.Fatalf("首层编码前两字节 = %c%c, 期望 FH", enc[0], enc[1])
	}
	dec, err := nbFirstLevelDecode(enc)
	if err != nil {
		t.Fatalf("nbFirstLevelDecode 返回错误: %v", err)
	}
	if dec != raw {
		t.Errorf("编解码不一致: got %q, want %q", string(dec[:]), string(raw[:]))
	}
	if _, err := nbFirstLevelDecode([]byte("AB")); err == nil {
		t.Errorf("过短的编码名应返回 error")
	}
	if _, err := nbFirstLevelDecode([]byte(strings.Repeat("a", 32))); err == nil {
		t.Errorf("非法字符的编码名应返回 error")
	}
}

func TestBuildNBSTATQuery(t *testing.T) {
	q := buildNBSTATQuery()
	if len(q) != 12+38 {
		t.Fatalf("NBSTAT 查询长度 = %d, 期望 %d", len(q), 12+38)
	}
	if q[4] != 0x00 || q[5] != 0x01 {
		t.Errorf("QDCOUNT = %d, 期望 1", binary.BigEndian.Uint16(q[4:6]))
	}
	if q[12] != 0x20 {
		t.Errorf("名字长度字节 = 0x%02x, 期望 0x20", q[12])
	}
	dec, err := nbFirstLevelDecode(q[13:45])
	if err != nil {
		t.Fatalf("查询里的首层编码非法: %v", err)
	}
	if !strings.HasPrefix(string(dec[:]), "*") {
		t.Errorf("NBSTAT 名字应为 *，实际 %q", strings.TrimRight(string(dec[:]), "\x00"))
	}
	if suffix := q[len(q)-4 : len(q)-2]; suffix[0] != 0x00 || suffix[1] != byte(nbTypeNBSTAT) {
		t.Errorf("QTYPE = % x, 期望 0021", suffix)
	}
}

func TestParseNetBIOS_OK(t *testing.T) {
	pkt := buildNBSTATResponse("WESTY-PC", "WORKGROUP", nbSuffixHost)
	res, err := parseNetBIOS(pkt)
	if err != nil {
		t.Fatalf("parseNetBIOS 返回错误: %v", err)
	}
	if res.Service != "netbios" {
		t.Errorf("service = %q, 期望 netbios", res.Service)
	}
	if res.Confidence != model.ConfidenceHigh {
		t.Errorf("confidence = %q, 期望 high", res.Confidence)
	}
	wantMeta := map[string]string{
		"netbios.hostname":   "WESTY-PC",
		"netbios.workgroup":  "WORKGROUP",
		"netbios.query_name": "*",
		"netbios.answers":    "1",
	}
	for k, v := range wantMeta {
		if got := res.Meta[k]; got != v {
			t.Errorf("meta %s = %q, 期望 %q", k, got, v)
		}
	}
	if res.Product != "NetBIOS Name Service" {
		t.Errorf("Product = %q", res.Product)
	}
	if !strings.Contains(res.Banner, "WESTY-PC") || !strings.Contains(res.Banner, "WORKGROUP") {
		t.Errorf("banner = %q", res.Banner)
	}
	if !hasEvidence(res.Evidence, "udp:netbios-nbstat-response") {
		t.Errorf("缺少判据: %v", res.Evidence)
	}
}

func TestParseNetBIOS_DomainController(t *testing.T) {
	// 域控场景：第 0 个名字后缀 0x1c（域），随后是主机名（0x00）与工作组（0x1e）。
	pkt := buildNBSTATResponseWithNames([]nbName{
		{Name: "CORP", Suffix: nbSuffixDC, Flags: nbFlagGroupName},
		{Name: "DC01", Suffix: nbSuffixHost},
		{Name: "WORKGROUP", Suffix: nbSuffixGroup, Flags: nbFlagGroupName},
	})
	res, err := parseNetBIOS(pkt)
	if err != nil {
		t.Fatalf("parseNetBIOS 返回错误: %v", err)
	}
	if got := res.Meta["netbios.domain"]; got != "CORP" {
		t.Errorf("meta netbios.domain = %q, 期望 CORP", got)
	}
	if got := res.Meta["netbios.hostname"]; got != "DC01" {
		t.Errorf("meta netbios.hostname = %q, 期望 DC01", got)
	}
	if got := res.Meta["netbios.workgroup"]; got != "WORKGROUP" {
		t.Errorf("meta netbios.workgroup = %q, 期望 WORKGROUP", got)
	}
}

func TestParseNetBIOS_NoAnswers(t *testing.T) {
	pkt := buildNBSTATResponse("WESTY-PC", "", nbSuffixHost)
	binary.BigEndian.PutUint16(pkt[6:8], 0) // ANCOUNT = 0
	res, err := parseNetBIOS(pkt)
	if err != nil {
		t.Fatalf("ANCOUNT=0 应视为收到响应而命中，实际错误: %v", err)
	}
	if res.Confidence != model.ConfidenceMedium {
		t.Errorf("ANCOUNT=0 置信度应为 medium，实际 %q", res.Confidence)
	}
	if !hasEvidence(res.Evidence, "udp:netbios-no-answers") {
		t.Errorf("Evidence = %v", res.Evidence)
	}
}

func TestParseNetBIOS_Malformed(t *testing.T) {
	valid := buildNBSTATResponse("WESTY-PC", "WORKGROUP", nbSuffixHost)
	cases := []struct {
		name string
		pkt  []byte
	}{
		{"空报文", []byte{}},
		{"短于头部", []byte{0x12, 0x34, 0x84, 0x00}},
		{"答案段被截断", valid[:len(valid)-10]},
		{"非法名字长度", append(append([]byte{}, valid[:12]...), 0x40, 0x00, 0x00)},
		{"名字表条目数与长度不符", func() []byte {
			// 计数声明 3 条，但只放 1 条真实条目 —— 解析器必须报错而不是越界读
			full := buildNBSTATNamesTable(nbSuffixHost, "WESTY-PC", "")
			one := append([]byte{3}, full[1:1+nbNameLen+2]...)
			return buildNBSTATPacket(one)
		}()},
		{"答案类型非法", func() []byte {
			p := append([]byte{}, valid...)
			binary.BigEndian.PutUint16(p[59:61], 0x0001) // 改成 A 记录类型
			return p
		}()},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			assertNoPanic(t, c.name, func() {
				res, err := parseNetBIOS(c.pkt)
				if err == nil {
					t.Fatalf("期望返回 error，实际 res=%+v", res)
				}
			})
		})
	}
}

// ---------------------------------------------------------------------------
// 端到端测试：本地假 UDP 服务端 + Scan
// ---------------------------------------------------------------------------

func TestScan_DNS_EndToEnd(t *testing.T) {
	// 这两个值由假服务端的 handler **在另一个协程里**写入、由测试协程读取。
	// 必须用 atomic：裸变量之间没有同步边，是一个真实的 data race
	// （本地快机器上常常侥幸不触发，CI 上跑 -race 就会红 —— 这正是 CI 抓出来的问题）。
	var gotQueryType, gotQueryClass atomic.Uint32
	srv := startFakeServer(t, func(req []byte) []byte {
		if len(req) < dnsHeaderLen+5 {
			t.Errorf("DNS 请求过短: %d 字节", len(req))
			return nil
		}
		if req[4] != 0x00 || req[5] != 0x01 {
			t.Errorf("QDCOUNT = %d, 期望 1", binary.BigEndian.Uint16(req[4:6]))
		}
		if flags := binary.BigEndian.Uint16(req[2:4]); flags != dnsFlagRD {
			t.Errorf("Flags = 0x%04x, 期望 0x%04x（RD=1，其余为 0）", flags, dnsFlagRD)
		}
		gotQueryType.Store(uint32(binary.BigEndian.Uint16(req[len(req)-4 : len(req)-2])))
		gotQueryClass.Store(uint32(binary.BigEndian.Uint16(req[len(req)-2:])))
		if req[12] != 0x00 {
			t.Errorf("QNAME 首字节 = 0x%02x, 期望 0x00（根域）", req[12])
		}
		return buildDNSResponse(binary.BigEndian.Uint16(req[0:2]), 0, "a.root-servers.net")
	})
	withProbePorts(t, map[int]int{53: srv.port})

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	ch := Scan(ctx, testScope(t), []string{"127.0.0.1"}, []int{53}, Options{
		Timeout: 2 * time.Second, Concurrency: 2,
	})
	assets := collectAssets(t, ch)
	if len(assets) != 1 {
		t.Fatalf("资产数 = %d, 期望 1 (%+v)", len(assets), assets)
	}
	a := assets[0]
	if a.Service != "dns" || a.Source != "udpscan" || a.Port != srv.port {
		t.Errorf("资产字段不符: service=%q source=%q port=%d(期望 %d)", a.Service, a.Source, a.Port, srv.port)
	}
	if a.Host != "127.0.0.1" || a.IP != "127.0.0.1" {
		t.Errorf("Host/IP = %q/%q, 期望 127.0.0.1/127.0.0.1", a.Host, a.IP)
	}
	if a.MetaValue("probe") != "dns" || a.MetaValue("transport") != "udp" {
		t.Errorf("meta probe/transport 不符: %v", a.Meta)
	}
	if a.MetaValue("confidence") != model.ConfidenceHigh {
		t.Errorf("confidence = %q, 期望 high", a.MetaValue("confidence"))
	}
	if !strings.Contains(a.MetaValue("confidence_reason"), "符合") {
		t.Errorf("confidence_reason = %q", a.MetaValue("confidence_reason"))
	}
	if a.MetaValue("dns.ns") != "a.root-servers.net" {
		t.Errorf("meta dns.ns = %q", a.MetaValue("dns.ns"))
	}
	if !hasEvidence(a.Evidence, "udp:dns-rcode=0") {
		t.Errorf("Evidence = %v", a.Evidence)
	}
	if !strings.Contains(a.Banner, "NOERROR") {
		t.Errorf("Banner = %q", a.Banner)
	}
	if a.FoundAt.IsZero() {
		t.Errorf("FoundAt 未填充")
	}
	if qt, qc := gotQueryType.Load(), gotQueryClass.Load(); qt != dnsTypeNS || qc != dnsClassIN {
		t.Errorf("QTYPE/QCLASS = %d/%d, 期望 %d/%d", qt, qc, dnsTypeNS, dnsClassIN)
	}
}

func TestScan_NTP_EndToEnd(t *testing.T) {
	srv := startFakeServer(t, func(req []byte) []byte {
		if len(req) != ntpPacketLen {
			t.Errorf("NTP 请求长度 = %d, 期望 %d", len(req), ntpPacketLen)
		}
		if req[0] != 0x23 {
			t.Errorf("NTP 首字节 = 0x%02x, 期望 0x23(LI=0,VN=4,Mode=3)", req[0])
		}
		for i := 1; i < len(req); i++ {
			if req[i] != 0 {
				t.Errorf("NTP 请求第 %d 字节非 0: 0x%02x", i, req[i])
			}
		}
		// stratum=2 时参考 ID 是上游服务器 IPv4 地址
		return buildNTPResponse(2, "\xc0\xa8\x01\x01", 0xEE000000)
	})
	withProbePorts(t, map[int]int{123: srv.port})

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	ch := Scan(ctx, testScope(t), []string{"127.0.0.1"}, []int{123}, Options{
		Timeout: 2 * time.Second, Concurrency: 2,
	})
	assets := collectAssets(t, ch)
	if len(assets) != 1 {
		t.Fatalf("资产数 = %d, 期望 1 (%+v)", len(assets), assets)
	}
	a := assets[0]
	if a.Service != "ntp" || a.Source != "udpscan" || a.Port != srv.port {
		t.Errorf("资产字段不符: service=%q source=%q port=%d", a.Service, a.Source, a.Port)
	}
	if got := a.MetaValue("ntp.stratum"); got != "2" {
		t.Errorf("meta ntp.stratum = %q, 期望 2", got)
	}
	if got := a.MetaValue("ntp.ref_id"); got != "192.168.1.1" {
		t.Errorf("meta ntp.ref_id = %q, 期望 192.168.1.1", got)
	}
	if got := a.MetaValue("confidence"); got != model.ConfidenceHigh {
		t.Errorf("confidence = %q, 期望 high", got)
	}
	if !strings.Contains(a.Banner, "stratum=2") {
		t.Errorf("Banner = %q", a.Banner)
	}
	if !hasEvidence(a.Evidence, "udp:ntp-server-response") {
		t.Errorf("Evidence = %v", a.Evidence)
	}
}

func TestScan_SNMP_EndToEnd(t *testing.T) {
	descr := "Linux router 5.10.0 SMP"
	srv := startFakeServer(t, func(req []byte) []byte {
		assertWellFormedBER(t, req)
		if !strings.Contains(string(req), string(sysDescrOID)) {
			t.Errorf("SNMP 请求缺少 sysDescr OID: % x", req)
		}
		return buildSNMPResponse([]byte(descr), 0, 0)
	})
	withProbePorts(t, map[int]int{161: srv.port})

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	ch := Scan(ctx, testScope(t), []string{"127.0.0.1"}, []int{161}, Options{Timeout: 2 * time.Second})
	assets := collectAssets(t, ch)
	if len(assets) != 1 {
		t.Fatalf("资产数 = %d, 期望 1", len(assets))
	}
	a := assets[0]
	if a.Service != "snmp" || a.Port != srv.port {
		t.Errorf("service=%q port=%d", a.Service, a.Port)
	}
	if a.MetaValue("snmp.sys_descr") != descr {
		t.Errorf("meta snmp.sys_descr = %q", a.MetaValue("snmp.sys_descr"))
	}
	if a.Product != "Linux" || a.Version != "router 5.10.0 SMP" {
		t.Errorf("Product/Version = %q/%q, 期望 Linux/router 5.10.0 SMP", a.Product, a.Version)
	}
}

func TestScan_NetBIOS_EndToEnd(t *testing.T) {
	srv := startFakeServer(t, func(req []byte) []byte {
		if len(req) < 12 || req[12] != 0x20 {
			t.Errorf("NBSTAT 查询格式不符: % x", req)
		}
		return buildNBSTATResponse("WESTY-PC", "WORKGROUP", nbSuffixHost)
	})
	withProbePorts(t, map[int]int{137: srv.port})

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	ch := Scan(ctx, testScope(t), []string{"127.0.0.1"}, []int{137}, Options{Timeout: 2 * time.Second})
	assets := collectAssets(t, ch)
	if len(assets) != 1 {
		t.Fatalf("资产数 = %d, 期望 1", len(assets))
	}
	a := assets[0]
	if a.Service != "netbios" {
		t.Errorf("service = %q", a.Service)
	}
	if a.MetaValue("netbios.hostname") != "WESTY-PC" || a.MetaValue("netbios.workgroup") != "WORKGROUP" {
		t.Errorf("meta = %v", a.Meta)
	}
	if a.Product != "NetBIOS Name Service" {
		t.Errorf("Product = %q", a.Product)
	}
}

// TestScan_AllProbesOneHost 一次扫描覆盖全部 4 个探针，确认互不干扰。
func TestScan_AllProbesOneHost(t *testing.T) {
	dnsSrv := startFakeServer(t, func(req []byte) []byte {
		return buildDNSResponse(binary.BigEndian.Uint16(req[0:2]), 5) // REFUSED 也算命中
	})
	ntpSrv := startFakeServer(t, func(req []byte) []byte { return buildNTPKiss("DENY") })
	snmpSrv := startFakeServer(t, func(req []byte) []byte { return buildSNMPResponse(nil, 2, 1) })
	nbSrv := startFakeServer(t, func(req []byte) []byte {
		return buildNBSTATResponse("DC01", "CORP", nbSuffixHost)
	})
	withProbePorts(t, map[int]int{
		53:  dnsSrv.port,
		123: ntpSrv.port,
		137: nbSrv.port,
		161: snmpSrv.port,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	ch := Scan(ctx, testScope(t), []string{"127.0.0.1"},
		[]int{53, 123, 137, 161, 53, 9999}, Options{Timeout: 2 * time.Second, Concurrency: 4})

	services := map[string]model.Asset{}
	for _, a := range collectAssets(t, ch) {
		services[a.Service] = a
	}
	if len(services) != 4 {
		t.Fatalf("服务数 = %d, 期望 4 (%v)", len(services), services)
	}
	cases := []struct {
		service string
		port    int
		conf    string
		evi     string
	}{
		{"dns", dnsSrv.port, model.ConfidenceHigh, "udp:dns-refused"},
		{"ntp", ntpSrv.port, model.ConfidenceHigh, "udp:ntp-kiss-o-death"},
		{"snmp", snmpSrv.port, model.ConfidenceMedium, "udp:snmp-noSuchName"},
		{"netbios", nbSrv.port, model.ConfidenceHigh, "udp:netbios-nbstat-response"},
	}
	for _, c := range cases {
		a, ok := services[c.service]
		if !ok {
			t.Errorf("缺少 %s 资产", c.service)
			continue
		}
		if a.Port != c.port {
			t.Errorf("%s 端口 = %d, 期望 %d", c.service, a.Port, c.port)
		}
		if a.MetaValue("confidence") != c.conf {
			t.Errorf("%s confidence = %q, 期望 %q", c.service, a.MetaValue("confidence"), c.conf)
		}
		if !hasEvidence(a.Evidence, c.evi) {
			t.Errorf("%s Evidence = %v, 期望含 %s", c.service, a.Evidence, c.evi)
		}
		if a.MetaValue("probe") != c.service || a.Source != SourceName {
			t.Errorf("%s meta probe/Source 不符: %q/%q", c.service, a.MetaValue("probe"), a.Source)
		}
	}
}

// TestScan_UnsupportedPortsIgnored 确认没有探针的端口不会产生任何发包/资产。
func TestScan_UnsupportedPortsIgnored(t *testing.T) {
	called := make(chan struct{}, 4)
	srv := startFakeServer(t, func(req []byte) []byte {
		select {
		case called <- struct{}{}:
		default:
		}
		return nil
	})
	// 只映射 137，其它端口不该被改写，也不该被扫描。
	withProbePorts(t, map[int]int{137: srv.port})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ch := Scan(ctx, testScope(t), []string{"127.0.0.1"}, []int{9999, 53 + 100000, -1, 0, 65536}, Options{
		Timeout: 200 * time.Millisecond,
	})
	if assets := collectAssets(t, ch); len(assets) != 0 {
		t.Errorf("不支持端口不应产生资产: %+v", assets)
	}
	select {
	case <-called:
		t.Errorf("端口不在探针表内，不应发包")
	case <-time.After(300 * time.Millisecond):
	}
}

// TestScan_NoResponse 确认"没响应"不产出资产
// （UDP 无连接：超时既可能是 filtered 也可能是 open|filtered）。
func TestScan_NoResponse(t *testing.T) {
	srv := startFakeServer(t, func(req []byte) []byte { return nil }) // 只收不回
	withProbePorts(t, map[int]int{53: srv.port})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ch := Scan(ctx, testScope(t), []string{"127.0.0.1"}, []int{53}, Options{Timeout: 200 * time.Millisecond})
	if assets := collectAssets(t, ch); len(assets) != 0 {
		t.Errorf("无响应不应产出资产: %+v", assets)
	}
}

// TestScan_GarbledResponseIsMedium 确认"有响应但内容不符"仍算命中但降级。
// 样本是一个结构合法但 QR=0（看起来像查询而不是应答）的 DNS 报文。
func TestScan_GarbledResponseIsMedium(t *testing.T) {
	foreign := append([]byte{}, buildDNSHeader(0x4242, 0, 1, 0, 0, 0)...)
	foreign[2] &^= 0x80 // 清掉 QR 位：结构合法但不是应答
	foreign = append(foreign, 0x00, 0x00, byte(dnsTypeNS), 0x00, byte(dnsClassIN))

	srv := startFakeServer(t, func(req []byte) []byte { return foreign })
	withProbePorts(t, map[int]int{53: srv.port})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ch := Scan(ctx, testScope(t), []string{"127.0.0.1"}, []int{53}, Options{Timeout: time.Second})
	assets := collectAssets(t, ch)
	if len(assets) != 1 {
		t.Fatalf("有响应应记为命中，实际资产数 = %d", len(assets))
	}
	a := assets[0]
	if a.MetaValue("confidence") != model.ConfidenceMedium {
		t.Errorf("内容不符时置信度应为 medium，实际 %q", a.MetaValue("confidence"))
	}
	if !strings.Contains(a.MetaValue("confidence_reason"), "不符合") {
		t.Errorf("confidence_reason = %q", a.MetaValue("confidence_reason"))
	}
	if !hasEvidence(a.Evidence, "udp:dns-response-without-qr") {
		t.Errorf("Evidence = %v", a.Evidence)
	}
	if a.MetaValue("dns.qr") != "false" {
		t.Errorf("meta dns.qr = %q, 期望 false", a.MetaValue("dns.qr"))
	}
}

// TestScan_TooShortResponseIgnored 确认短到无法解析的响应不上报（避免噪声）。
func TestScan_TooShortResponseIgnored(t *testing.T) {
	srv := startFakeServer(t, func(req []byte) []byte { return []byte{0x00} })
	withProbePorts(t, map[int]int{53: srv.port})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ch := Scan(ctx, testScope(t), []string{"127.0.0.1"}, []int{53}, Options{Timeout: time.Second})
	if assets := collectAssets(t, ch); len(assets) != 0 {
		t.Errorf("畸形短响应不应产出资产: %+v", assets)
	}
}

// TestScan_AssetHostIsHostname 确认 Asset.Host 记录主机名（而非解析后的 IP）。
func TestScan_AssetHostIsHostname(t *testing.T) {
	srv := startFakeServer(t, func(req []byte) []byte {
		return buildDNSResponse(binary.BigEndian.Uint16(req[0:2]), 0, "a.root-servers.net")
	})
	withProbePorts(t, map[int]int{53: srv.port})

	sc := testScope(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	host, ip, err := sc.Guard(ctx, "localhost")
	if err != nil {
		t.Fatalf("Guard(localhost) 失败: %v", err)
	}
	res, err := probeDNS(ctx, udpNetwork(ip, srv.port), net.JoinHostPort(ip, strconv.Itoa(srv.port)), 2*time.Second)
	if err != nil || res == nil {
		t.Fatalf("probeDNS 失败: res=%v err=%v", res, err)
	}
	a, ok := finalize(ctx, job{host: host, ip: ip, port: srv.port}, srv.port, probeTable[53], res)
	if !ok {
		t.Fatalf("finalize 返回 false")
	}
	if a.Host != "localhost" {
		t.Errorf("Host = %q, 期望 localhost（主机名）", a.Host)
	}
	if a.IP != ip || net.ParseIP(a.IP) == nil {
		t.Errorf("IP = %q, 期望 Guard 解析出的 %q", a.IP, ip)
	}
}

// TestScan_ScopeDenied 确认授权范围外的目标被拦截（含 IP 字面量与 deny 优先）并回调 OnError。
func TestScan_ScopeDenied(t *testing.T) {
	// 192.0.2.0/24 是 RFC 5737 的测试网段，允许后也不会真的打到别人的资产上。
	sc, err := scope.New([]string{"192.0.2.0/24"}, nil, 16, true, true)
	if err != nil {
		t.Fatalf("构造 Scope 失败: %v", err)
	}
	var mu sync.Mutex
	var targets []string
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	ch := Scan(ctx, sc, []string{"127.0.0.1", "192.0.2.1"}, []int{53}, Options{
		Timeout: 200 * time.Millisecond,
		OnError: func(target string, err error) {
			mu.Lock()
			defer mu.Unlock()
			targets = append(targets, target)
		},
	})
	if assets := collectAssets(t, ch); len(assets) != 0 {
		t.Errorf("被拦截/无响应的目标不应产出资产: %+v", assets)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(targets) != 1 || targets[0] != "127.0.0.1" {
		t.Errorf("OnError 目标 = %v, 期望 [127.0.0.1]（192.0.2.1 在 allow 内，只是没响应）", targets)
	}

	// 追加校验：deny 优先于 allow，且错误信息带"授权范围"。
	var denied error
	sc2, err := scope.New([]string{"10.0.0.0/8"}, []string{"10.0.0.0/16"}, 16, true, true)
	if err != nil {
		t.Fatalf("构造 Scope 失败: %v", err)
	}
	ch2 := Scan(ctx, sc2, []string{"10.0.1.1"}, []int{53}, Options{
		Timeout: 100 * time.Millisecond,
		OnError: func(target string, err error) { denied = err },
	})
	collectAssets(t, ch2)
	if denied == nil || !strings.Contains(denied.Error(), "授权范围") {
		t.Errorf("deny 规则未生效: %v", denied)
	}
}

// TestScan_ContextCancelClosesChannel 确认 ctx 取消后 channel 会收敛关闭。
func TestScan_ContextCancelClosesChannel(t *testing.T) {
	srv := startFakeServer(t, func(req []byte) []byte { return nil }) // 不回包，让探测卡在 read
	withProbePorts(t, map[int]int{53: srv.port, 123: srv.port, 137: srv.port, 161: srv.port})

	ctx, cancel := context.WithCancel(context.Background())
	ch := Scan(ctx, testScope(t), []string{"127.0.0.1"}, []int{53, 123, 137, 161}, Options{
		Timeout: 30 * time.Second, Concurrency: 4,
	})
	time.Sleep(150 * time.Millisecond) // 让 worker 进入阻塞
	cancel()

	deadline := time.After(5 * time.Second)
	for {
		select {
		case _, ok := <-ch:
			if !ok {
				return // 已关闭，符合预期
			}
		case <-deadline:
			t.Fatalf("ctx 取消后 channel 未关闭")
		}
	}
}

// TestScan_ConcurrencyBound 用本地服务端测得的并发峰值验证 worker pool 上限。
//
// 注意：本机只接受发往 127.0.0.1 的 UDP（127.0.0.2 之类的回环地址不会真正送达），
// 所以这里用"1 个主机 × 4 个端口"制造 4 个作业，而不是多个回环 IP。
func TestScan_ConcurrencyBound(t *testing.T) {
	const limit = 2
	release := make(chan struct{})
	var inFlight, peak int32
	var once sync.Once
	srv := startFakeServer(t, func(req []byte) []byte {
		cur := atomic.AddInt32(&inFlight, 1)
		for {
			old := atomic.LoadInt32(&peak)
			if cur <= old || atomic.CompareAndSwapInt32(&peak, old, cur) {
				break
			}
		}
		if cur >= limit {
			once.Do(func() { close(release) })
		}
		select {
		case <-release:
		case <-time.After(3 * time.Second): // 兜底，避免死等
		}
		atomic.AddInt32(&inFlight, -1)
		return buildDNSResponse(binary.BigEndian.Uint16(req[0:2]), 0, "a.root-servers.net")
	})
	ports := []int{53, 123, 137, 161}
	withProbePorts(t, map[int]int{53: srv.port, 123: srv.port, 137: srv.port, 161: srv.port})

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	ch := Scan(ctx, testScope(t), []string{"127.0.0.1"}, ports, Options{
		Timeout: 2 * time.Second, Concurrency: limit,
	})
	assets := collectAssets(t, ch)

	// peak 由 handler 协程用 atomic 累加，读取也必须走 atomic ——
	// 直接读一个被其它协程原子修改的变量仍然是 data race（-race 会抓）。
	if got := atomic.LoadInt32(&peak); got > limit {
		t.Errorf("并发峰值 = %d, 超过 worker pool 上限 %d", got, limit)
	} else if got != limit {
		t.Errorf("并发峰值 = %d, 期望 %d（4 个作业 + 2 个 worker 必定吃满）", got, limit)
	}
	// 这个用例测的是 worker pool 的并发度，不是协议识别率：
	// 4 个作业共用同一个假服务端，而它只会回 DNS 应答，
	// 因此只有 DNS 探针能解析成功 —— 资产数只要求"非零"。
	if len(assets) == 0 {
		t.Errorf("资产数 = 0，DNS 探针应当能从该响应中得出结论")
	}
}

// TestScan_NilScopeOrEmptyInput 确认边界输入不会 panic，且 channel 立即关闭。
func TestScan_NilScopeOrEmptyInput(t *testing.T) {
	ctx := context.Background()
	if ch := Scan(ctx, nil, []string{"127.0.0.1"}, []int{53}, Options{}); ch == nil {
		t.Fatalf("Scan 不应返回 nil channel")
	} else if _, ok := <-ch; ok {
		t.Errorf("nil scope 应立即关闭 channel")
	}
	if _, ok := <-Scan(ctx, testScope(t), nil, nil, Options{}); ok {
		t.Errorf("空输入应立即关闭 channel")
	}
	if _, ok := <-Scan(ctx, testScope(t), []string{"127.0.0.1"}, nil, Options{}); ok {
		t.Errorf("空端口应立即关闭 channel")
	}
}

// ---------------------------------------------------------------------------
// 元数据与工具函数测试
// ---------------------------------------------------------------------------

func TestSupportedPorts(t *testing.T) {
	ports := SupportedPorts()
	want := []int{53, 123, 137, 161}
	if !reflect.DeepEqual(ports, want) {
		t.Fatalf("SupportedPorts() = %v, 期望 %v（升序、去重）", ports, want)
	}
	// 调用方修改返回值不能污染内部状态。
	ports[0] = 9999
	if again := SupportedPorts(); !reflect.DeepEqual(again, want) {
		t.Errorf("SupportedPorts() 第二次 = %v, 期望 %v", again, want)
	}
}

func TestFilterSupportedPorts(t *testing.T) {
	got := filterSupportedPorts([]int{53, 53, 123, 9999, 0, -5, 70000, 161, 137})
	want := []int{53, 123, 161, 137}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("filterSupportedPorts = %v, 期望 %v（去重、丢弃不支持/非法端口、保持顺序）", got, want)
	}
	if got := filterSupportedPorts(nil); len(got) != 0 {
		t.Errorf("nil 输入应返回空: %v", got)
	}
}

func TestSanitizeText(t *testing.T) {
	in := "Cisco IOS\r\n\tSoftware\x00 \x01 with   spaces"
	got := sanitizeText(in, 128)
	if strings.ContainsAny(got, "\r\n\t\x00\x01") {
		t.Errorf("sanitizeText 未清理控制字符: %q", got)
	}
	if !strings.Contains(got, "Cisco IOS Software with spaces") {
		t.Errorf("sanitizeText = %q", got)
	}
	if got := sanitizeText(strings.Repeat("a", 100), 10); len(got) != 10 {
		t.Errorf("sanitizeText 截断失败: %q", got)
	}
	if got := sanitizeText("keep", 0); got != "keep" {
		t.Errorf("max<=0 表示不截断，实际 %q", got)
	}
}

func TestFormatNTPRefID(t *testing.T) {
	cases := []struct {
		in      uint32
		stratum int
		want    string
	}{
		// stratum 0/1：4 字节 ASCII 码
		{0x47505300, 0, "GPS"},
		{0x52415445, 0, "RATE"},
		{0x4c4f434c, 1, "LOCL"},
		// stratum >= 2：上游服务器 IPv4
		{0xc0a80101, 2, "192.168.1.1"},
		{0x47505300, 2, "71.80.83.0"},
	}
	for _, c := range cases {
		if got := formatNTPRefID(c.in, c.stratum); got != c.want {
			t.Errorf("formatNTPRefID(0x%08x, stratum=%d) = %q, 期望 %q", c.in, c.stratum, got, c.want)
		}
	}
}

func TestNTPTimeString(t *testing.T) {
	if got := ntpTimeString(0); got != "" {
		t.Errorf("0 时间戳应返回空串，实际 %q", got)
	}
	// 0xE8FE6F80 = 3908988800（自 1900-01-01 起的秒）→ Unix 1700000000 = 2023-11-14T22:13:20Z
	if got := ntpTimeString(0xE8FE6F80); got != "2023-11-14T22:13:20Z" {
		t.Errorf("ntpTimeString = %q, 期望 2023-11-14T22:13:20Z", got)
	}
	// 秒字段是完整的 32 位；小数位于同一条目的后 4 字节，不参与本函数换算
	if got := ntpTimeString(0xE8FE6F81); got != "2023-11-14T22:13:21Z" {
		t.Errorf("相邻秒 = %q, 期望 2023-11-14T22:13:21Z", got)
	}
	// 秒字段明显过小（早于 1970）应判定为无效
	if got := ntpTimeString(1000); got != "" {
		t.Errorf("过小的秒字段应返回空串，实际 %q", got)
	}
}

func TestJoinNames(t *testing.T) {
	if got := joinNames([]string{"a.com", " ", "b.com", "a.com"}); got != "a.com,b.com" {
		t.Errorf("joinNames = %q, 期望 a.com,b.com", got)
	}
	many := make([]string, 0, 20)
	for i := 0; i < 20; i++ {
		many = append(many, "ns"+strconv.Itoa(i)+".example.com")
	}
	if n := len(strings.Split(joinNames(many), ",")); n != 8 {
		t.Errorf("joinNames 上限应为 8，实际 %d", n)
	}
}

func TestBerRoundTrip(t *testing.T) {
	// 长度 >= 128 时必须走长形式编码。
	long := make([]byte, 300)
	for i := range long {
		long[i] = byte(i)
	}
	tlv := berTLV(asn1OctetStr, long)
	if tlv[1] != 0x82 {
		t.Fatalf("长形式长度标签 = 0x%02x, 期望 0x82", tlv[1])
	}
	tag, val, next, err := berReadTLV(tlv, 0)
	if err != nil {
		t.Fatalf("berReadTLV 返回错误: %v", err)
	}
	if tag != asn1OctetStr || len(val) != len(long) || next != len(tlv) {
		t.Errorf("往返失败: tag=0x%02x len=%d next=%d", tag, len(val), next)
	}
	if _, _, _, err := berReadTLV(tlv[:5], 0); err == nil {
		t.Errorf("截断的长形式长度应返回 error")
	}
	if _, _, _, err := berReadTLV([]byte{0x30, 0x80, 0x00, 0x00}, 0); err == nil {
		t.Errorf("不定长编码应返回 error")
	}
	if _, _, _, err := berReadTLV(nil, 0); err == nil {
		t.Errorf("空输入应返回 error")
	}
}

func TestRandomUint16Range(t *testing.T) {
	seen := map[uint16]bool{}
	for i := 0; i < 64; i++ {
		seen[randomUint16()] = true
	}
	if len(seen) < 2 {
		t.Errorf("randomUint16 似乎没有随机性: %v", seen)
	}
}

// ---------------------------------------------------------------------------
// 辅助断言
// ---------------------------------------------------------------------------

// assertWellFormedBER 用一个独立的极简 BER 遍历交叉校验样本本身合法，
// 避免测试与实现共享同一套错误假设。
func assertWellFormedBER(t *testing.T, b []byte) {
	t.Helper()
	off := 0
	for off < len(b) {
		if off+2 > len(b) {
			t.Fatalf("测试样本 BER 头被截断: % x", b)
		}
		length := int(b[off+1])
		off += 2
		if off+length > len(b) {
			t.Fatalf("测试样本 BER 长度越界: % x", b)
		}
		off += length
	}
	if off != len(b) {
		t.Fatalf("测试样本 BER 尾部残留 %d 字节: % x", len(b)-off, b)
	}
}
