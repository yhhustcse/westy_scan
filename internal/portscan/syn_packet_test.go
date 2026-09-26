package portscan

import (
	"encoding/binary"
	"net"
	"testing"
)

func TestBuildSYNPacket(t *testing.T) {
	pkt, err := buildSYNPacket(net.ParseIP("10.0.0.5"), net.ParseIP("10.0.0.9"), 40000, 445, 12345)
	if err != nil {
		t.Fatalf("构包失败: %v", err)
	}
	if len(pkt) != 40 {
		t.Fatalf("报文长度应为 40，实际 %d", len(pkt))
	}
	if pkt[0] != 0x45 {
		t.Errorf("IP 版本/IHL 错误: 0x%02X", pkt[0])
	}
	if pkt[9] != ipProtoTCP {
		t.Errorf("协议号应为 6，实际 %d", pkt[9])
	}
	if got := binary.BigEndian.Uint16(pkt[2:4]); got != 40 {
		t.Errorf("IP 总长度字段错误: %d", got)
	}
	if got := net.IP(pkt[12:16]).String(); got != "10.0.0.5" {
		t.Errorf("源 IP 错误: %s", got)
	}
	if got := net.IP(pkt[16:20]).String(); got != "10.0.0.9" {
		t.Errorf("目的 IP 错误: %s", got)
	}

	tcp := pkt[20:]
	if got := binary.BigEndian.Uint16(tcp[0:2]); got != 40000 {
		t.Errorf("源端口错误: %d", got)
	}
	if got := binary.BigEndian.Uint16(tcp[2:4]); got != 445 {
		t.Errorf("目的端口错误: %d", got)
	}
	if got := binary.BigEndian.Uint32(tcp[4:8]); got != 12345 {
		t.Errorf("seq 错误: %d", got)
	}
	if tcp[13] != tcpFlagSYN {
		t.Errorf("标志位应为 SYN，实际 0x%02X", tcp[13])
	}

	// 校验和自检：把头一起算进去，结果应为 0（IP 头）
	if got := checksum(pkt[0:20]); got != 0 {
		t.Errorf("IP 头校验和错误: 0x%04X", got)
	}
	// TCP 校验和自检：把校验和字段置 0 重算应得到同值
	orig := binary.BigEndian.Uint16(tcp[16:18])
	tcp[16], tcp[17] = 0, 0
	if got := tcpChecksum(pkt[12:16], pkt[16:20], tcp); got != orig {
		t.Errorf("TCP 校验和不一致: 0x%04X != 0x%04X", got, orig)
	}
}

func TestBuildSYNPacketRejectsIPv6(t *testing.T) {
	if _, err := buildSYNPacket(net.ParseIP("2001:db8::1"), net.ParseIP("2001:db8::2"), 1, 2, 3); err == nil {
		t.Fatal("IPv6 应被拒绝（当前 SYN 扫描只支持 IPv4）")
	}
}

func TestParseIPv4TCP(t *testing.T) {
	// 构造一个 SYN+ACK 回包
	pkt, err := buildSYNPacket(net.ParseIP("10.0.0.9"), net.ParseIP("10.0.0.5"), 445, 40000, 999)
	if err != nil {
		t.Fatalf("构包失败: %v", err)
	}
	pkt[20+13] = tcpFlagSYN | tcpFlagACK
	binary.BigEndian.PutUint32(pkt[20+8:20+12], 12346) // ack = seq+1
	binary.BigEndian.PutUint16(pkt[20+16:20+18], 0)
	binary.BigEndian.PutUint16(pkt[20+16:20+18], tcpChecksum(pkt[12:16], pkt[16:20], pkt[20:]))

	r, err := parseIPv4TCP(pkt)
	if err != nil {
		t.Fatalf("拆包失败: %v", err)
	}
	if !r.IsSYNACK() || r.IsRST() {
		t.Errorf("应识别为 SYN+ACK: %+v", r)
	}
	if r.SrcPort != 445 || r.DstPort != 40000 {
		t.Errorf("端口解析错误: %+v", r)
	}
	if r.SrcIP.String() != "10.0.0.9" || r.DstIP.String() != "10.0.0.5" {
		t.Errorf("IP 解析错误: %+v", r)
	}
	if r.Ack != 12346 {
		t.Errorf("ack 解析错误: %d", r.Ack)
	}

	// RST 回包表示端口关闭
	pkt[20+13] = tcpFlagRST | tcpFlagACK
	r2, err := parseIPv4TCP(pkt)
	if err != nil {
		t.Fatalf("拆包失败: %v", err)
	}
	if !r2.IsRST() || r2.IsSYNACK() {
		t.Errorf("应识别为 RST: %+v", r2)
	}
}

func TestParseIPv4TCPRejectsGarbage(t *testing.T) {
	cases := [][]byte{
		nil,
		{},
		make([]byte, 10),
		make([]byte, 40), // 全零：version=0 不是 IPv4
		append([]byte{0x60}, make([]byte, 39)...), // IPv6
	}
	for i, c := range cases {
		if _, err := parseIPv4TCP(c); err == nil {
			t.Errorf("第 %d 个畸形报文应报错", i)
		}
	}

	// 合法 IPv4 头但协议不是 TCP
	notTCP := make([]byte, 40)
	notTCP[0] = 0x45
	notTCP[9] = 17 // UDP
	if _, err := parseIPv4TCP(notTCP); err == nil {
		t.Error("非 TCP 协议应报错")
	}

	// IP 头 IHL 声明超过实际长度
	truncated := make([]byte, 30)
	truncated[0] = 0x4F // IHL=15 -> 60 字节
	truncated[9] = ipProtoTCP
	if _, err := parseIPv4TCP(truncated); err == nil {
		t.Error("截断报文应报错")
	}
}
