package portscan

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
)

// 本文件是 SYN 扫描的"数据包层"：构包、校验和、拆包。
// 刻意与 socket 层分离，这样在任何平台上都能做单元测试（见 syn_packet_test.go）。

const (
	tcpFlagFIN = 0x01
	tcpFlagSYN = 0x02
	tcpFlagRST = 0x04
	tcpFlagPSH = 0x08
	tcpFlagACK = 0x10
	tcpFlagURG = 0x20

	ipProtoTCP = 6
)

// tcpResponse 是从原始报文里解析出的 TCP 响应摘要。
type tcpResponse struct {
	SrcIP   net.IP
	DstIP   net.IP
	SrcPort uint16
	DstPort uint16
	Seq     uint32
	Ack     uint32
	Flags   uint8
}

// IsSYNACK 表示目标端口开放（SYN+ACK）。
func (r tcpResponse) IsSYNACK() bool {
	return r.Flags&tcpFlagSYN != 0 && r.Flags&tcpFlagACK != 0
}

// IsRST 表示目标端口关闭（RST，可能带 ACK）。
func (r tcpResponse) IsRST() bool {
	return r.Flags&tcpFlagRST != 0
}

// buildSYNPacket 构造 IPv4 + TCP SYN 报文（含 IP 头与 TCP 头校验和）。
func buildSYNPacket(srcIP, dstIP net.IP, srcPort, dstPort uint16, seq uint32) ([]byte, error) {
	src4 := srcIP.To4()
	dst4 := dstIP.To4()
	if src4 == nil || dst4 == nil {
		return nil, errors.New("SYN 扫描目前只支持 IPv4")
	}

	pkt := make([]byte, 40)
	// ---- IPv4 头（20 字节）----
	pkt[0] = 0x45 // version 4, IHL 5
	pkt[1] = 0x00 // DSCP/ECN
	binary.BigEndian.PutUint16(pkt[2:4], uint16(len(pkt)))
	binary.BigEndian.PutUint16(pkt[4:6], uint16(srcPort)) // 用源端口充当 IP ID，便于回包匹配
	binary.BigEndian.PutUint16(pkt[6:8], 0x4000)          // DF
	pkt[8] = 64                                           // TTL
	pkt[9] = ipProtoTCP
	copy(pkt[12:16], src4)
	copy(pkt[16:20], dst4)
	binary.BigEndian.PutUint16(pkt[10:12], checksum(pkt[0:20]))

	// ---- TCP 头（20 字节）----
	tcp := pkt[20:]
	binary.BigEndian.PutUint16(tcp[0:2], srcPort)
	binary.BigEndian.PutUint16(tcp[2:4], dstPort)
	binary.BigEndian.PutUint32(tcp[4:8], seq)
	binary.BigEndian.PutUint32(tcp[8:12], 0) // ack = 0
	tcp[12] = 0x50                           // data offset 5
	tcp[13] = tcpFlagSYN
	binary.BigEndian.PutUint16(tcp[14:16], 64240) // window
	binary.BigEndian.PutUint16(tcp[16:18], 0)     // 校验和占位
	binary.BigEndian.PutUint16(tcp[18:20], 0)     // urgent

	binary.BigEndian.PutUint16(tcp[16:18], tcpChecksum(src4, dst4, tcp))
	return pkt, nil
}

// parseIPv4TCP 解析原始 IPv4 报文中的 TCP 头；非 TCP / 非 IPv4 / 截断都返回错误。
func parseIPv4TCP(pkt []byte) (*tcpResponse, error) {
	if len(pkt) < 20 {
		return nil, errors.New("报文长度不足 20 字节")
	}
	if pkt[0]>>4 != 4 {
		return nil, errors.New("不是 IPv4 报文")
	}
	ihl := int(pkt[0]&0x0F) * 4
	if ihl < 20 || len(pkt) < ihl+20 {
		return nil, errors.New("IP 头长度非法或报文被截断")
	}
	if pkt[9] != ipProtoTCP {
		return nil, fmt.Errorf("不是 TCP 报文（protocol=%d）", pkt[9])
	}
	totalLen := int(binary.BigEndian.Uint16(pkt[2:4]))
	frag := binary.BigEndian.Uint16(pkt[6:8])
	if frag&0x1FFF != 0 {
		return nil, errors.New("分片报文，暂不支持")
	}
	if totalLen > 0 && totalLen <= len(pkt) {
		pkt = pkt[:totalLen]
	}

	tcp := pkt[ihl:]
	dataOffset := int(tcp[12]>>4) * 4
	if dataOffset < 20 || len(tcp) < dataOffset {
		return nil, errors.New("TCP 头长度非法")
	}
	return &tcpResponse{
		SrcIP:   net.IPv4(pkt[12], pkt[13], pkt[14], pkt[15]),
		DstIP:   net.IPv4(pkt[16], pkt[17], pkt[18], pkt[19]),
		SrcPort: binary.BigEndian.Uint16(tcp[0:2]),
		DstPort: binary.BigEndian.Uint16(tcp[2:4]),
		Seq:     binary.BigEndian.Uint32(tcp[4:8]),
		Ack:     binary.BigEndian.Uint32(tcp[8:12]),
		Flags:   tcp[13],
	}, nil
}

// checksum 计算 16 位反码和（用于 IP 头）。
func checksum(data []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(data); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(data[i : i+2]))
	}
	if len(data)%2 == 1 {
		sum += uint32(data[len(data)-1]) << 8
	}
	return foldChecksum(sum)
}

// tcpChecksum 计算 TCP 校验和（含 IPv4 伪头）。
func tcpChecksum(src, dst net.IP, tcp []byte) uint16 {
	pseudo := make([]byte, 0, 12+len(tcp))
	pseudo = append(pseudo, src.To4()...)
	pseudo = append(pseudo, dst.To4()...)
	pseudo = append(pseudo, 0x00, ipProtoTCP)
	length := make([]byte, 2)
	binary.BigEndian.PutUint16(length, uint16(len(tcp)))
	pseudo = append(pseudo, length...)
	pseudo = append(pseudo, tcp...)
	return checksum(pseudo)
}

func foldChecksum(sum uint32) uint16 {
	for sum>>16 != 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	return ^uint16(sum)
}
