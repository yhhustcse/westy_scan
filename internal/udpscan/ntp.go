package udpscan

import (
	"bytes"
	"context"
	"fmt"
	"time"

	"westy_scan/internal/model"
)

// NTP 报文长度（RFC 5905）：头部 48 字节，可带扩展字段。
const ntpPacketLen = 48

// NTP 时间戳纪元是 1900-01-01，Unix 纪元是 1970-01-01，相差 2208988800 秒。
const ntpEpochOffset = 2208988800

// probeNTP 发送 NTPv4 客户端模式包并解析响应。
func probeNTP(ctx context.Context, network, addr string, timeout time.Duration) (*parseResult, error) {
	resp, err := exchange(ctx, network, addr, buildNTPRequest(), timeout)
	if err != nil || len(resp) == 0 {
		return nil, err
	}
	return parseNTP(resp)
}

// buildNTPRequest 构造 48 字节 NTPv4 客户端请求：
// 首字节 LI=0(2bit) | VN=4(3bit) | Mode=3(3bit) = 0x23，其余全 0。
func buildNTPRequest() []byte {
	b := make([]byte, ntpPacketLen)
	b[0] = 0x23 // LI=0, VN=4, Mode=3（客户端）
	return b
}

// ntpResp 是解析后的 NTP 响应关键字段。
type ntpResp struct {
	Leap           int
	Version        int
	Mode           int
	Stratum        int
	Poll           int
	Precision      int
	RootDelay      uint32
	RootDispersion uint32
	RefID          uint32
	RefTime        uint32
	OrigTime       uint32
	RecvTime       uint32
	TxTime         uint32
}

// parseNTP 解析 NTP 响应。至少需要完整头部，否则返回 error。
func parseNTP(pkt []byte) (*parseResult, error) {
	if len(pkt) < ntpPacketLen {
		return nil, fmt.Errorf("ntp: 响应过短 %d 字节（头部需 %d 字节）", len(pkt), ntpPacketLen)
	}
	b := pkt[:ntpPacketLen]

	r := ntpResp{
		Leap:           int(b[0] >> 6),
		Version:        int(b[0]>>3) & 0x07,
		Mode:           int(b[0]) & 0x07,
		Stratum:        int(b[1]),
		Poll:           int(int8(b[2])),
		Precision:      int(int8(b[3])),
		RootDelay:      be32(b[4:8]),
		RootDispersion: be32(b[8:12]),
		RefID:          be32(b[12:16]),
		RefTime:        be32(b[16:20]),
		OrigTime:       be32(b[24:28]),
		RecvTime:       be32(b[32:36]),
		TxTime:         be32(b[40:44]),
	}

	refID := formatNTPRefID(r.RefID, r.Stratum)
	modeText := ntpModeText(r.Mode)
	leapText := ntpLeapText(r.Leap)

	meta := map[string]string{
		"ntp.leap":            fmt.Sprintf("%d(%s)", r.Leap, leapText),
		"ntp.version":         fmt.Sprint(r.Version),
		"ntp.mode":            fmt.Sprintf("%d(%s)", r.Mode, modeText),
		"ntp.stratum":         fmt.Sprint(r.Stratum),
		"ntp.poll":            fmt.Sprint(r.Poll),
		"ntp.precision":       fmt.Sprint(r.Precision),
		"ntp.root_delay":      fmt.Sprintf("%.3fs", float64(r.RootDelay)/65536.0),
		"ntp.root_dispersion": fmt.Sprintf("%.3fs", float64(r.RootDispersion)/65536.0),
		"ntp.ref_id":          refID,
	}
	if ts := ntpTimeString(r.TxTime); ts != "" {
		meta["ntp.tx_time"] = ts
	}
	if ts := ntpTimeString(r.RefTime); ts != "" {
		meta["ntp.ref_time"] = ts
	}
	if r.Stratum == 0 {
		// stratum=0 是未同步/特殊包，参考 ID 才有意义（kiss-o'-death 时是 4 字符代码）。
		meta["ntp.kiss_code"] = refID
	}

	evidence := []string{
		fmt.Sprintf("udp:ntp-mode=%d", r.Mode),
		fmt.Sprintf("udp:ntp-stratum=%d", r.Stratum),
	}
	res := &parseResult{
		Service: "ntp",
		Banner: fmt.Sprintf("NTP v%d %s stratum=%d leap=%s refid=%s poll=%d",
			r.Version, modeText, r.Stratum, leapText, refID, r.Poll),
		Meta: meta,
	}

	switch {
	case r.Mode == 4 && r.Stratum == 0:
		// kiss-o'-death：服务器明确要求客户端退避，仍然是活的 NTP 服务。
		res.Evidence = append(evidence, "udp:ntp-kiss-o-death")
		res.Confidence = model.ConfidenceHigh
	case r.Mode == 4 && r.Stratum >= 1 && r.Stratum <= 15:
		res.Exact = true
		res.Evidence = append(evidence, "udp:ntp-server-response")
		res.Confidence = model.ConfidenceHigh
	case r.Mode == 5:
		// 广播模式同样说明对端在跑 NTP。
		res.Evidence = append(evidence, "udp:ntp-broadcast")
		res.Confidence = model.ConfidenceHigh
	case r.Stratum > 15:
		// 16 表示未同步（RFC 5905），17-255 保留：能回这种包的多半是 NTP 实现或仿冒服务。
		res.Evidence = append(evidence, fmt.Sprintf("udp:ntp-unsynchronized-stratum=%d", r.Stratum))
		res.Confidence = model.ConfidenceMedium
	default:
		res.Evidence = append(evidence, fmt.Sprintf("udp:ntp-atypical-mode=%d", r.Mode))
		res.Confidence = model.ConfidenceMedium
	}
	return res, nil
}

// formatNTPRefID 按 stratum 解释参考 ID（RFC 5905 §7.3）：
//
//   - stratum 0/1：refid 是 4 字节 ASCII 码，如 "GPS\0"、"GOES"、"DENY"、"RATE"；
//   - stratum >= 2：refid 是上游服务器的 IPv4 地址。
//
// 所以这里必须按 stratum 分支，否则会把 "GPS\0" 打成 71.80.83.0。
func formatNTPRefID(v uint32, stratum int) string {
	b := []byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)}
	if stratum <= 1 {
		return string(bytes.TrimRight(b, "\x00"))
	}
	return fmt.Sprintf("%d.%d.%d.%d", b[0], b[1], b[2], b[3])
}

// ntpTimeString 把 NTP 时间戳的**秒字段**（32 位，自 1900-01-01 起）转成 RFC3339。
//
// NTP 的 64 位时间戳 = 32 位秒 + 32 位小数，报文里四个时间戳各占 8 字节；
// 本函数只接收其中的秒部分（小数部分在紧随其后的 4 字节里，本模块不参与格式化），
// 因此这里不做任何位拆分 —— 把低 16 位当小数是一个常见但错误的做法。
func ntpTimeString(v uint32) string {
	if v == 0 {
		return ""
	}
	secs := int64(v) - ntpEpochOffset
	if secs <= 0 {
		return ""
	}
	t := time.Unix(secs, 0).UTC()
	if t.Year() < 1970 || t.Year() > 2200 {
		return ""
	}
	return t.Format(time.RFC3339)
}

// ntpModeText 返回 NTP 模式的可读名称。
func ntpModeText(mode int) string {
	switch mode {
	case 1:
		return "symmetric-active"
	case 2:
		return "symmetric-passive"
	case 3:
		return "client"
	case 4:
		return "server"
	case 5:
		return "broadcast"
	case 6:
		return "control"
	case 7:
		return "private"
	default:
		return "reserved"
	}
}

// ntpLeapText 返回闰秒指示的可读名称。
func ntpLeapText(leap int) string {
	switch leap {
	case 1:
		return "last-minute-61s"
	case 2:
		return "last-minute-59s"
	case 3:
		return "unsynchronized"
	default:
		return "no-warning"
	}
}
