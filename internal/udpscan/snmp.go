package udpscan

import (
	"context"
	"fmt"
	"strings"
	"time"

	"westy_scan/internal/model"
)

// BER/DER 标签（SNMP 只用其中一小部分子集）。
const (
	asn1Integer    = 0x02
	asn1OctetStr   = 0x04
	asn1Null       = 0x05
	asn1ObjectID   = 0x06
	asn1Sequence   = 0x30
	asn1GetRequest = 0xa0
)

// sysDescrOID 是 1.3.6.1.2.1.1.1.0（SNMPv2-MIB::sysDescr.0）。
var sysDescrOID = []byte{0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00}

// snmpErrorStatusText 是 PDU error-status 的可读文本（RFC 3416）。
var snmpErrorStatusText = map[int]string{
	0:  "noError",
	1:  "tooBig",
	2:  "noSuchName",
	3:  "badValue",
	4:  "readOnly",
	5:  "genErr",
	6:  "noAccess",
	7:  "wrongType",
	8:  "wrongLength",
	9:  "wrongEncoding",
	10: "wrongValue",
	11: "noCreation",
	12: "inconsistentValue",
	13: "resourceUnavailable",
	14: "commitFailed",
	15: "undoFailed",
	16: "authorizationError",
	17: "notWritable",
	18: "inconsistentName",
}

// probeSNMP 发送 SNMPv2c GetRequest 读取 sysDescr，并解析响应。
func probeSNMP(ctx context.Context, network, addr string, timeout time.Duration) (*parseResult, error) {
	resp, err := exchange(ctx, network, addr, buildSNMPGetRequest(), timeout)
	if err != nil || len(resp) == 0 {
		return nil, err
	}
	return parseSNMP(resp)
}

// buildSNMPGetRequest 手工构造 SNMPv2c GetRequest：
//
//	SEQUENCE {
//	  INTEGER version=1 (v2c)
//	  OCTET STRING community="public"
//	  [0] GetRequest {
//	    INTEGER request-id
//	    INTEGER error-status=0
//	    INTEGER error-index=0
//	    SEQUENCE { SEQUENCE { OID 1.3.6.1.2.1.1.1.0, NULL } }
//	  }
//	}
func buildSNMPGetRequest() []byte {
	varbind := berTLV(asn1Sequence, append(berTLV(asn1ObjectID, sysDescrOID), berTLV(asn1Null, nil)...))
	varbindList := berTLV(asn1Sequence, varbind)

	var pduBody []byte
	pduBody = append(pduBody, berTLV(asn1Integer, berUint(uint64(randomUint16())))...)
	pduBody = append(pduBody, berTLV(asn1Integer, berUint(0))...) // error-status
	pduBody = append(pduBody, berTLV(asn1Integer, berUint(0))...) // error-index
	pduBody = append(pduBody, varbindList...)
	pdu := berTLV(asn1GetRequest, pduBody)

	var body []byte
	body = append(body, berTLV(asn1Integer, berUint(1))...)        // version = v2c
	body = append(body, berTLV(asn1OctetStr, []byte("public"))...) // community
	body = append(body, pdu...)
	return berTLV(asn1Sequence, body)
}

// snmpResp 是解析后的 SNMP 响应关键字段。
type snmpResp struct {
	Version     int
	Community   string
	RequestID   int
	ErrorStatus int
	ErrorIndex  int
	SysDescr    string
	HasVarbind  bool
}

// parseSNMP 解析 SNMP 响应，提取 sysDescr。
//
// 关键兼容点：sysDescr 的 value 是 NULL 时说明返回了错误状态
// （noSuchName / authorizationError 等），但这依然是 SNMP 服务的强证据，
// 所以照样产出资产，只把置信度降到 medium。
func parseSNMP(pkt []byte) (*parseResult, error) {
	r, err := decodeSNMP(pkt)
	if err != nil {
		return nil, err
	}

	errText, ok := snmpErrorStatusText[r.ErrorStatus]
	if !ok {
		errText = fmt.Sprintf("errorStatus(%d)", r.ErrorStatus)
	}
	evidence := []string{fmt.Sprintf("udp:snmp-error-status=%d", r.ErrorStatus)}
	meta := map[string]string{
		"snmp.community":    r.Community,
		"snmp.version":      snmpVersionText(r.Version),
		"snmp.request_id":   fmt.Sprint(r.RequestID),
		"snmp.error_status": fmt.Sprintf("%d(%s)", r.ErrorStatus, errText),
		"snmp.error_index":  fmt.Sprint(r.ErrorIndex),
	}
	sysDescr := sanitizeText(r.SysDescr, 512)
	if sysDescr != "" {
		meta["snmp.sys_descr"] = sysDescr
	}

	res := &parseResult{
		Service: "snmp",
		Meta:    meta,
	}
	if sysDescr != "" {
		res.Banner = "SNMP sysDescr: " + sysDescr
		res.Product, res.Version = snmpFingerprint(sysDescr)
	} else {
		res.Banner = fmt.Sprintf("SNMP %s error-status=%s", snmpVersionText(r.Version), errText)
	}

	switch {
	case r.ErrorStatus == 0 && sysDescr != "":
		res.Exact = true
		res.Evidence = append(evidence, "udp:snmp-sysdescr")
		res.Confidence = model.ConfidenceHigh
	case r.ErrorStatus == 2: // noSuchName
		res.Evidence = append(evidence, "udp:snmp-noSuchName")
		res.Confidence = model.ConfidenceMedium
	case r.ErrorStatus == 16: // authorizationError
		res.Evidence = append(evidence, "udp:snmp-authorizationError")
		res.Confidence = model.ConfidenceMedium
	case r.ErrorStatus == 6: // noAccess
		res.Evidence = append(evidence, "udp:snmp-noAccess")
		res.Confidence = model.ConfidenceMedium
	default:
		res.Evidence = append(evidence, "udp:snmp-error-status")
		res.Confidence = model.ConfidenceMedium
	}
	return res, nil
}

// snmpFingerprint 从 sysDescr 里做保守的产品/版本提取。
// 只在模式明确命中时返回结果，避免把整段描述硬塞进 Product 造成误报。
func snmpFingerprint(sysDescr string) (product, version string) {
	s := strings.TrimSpace(sysDescr)
	lower := strings.ToLower(s)
	switch {
	case strings.HasPrefix(s, "Cisco IOS Software"):
		return "Cisco IOS", extractVersionToken(s, "Version ")
	case strings.HasPrefix(s, "Cisco NX-OS"):
		return "Cisco NX-OS", extractVersionToken(s, "version ")
	case strings.HasPrefix(s, "Cisco Internetwork Operating System"):
		return "Cisco IOS", ""
	case strings.HasPrefix(s, "Linux "):
		return "Linux", strings.TrimSpace(strings.TrimPrefix(s, "Linux "))
	case strings.HasPrefix(s, "Microsoft Windows"):
		return "Windows", extractVersionToken(s, "Version ")
	case strings.HasPrefix(s, "Hardware: ") && strings.Contains(s, "Windows"):
		// 微软 SNMP 扩展代理的另一类格式，仅标记产品。
		return "Windows", ""
	case strings.HasPrefix(s, "FreeBSD "):
		return "FreeBSD", extractVersionToken(s, "FreeBSD ")
	case strings.HasPrefix(s, "SunOS "):
		return "SunOS", extractVersionToken(s, "SunOS ")
	case strings.HasPrefix(s, "MikroTik"):
		return "RouterOS", extractVersionToken(s, "RouterOS ")
	case strings.HasPrefix(s, "Juniper"):
		return "Junos", extractVersionToken(s, "JUNOS ")
	case strings.Contains(lower, "pfsense"):
		return "pfSense", ""
	case strings.Contains(lower, "apache"):
		return "Apache HTTPD", extractVersionToken(s, "Apache/")
	case strings.Contains(lower, "nginx"):
		return "nginx", extractVersionToken(s, "nginx/")
	case strings.Contains(lower, "snmpv2"):
		return "SNMP Agent", ""
	default:
		return "", ""
	}
}

// extractVersionToken 从 s 中取 marker 之后的连续版本样式 token。
// 只接受数字、字母与 . _ +，遇到 '-'（如 13.2-RELEASE）或空格即停止，
// 避免把描述性后缀当成版本号。
func extractVersionToken(s, marker string) string {
	i := strings.Index(strings.ToLower(s), strings.ToLower(marker))
	if i < 0 {
		return ""
	}
	rest := strings.TrimSpace(s[i+len(marker):])
	end := 0
	for end < len(rest) {
		c := rest[end]
		if (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
			c == '.' || c == '_' || c == '+' {
			end++
			continue
		}
		break
	}
	return rest[:end]
}

// decodeSNMP 逐层拆解 BER 结构。
func decodeSNMP(pkt []byte) (snmpResp, error) {
	var r snmpResp
	topTag, seq, _, err := berReadTLV(pkt, 0)
	if err != nil {
		return r, fmt.Errorf("snmp: 顶层 SEQUENCE 解析失败: %w", err)
	}
	if topTag != asn1Sequence {
		return r, fmt.Errorf("snmp: 顶层标签非法 0x%02x（期望 SEQUENCE）", topTag)
	}
	off := 0
	body := seq

	// version
	tag, val, next, err := berReadTLV(body, off)
	if err != nil {
		return r, fmt.Errorf("snmp: version 解析失败: %w", err)
	}
	if tag != asn1Integer {
		return r, fmt.Errorf("snmp: version 标签非法 0x%02x", tag)
	}
	r.Version = berInt(val)
	off = next

	// community
	tag, val, next, err = berReadTLV(body, off)
	if err != nil {
		return r, fmt.Errorf("snmp: community 解析失败: %w", err)
	}
	if tag != asn1OctetStr {
		return r, fmt.Errorf("snmp: community 标签非法 0x%02x", tag)
	}
	r.Community = string(val)
	off = next

	// PDU
	tag, val, _, err = berReadTLV(body, off)
	if err != nil {
		return r, fmt.Errorf("snmp: PDU 解析失败: %w", err)
	}
	if !isSNMPPDUTag(tag) {
		return r, fmt.Errorf("snmp: PDU 标签非法 0x%02x", tag)
	}
	pdu := val
	p := 0
	if r.RequestID, p, err = berReadInt(pdu, p); err != nil {
		return r, fmt.Errorf("snmp: request-id 解析失败: %w", err)
	}
	if r.ErrorStatus, p, err = berReadInt(pdu, p); err != nil {
		return r, fmt.Errorf("snmp: error-status 解析失败: %w", err)
	}
	if r.ErrorIndex, p, err = berReadInt(pdu, p); err != nil {
		return r, fmt.Errorf("snmp: error-index 解析失败: %w", err)
	}

	// 没有 varbind 列表：错误响应（noSuchName/authorizationError 等）常见形态。
	if p >= len(pdu) {
		return r, nil
	}
	vblTag, vbl, _, err := berReadTLV(pdu, p)
	if err != nil {
		return r, fmt.Errorf("snmp: varbind-list 解析失败: %w", err)
	}
	if vblTag != asn1Sequence {
		return r, fmt.Errorf("snmp: varbind-list 标签非法 0x%02x", vblTag)
	}
	// varbind-list 为空：同上，属于合法的错误响应。
	if len(vbl) == 0 {
		return r, nil
	}
	vbTag, vb, _, err := berReadTLV(vbl, 0)
	if err != nil {
		return r, fmt.Errorf("snmp: varbind 解析失败: %w", err)
	}
	if vbTag != asn1Sequence {
		return r, fmt.Errorf("snmp: varbind 标签非法 0x%02x", vbTag)
	}
	oidTag, _, vnext, err := berReadTLV(vb, 0)
	if err != nil {
		return r, fmt.Errorf("snmp: varbind OID 解析失败: %w", err)
	}
	if oidTag != asn1ObjectID {
		return r, fmt.Errorf("snmp: varbind OID 标签非法 0x%02x", oidTag)
	}
	if vnext >= len(vb) {
		return r, nil
	}
	valTag, vval, _, err := berReadTLV(vb, vnext)
	if err != nil {
		return r, fmt.Errorf("snmp: varbind value 解析失败: %w", err)
	}
	r.HasVarbind = true
	switch valTag {
	case asn1OctetStr:
		r.SysDescr = string(vval)
	case asn1Null:
		// 值缺失：多半是 error-status != 0，保留错误信息即可
	default:
		// 非 OCTET STRING 的值（如 Counter/OID）：记录不作为 sysDescr
	}
	return r, nil
}

// berReadInt 读取一个 BER INTEGER 并返回其整数值与新偏移。
func berReadInt(b []byte, off int) (int, int, error) {
	tag, val, next, err := berReadTLV(b, off)
	if err != nil {
		return 0, off, err
	}
	if tag != asn1Integer {
		return 0, off, fmt.Errorf("期望 INTEGER，实际标签 0x%02x", tag)
	}
	return berInt(val), next, nil
}

// berReadTLV 读取一个 TLV，返回 tag、value 切片与下一个 TLV 的偏移。
//
// 支持多字节长度（0x81/0x82/0x83/0x84）；所有长度都会做越界检查，
// 保证调用方拿到的 value 一定落在输入切片内。
func berReadTLV(b []byte, off int) (tag byte, value []byte, next int, err error) {
	if off < 0 || off >= len(b) {
		return 0, nil, 0, fmt.Errorf("BER: 偏移 %d 越界 (len=%d)", off, len(b))
	}
	tag = b[off]
	off++
	if off >= len(b) {
		return 0, nil, 0, fmt.Errorf("BER: 标签 0x%02x 后缺少长度字段", tag)
	}
	first := b[off]
	off++
	var length int
	switch {
	case first < 0x80:
		length = int(first)
	case first == 0x80:
		return 0, nil, 0, fmt.Errorf("BER: 不支持不定长编码 (0x80)")
	default:
		n := int(first & 0x7f)
		if n > 4 {
			return 0, nil, 0, fmt.Errorf("BER: 长度字段过长 (%d 字节)", n)
		}
		if off+n > len(b) {
			return 0, nil, 0, fmt.Errorf("BER: 长度字段被截断")
		}
		for i := 0; i < n; i++ {
			length = length<<8 | int(b[off+i])
		}
		off += n
	}
	if length < 0 || off+length > len(b) {
		return 0, nil, 0, fmt.Errorf("BER: 值长度 %d 越界 (剩余 %d)", length, len(b)-off)
	}
	return tag, b[off : off+length], off + length, nil
}

// berInt 把 BER INTEGER 的值字节转成 int（大端、二进制补码，负数返回 0）。
func berInt(val []byte) int {
	if len(val) == 0 {
		return 0
	}
	n := 0
	for _, c := range val {
		n = n<<8 | int(c)
	}
	return n
}

// berTLV 编码一个 TLV。长度 >= 128 时使用长形式。
func berTLV(tag byte, value []byte) []byte {
	out := make([]byte, 0, len(value)+4)
	out = append(out, tag)
	out = append(out, berLength(len(value))...)
	return append(out, value...)
}

// berLength 编码 BER 长度字段。
func berLength(n int) []byte {
	if n < 0x80 {
		return []byte{byte(n)}
	}
	var tmp [4]byte
	i := len(tmp)
	for n > 0 {
		i--
		tmp[i] = byte(n & 0xff)
		n >>= 8
	}
	out := make([]byte, 0, 1+len(tmp)-i)
	out = append(out, 0x80|byte(len(tmp)-i))
	return append(out, tmp[i:]...)
}

// berUint 把非负整数编码成 BER INTEGER 值字节（最小长度，正数补 0x00 防歧义）。
func berUint(n uint64) []byte {
	if n == 0 {
		return []byte{0x00}
	}
	var tmp [8]byte
	i := len(tmp)
	for n > 0 {
		i--
		tmp[i] = byte(n & 0xff)
		n >>= 8
	}
	out := tmp[i:]
	if out[0]&0x80 != 0 {
		out = append([]byte{0x00}, out...)
	}
	return out
}

func isSNMPPDUTag(tag byte) bool {
	switch tag {
	case 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8:
		return true
	default:
		return false
	}
}

func snmpVersionText(v int) string {
	switch v {
	case 0:
		return "v1"
	case 1:
		return "v2c"
	case 3:
		return "v3"
	default:
		return fmt.Sprintf("v%d", v)
	}
}
