package probe

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"westy_scan/internal/model"
)

// errNotThisProtocol 表示"连上了，但响应对不上这个协议"。
var errNotThisProtocol = errors.New("响应不符合该协议特征")

// registry 是全部内置探针，顺序即尝试顺序（越靠前越常见）。
var registry = []Probe{
	sshProbe, ftpProbe, smtpProbe, mysqlProbe, postgresProbe, redisProbe,
	memcachedProbe, vncProbe, smbProbe, rdpProbe, mongoProbe,
}

var tlsPorts = []int{443, 465, 636, 990, 993, 995, 5986, 8443, 9443}

func isTLSPort(port int) bool {
	for _, p := range tlsPorts {
		if p == port {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// SSH / FTP / SMTP —— 服务端先说话的文本协议，可直接复用端口扫描抓到的 Banner
// ---------------------------------------------------------------------------

var sshProbe = Probe{
	Name:  "ssh",
	Ports: []int{22, 222, 2222, 22022},
	Run: func(ctx context.Context, cn *Conn, host string, port int) (*Result, error) {
		data, err := cn.ReadLine()
		if err != nil {
			return nil, err
		}
		if r := parseSSH(string(data)); r != nil {
			return r, nil
		}
		return nil, errNotThisProtocol
	},
}

var reSSH = regexp.MustCompile(`(?m)^SSH-([0-9.]+)-([^\s\r\n]+)(?:\s+(.*))?$`)

func parseSSH(text string) *Result {
	m := reSSH.FindStringSubmatch(text)
	if m == nil {
		return nil
	}
	proto, software := m[1], m[2]
	comment := ""
	if len(m) > 3 {
		comment = strings.TrimSpace(m[3])
	}
	product, version := splitProductVersion(software)
	extra := map[string]string{"ssh_protocol": proto}
	if comment != "" {
		extra["ssh_comment"] = comment
	}
	return &Result{
		Service:    "ssh",
		Product:    product,
		Version:    version,
		Confidence: model.ConfidenceHigh,
		Evidence:   "ssh-banner:" + software,
		Extra:      extra,
		Banner:     "SSH " + software + " " + comment,
	}
}

var ftpProbe = Probe{
	Name:  "ftp",
	Ports: []int{21, 2121, 8021},
	Run: func(ctx context.Context, cn *Conn, host string, port int) (*Result, error) {
		data, err := cn.ReadLine()
		if err != nil {
			return nil, err
		}
		if r := parseFTP(string(data)); r != nil {
			return r, nil
		}
		return nil, errNotThisProtocol
	},
}

var reFTPProduct = regexp.MustCompile(`(?i)(vsftpd|proftpd|pure-ftpd|filezilla|serv-u|microsoft ftp service|wu-ftpd|glftpd|pyftpdlib)[\s/_-]*([0-9][0-9a-z.\-_]*)?`)

func parseFTP(text string) *Result {
	t := cleanText(text)
	if !strings.HasPrefix(t, "220") {
		return nil
	}
	r := &Result{
		Service:    "ftp",
		Product:    "FTP",
		Confidence: model.ConfidenceMedium,
		Evidence:   "ftp-banner",
		Banner:     t,
		Extra:      map[string]string{},
	}
	if m := reFTPProduct.FindStringSubmatch(t); m != nil {
		r.Product = m[1]
		if len(m) > 2 {
			r.Version = strings.Trim(m[2], ".-_ ")
		}
		r.Evidence = "ftp-banner:" + r.Product
		if r.Version != "" {
			r.Evidence += "/" + r.Version
		}
	}
	if strings.HasPrefix(t, "220-") {
		r.Extra["ftp_multiline_banner"] = "true"
	}
	return r
}

var smtpProbe = Probe{
	Name:  "smtp",
	Ports: []int{25, 587, 2525, 465},
	Run: func(ctx context.Context, cn *Conn, host string, port int) (*Result, error) {
		data, err := cn.ReadLine()
		if err != nil {
			return nil, err
		}
		if r := parseSMTP(string(data)); r != nil {
			return r, nil
		}
		return nil, errNotThisProtocol
	},
}

var reSMTPProduct = regexp.MustCompile(`(?i)(postfix|exim|sendmail|microsoft esmtp mail service|haraka|opensmtpd|qmail|mailenable|icewarp|hMailServer)[\s/_-]*([0-9][0-9a-z.\-_]*)?`)
var reSMTPHost = regexp.MustCompile(`^220[\s-]+([A-Za-z0-9._-]+)`)

func parseSMTP(text string) *Result {
	t := cleanText(text)
	if !strings.HasPrefix(t, "220") {
		return nil
	}
	r := &Result{
		Service:    "smtp",
		Product:    "SMTP",
		Confidence: model.ConfidenceMedium,
		Evidence:   "smtp-banner",
		Banner:     t,
		Extra:      map[string]string{},
	}
	if m := reSMTPHost.FindStringSubmatch(t); m != nil {
		r.Extra["smtp_helo_host"] = m[1]
	}
	if m := reSMTPProduct.FindStringSubmatch(t); m != nil {
		r.Product = m[1]
		if len(m) > 2 {
			r.Version = strings.Trim(m[2], ".-_ ")
		}
		r.Evidence = "smtp-banner:" + r.Product
	}
	return r
}

// ---------------------------------------------------------------------------
// MySQL / MariaDB —— 服务端先发握手包，版本与认证插件都在包里
// ---------------------------------------------------------------------------

var mysqlProbe = Probe{
	Name:  "mysql",
	Ports: []int{3306, 3307, 33060},
	Run: func(ctx context.Context, cn *Conn, host string, port int) (*Result, error) {
		// MySQL 握手包是定长的：先读 4 字节包头（3 字节长度 + 1 字节序号），
		// 再按声明长度读满整个 payload —— 单次 Read 可能拿到半个包。
		hdr, err := cn.ReadFull(4)
		if err != nil {
			return nil, err
		}
		plen := int(hdr[0]) | int(hdr[1])<<8 | int(hdr[2])<<16
		if plen <= 0 || plen > 8192 {
			return nil, errNotThisProtocol
		}
		payload, err := cn.ReadFull(plen)
		if err != nil {
			return nil, err
		}
		if r := parseMySQL(append(hdr, payload...)); r != nil {
			return r, nil
		}
		return nil, errNotThisProtocol
	},
}

func parseMySQL(data []byte) *Result {
	if len(data) < 5 {
		return nil
	}
	// 包长 3 字节(小端) + 序号 1 字节
	plen := int(data[0]) | int(data[1])<<8 | int(data[2])<<16
	payload := data[4:]
	if plen > 0 && plen < len(payload) {
		payload = payload[:plen]
	}
	if len(payload) == 0 {
		return nil
	}
	if payload[0] == 0xFF { // ERR 包
		msg := ""
		if len(payload) > 3 {
			msg = cleanText(string(payload[3:]))
		}
		return &Result{
			Service:    "mysql",
			Product:    "MySQL",
			Confidence: model.ConfidenceMedium,
			Evidence:   "mysql-err-packet",
			Banner:     "MySQL: " + msg,
		}
	}
	if payload[0] != 0x0A { // 协议版本 10
		return nil
	}
	rest := payload[1:]
	nul := bytes.IndexByte(rest, 0x00)
	if nul <= 0 {
		return nil
	}
	serverVersion := string(rest[:nul])
	p := nul + 1
	// thread_id(4) + auth_plugin_data_1(8) + filler(1) + cap_low(2) + charset(1) + status(2) + cap_high(2)
	if len(rest) < p+4+8+1+2+1+2+2 {
		return nil
	}
	p += 4 + 8 + 1
	capLow := binary.LittleEndian.Uint16(rest[p : p+2])
	p += 2 + 1 + 2
	capHigh := binary.LittleEndian.Uint16(rest[p : p+2])
	p += 2
	caps := uint32(capLow) | uint32(capHigh)<<16

	// auth_plugin_data_len(1) + reserved(10) + auth_plugin_data_part_2(≥13)
	authLen := 0
	if p < len(rest) {
		authLen = int(rest[p])
	}
	p++
	p += 10
	part2 := 13
	if authLen-8 > part2 {
		part2 = authLen - 8
	}
	if p+part2 <= len(rest) {
		p += part2
	}
	authPlugin := ""
	if caps&0x00080000 != 0 && p < len(rest) { // CLIENT_PLUGIN_AUTH
		if end := bytes.IndexByte(rest[p:], 0x00); end > 0 {
			authPlugin = string(rest[p : p+end])
		}
	}

	product, version := "MySQL", serverVersion
	if strings.Contains(strings.ToLower(serverVersion), "mariadb") {
		product = "MariaDB"
		version = extractMariaVersion(serverVersion)
	} else {
		version = leadingVersion(serverVersion)
	}

	extra := map[string]string{
		"mysql_server_version": serverVersion,
		"mysql_capabilities":   fmt.Sprintf("0x%08X", caps),
		"mysql_ssl":            boolText(caps&0x0800 != 0), // CLIENT_SSL
	}
	if authPlugin != "" {
		extra["mysql_auth_plugin"] = authPlugin
	}
	return &Result{
		Service:    "mysql",
		Product:    product,
		Version:    version,
		Confidence: model.ConfidenceHigh,
		Evidence:   "mysql-handshake:" + serverVersion,
		Extra:      extra,
		Banner:     product + " " + serverVersion,
	}
}

// ---------------------------------------------------------------------------
// PostgreSQL —— 用 SSLRequest 探测：应答 S/N/E 都是 PostgreSQL 的强特征
// ---------------------------------------------------------------------------

var postgresProbe = Probe{
	Name:  "postgres",
	Ports: []int{5432, 5433},
	Run: func(ctx context.Context, cn *Conn, host string, port int) (*Result, error) {
		if err := cn.Write(postgresSSLRequest()); err != nil {
			return nil, err
		}
		data, err := cn.ReadSome()
		if err != nil {
			return nil, err
		}
		if r := parsePostgres(data); r != nil {
			return r, nil
		}
		return nil, errNotThisProtocol
	},
}

func parsePostgres(data []byte) *Result {
	if len(data) == 0 {
		return nil
	}
	switch data[0] {
	case 'S':
		return &Result{
			Service: "postgres", Product: "PostgreSQL",
			Confidence: model.ConfidenceHigh, Evidence: "pg-sslrequest:S",
			Extra:  map[string]string{"pg_ssl": "supported"},
			Banner: "PostgreSQL (SSLRequest accepted)",
		}
	case 'N':
		return &Result{
			Service: "postgres", Product: "PostgreSQL",
			Confidence: model.ConfidenceHigh, Evidence: "pg-sslrequest:N",
			Extra:  map[string]string{"pg_ssl": "unsupported"},
			Banner: "PostgreSQL (SSL unsupported)",
		}
	case 'E':
		msg := parsePGError(data)
		extra := map[string]string{"pg_ssl": "error-response"}
		if msg != "" {
			extra["pg_error"] = msg
		}
		return &Result{
			Service: "postgres", Product: "PostgreSQL",
			Confidence: model.ConfidenceHigh, Evidence: "pg-errorresponse",
			Extra:  extra,
			Banner: "PostgreSQL: " + msg,
		}
	}
	return nil
}

// parsePGError 解析 ErrorResponse 的字段（type byte + cstring，直到 0x00 结束）。
func parsePGError(data []byte) string {
	if len(data) < 5 {
		return ""
	}
	p := 5 // 'E' + int32 长度
	var severity, message string
	for p < len(data) {
		fieldType := data[p]
		if fieldType == 0x00 {
			break
		}
		p++
		end := bytes.IndexByte(data[p:], 0x00)
		if end < 0 {
			break
		}
		val := string(data[p : p+end])
		p += end + 1
		switch fieldType {
		case 'S':
			severity = val
		case 'M':
			message = val
		}
	}
	return cleanText(strings.TrimSpace(severity + " " + message))
}

// ---------------------------------------------------------------------------
// Redis / Memcached —— 发一条只读命令取版本
// ---------------------------------------------------------------------------

var redisProbe = Probe{
	Name:  "redis",
	Ports: []int{6379, 6380, 16379},
	Run: func(ctx context.Context, cn *Conn, host string, port int) (*Result, error) {
		if err := cn.Write(redisInfoCommand()); err != nil {
			return nil, err
		}
		data, err := cn.ReadSome()
		if err != nil {
			return nil, err
		}
		if r := parseRedis(data); r != nil {
			return r, nil
		}
		return nil, errNotThisProtocol
	},
}

func parseRedis(data []byte) *Result {
	text := string(data)
	switch {
	case strings.HasPrefix(text, "-NOAUTH"):
		return &Result{
			Service: "redis", Product: "Redis", Confidence: model.ConfidenceHigh,
			Evidence: "redis-noauth", Banner: cleanText(text),
			Extra: map[string]string{"redis_auth_required": "true"},
		}
	case strings.HasPrefix(text, "-DENIED"):
		return &Result{
			Service: "redis", Product: "Redis", Confidence: model.ConfidenceHigh,
			Evidence: "redis-protected-mode", Banner: cleanText(text),
			Extra: map[string]string{"redis_protected_mode": "true"},
		}
	case strings.HasPrefix(text, "-ERR"), strings.HasPrefix(text, "-WRONGPASS"), strings.HasPrefix(text, "+PONG"):
		return &Result{
			Service: "redis", Product: "Redis", Confidence: model.ConfidenceMedium,
			Evidence: "redis-reply", Banner: cleanText(text),
		}
	}
	i := strings.Index(text, "redis_version:")
	if i < 0 {
		return nil
	}
	version := firstLineValue(text[i+len("redis_version:"):])
	extra := map[string]string{}
	if v := fieldAfter(text, "redis_mode:"); v != "" {
		extra["redis_mode"] = v
	}
	if v := fieldAfter(text, "os:"); v != "" {
		extra["redis_os"] = v
	}
	if v := fieldAfter(text, "tcp_port:"); v != "" {
		extra["redis_tcp_port"] = v
	}
	return &Result{
		Service: "redis", Product: "Redis", Version: version,
		Confidence: model.ConfidenceHigh, Evidence: "redis-info:redis_version=" + version,
		Extra: extra, Banner: "Redis " + version,
	}
}

var memcachedProbe = Probe{
	Name:  "memcached",
	Ports: []int{11211, 11212},
	Run: func(ctx context.Context, cn *Conn, host string, port int) (*Result, error) {
		if err := cn.Write(memcachedVersionCommand()); err != nil {
			return nil, err
		}
		data, err := cn.ReadSome()
		if err != nil {
			return nil, err
		}
		if r := parseMemcached(data); r != nil {
			return r, nil
		}
		return nil, errNotThisProtocol
	},
}

var reMemcachedVersion = regexp.MustCompile(`(?i)^VERSION\s+([0-9][0-9a-z.\-_]*)`)

func parseMemcached(data []byte) *Result {
	t := cleanText(string(data))
	if m := reMemcachedVersion.FindStringSubmatch(t); m != nil {
		return &Result{
			Service: "memcached", Product: "Memcached", Version: m[1],
			Confidence: model.ConfidenceHigh, Evidence: "memcached-version:" + m[1],
			Banner: "Memcached " + m[1],
		}
	}
	if strings.HasPrefix(t, "ERROR") || strings.HasPrefix(t, "CLIENT_ERROR") {
		return &Result{
			Service: "memcached", Product: "Memcached",
			Confidence: model.ConfidenceMedium, Evidence: "memcached-error", Banner: t,
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// VNC —— RFB 版本 + 安全类型（可以看出是否"无认证"）
// ---------------------------------------------------------------------------

var vncProbe = Probe{
	Name:  "vnc",
	Ports: []int{5900, 5901, 5902, 5903},
	Run: func(ctx context.Context, cn *Conn, host string, port int) (*Result, error) {
		// RFB 版本固定 12 字节
		data, err := cn.ReadFull(12)
		if err != nil {
			return nil, err
		}
		r := parseVNCServer(string(data))
		if r == nil {
			return nil, errNotThisProtocol
		}
		// 回送服务端给出的版本号（必须用线格式 "RFB 003.008\n"）
		wire := r.Extra["rfb_version_wire"]
		if wire == "" {
			return r, nil
		}
		if err := cn.Write([]byte("RFB " + wire + "\n")); err != nil {
			return r, nil
		}
		// 按 RFB 规范读安全类型：1 字节数量 + N 字节类型；
		// RFB 3.3 是 4 字节大端；数量为 0 表示握手失败，后跟原因字符串。
		first, err := cn.ReadFull(1)
		if err != nil {
			return r, nil
		}
		n := int(first[0])
		switch {
		case n == 0:
			rest, err := cn.ReadFull(4)
			if err != nil {
				return r, nil
			}
			l := int(int32(binary.BigEndian.Uint32(rest)))
			if l > 0 && l <= 512 {
				if reason, err := cn.ReadFull(l); err == nil {
					r.Extra["vnc_handshake_error"] = cleanText(string(reason))
				}
			}
			return r, nil
		case n > 20: // 3.3 时代的 4 字节安全类型
			rest, err := cn.ReadFull(3)
			if err != nil {
				return r, nil
			}
			parseVNCSecurity(append(first, rest...), r)
			return r, nil
		default:
			rest, err := cn.ReadFull(n)
			if err != nil {
				return r, nil
			}
			parseVNCSecurity(append(first, rest...), r)
			return r, nil
		}
	},
}

var reRFB = regexp.MustCompile(`^RFB ([0-9]{3})\.([0-9]{3})\n`)

func parseVNCServer(text string) *Result {
	m := reRFB.FindStringSubmatch(text)
	if m == nil {
		return nil
	}
	// 线格式是 "003.008"，对外展示归一化成 "3.8"；回送时必须用线格式
	major := strings.TrimLeft(m[1], "0")
	minor := strings.TrimLeft(m[2], "0")
	if major == "" {
		major = "0"
	}
	if minor == "" {
		minor = "0"
	}
	ver := major + "." + minor
	wire := m[1] + "." + m[2]
	return &Result{
		Service: "vnc", Product: "VNC", Version: ver,
		Confidence: model.ConfidenceHigh, Evidence: "vnc-banner:RFB " + wire,
		Extra:  map[string]string{"rfb_version": ver, "rfb_version_wire": wire},
		Banner: "VNC (RFB " + ver + ")",
	}
}

func parseVNCSecurity(data []byte, r *Result) {
	if len(data) == 0 {
		return
	}
	if r.Extra["rfb_version"] == "3.3" {
		if len(data) < 4 {
			return
		}
		t := binary.BigEndian.Uint32(data[0:4])
		r.Extra["vnc_security_types"] = vncSecurityName(byte(t))
		if t == 1 {
			r.Extra["vnc_auth_none"] = "true"
		}
		return
	}
	n := int(data[0])
	if n == 0 {
		// RFB 3.8：0 表示协商失败，后面是原因字符串
		if len(data) >= 5 {
			l := int(int32(binary.BigEndian.Uint32(data[1:5])))
			if l > 0 && 5+l <= len(data) {
				r.Extra["vnc_handshake_error"] = cleanText(string(data[5 : 5+l]))
			}
		}
		return
	}
	if 1+n > len(data) {
		return
	}
	names := make([]string, 0, n)
	hasNone := false
	for _, t := range data[1 : 1+n] {
		names = append(names, vncSecurityName(t))
		if t == 1 {
			hasNone = true
		}
	}
	r.Extra["vnc_security_types"] = strings.Join(names, ",")
	if hasNone {
		r.Extra["vnc_auth_none"] = "true"
	}
}

func vncSecurityName(t byte) string {
	switch t {
	case 0:
		return "Invalid"
	case 1:
		return "None"
	case 2:
		return "VNC-Auth"
	case 5:
		return "RA2"
	case 6:
		return "RA2ne"
	case 16:
		return "Tight"
	case 17:
		return "Ultra"
	case 18:
		return "TLS"
	case 19:
		return "VeNCrypt"
	case 20:
		return "GTK-VNC-SASL"
	case 21:
		return "MD5-hash"
	case 22:
		return "xvp"
	default:
		return fmt.Sprintf("Unknown(%d)", t)
	}
}

// ---------------------------------------------------------------------------
// SMB2 —— NEGOTIATE 响应给出版本方言与签名要求
// ---------------------------------------------------------------------------

var smbProbe = Probe{
	Name:  "smb",
	Ports: []int{445},
	Run: func(ctx context.Context, cn *Conn, host string, port int) (*Result, error) {
		if err := cn.Write(smb2Negotiate()); err != nil {
			return nil, err
		}
		hdr, err := cn.ReadFull(4)
		if err != nil {
			return nil, err
		}
		n := int(hdr[1])<<16 | int(hdr[2])<<8 | int(hdr[3])
		if n < 64 || n > 8192 {
			return nil, errNotThisProtocol
		}
		body, err := cn.ReadFull(n)
		if err != nil {
			return nil, err
		}
		if r := parseSMB2(body); r != nil {
			return r, nil
		}
		return nil, errNotThisProtocol
	},
}

func parseSMB2(data []byte) *Result {
	if len(data) < 66 {
		return nil
	}
	if !bytes.Equal(data[0:4], []byte{0xFE, 'S', 'M', 'B'}) {
		return nil
	}
	command := binary.LittleEndian.Uint16(data[12:14])
	if command != 0 { // 只认 NEGOTIATE
		return nil
	}
	status := binary.LittleEndian.Uint32(data[8:12])
	if status != 0 {
		return nil
	}
	body := data[64:]
	if len(body) < 8 {
		return nil
	}
	if binary.LittleEndian.Uint16(body[0:2]) != 65 { // StructureSize
		return nil
	}
	securityMode := binary.LittleEndian.Uint16(body[2:4])
	dialect := binary.LittleEndian.Uint16(body[4:6])

	signingEnabled := securityMode&0x0001 != 0
	signingRequired := securityMode&0x0002 != 0
	name := dialectName(dialect)

	extra := map[string]string{
		"smb_dialect_raw":      fmt.Sprintf("0x%04X", dialect),
		"smb_signing_enabled":  boolText(signingEnabled),
		"smb_signing_required": boolText(signingRequired),
		"smb_dialect":          name,
	}
	if len(body) >= 24 {
		extra["smb_server_guid"] = fmt.Sprintf("%X", body[8:24])
	}
	if len(body) >= 40 {
		extra["smb_max_read_size"] = fmt.Sprintf("%d", binary.LittleEndian.Uint32(body[32:36]))
		extra["smb_max_write_size"] = fmt.Sprintf("%d", binary.LittleEndian.Uint32(body[36:40]))
	}
	banner := "SMB " + name
	if signingRequired {
		banner += "（强制签名）"
	} else if signingEnabled {
		banner += "（支持签名）"
	}
	// 方言名作为版本号：SMB 没有"产品版本"概念，用方言表达最准确
	return &Result{
		Service: "smb", Product: "SMB", Version: name,
		Confidence: model.ConfidenceHigh, Evidence: "smb2-negotiate:dialect=" + name,
		Extra: extra, Banner: banner,
	}
}

func dialectName(d uint16) string {
	switch d {
	case 0x0202:
		return "2.0.2"
	case 0x0210:
		return "2.1"
	case 0x0300:
		return "3.0"
	case 0x0302:
		return "3.0.2"
	case 0x0311:
		return "3.1.1"
	case 0x02FF:
		return "2.x(wildcard)"
	default:
		return fmt.Sprintf("0x%04X", d)
	}
}

// ---------------------------------------------------------------------------
// RDP —— X.224 + RDP 协商响应给出版本选择（能看出是否强制 NLA）
// ---------------------------------------------------------------------------

var rdpProbe = Probe{
	Name:  "rdp",
	Ports: []int{3389},
	Run: func(ctx context.Context, cn *Conn, host string, port int) (*Result, error) {
		if err := cn.Write(rdpNegotiationRequest()); err != nil {
			return nil, err
		}
		hdr, err := cn.ReadFull(4)
		if err != nil {
			return nil, err
		}
		if hdr[0] != 0x03 {
			return nil, errNotThisProtocol
		}
		total := int(hdr[2])<<8 | int(hdr[3])
		if total < 11 || total > 8192 {
			return nil, errNotThisProtocol
		}
		body, err := cn.ReadFull(total - 4)
		if err != nil {
			return nil, err
		}
		full := append(hdr, body...)
		if r := parseRDP(full); r != nil {
			return r, nil
		}
		return nil, errNotThisProtocol
	},
}

func parseRDP(data []byte) *Result {
	if len(data) < 11 {
		return nil
	}
	if data[0] != 0x03 || data[1] != 0x00 {
		return nil
	}
	r := &Result{
		Service: "rdp", Product: "RDP", Confidence: model.ConfidenceMedium,
		Evidence: "rdp-x224", Extra: map[string]string{}, Banner: "RDP",
	}
	switch data[5] {
	case 0xD0: // Connection Confirm
	case 0x7F: // 服务端主动断开
		r.Extra["rdp_disconnect"] = "true"
		return r
	default:
		return nil
	}
	if len(data) >= 19 && data[11] == 0x02 { // RDP_NEG_RSP
		proto := binary.LittleEndian.Uint32(data[15:19])
		name, nla := rdpProtocol(proto)
		r.Extra["rdp_selected_protocol"] = name
		r.Extra["rdp_nla_required"] = boolText(nla)
		r.Evidence = "rdp-negotiation:" + name
		r.Confidence = model.ConfidenceHigh
		r.Banner = "RDP (" + name + ")"
	}
	return r
}

func rdpProtocol(v uint32) (string, bool) {
	switch v {
	case 0:
		return "PROTOCOL_RDP(标准RDP安全)", false
	case 1:
		return "PROTOCOL_SSL(TLS)", false
	case 2:
		return "PROTOCOL_HYBRID(NLA/CredSSP)", true
	case 8:
		return "PROTOCOL_HYBRID_EX", true
	case 0xFFFFFFFF:
		return "协商失败(服务端要求未提供的协议)", true
	default:
		return fmt.Sprintf("未知(0x%X)", v), false
	}
}

// ---------------------------------------------------------------------------
// MongoDB —— OP_MSG hello，从 maxWireVersion 推断版本族
// ---------------------------------------------------------------------------

var mongoProbe = Probe{
	Name:  "mongodb",
	Ports: []int{27017, 27018, 27019},
	Run: func(ctx context.Context, cn *Conn, host string, port int) (*Result, error) {
		if err := cn.Write(mongoHello()); err != nil {
			return nil, err
		}
		hdr, err := cn.ReadFull(16)
		if err != nil {
			return nil, err
		}
		total := int(int32(binary.LittleEndian.Uint32(hdr[0:4])))
		op := binary.LittleEndian.Uint32(hdr[12:16])
		if total < 16 || total > 8192 {
			return nil, errNotThisProtocol
		}
		body, err := cn.ReadFull(total - 16)
		if err != nil {
			return nil, err
		}
		if r := parseMongo(op, body); r != nil {
			return r, nil
		}
		return nil, errNotThisProtocol
	},
}

func parseMongo(op uint32, body []byte) *Result {
	var doc []byte
	switch op {
	case 2013: // OP_MSG
		if len(body) < 5 || body[4] != 0x00 {
			return nil
		}
		doc = body[5:]
	case 1: // OP_REPLY（老版本）
		if len(body) < 20 {
			return nil
		}
		doc = body[20:]
	default:
		return nil
	}

	wire, ok := bsonLookupInt32(doc, "maxWireVersion")
	if !ok {
		if msg, ok2 := bsonLookupString(doc, "errmsg"); ok2 {
			return &Result{
				Service: "mongodb", Product: "MongoDB",
				Confidence: model.ConfidenceMedium, Evidence: "mongodb-errmsg",
				Banner: cleanText(msg),
			}
		}
		return nil
	}
	extra := map[string]string{
		"mongodb_max_wire_version": fmt.Sprintf("%d", wire),
		"mongodb_version_family":   mongoVersionFamily(wire),
	}
	if b, ok := bsonLookupBool(doc, "isWritablePrimary"); ok {
		extra["mongodb_primary"] = boolText(b)
	}
	return &Result{
		Service: "mongodb", Product: "MongoDB",
		Confidence: model.ConfidenceHigh,
		Evidence:   fmt.Sprintf("mongodb-hello:maxWireVersion=%d", wire),
		Extra:      extra,
		Banner:     fmt.Sprintf("MongoDB (wire %d，对应 %s)", wire, mongoVersionFamily(wire)),
	}
}

func mongoVersionFamily(wire int32) string {
	switch {
	case wire >= 25:
		return "8.0+"
	case wire >= 21:
		return "7.0"
	case wire >= 17:
		return "6.0"
	case wire >= 13:
		return "5.0"
	case wire >= 9:
		return "4.4"
	case wire >= 8:
		return "4.2"
	case wire >= 7:
		return "4.0"
	case wire >= 6:
		return "3.6"
	default:
		return "未知"
	}
}

// ---------------------------------------------------------------------------
// TLS —— 用标准库完成握手，取协议版本/套件/ALPN/证书
// ---------------------------------------------------------------------------

var tlsProbe = Probe{
	Name:    "tls",
	Generic: true,
	Ports:   tlsPorts,
	Run: func(ctx context.Context, cn *Conn, host string, port int) (*Result, error) {
		timeout := cn.timeout
		if timeout > 1500*time.Millisecond {
			timeout = 1500 * time.Millisecond // 非 TLS 服务会一直等到超时，缩短它
		}
		cfg := &tls.Config{
			InsecureSkipVerify: true, //nolint:gosec // 授权测试场景需接受自签名证书
			ServerName:         sniName(host),
			MinVersion:         tls.VersionTLS10,
		}
		tc := tls.Client(cn.NetConn(), cfg)
		if err := tc.SetDeadline(time.Now().Add(timeout)); err != nil {
			return nil, err
		}
		if err := tc.HandshakeContext(ctx); err != nil {
			return nil, err
		}
		st := tc.ConnectionState()
		versionName := tls.VersionName(st.Version)

		extra := map[string]string{
			"tls_version": versionName,
			"tls_cipher":  tls.CipherSuiteName(st.CipherSuite),
		}
		if st.NegotiatedProtocol != "" {
			extra["tls_alpn"] = st.NegotiatedProtocol
		}
		if cfg.ServerName != "" {
			extra["tls_sni"] = cfg.ServerName
		}
		banner := "TLS " + versionName
		if len(st.PeerCertificates) > 0 {
			cert := st.PeerCertificates[0]
			extra["tls_cert_subject"] = cert.Subject.CommonName
			extra["tls_cert_issuer"] = cert.Issuer.CommonName
			extra["tls_cert_not_after"] = cert.NotAfter.Format(time.RFC3339)
			if len(cert.DNSNames) > 0 {
				extra["tls_cert_dns"] = strings.Join(limitStrings(cert.DNSNames, 5), ",")
			}
			if time.Now().After(cert.NotAfter) {
				extra["tls_cert_expired"] = "true"
			}
			banner = "TLS " + versionName + " CN=" + cert.Subject.CommonName
		}
		return &Result{
			Service: "tls", Confidence: model.ConfidenceHigh,
			Evidence: "tls-handshake:" + versionName,
			Extra:    extra, Banner: banner,
		}, nil
	},
}

// ---------------------------------------------------------------------------
// 小工具
// ---------------------------------------------------------------------------

var reSpaces = regexp.MustCompile(`\s+`)

func cleanText(s string) string {
	return strings.TrimSpace(reSpaces.ReplaceAllString(s, " "))
}

// splitProductVersion 把 "OpenSSH_9.6p1" 拆成 ("OpenSSH","9.6p1")。
func splitProductVersion(s string) (string, string) {
	if i := strings.IndexByte(s, '_'); i > 0 && i < len(s)-1 {
		return s[:i], s[i+1:]
	}
	return s, ""
}

var reLeadingVersion = regexp.MustCompile(`^\d+(?:\.\d+){0,3}`)

func leadingVersion(s string) string {
	return reLeadingVersion.FindString(s)
}

// extractMariaVersion 处理 MariaDB 的 "5.5.5-10.4.11-MariaDB" 假版本前缀。
func extractMariaVersion(s string) string {
	if strings.HasPrefix(s, "5.5.5-") {
		return leadingVersion(s[len("5.5.5-"):])
	}
	return leadingVersion(s)
}

func boolText(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

func limitStrings(list []string, n int) []string {
	if len(list) <= n {
		return list
	}
	return list[:n]
}

func sniName(host string) string {
	if host == "" {
		return ""
	}
	// IP 字面量不发 SNI
	if strings.Count(host, ".") == 3 && !strings.ContainsAny(host, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-") {
		return ""
	}
	if strings.Contains(host, ":") {
		return ""
	}
	return host
}

// fieldAfter 从 Redis INFO 文本里取 "key:value" 的 value（按行）。
func fieldAfter(text, key string) string {
	i := strings.Index(text, key)
	if i < 0 {
		return ""
	}
	return firstLineValue(text[i+len(key):])
}

func firstLineValue(s string) string {
	if i := strings.IndexAny(s, "\r\n"); i >= 0 {
		s = s[:i]
	}
	return strings.TrimSpace(s)
}
