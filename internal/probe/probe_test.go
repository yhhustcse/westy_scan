package probe

import (
	"context"
	"encoding/binary"
	"net"
	"strings"
	"testing"
	"time"

	"westy_scan/internal/model"
)

// ---------------------------------------------------------------------------
// 解析器单测（离线字节样本，不依赖网络）
// ---------------------------------------------------------------------------

func TestParseSSH(t *testing.T) {
	r := parseSSH("SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13\r\n")
	if r == nil {
		t.Fatal("SSH Banner 未识别")
	}
	if r.Product != "OpenSSH" || r.Version != "9.6p1" {
		t.Errorf("产品/版本解析错误: %+v", r)
	}
	if r.Extra["ssh_protocol"] != "2.0" {
		t.Errorf("协议版本错误: %v", r.Extra)
	}
	if !strings.Contains(r.Extra["ssh_comment"], "Ubuntu") {
		t.Errorf("注释未解析: %v", r.Extra)
	}
	if r.Confidence != model.ConfidenceHigh {
		t.Errorf("Banner 是权威证据，应为 high，实际 %q", r.Confidence)
	}

	// Dropbear 这种没有 _ 分隔的软件名
	r2 := parseSSH("SSH-2.0-dropbear_2022.83\r\n")
	if r2 == nil || r2.Product != "dropbear" || r2.Version != "2022.83" {
		t.Errorf("dropbear 解析错误: %+v", r2)
	}
	if parseSSH("HTTP/1.1 200 OK") != nil {
		t.Error("非 SSH 文本不应误判")
	}
}

// 构造一个真实的 MySQL 握手包
func mysqlHandshake(serverVersion, authPlugin string, caps uint32) []byte {
	payload := []byte{0x0A}
	payload = append(payload, serverVersion...)
	payload = append(payload, 0x00)
	payload = append(payload, 1, 0, 0, 0)         // thread id
	payload = append(payload, make([]byte, 8)...) // auth-plugin-data-1
	payload = append(payload, 0x00)               // filler
	payload = append(payload, byte(caps), byte(caps>>8))
	payload = append(payload, 0x21) // charset utf8_general_ci
	payload = append(payload, 0x02, 0x00)
	payload = append(payload, byte(caps>>16), byte(caps>>24))
	payload = append(payload, 21)                         // auth plugin data len
	payload = append(payload, make([]byte, 10)...)        // reserved
	payload = append(payload, []byte("abcdefghijklm")...) // auth-plugin-data-2
	payload = append(payload, authPlugin...)
	payload = append(payload, 0x00)

	out := []byte{byte(len(payload)), byte(len(payload) >> 8), byte(len(payload) >> 16), 0x00}
	return append(out, payload...)
}

func TestParseMySQL(t *testing.T) {
	// CLIENT_SSL(0x0800) | CLIENT_PLUGIN_AUTH(0x00080000)
	data := mysqlHandshake("8.0.35", "caching_sha2_password", 0x00080800)
	r := parseMySQL(data)
	if r == nil {
		t.Fatal("MySQL 握手包未识别")
	}
	if r.Product != "MySQL" || r.Version != "8.0.35" {
		t.Errorf("MySQL 识别错误: %+v", r)
	}
	if r.Extra["mysql_auth_plugin"] != "caching_sha2_password" {
		t.Errorf("认证插件未解析: %v", r.Extra)
	}
	if r.Extra["mysql_ssl"] != "true" {
		t.Errorf("CLIENT_SSL 标志未解析: %v", r.Extra)
	}
	if r.Confidence != model.ConfidenceHigh {
		t.Errorf("握手解析应为 high，实际 %q", r.Confidence)
	}

	// MariaDB 的 5.5.5- 假版本前缀必须剥掉
	maria := parseMySQL(mysqlHandshake("5.5.5-10.4.11-MariaDB", "mysql_native_password", 0x00080000))
	if maria == nil || maria.Product != "MariaDB" || maria.Version != "10.4.11" {
		t.Errorf("MariaDB 版本解析错误: %+v", maria)
	}
}

func TestParsePostgres(t *testing.T) {
	if r := parsePostgres([]byte{'S'}); r == nil || r.Extra["pg_ssl"] != "supported" {
		t.Errorf("SSLRequest 'S' 应答未识别: %+v", r)
	}
	if r := parsePostgres([]byte{'N'}); r == nil || r.Extra["pg_ssl"] != "unsupported" {
		t.Errorf("SSLRequest 'N' 应答未识别: %+v", r)
	}

	// ErrorResponse: 'E' + int32 长度 + 字段列表
	fields := []byte{'S'}
	fields = append(fields, []byte("FATAL")...)
	fields = append(fields, 0x00)
	fields = append(fields, 'C')
	fields = append(fields, []byte("28000")...)
	fields = append(fields, 0x00)
	fields = append(fields, 'M')
	fields = append(fields, []byte("no pg_hba.conf entry")...)
	fields = append(fields, 0x00, 0x00)
	msg := append([]byte{'E'}, 0, 0, 0, 0)
	binary.BigEndian.PutUint32(msg[1:5], uint32(len(fields)+4))
	msg = append(msg, fields...)

	r := parsePostgres(msg)
	if r == nil || !strings.Contains(r.Extra["pg_error"], "no pg_hba.conf entry") {
		t.Errorf("ErrorResponse 未解析: %+v", r)
	}
	if parsePostgres([]byte("hello")) != nil {
		t.Error("非 PostgreSQL 响应不应误判")
	}
}

func TestParseRedis(t *testing.T) {
	info := "$120\r\n# Server\r\nredis_version:7.0.11\r\nredis_mode:standalone\r\nos:Linux 5.15\r\ntcp_port:6379\r\n\r\n"
	r := parseRedis([]byte(info))
	if r == nil || r.Version != "7.0.11" {
		t.Fatalf("Redis INFO 未解析: %+v", r)
	}
	if r.Extra["redis_mode"] != "standalone" || r.Extra["redis_tcp_port"] != "6379" {
		t.Errorf("INFO 附加字段解析错误: %v", r.Extra)
	}

	noauth := parseRedis([]byte("-NOAUTH Authentication required.\r\n"))
	if noauth == nil || noauth.Extra["redis_auth_required"] != "true" {
		t.Errorf("NOAUTH 未识别: %+v", noauth)
	}
	if noauth.Confidence != model.ConfidenceHigh {
		t.Errorf("NOAUTH 是 Redis 专属错误，应为 high")
	}

	if parseRedis([]byte("+OK\r\n")) != nil {
		t.Error("无关回复不应误判为 Redis")
	}
}

func TestParseMemcached(t *testing.T) {
	r := parseMemcached([]byte("VERSION 1.6.17\r\n"))
	if r == nil || r.Version != "1.6.17" {
		t.Fatalf("Memcached 版本未解析: %+v", r)
	}
	if parseMemcached([]byte("VERSION")) != nil {
		t.Error("缺少版本号不应命中")
	}
}

func TestParseVNC(t *testing.T) {
	r := parseVNCServer("RFB 003.008\n")
	if r == nil || r.Version != "3.8" {
		t.Fatalf("RFB 版本未解析: %+v", r)
	}
	// 安全类型：数量 2，类型 None(1) 与 VNC-Auth(2)
	parseVNCSecurity([]byte{2, 1, 2}, r)
	if r.Extra["vnc_security_types"] != "None,VNC-Auth" {
		t.Errorf("安全类型解析错误: %v", r.Extra)
	}
	if r.Extra["vnc_auth_none"] != "true" {
		t.Error("应标记出无认证")
	}
	if parseVNCServer("RFB 00") != nil {
		t.Error("截断的 RFB 头不应命中")
	}
}

func smb2NegotiateResponse(dialect uint16, securityMode uint16) []byte {
	header := make([]byte, 64)
	copy(header[0:4], []byte{0xFE, 'S', 'M', 'B'})
	binary.LittleEndian.PutUint16(header[4:6], 64)
	binary.LittleEndian.PutUint16(header[12:14], 0) // NEGOTIATE

	body := make([]byte, 64)
	binary.LittleEndian.PutUint16(body[0:2], 65)
	binary.LittleEndian.PutUint16(body[2:4], securityMode)
	binary.LittleEndian.PutUint16(body[4:6], dialect)
	copy(body[8:24], []byte("0123456789abcdef"))
	binary.LittleEndian.PutUint32(body[32:36], 1048576)
	binary.LittleEndian.PutUint32(body[36:40], 1048576)
	return append(header, body...)
}

func TestParseSMB2(t *testing.T) {
	r := parseSMB2(smb2NegotiateResponse(0x0311, 0x0003))
	if r == nil {
		t.Fatal("SMB2 NEGOTIATE 响应未识别")
	}
	if r.Version != "3.1.1" {
		t.Errorf("方言解析错误: %+v", r)
	}
	if r.Extra["smb_signing_required"] != "true" {
		t.Errorf("签名要求未解析: %v", r.Extra)
	}
	if r.Confidence != model.ConfidenceHigh {
		t.Errorf("应为 high，实际 %q", r.Confidence)
	}

	// 2.1 方言 + 不要求签名
	r2 := parseSMB2(smb2NegotiateResponse(0x0210, 0x0001))
	if r2 == nil || r2.Version != "2.1" || r2.Extra["smb_signing_required"] != "false" {
		t.Errorf("SMB 2.1 解析错误: %+v", r2)
	}

	if parseSMB2(make([]byte, 200)) != nil {
		t.Error("全零数据不应误判为 SMB2")
	}
}

func TestParseRDP(t *testing.T) {
	// TPKT + X.224 CC + RDP_NEG_RSP(selectedProtocol=HYBRID)
	data := []byte{0x03, 0x00, 0x00, 0x13, 0x0E, 0xD0, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x02, 0x00, 0x08, 0x00, 0x02, 0x00, 0x00, 0x00}
	r := parseRDP(data)
	if r == nil {
		t.Fatal("RDP 协商响应未识别")
	}
	if r.Extra["rdp_nla_required"] != "true" {
		t.Errorf("NLA 判定错误: %v", r.Extra)
	}
	if r.Confidence != model.ConfidenceHigh {
		t.Errorf("协商响应应为 high，实际 %q", r.Confidence)
	}

	// 无协商响应（老系统）
	old := []byte{0x03, 0x00, 0x00, 0x0B, 0x06, 0xD0, 0x00, 0x00, 0x00, 0x00, 0x00}
	r2 := parseRDP(old)
	if r2 == nil || r2.Confidence != model.ConfidenceMedium {
		t.Errorf("老式 RDP 应为 medium: %+v", r2)
	}
	if len(old) > 0 && parseRDP([]byte{0x03, 0x00}) != nil {
		t.Error("截断数据不应命中")
	}
}

func bsonElemBool(name string, v bool) []byte {
	out := []byte{0x08}
	out = append(out, name...)
	out = append(out, 0x00)
	if v {
		return append(out, 0x01)
	}
	return append(out, 0x00)
}

func TestParseMongo(t *testing.T) {
	doc := bsonDoc(
		bsonElemInt32("maxWireVersion", 17),
		bsonElemBool("isWritablePrimary", true),
		bsonElemString("msg", "isdbgrid"),
	)
	body := append([]byte{0, 0, 0, 0, 0x00}, doc...)
	r := parseMongo(2013, body)
	if r == nil {
		t.Fatal("MongoDB hello 响应未识别")
	}
	if r.Extra["mongodb_max_wire_version"] != "17" || r.Extra["mongodb_version_family"] != "6.0" {
		t.Errorf("wire version 解析错误: %v", r.Extra)
	}
	if r.Extra["mongodb_primary"] != "true" {
		t.Errorf("primary 标志错误: %v", r.Extra)
	}

	// errmsg 型拒绝响应（未授权）也算识别成功，但置信度降级
	errDoc := bsonDoc(bsonElemString("errmsg", "command hello requires authentication"))
	errBody := append([]byte{0, 0, 0, 0, 0x00}, errDoc...)
	r2 := parseMongo(2013, errBody)
	if r2 == nil || r2.Confidence != model.ConfidenceMedium {
		t.Errorf("errmsg 响应应识别为 medium: %+v", r2)
	}
	if parseMongo(9999, body) != nil {
		t.Error("未知 opCode 不应命中")
	}
}

// 所有解析器都必须能扛住畸形输入（不得 panic）
func TestParsersSurviveGarbage(t *testing.T) {
	garbage := [][]byte{
		nil,
		{},
		{0x00},
		{0xFF, 0xFF, 0xFF},
		[]byte(strings.Repeat("A", 300)),
	}
	for _, g := range garbage {
		_ = parseSSH(string(g))
		_ = parseFTP(string(g))
		_ = parseSMTP(string(g))
		_ = parseMySQL(g)
		_ = parsePostgres(g)
		_ = parseRedis(g)
		_ = parseMemcached(g)
		_ = parseVNCServer(string(g))
		parseVNCSecurity(g, &Result{Extra: map[string]string{}})
		_ = parseSMB2(g)
		_ = parseRDP(g)
		_ = parseMongo(2013, g)
		_ = parseMongo(1, g)
	}
}

func TestVersionHelpers(t *testing.T) {
	if p, v := splitProductVersion("OpenSSH_9.6p1"); p != "OpenSSH" || v != "9.6p1" {
		t.Errorf("splitProductVersion 错误: %q %q", p, v)
	}
	if p, v := splitProductVersion("Cisco-1.25"); p != "Cisco-1.25" || v != "" {
		t.Errorf("无下划线时应整体作为产品名: %q %q", p, v)
	}
	if got := leadingVersion("8.0.35-log"); got != "8.0.35" {
		t.Errorf("leadingVersion(%q)=%q", "8.0.35-log", got)
	}
	if got := extractMariaVersion("5.5.5-10.4.11-MariaDB"); got != "10.4.11" {
		t.Errorf("extractMariaVersion 错误: %q", got)
	}
	if got := mongoVersionFamily(21); got != "7.0" {
		t.Errorf("mongoVersionFamily(21)=%q", got)
	}
}

// ---------------------------------------------------------------------------
// 端到端：起本地假服务端，验证探针的收发包与解析全链路
// ---------------------------------------------------------------------------

func fakeServer(t *testing.T, handler func(c net.Conn)) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("监听失败: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				handler(c)
			}(c)
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port
}

func runProbe(t *testing.T, p Probe, port int) *Result {
	t.Helper()
	ctx := context.Background()
	cn, err := dial(ctx, "127.0.0.1", port, 2*time.Second)
	if err != nil {
		t.Fatalf("连接失败: %v", err)
	}
	defer cn.Close()
	res, err := p.Run(ctx, cn, "127.0.0.1", port)
	if err != nil {
		t.Fatalf("探针 %s 执行失败: %v", p.Name, err)
	}
	if res == nil {
		t.Fatalf("探针 %s 未返回结果", p.Name)
	}
	return res
}

func TestSSHProbeEndToEnd(t *testing.T) {
	port := fakeServer(t, func(c net.Conn) {
		_, _ = c.Write([]byte("SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13\r\n"))
	})
	r := runProbe(t, sshProbe, port)
	if r.Product != "OpenSSH" || r.Version != "9.6p1" {
		t.Errorf("端到端 SSH 识别错误: %+v", r)
	}
}

func TestMySQLProbeEndToEnd(t *testing.T) {
	port := fakeServer(t, func(c net.Conn) {
		_, _ = c.Write(mysqlHandshake("8.0.35", "caching_sha2_password", 0x00080800))
	})
	r := runProbe(t, mysqlProbe, port)
	if r.Product != "MySQL" || r.Version != "8.0.35" {
		t.Errorf("端到端 MySQL 识别错误: %+v", r)
	}
}

func TestPostgresProbeEndToEnd(t *testing.T) {
	var got []byte
	port := fakeServer(t, func(c net.Conn) {
		buf := make([]byte, 8)
		n, _ := c.Read(buf)
		got = buf[:n]
		_, _ = c.Write([]byte{'S'})
	})
	r := runProbe(t, postgresProbe, port)
	if r.Product != "PostgreSQL" || r.Extra["pg_ssl"] != "supported" {
		t.Errorf("端到端 PostgreSQL 识别错误: %+v", r)
	}
	if len(got) != 8 || got[4] != 0x04 {
		t.Errorf("SSLRequest 载荷不对: %v", got)
	}
}

func TestRedisProbeEndToEnd(t *testing.T) {
	port := fakeServer(t, func(c net.Conn) {
		buf := make([]byte, 64)
		n, _ := c.Read(buf)
		if !strings.HasPrefix(string(buf[:n]), "INFO") {
			_, _ = c.Write([]byte("-ERR unknown command\r\n"))
			return
		}
		_, _ = c.Write([]byte("$40\r\n# Server\r\nredis_version:7.2.4\r\n\r\n"))
	})
	r := runProbe(t, redisProbe, port)
	if r.Version != "7.2.4" {
		t.Errorf("端到端 Redis 识别错误: %+v", r)
	}
}

func TestVNCProbeEndToEnd(t *testing.T) {
	port := fakeServer(t, func(c net.Conn) {
		_, _ = c.Write([]byte("RFB 003.008\n"))
		buf := make([]byte, 12)
		_, _ = c.Read(buf) // 读客户端回送的版本
		_, _ = c.Write([]byte{2, 1, 2})
	})
	r := runProbe(t, vncProbe, port)
	if r.Version != "3.8" || r.Extra["vnc_auth_none"] != "true" {
		t.Errorf("端到端 VNC 识别错误: %+v", r)
	}
}

func TestSMBProbeEndToEnd(t *testing.T) {
	port := fakeServer(t, func(c net.Conn) {
		hdr := make([]byte, 4)
		if _, err := c.Read(hdr); err != nil {
			return
		}
		n := int(hdr[1])<<16 | int(hdr[2])<<8 | int(hdr[3])
		if n <= 0 || n > 4096 {
			return
		}
		body := make([]byte, n)
		if _, err := c.Read(body); err != nil {
			return
		}
		resp := smb2NegotiateResponse(0x0311, 0x0003)
		_, _ = c.Write([]byte{0x00, byte(len(resp) >> 16), byte(len(resp) >> 8), byte(len(resp))})
		_, _ = c.Write(resp)
	})
	r := runProbe(t, smbProbe, port)
	if r.Version != "3.1.1" || r.Extra["smb_signing_required"] != "true" {
		t.Errorf("端到端 SMB 识别错误: %+v", r)
	}
}

func TestRDPProbeEndToEnd(t *testing.T) {
	port := fakeServer(t, func(c net.Conn) {
		buf := make([]byte, 64)
		_, _ = c.Read(buf)
		_, _ = c.Write([]byte{0x03, 0x00, 0x00, 0x13, 0x0E, 0xD0, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x02, 0x00, 0x08, 0x00, 0x02, 0x00, 0x00, 0x00})
	})
	r := runProbe(t, rdpProbe, port)
	if r.Extra["rdp_nla_required"] != "true" {
		t.Errorf("端到端 RDP 识别错误: %+v", r)
	}
}

// 客户端先说话但服务端不是该协议时，探针必须干净失败而不是卡死或误判
func TestProbeRejectsWrongProtocol(t *testing.T) {
	port := fakeServer(t, func(c net.Conn) {
		buf := make([]byte, 256)
		_, _ = c.Read(buf)
		_, _ = c.Write([]byte("完全不是这些协议\r\n"))
	})
	ctx := context.Background()
	for _, p := range []Probe{postgresProbe, redisProbe, memcachedProbe} {
		cn, err := dial(ctx, "127.0.0.1", port, 1500*time.Millisecond)
		if err != nil {
			t.Fatalf("连接失败: %v", err)
		}
		res, err := p.Run(ctx, cn, "127.0.0.1", port)
		_ = cn.Close()
		if err == nil || res != nil {
			t.Errorf("探针 %s 不应对错误协议返回结果: %+v", p.Name, res)
		}
	}
}

func TestProbesForPort(t *testing.T) {
	if got := ProbesForPort(3306); got[0].Name != "mysql" {
		t.Errorf("3306 首选探针应为 mysql，实际 %v", got)
	}
	if got := ProbesForPort(445); got[0].Name != "smb" {
		t.Errorf("445 首选探针应为 smb，实际 %v", got)
	}
	// 未知端口只做 TLS 判断，避免对陌生服务乱发包
	got := ProbesForPort(54321)
	if len(got) != 1 || got[0].Name != "tls" {
		t.Errorf("未知端口应只尝试 TLS，实际 %v", got)
	}
	// 常见 TLS 端口应补上 TLS 探针
	names := make([]string, 0, 3)
	for _, p := range ProbesForPort(465) {
		names = append(names, p.Name)
	}
	if !strings.Contains(strings.Join(names, ","), "tls") {
		t.Errorf("465 应包含 tls 探针，实际 %v", names)
	}
	if len(SupportedPorts()) < 20 {
		t.Errorf("覆盖端口过少: %v", SupportedPorts())
	}
}
