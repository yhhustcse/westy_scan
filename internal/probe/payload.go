package probe

import "encoding/binary"

// 本文件只放"请求载荷构造"与"字节序辅助"，不含网络 I/O，方便单测。

// postgresSSLRequest 是 PostgreSQL 的 SSLRequest 报文：
// 长度 8 + 魔数 80877103（0x04D2162F）。服务端以单字节 'S' / 'N' / 'E' 应答。
func postgresSSLRequest() []byte {
	return []byte{0x00, 0x00, 0x00, 0x08, 0x04, 0xD2, 0x16, 0x2F}
}

// redisInfoCommand 是只读的 INFO 命令，用于取版本；无权限时服务端会回 -NOAUTH。
func redisInfoCommand() []byte { return []byte("INFO server\r\n") }

// memcachedVersionCommand 请求版本号。
func memcachedVersionCommand() []byte { return []byte("version\r\n") }

// smb2Negotiate 构造 SMB2 NEGOTIATE 请求：
// NetBIOS 会话头(4) + SMB2 头(64) + NEGOTIATE 体(36 + 2×方言数)。
func smb2Negotiate() []byte {
	dialects := []uint16{0x0202, 0x0210, 0x0300, 0x0302, 0x0311}

	body := make([]byte, 0, 36+2*len(dialects))
	body = append(body, 36, 0)                  // StructureSize = 36
	body = append(body, byte(len(dialects)), 0) // DialectCount
	body = append(body, 1, 0)                   // SecurityMode = 允许签名
	body = append(body, 0, 0)                   // Reserved
	body = append(body, 0, 0, 0, 0)             // Capabilities
	body = append(body, make([]byte, 16)...)    // ClientGuid（全 0 合法）
	body = append(body, make([]byte, 8)...)     // ClientStartTime（3.1.1 起）
	for _, d := range dialects {
		body = append(body, byte(d), byte(d>>8))
	}

	header := make([]byte, 64)
	copy(header[0:4], []byte{0xFE, 'S', 'M', 'B'})
	binary.LittleEndian.PutUint16(header[4:6], 64)  // StructureSize
	binary.LittleEndian.PutUint16(header[6:8], 1)   // CreditCharge
	binary.LittleEndian.PutUint16(header[14:16], 1) // CreditRequest

	msg := append(header, body...)
	nb := []byte{0x00, byte(len(msg) >> 16), byte(len(msg) >> 8), byte(len(msg))}
	return append(nb, msg...)
}

// rdpNegotiationRequest 构造 X.224 连接请求 + RDP 协商请求（请求 SSL|HYBRID）。
func rdpNegotiationRequest() []byte {
	neg := []byte{0x01, 0x00, 0x08, 0x00, 0x03, 0x00, 0x00, 0x00}
	// LI=14, CR CDT=0xE0, dst-ref(2), src-ref(2), class(1)
	x224 := append([]byte{0x0E, 0xE0, 0x00, 0x00, 0x00, 0x00, 0x00}, neg...)
	total := 4 + len(x224)
	return append([]byte{0x03, 0x00, byte(total >> 8), byte(total)}, x224...)
}

// mongoHello 构造 OP_MSG 的 {hello:1,$db:"admin"} 请求。
func mongoHello() []byte {
	doc := bsonDoc(
		bsonElemInt32("hello", 1),
		bsonElemString("$db", "admin"),
	)
	body := append([]byte{0, 0, 0, 0, 0x00}, doc...) // flagBits(4) + section kind(1)
	total := 16 + len(body)

	out := make([]byte, 16, total)
	binary.LittleEndian.PutUint32(out[0:4], uint32(total))
	binary.LittleEndian.PutUint32(out[4:8], 1)      // requestID
	binary.LittleEndian.PutUint32(out[8:12], 0)     // responseTo
	binary.LittleEndian.PutUint32(out[12:16], 2013) // opCode = OP_MSG
	return append(out, body...)
}

// ---------------- BSON 极简编码/解码（只覆盖识别版本号所需） ----------------

func bsonDoc(elems ...[]byte) []byte {
	size := 5
	for _, e := range elems {
		size += len(e)
	}
	out := make([]byte, 0, size)
	out = append(out, 0, 0, 0, 0)
	for _, e := range elems {
		out = append(out, e...)
	}
	out = append(out, 0x00)
	binary.LittleEndian.PutUint32(out[0:4], uint32(len(out)))
	return out
}

func bsonElemInt32(name string, v int32) []byte {
	out := []byte{0x10}
	out = append(out, name...)
	out = append(out, 0x00)
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, uint32(v))
	return append(out, b...)
}

func bsonElemString(name, v string) []byte {
	out := []byte{0x02}
	out = append(out, name...)
	out = append(out, 0x00)
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, uint32(len(v)+1))
	out = append(out, b...)
	out = append(out, v...)
	return append(out, 0x00)
}

// bsonLookupInt32 在 BSON 文档里找 int32 字段；找不到返回 (0,false)。
func bsonLookupInt32(doc []byte, name string) (int32, bool) {
	v, ok := bsonLookup(doc, name, 0x10)
	if !ok {
		return 0, false
	}
	b, ok := v.([]byte)
	if !ok || len(b) < 4 {
		return 0, false
	}
	return int32(binary.LittleEndian.Uint32(b)), true
}

// bsonLookupBool 在 BSON 文档里找 bool 字段。
func bsonLookupBool(doc []byte, name string) (bool, bool) {
	v, ok := bsonLookup(doc, name, 0x08)
	if !ok {
		return false, false
	}
	b, ok := v.([]byte)
	if !ok || len(b) < 1 {
		return false, false
	}
	return b[0] != 0, true
}

// bsonLookupString 在 BSON 文档里找 string 字段。
func bsonLookupString(doc []byte, name string) (string, bool) {
	v, ok := bsonLookup(doc, name, 0x02)
	if !ok {
		return "", false
	}
	b, ok := v.([]byte)
	if !ok || len(b) < 5 {
		return "", false
	}
	n := int(int32(binary.LittleEndian.Uint32(b[0:4])))
	if n <= 1 || 4+n > len(b) {
		return "", false
	}
	return string(b[4 : 4+n-1]), true
}

// bsonLookup 遍历文档顶层元素。只支持识别所需的基本类型，遇到未知类型即放弃。
func bsonLookup(doc []byte, name string, wantType byte) (any, bool) {
	if len(doc) < 5 {
		return nil, false
	}
	total := int(int32(binary.LittleEndian.Uint32(doc[0:4])))
	if total <= 5 || total > len(doc) {
		total = len(doc)
	}
	p := 4
	for p < total-1 {
		t := doc[p]
		p++
		end := indexByteFrom(doc, p, 0x00)
		if end < 0 {
			return nil, false
		}
		field := string(doc[p:end])
		p = end + 1

		switch t {
		case 0x01: // double
			if p+8 > total {
				return nil, false
			}
			if field == name && wantType == t {
				return doc[p : p+8], true
			}
			p += 8
		case 0x02: // string
			if p+4 > total {
				return nil, false
			}
			n := int(int32(binary.LittleEndian.Uint32(doc[p : p+4])))
			if n < 0 || p+4+n > total {
				return nil, false
			}
			if field == name && wantType == t {
				return doc[p : p+4+n], true
			}
			p += 4 + n
		case 0x03, 0x04: // document / array
			if p+4 > total {
				return nil, false
			}
			n := int(int32(binary.LittleEndian.Uint32(doc[p : p+4])))
			if n < 5 || p+n > total {
				return nil, false
			}
			p += n
		case 0x05: // binary
			if p+5 > total {
				return nil, false
			}
			n := int(int32(binary.LittleEndian.Uint32(doc[p : p+4])))
			if n < 0 || p+5+n > total {
				return nil, false
			}
			p += 5 + n
		case 0x07: // objectid
			p += 12
		case 0x08: // bool
			if p+1 > total {
				return nil, false
			}
			if field == name && wantType == t {
				return doc[p : p+1], true
			}
			p++
		case 0x09, 0x11, 0x12: // datetime / timestamp / int64
			p += 8
		case 0x0A: // null
		case 0x10: // int32
			if p+4 > total {
				return nil, false
			}
			if field == name && wantType == t {
				return doc[p : p+4], true
			}
			p += 4
		case 0x13: // decimal128
			p += 16
		default:
			return nil, false
		}
	}
	return nil, false
}

func indexByteFrom(b []byte, from int, c byte) int {
	if from < 0 || from >= len(b) {
		return -1
	}
	for i := from; i < len(b); i++ {
		if b[i] == c {
			return i
		}
	}
	return -1
}
