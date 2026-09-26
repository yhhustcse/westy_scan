package model

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// TestKeyStable 验证 Key() 的可重复性：同一资产多次调用必须得到完全相同的键。
func TestKeyStable(t *testing.T) {
	a := Asset{Host: "10.0.0.5", Port: 22, Service: "ssh"}
	first := a.Key()
	for i := 0; i < 5; i++ {
		if got := a.Key(); got != first {
			t.Fatalf("第 %d 次 Key() = %q，期望稳定的 %q", i, got, first)
		}
	}
	// 值拷贝出去之后 Key() 也应当不变（Key 用的是值接收者）。
	cp := a
	if got := cp.Key(); got != first {
		t.Fatalf("值拷贝的 Key() = %q，期望 %q", got, first)
	}
}

// TestKeyDiscriminates 验证 Key() 对不同 host/port/url 的区分度。
func TestKeyDiscriminates(t *testing.T) {
	cases := []struct {
		name string
		a, b Asset
	}{
		{
			name: "不同 host 不同键",
			a:    Asset{Host: "a.example.com", Port: 443},
			b:    Asset{Host: "b.example.com", Port: 443},
		},
		{
			name: "不同 port 不同键",
			a:    Asset{Host: "a.example.com", Port: 80},
			b:    Asset{Host: "a.example.com", Port: 443},
		},
		{
			name: "URL 与端口资产不同键",
			a:    Asset{Host: "a.example.com", Port: 443, URL: "https://a.example.com/"},
			b:    Asset{Host: "a.example.com", Port: 443},
		},
		{
			name: "不同 URL 不同键",
			a:    Asset{URL: "https://a.example.com/a"},
			b:    Asset{URL: "https://a.example.com/b"},
		},
		{
			name: "不同 scheme 的同一主机不同键（URL 优先）",
			a:    Asset{URL: "http://a.example.com/"},
			b:    Asset{URL: "https://a.example.com/"},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ka, kb := c.a.Key(), c.b.Key()
			if ka == kb {
				t.Fatalf("两个不同资产得到相同 Key(): %q", ka)
			}
		})
	}
}

// TestKeyIPv6Normalization 验证 IPv6 的归一化语义：
// 带方括号的 host（含 :port 的 URL 形式）与 net.JoinHostPort 产出的裸地址
// 只要 host 字面量一致，Key() 就一致；同时方括号/裸地址本身仍是不同的 key，
// Key() 自身不做任何规范化（这是调用方的责任）。
func TestKeyIPv6Normalization(t *testing.T) {
	const host = "2001:db8::1"

	bare := Asset{Host: host, Port: 8080}
	bracketed := Asset{Host: "[" + host + "]", Port: 8080}

	if bare.Key() != "tcp|2001:db8::1|8080" {
		t.Fatalf("裸 IPv6 Key() = %q，期望 tcp|2001:db8::1|8080", bare.Key())
	}
	if bracketed.Key() != "tcp|[2001:db8::1]|8080" {
		t.Fatalf("带方括号 IPv6 Key() = %q，期望 tcp|[2001:db8::1]|8080", bracketed.Key())
	}
	// 同一份输入永远得到同一个键（归一化后的资产需要 Key 稳定）。
	if bare.Key() != bare.Key() {
		t.Fatal("同一 IPv6 资产两次 Key() 不一致")
	}
	// 不同端口的 IPv6 资产必须区分开。
	if bare.Key() == (Asset{Host: host, Port: 8081}).Key() {
		t.Fatal("IPv6 不同端口得到相同 Key()")
	}
	// 两个不同 IPv6 地址必须区分开。
	if bare.Key() == (Asset{Host: "2001:db8::2", Port: 8080}).Key() {
		t.Fatal("不同 IPv6 地址得到相同 Key()")
	}
}

// TestKeyHostOnlyAndURLPriority 覆盖 Key() 的三个分支与优先级。
func TestKeyHostOnlyAndURLPriority(t *testing.T) {
	if got := (Asset{Host: "example.com"}).Key(); got != "host|example.com" {
		t.Fatalf("无端口资产 Key() = %q，期望 host|example.com", got)
	}
	if got := (Asset{Host: "example.com", Port: 0}).Key(); got != "host|example.com" {
		t.Fatalf("端口为 0 的资产 Key() = %q，期望 host|example.com", got)
	}
	if got := (Asset{Port: 0}).Key(); got != "host|" {
		t.Fatalf("空资产 Key() = %q，期望 host|", got)
	}
	// URL 优先级高于 host+port。
	a := Asset{Host: "example.com", Port: 8443, URL: "https://example.com/x"}
	if got := a.Key(); got != "url|https://example.com/x" {
		t.Fatalf("有 URL 的资产 Key() = %q，期望 url|https://example.com/x", got)
	}
}

// TestRaiseConfidenceOnlyRaises 验证置信度只升不降。
func TestRaiseConfidenceOnlyRaises(t *testing.T) {
	cases := []struct {
		desc string
		from string
		set  string
		want string
	}{
		{"空 -> low 生效", "", ConfidenceLow, ConfidenceLow},
		{"空 -> high 生效", "", ConfidenceHigh, ConfidenceHigh},
		{"low -> high 生效", ConfidenceLow, ConfidenceHigh, ConfidenceHigh},
		{"low -> medium 生效", ConfidenceLow, ConfidenceMedium, ConfidenceMedium},
		{"medium -> high 生效", ConfidenceMedium, ConfidenceHigh, ConfidenceHigh},
		{"high -> low 不生效", ConfidenceHigh, ConfidenceLow, ConfidenceHigh},
		{"high -> medium 不生效", ConfidenceHigh, ConfidenceMedium, ConfidenceHigh},
		{"medium -> low 不生效", ConfidenceMedium, ConfidenceLow, ConfidenceMedium},
		{"high -> high 保持", ConfidenceHigh, ConfidenceHigh, ConfidenceHigh},
		{"high -> 空 不生效", ConfidenceHigh, "", ConfidenceHigh},
		{"high -> 未知值 不生效", ConfidenceHigh, "banana", ConfidenceHigh},
		{"空 -> 未知值 不生效", "", "banana", ""},
	}
	for _, c := range cases {
		t.Run(c.desc, func(t *testing.T) {
			a := Asset{Confidence: c.from}
			a.RaiseConfidence(c.set)
			if a.Confidence != c.want {
				t.Fatalf("Confidence 从 %q 提升为 %q 后 = %q，期望 %q", c.from, c.set, a.Confidence, c.want)
			}
		})
	}
}

// TestRaiseConfidenceMonotonicSequence 验证一串混合调用后不会回退。
func TestRaiseConfidenceMonotonicSequence(t *testing.T) {
	a := Asset{}
	seq := []string{ConfidenceMedium, ConfidenceLow, ConfidenceHigh, ConfidenceMedium, ConfidenceLow}
	want := []string{ConfidenceMedium, ConfidenceMedium, ConfidenceHigh, ConfidenceHigh, ConfidenceHigh}
	for i, lv := range seq {
		a.RaiseConfidence(lv)
		if a.Confidence != want[i] {
			t.Fatalf("第 %d 步 RaiseConfidence(%q) 后 = %q，期望 %q", i, lv, a.Confidence, want[i])
		}
	}
}

// TestAddEvidenceAppendsAndDedupes 验证证据是追加而非覆盖、自动去重且不影响 Key。
func TestAddEvidenceAppendsAndDedupes(t *testing.T) {
	a := Asset{Host: "h", Port: 80}
	keyBefore := a.Key()

	a.AddEvidence("端口开放")
	a.AddEvidence("banner 命中 nginx")
	if len(a.Evidence) != 2 {
		t.Fatalf("证据条数 = %d，期望 2（追加而非覆盖）：%v", len(a.Evidence), a.Evidence)
	}
	if a.Evidence[0] != "端口开放" || a.Evidence[1] != "banner 命中 nginx" {
		t.Fatalf("证据顺序/内容被改写: %v", a.Evidence)
	}

	// 重复项不追加。
	a.AddEvidence("端口开放")
	if len(a.Evidence) != 2 {
		t.Fatalf("重复证据被再次追加: %v", a.Evidence)
	}
	// 一批里既有重复项也有新项。
	a.AddEvidence("端口开放", "tls 证书 CN 命中", "tls 证书 CN 命中")
	if len(a.Evidence) != 3 {
		t.Fatalf("批量追加后条数 = %d，期望 3: %v", len(a.Evidence), a.Evidence)
	}
	// 空串与纯空白被忽略。
	a.AddEvidence("", "   ", "\t\n")
	if len(a.Evidence) != 3 {
		t.Fatalf("空证据被写入: %v", a.Evidence)
	}
	// 首尾空白会被裁剪。
	a.AddEvidence("  两侧空白  ")
	if len(a.Evidence) != 4 || a.Evidence[3] != "两侧空白" {
		t.Fatalf("证据未裁剪空白: %v", a.Evidence)
	}
	// 证据不影响 Key()。
	if got := a.Key(); got != keyBefore {
		t.Fatalf("AddEvidence 改变了 Key(): %q -> %q", keyBefore, got)
	}
}

// TestIdentifySemantics 验证 Identify() 的实际语义（只在为空时写入 + 置信度只升不降）。
func TestIdentifySemantics(t *testing.T) {
	t.Run("空资产全部写入", func(t *testing.T) {
		a := Asset{}
		a.Identify("http", "nginx", "1.24.0", ConfidenceMedium, "Server 头命中")
		if a.Service != "http" || a.Product != "nginx" || a.Version != "1.24.0" {
			t.Fatalf("Identify 写入不完整: service=%q product=%q version=%q", a.Service, a.Product, a.Version)
		}
		if a.Confidence != ConfidenceMedium {
			t.Fatalf("Confidence = %q，期望 medium", a.Confidence)
		}
		if len(a.Evidence) != 1 || a.Evidence[0] != "Server 头命中" {
			t.Fatalf("证据 = %v", a.Evidence)
		}
		if len(a.Products) != 1 || a.Products[0] != "nginx" {
			t.Fatalf("Products = %v，期望 [nginx]", a.Products)
		}
	})

	t.Run("已有更强结论不被覆盖", func(t *testing.T) {
		a := Asset{}
		a.Identify("mysql", "MySQL", "8.0.35", ConfidenceHigh, "握手包版本号")
		a.Identify("http", "nginx", "1.24.0", ConfidenceLow, "端口猜测")
		if a.Service != "mysql" {
			t.Fatalf("Service 被弱结论覆盖: %q", a.Service)
		}
		if a.Product != "MySQL" {
			t.Fatalf("Product 被弱结论覆盖: %q", a.Product)
		}
		if a.Version != "8.0.35" {
			t.Fatalf("Version 被弱结论覆盖: %q", a.Version)
		}
		if a.Confidence != ConfidenceHigh {
			t.Fatalf("Confidence 被拉低: %q", a.Confidence)
		}
		// 产品列表仍然会追加新发现（追加而非覆盖）。
		if len(a.Products) != 2 {
			t.Fatalf("Products = %v，期望追加 2 项", a.Products)
		}
		if len(a.Evidence) != 2 {
			t.Fatalf("Evidence = %v，期望 2 条", a.Evidence)
		}
	})

	t.Run("空参数不破坏已有值", func(t *testing.T) {
		a := Asset{Service: "ssh", Product: "OpenSSH", Version: "9.6p1", Confidence: ConfidenceHigh}
		a.Identify("", "", "", "", "")
		if a.Service != "ssh" || a.Product != "OpenSSH" || a.Version != "9.6p1" || a.Confidence != ConfidenceHigh {
			t.Fatalf("空 Identify 改动了资产: %+v", a)
		}
		if len(a.Evidence) != 0 || len(a.Products) != 0 {
			t.Fatalf("空 Identify 写入了内容: evidence=%v products=%v", a.Evidence, a.Products)
		}
	})
}

// TestIsWeb 验证 IsWeb() 的边界语义。
func TestIsWeb(t *testing.T) {
	cases := []struct {
		desc string
		a    Asset
		want bool
	}{
		{"空资产非 Web", Asset{}, false},
		{"仅有端口非 Web", Asset{Host: "h", Port: 8080}, false},
		{"仅有 scheme 是 Web", Asset{Scheme: "https"}, true},
		{"有 URL 是 Web", Asset{URL: "http://example.com/"}, true},
		{"service=http 是 Web", Asset{Service: "http"}, true},
		{"service=HTTPS 大小写不敏感", Asset{Service: "HTTPS"}, true},
		{"service=http2 不是 Web", Asset{Service: "http2"}, false},
		{"banner HTTP/1.1 是 Web", Asset{Banner: "HTTP/1.1 200 OK\r\n"}, true},
		{"banner 小写 http/ 也算 Web（代码先 ToUpper 再比前缀）", Asset{Banner: "http/1.1 200 OK"}, true},
		{"banner 前缀非 HTTP/ 不是 Web", Asset{Banner: "XHTTP/1.1"}, false},
		{"空 title 不影响判定", Asset{Host: "h", Port: 80, Title: ""}, false},
		{"ssh 服务非 Web", Asset{Service: "ssh", Banner: "SSH-2.0-OpenSSH_9.6"}, false},
	}
	for _, c := range cases {
		t.Run(c.desc, func(t *testing.T) {
			if got := c.a.IsWeb(); got != c.want {
				t.Fatalf("IsWeb() = %v，期望 %v（资产 %+v）", got, c.want, c.a)
			}
		})
	}
}

// TestMetaAndSetMeta 验证 Meta/SetMeta/MetaValue 的读写语义。
func TestMetaAndSetMeta(t *testing.T) {
	var a Asset
	if got := a.MetaValue("缺失"); got != "" {
		t.Fatalf("nil map 取不存在的键 = %q，期望空串", got)
	}
	if got := a.MetaValue(""); got != "" {
		t.Fatalf("nil map 取空键 = %q，期望空串", got)
	}

	a.SetMeta("duplicate_of", "https://example.com/a")
	if a.Meta == nil {
		t.Fatal("SetMeta 未初始化 map")
	}
	if got := a.MetaValue("duplicate_of"); got != "https://example.com/a" {
		t.Fatalf("MetaValue = %q", got)
	}
	if got := a.MetaValue("js.endpoint_count"); got != "" {
		t.Fatalf("不存在的键 = %q，期望空串", got)
	}

	// 空值不写入。
	a.SetMeta("empty", "")
	if got := a.MetaValue("empty"); got != "" {
		t.Fatalf("空值被写入: %q", got)
	}
	if _, ok := a.Meta["empty"]; ok {
		t.Fatal("SetMeta 把空值写进了 map")
	}

	// 覆盖写。
	a.SetMeta("dup", "1")
	a.SetMeta("dup", "2")
	if got := a.MetaValue("dup"); got != "2" {
		t.Fatalf("覆盖写后 = %q，期望 2", got)
	}

	// 取地址后的指针也读得到同一份 Meta。
	if got := (&a).MetaValue("dup"); got != "2" {
		t.Fatalf("指针取值 = %q", got)
	}
}

// TestAddProductDedupe 验证产品指纹追加与大小写不敏感去重。
func TestAddProductDedupe(t *testing.T) {
	var a Asset
	a.AddProduct("nginx")
	a.AddProduct("NGINX")
	a.AddProduct("nginx")
	if len(a.Products) != 1 {
		t.Fatalf("大小写不敏感去重失败: %v", a.Products)
	}
	a.AddProduct("  ", "", "OpenSSL")
	if len(a.Products) != 2 {
		t.Fatalf("空白产品被写入: %v", a.Products)
	}
	a.AddProduct("  MySQL  ")
	if got := a.Products[2]; got != "MySQL" {
		t.Fatalf("产品未裁剪空白: %q", got)
	}
	if len(a.Products) != 3 {
		t.Fatalf("产品条数 = %d，期望 3: %v", len(a.Products), a.Products)
	}
}

// TestAssetJSONRoundTrip 验证契约结构可无损 JSON 往返（分布式场景的关键）。
func TestAssetJSONRoundTrip(t *testing.T) {
	now := time.Date(2024, 5, 6, 7, 8, 9, 0, time.UTC)
	a := Asset{
		Input:      "10.0.0.0/24",
		Host:       "example.com",
		IP:         "93.184.216.34",
		Port:       8443,
		Scheme:     "https",
		URL:        "https://example.com:8443/",
		Service:    "https",
		Product:    "nginx",
		Version:    "1.24.0",
		Products:   []string{"nginx", "OpenSSL"},
		Title:      "Example",
		StatusCode: 200,
		Server:     "nginx",
		Banner:     "HTTP/1.1 200 OK",
		TLS:        &TLSInfo{Subject: "CN=example.com", Expired: true},
		Depth:      1,
		Source:     "httpinfo",
		Confidence: ConfidenceHigh,
		Evidence:   []string{"握手", "banner"},
		CDN:        "cloudflare",
		BehindCDN:  true,
		Params:     []string{"id"},
		Forms:      []Form{{Action: "https://example.com/login", Method: "POST", Fields: []string{"user"}}},
		Meta:       map[string]string{"js.endpoint_count": "3"},
		FoundAt:    now,
	}
	data, err := json.Marshal(a)
	if err != nil {
		t.Fatalf("Marshal 失败: %v", err)
	}
	var back Asset
	if err := json.Unmarshal(data, &back); err != nil {
		t.Fatalf("Unmarshal 失败: %v", err)
	}
	if back.Key() != a.Key() {
		t.Fatalf("往返后 Key 变化: %q -> %q", a.Key(), back.Key())
	}
	if back.MetaValue("js.endpoint_count") != "3" {
		t.Fatalf("往返后 Meta 丢失: %v", back.Meta)
	}
	if len(back.Forms) != 1 || back.Forms[0].Fields[0] != "user" {
		t.Fatalf("往返后 Forms 丢失: %+v", back.Forms)
	}
	if back.TLS == nil || !back.TLS.Expired {
		t.Fatalf("往返后 TLS 丢失: %+v", back.TLS)
	}
	if back.Confidence != ConfidenceHigh || !back.FoundAt.Equal(now) {
		t.Fatalf("往返后字段不一致: %+v", back)
	}
}

// TestHostJSONOmitEmpty 验证 Host 的可选字段被 omitempty 省略（协议兼容性）。
func TestHostJSONOmitEmpty(t *testing.T) {
	h := Host{Input: "example.com", Host: "example.com"}
	data, err := json.Marshal(h)
	if err != nil {
		t.Fatalf("Marshal 失败: %v", err)
	}
	got := string(data)
	if strings.Contains(got, "ports") {
		t.Fatalf("空 ports 未被省略: %s", got)
	}
	if !strings.Contains(got, `"host":"example.com"`) {
		t.Fatalf("host 字段缺失: %s", got)
	}
}
