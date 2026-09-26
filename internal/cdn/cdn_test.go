package cdn

import (
	"net/http"
	"strings"
	"testing"
)

func hdr(kv ...string) http.Header {
	h := http.Header{}
	for i := 0; i+1 < len(kv); i += 2 {
		h.Add(kv[i], kv[i+1])
	}
	return h
}

func TestDetectByCNAME(t *testing.T) {
	cases := []struct {
		cname string
		want  string
	}{
		{"demo.example.com.cdn.cloudflare.net.", "Cloudflare"},
		{"x.akamaiedge.net", "Akamai"},
		{"x.cloudfront.net", "AWS CloudFront"},
		{"x.kunlun.com", "阿里云 CDN"},
		{"x.dnsv1.com", "腾讯云 CDN"},
		{"x.wscdns.com", "网宿科技"},
		{"x.incapdns.net", "Imperva Incapsula"},
	}
	for _, c := range cases {
		d := Detect(c.cname, nil, nil)
		if d.CDN != c.want {
			t.Errorf("CNAME %q 识别为 %q，期望 %q", c.cname, d.CDN, c.want)
		}
		if !d.BehindCDN {
			t.Errorf("CNAME %q 命中后应标记 BehindCDN", c.cname)
		}
		if len(d.Evidence) == 0 || !strings.HasPrefix(d.Evidence[0], "cname:") {
			t.Errorf("CNAME %q 缺少 cname 判据: %v", c.cname, d.Evidence)
		}
	}
}

func TestDetectByHeaders(t *testing.T) {
	cases := []struct {
		name     string
		headers  http.Header
		wantCDN  string
		wantWAF  string
		evidence string
	}{
		{"cloudflare cf-ray", hdr("CF-RAY", "7a1b2c3d4e5f-LAX"), "Cloudflare", "Cloudflare", "header:cf-ray"},
		{"cloudflare server", hdr("Server", "cloudflare"), "Cloudflare", "Cloudflare", "header:server"},
		{"cloudfront", hdr("X-Amz-Cf-Id", "abc123"), "AWS CloudFront", "", "header:x-amz-cf-id"},
		{"fastly", hdr("X-Served-By", "cache-lhr6370-LHR"), "Fastly", "", "header:x-served-by"},
		{"akamai", hdr("X-Akamai-Transformed", "9 12345 0 pmb=mRUM,1"), "Akamai", "", "header:x-akamai-transformed"},
		{"azure fd", hdr("X-Azure-Ref", "0abc"), "Azure Front Door", "", "header:x-azure-ref"},
		{"aliyun", hdr("Ali-Swift-Global-Savetime", "1699999999"), "阿里云 CDN", "", "header:ali-swift-global-savetime"},
		{"wangsu", hdr("X-Ws-Request-Id", "abc-123"), "网宿科技", "", "header:x-ws-request-id"},
		{"sucuri", hdr("X-Sucuri-Id", "00000000"), "Sucuri", "Sucuri", "header:x-sucuri-id"},
		{"imperva", hdr("X-Iinfo", "9-12345-12346 NNNN"), "Imperva Incapsula", "Imperva Incapsula", "header:x-iinfo"},
		{"f5 waf", hdr("Server", "BIG-IP"), "", "F5 BIG-IP", "header:server"},
		{"modsecurity", hdr("Server", "Apache/2.4 (mod_security)"), "", "ModSecurity", "header:server"},
	}
	for _, c := range cases {
		d := Detect("", c.headers, nil)
		if d.CDN != c.wantCDN {
			t.Errorf("%s: CDN = %q，期望 %q", c.name, d.CDN, c.wantCDN)
		}
		if d.WAF != c.wantWAF {
			t.Errorf("%s: WAF = %q，期望 %q", c.name, d.WAF, c.wantWAF)
		}
		found := false
		for _, e := range d.Evidence {
			if e == c.evidence {
				found = true
			}
		}
		if !found {
			t.Errorf("%s: 缺少判据 %q，实际 %v", c.name, c.evidence, d.Evidence)
		}
	}
}

func TestDetectByCookies(t *testing.T) {
	cases := []struct {
		cookie  string
		wantCDN string
		wantWAF string
	}{
		{"__cfduid", "Cloudflare", "Cloudflare"},
		{"cf_clearance", "", "Cloudflare"},
		{"incap_ses_1234_5678", "Imperva Incapsula", "Imperva Incapsula"},
		{"BIGipServerpool_web", "", "F5 BIG-IP"},
		{"ak_bmsc", "", "Akamai Bot Manager"},
		{"sucuri_cloudproxy_uuid_abc", "Sucuri", "Sucuri"},
		{"wzws_sessionid", "", "网防G01"},
		{"HWWAFSESID", "", "华为云 WAF"},
	}
	for _, c := range cases {
		d := Detect("", nil, []string{c.cookie})
		if d.CDN != c.wantCDN || d.WAF != c.wantWAF {
			t.Errorf("cookie %q → CDN=%q WAF=%q，期望 %q/%q", c.cookie, d.CDN, d.WAF, c.wantCDN, c.wantWAF)
		}
	}
}

// 普通站点绝不能误报
func TestNoFalsePositiveOnPlainSite(t *testing.T) {
	h := hdr(
		"Server", "nginx/1.25.3",
		"Content-Type", "text/html",
		"X-Powered-By", "PHP/8.2",
		"Set-Cookie", "PHPSESSID=abc123; path=/",
	)
	d := Detect("www.example.com", h, CookieNames(h))
	if !d.Empty() {
		t.Errorf("普通 nginx 站点被误判: CDN=%q WAF=%q evidence=%v", d.CDN, d.WAF, d.Evidence)
	}
	if d.BehindCDN {
		t.Error("普通站点不应标记 BehindCDN")
	}
	if d.OriginHint() != "" {
		t.Error("未命中 CDN 时不应给出源站提示")
	}
}

func TestCookieNames(t *testing.T) {
	h := hdr(
		"Set-Cookie", "PHPSESSID=abc; path=/; HttpOnly",
		"Set-Cookie", "cf_clearance=xyz; domain=.example.com",
	)
	names := CookieNames(h)
	want := map[string]bool{"PHPSESSID": true, "cf_clearance": true}
	if len(names) != 2 {
		t.Fatalf("解析出 %d 个 Cookie，期望 2: %v", len(names), names)
	}
	for _, n := range names {
		if !want[n] {
			t.Errorf("意外的 Cookie 名: %q", n)
		}
	}
	if CookieNames(nil) != nil {
		t.Error("nil 头应返回 nil")
	}
}

func TestCNAMEPriorityOverHeaders(t *testing.T) {
	// CNAME 指向 Cloudflare，但响应头带 AWS 特征：CNAME 是更强证据，应优先
	d := Detect("x.cloudflare.net", hdr("X-Amz-Cf-Id", "abc"), nil)
	if d.CDN != "Cloudflare" {
		t.Errorf("CNAME 应优先，实际 CDN=%q", d.CDN)
	}
	if !strings.Contains(strings.Join(d.Evidence, ","), "cname:") {
		t.Errorf("应记录 CNAME 判据: %v", d.Evidence)
	}
}

func TestOriginHint(t *testing.T) {
	d := Detect("x.cloudfront.net", nil, nil)
	hint := d.OriginHint()
	if !strings.Contains(hint, "AWS CloudFront") {
		t.Errorf("提示里应含厂商名: %q", hint)
	}
	if !strings.Contains(hint, "不主动绕过") {
		t.Errorf("提示应表明不做 WAF 绕过: %q", hint)
	}
}
