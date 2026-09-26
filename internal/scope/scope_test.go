package scope

import (
	"context"
	"testing"
)

func TestUnauthorizedIsRefused(t *testing.T) {
	if _, err := New([]string{"10.0.0.0/24"}, nil, 256, false, false); err == nil {
		t.Fatal("未声明授权时构造 Scope 必须失败")
	}
}

func TestStrictRequiresAllowList(t *testing.T) {
	if _, err := New(nil, nil, 256, true, true); err == nil {
		t.Fatal("严格模式且无 allow 规则时必须失败")
	}
}

func TestCheckCIDRAndDomain(t *testing.T) {
	s, err := New([]string{"10.0.0.0/24", "example.com"}, []string{"10.0.0.66"}, 256, false, true)
	if err != nil {
		t.Fatalf("构造 Scope 失败: %v", err)
	}
	cases := []struct {
		target string
		ok     bool
	}{
		{"10.0.0.5", true},
		{"10.0.0.66", false}, // deny 优先
		{"10.0.1.5", false},
		{"https://a.example.com/x", true},
		{"example.com:8443", true},
		{"notexample.com", false},
		{"evil.com", false},
	}
	for _, c := range cases {
		host, ok, reason := s.Check(c.target)
		if ok != c.ok {
			t.Errorf("Check(%q) = %v (host=%s reason=%s)，期望 %v", c.target, ok, host, reason, c.ok)
		}
	}
}

func TestNormalizeHost(t *testing.T) {
	cases := map[string]string{
		"https://Example.COM:8443/a/b?c=1": "example.com",
		"http://[2001:db8::1]:8080/":       "2001:db8::1",
		"10.0.0.1:22":                      "10.0.0.1",
		"example.com.":                     "example.com",
	}
	for in, want := range cases {
		if got := NormalizeHost(in); got != want {
			t.Errorf("NormalizeHost(%q) = %q，期望 %q", in, got, want)
		}
	}
}

func TestDenyByResolvedIP(t *testing.T) {
	// 127.0.0.1 同时出现在 allow 与 deny 中，Guard 必须在解析后再拦一次
	s, err := New([]string{"127.0.0.0/8"}, []string{"127.0.0.1"}, 16, false, true)
	if err != nil {
		t.Fatalf("构造 Scope 失败: %v", err)
	}
	if _, _, err := s.Guard(context.Background(), "localhost"); err == nil {
		t.Fatal("解析到 deny 网段的域名必须被拦截")
	}
}
