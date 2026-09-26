package authz

import (
	"testing"
	"time"
)

func baseRecord() Record {
	now := time.Now()
	return Record{
		ID:        "AB-2026-0142",
		Client:    "某客户",
		Allow:     []string{"10.0.0.0/24", "demo.example.com"},
		Deny:      []string{"10.0.0.1"},
		ValidFrom: now.Add(-time.Hour),
		ValidTo:   now.Add(24 * time.Hour),
		Approver:  "张三",
		Ticket:    "SEC-2026-118",
		CreatedAt: now,
	}
}

func TestValidateRecord(t *testing.T) {
	if err := ValidateRecord(baseRecord()); err != nil {
		t.Fatalf("合法授权书应通过校验: %v", err)
	}
	cases := []struct {
		name   string
		mutate func(*Record)
		want   string
	}{
		{"缺编号", func(r *Record) { r.ID = "" }, "编号"},
		{"缺委托方", func(r *Record) { r.Client = "" }, "委托方"},
		{"缺范围", func(r *Record) { r.Allow = nil }, "允许范围"},
		{"非法规则", func(r *Record) { r.Allow = []string{"10.0.0.0/99"} }, "非法"},
		{"有效期倒置", func(r *Record) {
			r.ValidFrom = time.Now().Add(time.Hour)
			r.ValidTo = time.Now()
		}, "有效期"},
	}
	for _, c := range cases {
		rec := baseRecord()
		c.mutate(&rec)
		err := ValidateRecord(rec)
		if err == nil {
			t.Errorf("%s: 应校验失败", c.name)
			continue
		}
	}
}

func TestGuardAllowsInScopeOnly(t *testing.T) {
	g, err := NewGuard(baseRecord(), time.Now())
	if err != nil {
		t.Fatalf("构造闸门失败: %v", err)
	}
	cases := []struct {
		target string
		ok     bool
	}{
		{"10.0.0.5", true},
		{"10.0.0.1", false}, // deny 优先
		{"10.0.1.5", false},
		{"demo.example.com", true},
		{"https://demo.example.com/x", true},
		{"other.example.com", false},
	}
	for _, c := range cases {
		ok, reason := g.Allow(c.target)
		if ok != c.ok {
			t.Errorf("Allow(%q) = %v（%s），期望 %v", c.target, ok, reason, c.ok)
		}
	}

	// 批量校验：返回第一个越界目标
	if bad, reason := g.AllowAll([]string{"10.0.0.5", "evil.com", "10.0.0.6"}); bad != "evil.com" || reason == "" {
		t.Errorf("批量校验应返回第一个越界目标，实际 %q %q", bad, reason)
	}
	if bad, _ := g.AllowAll([]string{"10.0.0.5", "demo.example.com"}); bad != "" {
		t.Errorf("全部在范围内时不应返回越界目标: %q", bad)
	}
}

func TestGuardRejectsExpiredAndNotYetValid(t *testing.T) {
	now := time.Now()

	expired := baseRecord()
	expired.ValidFrom = now.Add(-48 * time.Hour)
	expired.ValidTo = now.Add(-time.Hour)
	if _, err := NewGuard(expired, now); err == nil {
		t.Error("过期授权书必须拒绝")
	}

	future := baseRecord()
	future.ValidFrom = now.Add(time.Hour)
	future.ValidTo = now.Add(48 * time.Hour)
	if _, err := NewGuard(future, now); err == nil {
		t.Error("尚未生效的授权书必须拒绝")
	}

	// 未设置截止时间 = 长期有效，但仍需 allow
	perpetual := baseRecord()
	perpetual.ValidTo = time.Time{}
	g, err := NewGuard(perpetual, now)
	if err != nil {
		t.Fatalf("长期授权书应可用: %v", err)
	}
	if ok, _ := g.Allow("10.0.0.5"); !ok {
		t.Error("长期授权书应放行范围内目标")
	}
	if g.Describe() == "" {
		t.Error("Describe 不应为空（审计需要）")
	}
}

func TestExpiredHelper(t *testing.T) {
	rec := baseRecord()
	if rec.Expired(time.Now()) {
		t.Error("未过期")
	}
	if !rec.Expired(time.Now().Add(48 * time.Hour)) {
		t.Error("应判定为已过期")
	}
	rec.ValidTo = time.Time{}
	if rec.Expired(time.Now().Add(10000 * time.Hour)) {
		t.Error("未设置截止时间不应判定为过期")
	}
}
