package target

import (
	"reflect"
	"testing"
)

func TestParsePorts(t *testing.T) {
	cases := []struct {
		spec    string
		want    []int
		wantErr bool
	}{
		{spec: "80,443", want: []int{80, 443}},
		{spec: "443,80,80", want: []int{80, 443}},
		{spec: "8000-8002", want: []int{8000, 8001, 8002}},
		{spec: "", want: DefaultPorts()},
		{spec: "0", wantErr: true},
		{spec: "70000", wantErr: true},
		{spec: "100-10", wantErr: true},
		{spec: "abc", wantErr: true},
	}
	for _, c := range cases {
		got, err := ParsePorts(c.spec)
		if c.wantErr {
			if err == nil {
				t.Errorf("ParsePorts(%q) 期望报错，实际通过", c.spec)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParsePorts(%q) 意外报错: %v", c.spec, err)
			continue
		}
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("ParsePorts(%q) = %v, 期望 %v", c.spec, got, c.want)
		}
	}
}

func TestParseNamedPortGroups(t *testing.T) {
	web, err := ParsePorts("web")
	if err != nil {
		t.Fatalf("ParsePorts(web) 报错: %v", err)
	}
	if len(web) == 0 {
		t.Fatal("web 端口组为空")
	}
	if !IsWebPort(443) || IsWebPort(22) {
		t.Fatal("IsWebPort 判定异常")
	}
}

func TestParseTargets(t *testing.T) {
	hosts, err := ParseAll([]string{"https://example.com/a/b?x=1", "10.0.0.7:8443", "example.com"}, 4096)
	if err != nil {
		t.Fatalf("ParseAll 报错: %v", err)
	}
	if len(hosts) != 2 {
		t.Fatalf("期望去重后 2 个目标，实际 %d: %+v", len(hosts), hosts)
	}
	if hosts[0].Host != "example.com" {
		t.Errorf("URL 归一化失败: %q", hosts[0].Host)
	}
	if hosts[1].Host != "10.0.0.7" || hosts[1].IP != "10.0.0.7" {
		t.Errorf("IP 解析失败: %+v", hosts[1])
	}
}

func TestParseCIDR(t *testing.T) {
	hosts, err := Parse("10.0.0.0/30", 4096)
	if err != nil {
		t.Fatalf("Parse(/30) 报错: %v", err)
	}
	// /30 去掉网络号与广播后剩 2 个可用地址
	if len(hosts) != 2 {
		t.Fatalf("期望 2 个地址，实际 %d: %+v", len(hosts), hosts)
	}
	if hosts[0].Host != "10.0.0.1" || hosts[1].Host != "10.0.0.2" {
		t.Errorf("网段展开结果异常: %+v", hosts)
	}

	if _, err := Parse("10.0.0.0/8", 256); err == nil {
		t.Error("超过 maxHosts 的网段应当被拒绝")
	}
}
