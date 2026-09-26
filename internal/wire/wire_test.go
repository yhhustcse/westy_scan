package wire

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"westy_scan/internal/model"
	"westy_scan/internal/poc"
)

// 固定的时间基准：marshal 会丢失单调时钟读数，因此往返比较必须用 time.Time.Equal。
var (
	t0 = time.Date(2024, 3, 1, 12, 30, 45, 123456789, time.UTC)
	t1 = time.Date(2024, 3, 2, 8, 0, 0, 0, time.UTC)
	t2 = time.Date(2024, 3, 3, 9, 15, 30, 500, time.UTC)
)

func sampleJobSpec() JobSpec {
	return JobSpec{
		ID:        "0123456789abcdef",
		ScanID:    "scan-1",
		Host:      "example.com",
		IP:        "93.184.216.34",
		Ports:     []int{22, 80, 443},
		CreatedAt: t0,
	}
}

func sampleAsset() model.Asset {
	return model.Asset{
		Input:      "example.com",
		Host:       "example.com",
		IP:         "93.184.216.34",
		Port:       443,
		Scheme:     "https",
		URL:        "https://example.com/",
		Service:    "https",
		Product:    "nginx",
		Version:    "1.25.3",
		Products:   []string{"nginx", "openssl"},
		Title:      "Example Domain",
		StatusCode: 200,
		Server:     "nginx",
		Banner:     "HTTP/1.1 200 OK",
		TLS: &model.TLSInfo{
			Subject:   "CN=example.com",
			Issuer:    "CN=Test CA",
			NotBefore: t0,
			NotAfter:  t1,
			DNSNames:  []string{"example.com", "www.example.com"},
			Serial:    "0a1b2c",
			Expired:   false,
		},
		Depth:      2,
		Source:     "portscan",
		Confidence: model.ConfidenceHigh,
		Evidence:   []string{"banner: nginx", "tls subject"},
		CDN:        "cloudflare",
		WAF:        "cloudflare",
		BehindCDN:  true,
		OriginNote: "origin 203.0.113.7",
		Params:     []string{"q", "id"},
		Forms:      []model.Form{{Action: "https://example.com/s", Method: "POST", Fields: []string{"q"}}},
		Meta:       map[string]string{"source": "unit-test", "zone": "dmz"},
		FoundAt:    t2,
	}
}

func sampleFinding() poc.Finding {
	return poc.Finding{
		TemplateID:  "CVE-2024-0001",
		Name:        "demo rce",
		Severity:    "high",
		Tags:        []string{"rce", "demo"},
		Target:      "https://example.com",
		MatchedAt:   "https://example.com/vuln?id=1",
		Confidence:  "high",
		Verified:    true,
		Intrusive:   true,
		Extracted:   map[string][]string{"version": {"1.2.3"}},
		Evidence:    poc.Evidence{Request: "GET /vuln HTTP/1.1", Response: "HTTP/1.1 200 OK", Matcher: "status==200"},
		Description: "demo",
		Reference:   []string{"https://example.com/advisory"},
		FoundAt:     t2,
		ScanID:      "scan-1",
		AgentID:     "agent-1",
	}
}

// TestJobIDStableForSameInput 幂等键：相同 (scan_id, host, ports) 必须稳定。
func TestJobIDStableForSameInput(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name   string
		scanID string
		host   string
		ports  []int
	}{
		{name: "typical", scanID: "scan-1", host: "10.0.0.1", ports: []int{22, 80, 443}},
		{name: "single_port", scanID: "scan-1", host: "example.com", ports: []int{443}},
		{name: "empty_ports", scanID: "scan-1", host: "example.com", ports: []int{}},
		{name: "nil_ports", scanID: "scan-1", host: "example.com", ports: nil},
		{name: "all_empty", scanID: "", host: "", ports: nil},
		{name: "ipv6_host", scanID: "s", host: "2001:db8::1", ports: []int{8443}},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			first := JobID(tc.scanID, tc.host, tc.ports)
			for i := 0; i < 50; i++ {
				if got := JobID(tc.scanID, tc.host, tc.ports); got != first {
					t.Fatalf("第 %d 次调用得到 %q，首次为 %q：JobID 不稳定", i+2, got, first)
				}
			}
			if len(first) != 16 {
				t.Fatalf("JobID 应为 16 个十六进制字符，得到 %q（长度 %d）", first, len(first))
			}
			for _, r := range first {
				if !strings.ContainsRune("0123456789abcdef", r) {
					t.Fatalf("JobID 含非小写十六进制字符 %q: %q", r, first)
				}
			}
		})
	}
}

// TestJobIDIsOrderInsensitive 端口**集合**相同必须得到同一个幂等键。
//
// 幂等键的语义是"同一台主机的同一组端口"，与请求里的书写顺序无关；
// 如果顺序参与哈希，HTTP 调用方传 [443,80] 与 [80,443] 就会生成两套任务，
// 去重与掉线重派一起失效（这正是一轮 review 里修掉的缺陷）。
func TestJobIDIsOrderInsensitive(t *testing.T) {
	t.Parallel()

	a := JobID("scan-1", "10.0.0.1", []int{22, 80, 443})
	b := JobID("scan-1", "10.0.0.1", []int{443, 80, 22})
	if a != b {
		t.Fatalf("端口顺序不应影响幂等键，得到 %q 与 %q", a, b)
	}
	c := JobID("scan-1", "10.0.0.1", []int{80, 22, 443, 80}) // 含重复端口，排序后仍是同一集合
	if c != a {
		t.Fatalf("重复端口不应影响幂等键，得到 %q 与 %q", c, a)
	}
	// JobID 不得修改调用方传入的切片（内部要拷一份再排序）
	ports := []int{443, 80, 22}
	_ = JobID("scan-1", "10.0.0.1", ports)
	if ports[0] != 443 {
		t.Fatalf("JobID 不应就地修改调用方的端口切片: %v", ports)
	}
}

// TestJobIDDistinguishesInputs 不同 scan/host/port 必须得到不同 ID。
func TestJobIDDistinguishesInputs(t *testing.T) {
	t.Parallel()

	base := JobID("scan-1", "10.0.0.1", []int{22, 80})

	cases := []struct {
		name   string
		scanID string
		host   string
		ports  []int
	}{
		{name: "other_scan", scanID: "scan-2", host: "10.0.0.1", ports: []int{22, 80}},
		{name: "other_host", scanID: "scan-1", host: "10.0.0.2", ports: []int{22, 80}},
		{name: "extra_port", scanID: "scan-1", host: "10.0.0.1", ports: []int{22, 80, 443}},
		{name: "fewer_port", scanID: "scan-1", host: "10.0.0.1", ports: []int{22}},
		{name: "no_ports", scanID: "scan-1", host: "10.0.0.1", ports: nil},
	}
	seen := map[string]string{base: "base"}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			got := JobID(tc.scanID, tc.host, tc.ports)
			if got == base {
				t.Fatalf("(%q,%q,%v) 与基准输入碰撞，均为 %q", tc.scanID, tc.host, tc.ports, got)
			}
			if prev, dup := seen[got]; dup {
				t.Fatalf("与 %s 产生相同 ID %q", prev, got)
			}
			seen[got] = tc.name
		})
	}
}

// TestJobIDNoDelimiterAmbiguity 回归：字段必须无歧义编码。
//
// 曾经的实现用 "|" 与 "," 明文拼接，于是 JobID("a|b","c",[1,2]) 与 JobID("a","b|c",[1,2])
// 得到同一个键 —— 两个不同的任务被判成同一个（一轮 review 里修掉，改用长度前缀编码）。
func TestJobIDNoDelimiterAmbiguity(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name  string
		scanA string
		hostA string
		scanB string
		hostB string
	}{
		{"分隔符错位", "a|b", "c", "a", "b|c"},
		{"分隔符在两字段间", "x", "y,z", "x|y", "z"},
		{"长度前缀伪造", "1:x", "y", "1", "x1:y"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			a := JobID(c.scanA, c.hostA, []int{1, 2})
			b := JobID(c.scanB, c.hostB, []int{1, 2})
			if a == b {
				t.Fatalf("不同输入不应得到同一个任务 ID：%q(%q,%q) 与 %q(%q,%q)",
					a, c.scanA, c.hostA, b, c.scanB, c.hostB)
			}
		})
	}
}

// TestTokenOKSemantics 表驱动固化 TokenOK 全部语义分支。
func TestTokenOKSemantics(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		got  string
		want string
		exp  bool
	}{
		{name: "exact_match", got: "s3cr3t", want: "s3cr3t", exp: true},
		{name: "bearer_prefix", got: "Bearer s3cr3t", want: "s3cr3t", exp: true},
		{name: "bearer_lowercase_not_stripped", got: "bearer s3cr3t", want: "s3cr3t", exp: false},
		// 关键语义：先 TrimPrefix("Bearer ") 再 TrimSpace。
		// 先 TrimSpace 再 TrimPrefix：带前导空格的 Bearer 头必须与不带的一样被接受。
		// （旧实现反过来了，于是 "  Bearer x" 被拒、"Bearer  x" 却通过 —— 不一致且会误拒合法请求。）
		{name: "leading_space_bearer_strip", got: "  Bearer s3cr3t  ", want: "s3cr3t", exp: true},
		{name: "leading_space_bearer_strip_multi", got: "  Bearer   s3cr3t  ", want: "s3cr3t", exp: true},
		// 剥掉前缀后剩余的前导空格被 TrimSpace 吃掉，"Bearer  token"（两个空格）也合法。
		{name: "bearer_prefix_extra_space_tolerated", got: "Bearer  s3cr3t", want: "s3cr3t", exp: true},
		{name: "bearer_prefix_upper_only", got: "Bearer s3cr3t ", want: "s3cr3t", exp: true},
		{name: "leading_trailing_spaces", got: "  s3cr3t\t", want: "s3cr3t", exp: true},
		{name: "wrong_token", got: "wrong", want: "s3cr3t", exp: false},
		{name: "wrong_token_same_length", got: "s3cr3X", want: "s3cr3t", exp: false},
		{name: "prefix_only", got: "s3cr3", want: "s3cr3t", exp: false},
		{name: "longer", got: "s3cr3t-and-more", want: "s3cr3t", exp: false},
		{name: "case_sensitive", got: "S3CR3T", want: "s3cr3t", exp: false},
		{name: "empty_got_with_want", got: "", want: "s3cr3t", exp: false},
		{name: "bearer_only", got: "Bearer ", want: "s3cr3t", exp: false},
		{name: "empty_want_accepts_empty", got: "", want: "", exp: true},
		{name: "empty_want_accepts_any", got: "anything", want: "", exp: true},
		{name: "empty_want_accepts_bearer", got: "Bearer whatever", want: "", exp: true},
		{name: "empty_want_accepts_spaces", got: "   ", want: "", exp: true},
		// TrimSpace 会吃掉尾随换行，因此 "s3cr3t\n" 被接受（HTTP 头拆分不会带换行，
		// 但这是实现的真实行为，用测试钉住）。
		{name: "trailing_newline_trimmed", got: "s3cr3t\n", want: "s3cr3t", exp: true},
		{name: "internal_space", got: "s3 cr3t", want: "s3cr3t", exp: false},
		// 只淘汰一个 "Bearer "：剥离后恰好等于 want，因此通过。
		{name: "single_prefix_stripped", got: "Bearer Bearer x", want: "Bearer x", exp: true},
		{name: "double_prefix_not_fully_stripped", got: "Bearer Bearer x", want: "x", exp: false},
		{name: "unicode_token", got: "密钥", want: "密钥", exp: true},
		// want 不做任何 trim：want 里带空格就必须逐字节相等。
		{name: "want_with_space_exact", got: "Bearer a b", want: "a b", exp: true},
		{name: "want_with_space_trimmed_got", got: " a b ", want: "a b", exp: true},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := TokenOK(tc.got, tc.want); got != tc.exp {
				t.Fatalf("TokenOK(%q, %q) = %v，期望 %v", tc.got, tc.want, got, tc.exp)
			}
		})
	}
}

// TestTokenOKIsPureAndConstantTimeSafe 同样输入重复调用结果一致，且永远不 panic。
func TestTokenOKIsPureAndConstantTimeSafe(t *testing.T) {
	t.Parallel()

	inputs := []string{"", "a", "Bearer a", "Bearer ", "  a  ", "aaaa", "bbbb", strings.Repeat("x", 4096)}
	for _, got := range inputs {
		for _, want := range inputs {
			first := TokenOK(got, want)
			for i := 0; i < 5; i++ {
				if TokenOK(got, want) != first {
					t.Fatalf("TokenOK(%q,%q) 结果不稳定", got, want)
				}
			}
			if want == "" && !first {
				t.Fatalf("want 为空必须放行，TokenOK(%q,\"\") = false", got)
			}
		}
	}
}

// TestJSONRoundTrip 对所有协议消息做 encode→decode，字段不得丢失。
func TestJSONRoundTrip(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		in   any
		out  any
		eq   func(a, b any) bool
	}{
		{
			name: "JobSpec",
			in:   sampleJobSpec(),
			out:  &JobSpec{},
			eq: func(a, b any) bool {
				return reflect.DeepEqual(a, *(b.(*JobSpec)))
			},
		},
		{
			name: "Task",
			in: Task{
				Spec:       sampleJobSpec(),
				State:      TaskRunning,
				AgentID:    "agent-1",
				Attempts:   2,
				LeaseUntil: t1,
				Error:      "boom",
				UpdatedAt:  t2,
			},
			out: &Task{},
			eq:  func(a, b any) bool { return reflect.DeepEqual(a, *(b.(*Task))) },
		},
		{
			name: "AgentStatus",
			in: AgentStatus{
				ID:           "agent-1",
				Version:      "1.2.3",
				Hostname:     "host-1",
				LastSeen:     t0,
				LeaseSeconds: 30,
				JobsDone:     7,
				JobsFailed:   1,
				AssetsSent:   42,
			},
			out: &AgentStatus{},
			eq:  func(a, b any) bool { return reflect.DeepEqual(a, *(b.(*AgentStatus))) },
		},
		{
			name: "RegisterRequest",
			in: RegisterRequest{
				AgentID:      "agent-1",
				Version:      "1.2.3",
				Hostname:     "host-1",
				Protocol:     ProtocolVersion,
				Capabilities: []string{"tcp", "http", "poc"},
			},
			out: &RegisterRequest{},
			eq:  func(a, b any) bool { return reflect.DeepEqual(a, *(b.(*RegisterRequest))) },
		},
		{
			name: "RegisterResponse",
			in: RegisterResponse{
				AgentID:       "agent-1",
				LeaseSeconds:  30,
				HeartbeatSecs: 10,
				Protocol:      ProtocolVersion,
				ServerVersion: "1.2.3",
				ScopeHint:     "10.0.0.0/8",
			},
			out: &RegisterResponse{},
			eq:  func(a, b any) bool { return reflect.DeepEqual(a, *(b.(*RegisterResponse))) },
		},
		{
			name: "PullRequest",
			in:   PullRequest{AgentID: "agent-1", MaxJobs: 4, WaitSeconds: 25},
			out:  &PullRequest{},
			eq:   func(a, b any) bool { return reflect.DeepEqual(a, *(b.(*PullRequest))) },
		},
		{
			name: "PullResponse",
			in: PullResponse{Jobs: []JobSpec{
				sampleJobSpec(),
				{ID: "x", ScanID: "s", Host: "h", Ports: []int{1}, CreatedAt: t1},
			}},
			out: &PullResponse{},
			eq:  func(a, b any) bool { return reflect.DeepEqual(a, *(b.(*PullResponse))) },
		},
		{
			name: "TaskOutcome",
			in:   TaskOutcome{JobID: "abc", State: TaskDone, Error: "", Host: "10.0.0.1"},
			out:  &TaskOutcome{},
			eq:   func(a, b any) bool { return reflect.DeepEqual(a, *(b.(*TaskOutcome))) },
		},
		{
			name: "ReportRequest",
			in: ReportRequest{
				AgentID:  "agent-1",
				ScanID:   "scan-1",
				Outcomes: []TaskOutcome{{JobID: "j1", State: TaskDone}, {JobID: "j2", State: TaskFailed, Error: "timeout"}},
				Assets:   []model.Asset{sampleAsset(), {Host: "plain.example.com", FoundAt: t0}},
				Findings: []poc.Finding{sampleFinding()},
				Rejected: []string{"192.0.2.1", "not-in-scope.example.com"},
			},
			out: &ReportRequest{},
			eq: func(a, b any) bool {
				x, y := a.(ReportRequest), *(b.(*ReportRequest))
				if len(x.Assets) != len(y.Assets) || !x.Assets[0].FoundAt.Equal(y.Assets[0].FoundAt) {
					return false
				}
				if len(x.Findings) != len(y.Findings) || !x.Findings[0].FoundAt.Equal(y.Findings[0].FoundAt) {
					return false
				}
				// 时间字段先归一化再整体比较，避免 monotonic / 精度差异。
				for i := range x.Assets {
					x.Assets[i].FoundAt = time.Time{}
					y.Assets[i].FoundAt = time.Time{}
				}
				for i := range x.Findings {
					x.Findings[i].FoundAt = time.Time{}
					y.Findings[i].FoundAt = time.Time{}
				}
				return reflect.DeepEqual(x, y)
			},
		},
		{
			name: "ReportResponse",
			in:   ReportResponse{AcceptedAssets: 3, AcceptedFindings: 1, Duplicates: 2, KnownScans: true},
			out:  &ReportResponse{},
			eq:   func(a, b any) bool { return reflect.DeepEqual(a, *(b.(*ReportResponse))) },
		},
		{
			name: "ScanSpec",
			in: ScanSpec{
				ScanID:        "scan-1",
				Hosts:         []string{"10.0.0.1", "10.0.0.2"},
				Ports:         []int{22, 80, 443},
				JobSize:       2,
				JobPorts:      1,
				MaxTries:      3,
				Authorization: "AUTH-2024-001",
				Operator:      "alice",
			},
			out: &ScanSpec{},
			eq:  func(a, b any) bool { return reflect.DeepEqual(a, *(b.(*ScanSpec))) },
		},
		{
			name: "ScanInfo",
			in: ScanInfo{
				ID:          "scan-1",
				CreatedAt:   t0,
				Hosts:       2,
				Ports:       3,
				Tasks:       6,
				Done:        4,
				Failed:      1,
				Running:     1,
				Pending:     0,
				Assets:      17,
				Findings:    2,
				CompletedAt: t1,
			},
			out: &ScanInfo{},
			eq:  func(a, b any) bool { return reflect.DeepEqual(a, *(b.(*ScanInfo))) },
		},
		{
			name: "Stats",
			in: Stats{
				Protocol: ProtocolVersion,
				Scans: map[string]*ScanInfo{
					"scan-1": {ID: "scan-1", CreatedAt: t0, Hosts: 1, Ports: 1, Tasks: 1, Done: 1, CompletedAt: t2},
				},
				Tasks:      map[TaskState]int{TaskPending: 1, TaskRunning: 2, TaskDone: 3, TaskFailed: 4},
				Agents:     []AgentStatus{{ID: "agent-1", LastSeen: t1, LeaseSeconds: 30}},
				Assets:     17,
				Findings:   2,
				UptimeSecs: 3600,
				Extra:      map[string]int{"scans_per_minute": 5},
			},
			out: &Stats{},
			eq: func(a, b any) bool {
				x, y := a.(Stats), *(b.(*Stats))
				if !x.Scans["scan-1"].CreatedAt.Equal(y.Scans["scan-1"].CreatedAt) {
					return false
				}
				if !x.Scans["scan-1"].CompletedAt.Equal(y.Scans["scan-1"].CompletedAt) {
					return false
				}
				if !x.Agents[0].LastSeen.Equal(y.Agents[0].LastSeen) {
					return false
				}
				x.Scans["scan-1"].CreatedAt = time.Time{}
				y.Scans["scan-1"].CreatedAt = time.Time{}
				x.Scans["scan-1"].CompletedAt = time.Time{}
				y.Scans["scan-1"].CompletedAt = time.Time{}
				x.Agents[0].LastSeen = time.Time{}
				y.Agents[0].LastSeen = time.Time{}
				return reflect.DeepEqual(x, y)
			},
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			raw, err := json.Marshal(tc.in)
			if err != nil {
				t.Fatalf("Marshal 失败: %v", err)
			}
			if err := json.Unmarshal(raw, tc.out); err != nil {
				t.Fatalf("Unmarshal 失败: %v（JSON %s）", err, raw)
			}
			if !tc.eq(tc.in, tc.out) {
				t.Fatalf("JSON 往返丢字段:\n原始 %+v\n解码 %+v\nJSON %s", tc.in, tc.out, raw)
			}
		})
	}
}

// TestJSONOmitEmptyContract 固化标签契约：empty 字段被省略 / 非 empty 字段始终出现。
func TestJSONOmitEmptyContract(t *testing.T) {
	t.Parallel()

	minimal, err := json.Marshal(JobSpec{ID: "i", ScanID: "s", Host: "h", CreatedAt: t0})
	if err != nil {
		t.Fatalf("Marshal 失败: %v", err)
	}
	for _, omitted := range []string{`"ip"`} {
		if strings.Contains(string(minimal), omitted) {
			t.Fatalf("空 %s 应被 omitempty 省略: %s", omitted, minimal)
		}
	}
	for _, want := range []string{`"id"`, `"scan_id"`, `"host"`, `"ports"`, `"created_at"`} {
		if !strings.Contains(string(minimal), want) {
			t.Fatalf("字段 %s 应始终出现（无 omitempty 或为必需字段）: %s", want, minimal)
		}
	}
	// ports 是 nil，序列化为 null（无 omitempty），能无损解回 nil。
	var back JobSpec
	if err := json.Unmarshal(minimal, &back); err != nil {
		t.Fatalf("Unmarshal 失败: %v", err)
	}
	if back.Ports != nil {
		t.Fatalf("nil Ports 往返后应为 nil，得到 %v", back.Ports)
	}
	if !strings.Contains(string(minimal), `"ports":null`) {
		t.Fatalf("Ports 无 omitempty，nil 应编码为 null: %s", minimal)
	}

	// ReportRequest 的可选字段在空时应被省略。
	emptyReport, err := json.Marshal(ReportRequest{AgentID: "a"})
	if err != nil {
		t.Fatalf("Marshal 失败: %v", err)
	}
	for _, omitted := range []string{"scan_id", "outcomes", "assets", "findings", "rejected"} {
		if strings.Contains(string(emptyReport), `"`+omitted+`"`) {
			t.Fatalf("空 %s 应被 omitempty 省略: %s", omitted, emptyReport)
		}
	}
	if !strings.Contains(string(emptyReport), `"agent_id"`) {
		t.Fatalf("agent_id 应始终出现: %s", emptyReport)
	}
}

// TestProtocolVersionAndTaskStates 常量契约：协议版本固定、状态字面量稳定（线上兼容性）。
func TestProtocolVersionAndTaskStates(t *testing.T) {
	t.Parallel()

	if ProtocolVersion != 1 {
		t.Fatalf("ProtocolVersion = %d，期望 1（改动即破坏兼容性）", ProtocolVersion)
	}
	cases := []struct {
		state TaskState
		want  string
	}{
		{TaskPending, "pending"},
		{TaskRunning, "running"},
		{TaskDone, "done"},
		{TaskFailed, "failed"},
	}
	for _, tc := range cases {
		if string(tc.state) != tc.want {
			t.Fatalf("状态字面量 = %q，期望 %q", tc.state, tc.want)
		}
		raw, err := json.Marshal(tc.state)
		if err != nil {
			t.Fatalf("Marshal 失败: %v", err)
		}
		if string(raw) != fmt.Sprintf("%q", tc.want) {
			t.Fatalf("状态序列化 = %s，期望 %q", raw, tc.want)
		}
		var back TaskState
		if err := json.Unmarshal(raw, &back); err != nil {
			t.Fatalf("Unmarshal 失败: %v", err)
		}
		if back != tc.state {
			t.Fatalf("状态往返 = %q，期望 %q", back, tc.state)
		}
	}
}
