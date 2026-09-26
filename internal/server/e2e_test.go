package server

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"westy_scan/internal/agent"
	"westy_scan/internal/audit"
	"westy_scan/internal/config"
	"westy_scan/internal/model"
	"westy_scan/internal/poc"
	"westy_scan/internal/wire"
)

func quietLogger() *log.Logger { return log.New(io.Discard, "", 0) }

// startLoopbackSites 在内核允许的前提下，在 127.0.0.2/3/4… 上各起一个假站点，
// 并且**绑定同一个端口**（扫描任务对同一批主机使用同一端口集合）。
// Windows 与 Linux 都把 127.0.0.0/8 视为回环，通常可直接绑定；不行就跳过该测试。
func startLoopbackSites(t *testing.T, n int) (hosts []string, port int, cleanup func()) {
	t.Helper()
	probe, err := net.Listen("tcp", "127.0.0.2:0")
	if err != nil {
		t.Skipf("本机无法绑定回环别名地址（%v），跳过多主机分布式测试", err)
	}
	port = probe.Addr().(*net.TCPAddr).Port
	_ = probe.Close()

	var servers []*http.Server
	var listeners []net.Listener
	closeAll := func() {
		for _, l := range listeners {
			_ = l.Close()
		}
		for _, s := range servers {
			_ = s.Close()
		}
	}
	for i := 0; i < n; i++ {
		addr := fmt.Sprintf("127.0.0.%d:%d", i+2, port)
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			closeAll()
			t.Skipf("本机无法绑定 %s（%v），跳过多主机分布式测试", addr, err)
		}
		mux := http.NewServeMux()
		mux.HandleFunc("/.git/config", func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprint(w, "[core]\n\trepositoryformatversion = 0\n[remote \"origin\"]\n\turl = https://git.example.com/app.git\n")
		})
		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprint(w, "<html><head><title>site</title></head><body>ok</body></html>")
		})
		srv := &http.Server{Handler: mux, ReadHeaderTimeout: 3 * time.Second}
		go func() { _ = srv.Serve(ln) }()
		servers = append(servers, srv)
		listeners = append(listeners, ln)
		hosts = append(hosts, fmt.Sprintf("127.0.0.%d", i+2))
	}
	return hosts, port, closeAll
}

func agentScanConfig() config.Config {
	cfg := config.Default()
	cfg.Authorized = true
	cfg.Allow = []string{"127.0.0.0/8"}
	cfg.StrictScope = true
	cfg.Concurrency = 8
	cfg.TimeoutSec = 2
	cfg.ServiceDetect = false
	cfg.Crawl = false
	cfg.POCEnabled = true
	cfg.POCVerify = true
	cfg.POCMaxTargets = 20
	cfg.OutputFormat = "table"
	return cfg
}

func waitScanDone(t *testing.T, s *Server, scanID string, timeout time.Duration) *wire.ScanInfo {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		info := s.ScanInfo(scanID)
		if info != nil && info.Done+info.Failed >= info.Tasks && info.Tasks > 0 {
			return info
		}
		time.Sleep(100 * time.Millisecond)
	}
	info := s.ScanInfo(scanID)
	t.Fatalf("扫描 %s 未在 %s 内完成: %+v", scanID, timeout, info)
	return nil
}

// 核心验收：多个 Agent 并行扫描，结果**不重不漏**，漏洞按 (模板,地址) 去重。
func TestDistributedScanNoLossNoDup(t *testing.T) {
	hosts, port, cleanup := startLoopbackSites(t, 3)
	defer cleanup()

	auditPath := filepath.Join(t.TempDir(), "server-audit.jsonl")
	aud, err := audit.Open(auditPath)
	if err != nil {
		t.Fatalf("打开审计失败: %v", err)
	}
	defer aud.Close()

	srv := New(Options{
		Token: "test-token", LeaseSeconds: 5, MaxTries: 3,
		SweepEvery: 100 * time.Millisecond, Audit: aud, Log: quietLogger(),
	})
	defer srv.Close()
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	info, err := srv.CreateScan(wire.ScanSpec{Hosts: hosts, Ports: []int{port}})
	if err != nil {
		t.Fatalf("创建扫描失败: %v", err)
	}
	if info.Tasks != 3 {
		t.Fatalf("应切成 3 个任务，实际 %d", info.Tasks)
	}

	// 启动 2 个 Agent 并行执行
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		ag, err := agent.New(agent.Config{
			ServerURL: ts.URL, Token: "test-token",
			AgentID:  fmt.Sprintf("agent-%d", i),
			Scan:     agentScanConfig(),
			SpoolDir: filepath.Join(t.TempDir(), fmt.Sprintf("spool-%d", i)),
			Log:      quietLogger(),
			MaxJobs:  2, PullWaitSecs: 2,
		})
		if err != nil {
			t.Fatalf("构造 Agent 失败: %v", err)
		}
		wg.Add(1)
		go func(a *agent.Agent) {
			defer wg.Done()
			_ = a.Run(ctx)
		}(ag)
	}

	done := waitScanDone(t, srv, info.ID, 60*time.Second)
	if done.Failed != 0 {
		t.Errorf("不应有失败任务: %+v", done)
	}
	if done.Done != 3 {
		t.Errorf("应完成 3 个任务，实际 %d", done.Done)
	}
	cancel()
	wg.Wait()

	// 资产：每台主机都要有结果，且整体无重复（去重键唯一）
	assets := srv.Assets()
	perHost := map[string]int{}
	portAssets := 0
	seenKeys := map[string]bool{}
	for _, a := range assets {
		perHost[a.Host]++
		if a.Source == "portscan" {
			portAssets++
		}
		if seenKeys[a.Key()] {
			t.Errorf("出现重复资产: %s", a.Key())
		}
		seenKeys[a.Key()] = true
	}
	for _, h := range hosts {
		if perHost[h] == 0 {
			t.Errorf("主机 %s 无资产（漏扫）", h)
		}
	}
	if portAssets != len(hosts) {
		t.Errorf("端口级资产 = %d，期望 %d（每台主机一条）", portAssets, len(hosts))
	}
	for _, a := range assets {
		if a.MetaValue("scan_id") != info.ID {
			t.Errorf("资产未标记 scan_id: %+v", a.Meta)
		}
		if a.MetaValue("agent_id") == "" {
			t.Errorf("资产未标记 agent_id: %+v", a.Meta)
		}
	}

	// 漏洞：每个站点命中一次 .git 暴露，且按 (模板,地址) 去重
	findings := srv.Findings()
	if len(findings) != len(hosts) {
		t.Errorf("漏洞条数 = %d，期望 %d（去重失效或有误报）: %+v", len(findings), len(hosts), findings)
	}
	for _, f := range findings {
		if f.TemplateID != "git-config-exposure" {
			t.Errorf("意外模板命中: %s", f.TemplateID)
		}
		if f.ScanID != info.ID || f.AgentID == "" {
			t.Errorf("漏洞结果缺少归属信息: scan_id=%q agent_id=%q", f.ScanID, f.AgentID)
		}
	}

	// 审计：能按 scan_id 对齐
	logText := readFile(t, auditPath)
	for _, want := range []string{"scan_created", "job_dispatched", "vuln_found"} {
		if !strings.Contains(logText, want) {
			t.Errorf("审计缺少事件 %s", want)
		}
	}
	if !strings.Contains(logText, info.ID) {
		t.Error("审计中缺少 scan_id，无法对齐证据链")
	}

	// 指标
	met := httptest.NewRecorder()
	srv.handleMetrics(met)
	body := met.Body.String()
	for _, want := range []string{
		"westy_tasks_done 3",
		fmt.Sprintf("westy_assets_total %d", len(assets)),
		fmt.Sprintf("westy_findings_total %d", len(findings)),
	} {
		if !strings.Contains(body, want) {
			t.Errorf("指标缺少 %q:\n%s", want, body)
		}
	}
}

// 租约机制：Agent 领了任务但不汇报（相当于进程被杀），租约过期后必须重派给别的 Agent。
func TestLeaseExpiryReassignsTask(t *testing.T) {
	srv := New(Options{
		Token: "t", LeaseSeconds: 1, MaxTries: 2,
		SweepEvery: 50 * time.Millisecond, Log: quietLogger(),
	})
	defer srv.Close()

	info, err := srv.CreateScan(wire.ScanSpec{Hosts: []string{"10.0.0.1"}, Ports: []int{80, 443}})
	if err != nil {
		t.Fatalf("创建扫描失败: %v", err)
	}

	// Agent A 领走任务后"失联"
	jobsA := srv.claim("agent-A", 1)
	if len(jobsA) != 1 {
		t.Fatalf("agent-A 应领到 1 个任务，实际 %d", len(jobsA))
	}
	jobID := jobsA[0].ID
	if st := srv.Stats(); st.Tasks[wire.TaskRunning] != 1 {
		t.Fatalf("任务应为 running: %+v", st.Tasks)
	}

	// 等租约过期 + 清理协程回收
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if st := srv.Stats(); st.Tasks[wire.TaskPending] == 1 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if st := srv.Stats(); st.Tasks[wire.TaskPending] != 1 {
		t.Fatalf("租约过期后任务应回到 pending: %+v", st.Tasks)
	}

	// Agent B 接手并完成
	jobsB := srv.claim("agent-B", 1)
	if len(jobsB) != 1 || jobsB[0].ID != jobID {
		t.Fatalf("agent-B 应接手同一任务: %+v", jobsB)
	}
	srv.applyOutcome(wire.TaskOutcome{JobID: jobID, State: wire.TaskDone, Host: "10.0.0.1"})

	st := srv.Stats()
	if st.Tasks[wire.TaskDone] != 1 || st.Tasks[wire.TaskRunning] != 0 {
		t.Errorf("最终状态错误: %+v", st.Tasks)
	}
	final := srv.ScanInfo(info.ID)
	if final.Done != 1 || final.Failed != 0 {
		t.Errorf("扫描视图错误: %+v", final)
	}

	// 反复失败超过上限 → 判失败，不再无限重派
	_, err = srv.CreateScan(wire.ScanSpec{ScanID: "scan-fail", Hosts: []string{"10.0.0.2"}, Ports: []int{80}})
	if err != nil {
		t.Fatalf("第二次创建扫描失败: %v", err)
	}
	var lastID string
	for i := 0; i < 3; i++ {
		jobs := srv.claim("agent-C", 1)
		if len(jobs) == 0 {
			break
		}
		lastID = jobs[0].ID
		srv.applyOutcome(wire.TaskOutcome{JobID: jobs[0].ID, State: wire.TaskFailed, Error: "模拟失败"})
	}
	if lastID == "" {
		t.Fatal("未取得可失败的任务")
	}
	srv.mu.Lock()
	task := srv.tasks[lastID]
	srv.mu.Unlock()
	if task.State != wire.TaskFailed {
		t.Errorf("超过重试上限后应判失败，实际 %s", task.State)
	}
}

// 同一份数据被两个 Agent 重复上报时必须去重
func TestDuplicateReportsAreDeduped(t *testing.T) {
	srv := New(Options{Token: "t", Log: quietLogger()})
	defer srv.Close()
	if _, err := srv.CreateScan(wire.ScanSpec{Hosts: []string{"10.0.0.9"}, Ports: []int{80}}); err != nil {
		t.Fatalf("创建扫描失败: %v", err)
	}

	asset := model.Asset{Host: "10.0.0.9", IP: "10.0.0.9", Port: 80, Source: "portscan", FoundAt: time.Now()}
	fnd := findingFor("git-config-exposure", "http://10.0.0.9/.git/config")

	for i := 0; i < 2; i++ {
		added, dup := srv.ingestAssets("scan-1", fmt.Sprintf("agent-%d", i), []model.Asset{asset})
		if i == 0 && (added != 1 || dup != 0) {
			t.Errorf("第一次上报应新增 1 条，实际 added=%d dup=%d", added, dup)
		}
		if i == 1 && (added != 0 || dup != 1) {
			t.Errorf("重复上报应被去重，实际 added=%d dup=%d", added, dup)
		}
		newFindings := srv.ingestFindings("scan-1", fmt.Sprintf("agent-%d", i), []poc.Finding{fnd})
		if i == 0 && newFindings != 1 {
			t.Errorf("第一次漏洞应新增 1 条，实际 %d", newFindings)
		}
		if i == 1 && newFindings != 0 {
			t.Errorf("重复漏洞应被去重，实际 %d", newFindings)
		}
	}
	if n := len(srv.Assets()); n != 1 {
		t.Errorf("资产应只有 1 条，实际 %d", n)
	}
	if n := len(srv.Findings()); n != 1 {
		t.Errorf("漏洞应只有 1 条，实际 %d", n)
	}
}

func findingFor(tpl, matchedAt string) poc.Finding {
	return poc.Finding{
		TemplateID: tpl,
		MatchedAt:  matchedAt,
		Severity:   "high",
		FoundAt:    time.Now(),
	}
}

// 鉴权：错误 token 必须被拒绝，且计入指标
func TestAuthRejectsBadToken(t *testing.T) {
	srv := New(Options{Token: "secret", Log: quietLogger()})
	defer srv.Close()
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	// 无 token
	resp, err := http.Post(ts.URL+"/api/v1/agents/pull", "application/json", strings.NewReader(`{"agent_id":"a"}`))
	if err != nil {
		t.Fatalf("请求失败: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("无 token 应返回 401，实际 %d", resp.StatusCode)
	}

	// 错误 token
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/agents/pull", strings.NewReader(`{"agent_id":"a"}`))
	req.Header.Set("Authorization", "Bearer wrong")
	resp2, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("请求失败: %v", err)
	}
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusUnauthorized {
		t.Errorf("错误 token 应返回 401，实际 %d", resp2.StatusCode)
	}

	// 正确 token
	req3, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/agents/pull", strings.NewReader(`{"agent_id":"a"}`))
	req3.Header.Set("Authorization", "Bearer secret")
	resp3, err := http.DefaultClient.Do(req3)
	if err != nil {
		t.Fatalf("请求失败: %v", err)
	}
	resp3.Body.Close()
	if resp3.StatusCode != http.StatusOK {
		t.Errorf("正确 token 应返回 200，实际 %d", resp3.StatusCode)
	}

	// healthz 不需要鉴权（探活用）
	resp4, err := http.Get(ts.URL + "/healthz")
	if err != nil {
		t.Fatalf("healthz 请求失败: %v", err)
	}
	resp4.Body.Close()
	if resp4.StatusCode != http.StatusOK {
		t.Errorf("healthz 应返回 200，实际 %d", resp4.StatusCode)
	}
}

// 幂等：同一个扫描重复创建任务不会重复入队
func TestCreateScanIdempotent(t *testing.T) {
	srv := New(Options{Token: "t", Log: quietLogger()})
	defer srv.Close()
	info, err := srv.CreateScan(wire.ScanSpec{ScanID: "s1", Hosts: []string{"a", "b"}, Ports: []int{80}})
	if err != nil {
		t.Fatalf("创建失败: %v", err)
	}
	if info.Tasks != 2 {
		t.Fatalf("应为 2 个任务，实际 %d", info.Tasks)
	}
	if _, err := srv.CreateScan(wire.ScanSpec{ScanID: "s1", Hosts: []string{"a", "b"}, Ports: []int{80}}); err == nil {
		t.Error("重复的 scan_id 应报错")
	}
	// 同一任务 ID 不应被重复入队
	if _, err := srv.CreateScan(wire.ScanSpec{ScanID: "s2", Hosts: []string{"a"}, Ports: []int{80}}); err != nil {
		t.Fatalf("创建失败: %v", err)
	}
	srv.mu.Lock()
	n := len(srv.tasks)
	srv.mu.Unlock()
	if n != 3 {
		t.Errorf("任务总数应为 3，实际 %d", n)
	}
}

// 端口分片：切片越细，任务越多、负载越均衡（掉线时损失也更小）
func TestCreateScanPortChunking(t *testing.T) {
	srv := New(Options{Token: "t", Log: quietLogger()})
	defer srv.Close()

	// 6 个端口，按 2 片 → 每台主机 3 个任务
	info, err := srv.CreateScan(wire.ScanSpec{
		ScanID: "chunked", Hosts: []string{"h1", "h2"},
		Ports: []int{80, 443, 8080, 8443, 22, 3306}, JobPorts: 2,
	})
	if err != nil {
		t.Fatalf("创建失败: %v", err)
	}
	if info.Tasks != 6 {
		t.Fatalf("2 主机 × 3 分片应为 6 个任务，实际 %d", info.Tasks)
	}
	// 每个任务的端口数不超过分片大小，且所有端口恰好覆盖一次
	srv.mu.Lock()
	defer srv.mu.Unlock()
	perHost := map[string]int{}
	allPorts := map[int]int{}
	for _, task := range srv.tasks {
		if len(task.Spec.Ports) > 2 {
			t.Errorf("任务 %s 端口数 %d 超过分片大小", task.Spec.ID, len(task.Spec.Ports))
		}
		perHost[task.Spec.Host] += len(task.Spec.Ports)
		for _, p := range task.Spec.Ports {
			allPorts[p]++
		}
	}
	if perHost["h1"] != 6 || perHost["h2"] != 6 {
		t.Errorf("每台主机应恰好覆盖 6 个端口: %v", perHost)
	}
	for p, n := range allPorts {
		if n != 2 { // 两台主机各一次
			t.Errorf("端口 %d 覆盖次数 %d，期望 2", p, n)
		}
	}
	if got := chunkPorts([]int{1, 2, 3}, 0); len(got) != 1 || len(got[0]) != 3 {
		t.Errorf("chunkPorts(0) 应不切分: %v", got)
	}
}

// Agent 的本地授权闸门必须生效：服务端可以下发任意目标，但 Agent 会拒绝并上报
func TestAgentLocalScopeGateRejectsOutOfScope(t *testing.T) {
	srv := New(Options{Token: "t", LeaseSeconds: 5, MaxTries: 1, SweepEvery: 100 * time.Millisecond, Log: quietLogger()})
	defer srv.Close()
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	// 下发一个不在 Agent 授权范围内的目标
	if _, err := srv.CreateScan(wire.ScanSpec{Hosts: []string{"192.0.2.77"}, Ports: []int{80}}); err != nil {
		t.Fatalf("创建扫描失败: %v", err)
	}

	cfg := agentScanConfig()
	cfg.Allow = []string{"127.0.0.0/8"} // 明确不含 192.0.2.0/24

	ag, err := agent.New(agent.Config{
		ServerURL: ts.URL, Token: "t", AgentID: "agent-gate",
		Scan: cfg, PullWaitSecs: 1, Log: quietLogger(),
		SpoolDir: t.TempDir(),
	})
	if err != nil {
		t.Fatalf("构造 Agent 失败: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	go func() { _ = ag.Run(ctx) }()

	deadline := time.Now().Add(25 * time.Second)
	for time.Now().Before(deadline) {
		st := srv.Stats()
		if st.Tasks[wire.TaskFailed]+st.Tasks[wire.TaskDone] > 0 {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	st := srv.Stats()
	if st.Tasks[wire.TaskFailed] != 1 {
		t.Fatalf("越界目标应判失败，实际 %+v", st.Tasks)
	}
	if n := len(srv.Assets()); n != 0 {
		t.Errorf("越界目标不应产生资产，实际 %d", n)
	}
	srv.mu.Lock()
	var rejected int
	for _, a := range srv.agents {
		_ = a
	}
	rejected = int(srv.counters.rejected)
	srv.mu.Unlock()
	if rejected == 0 {
		t.Error("Agent 应把被拦下的目标上报为 rejected（审计需要）")
	}
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("读取 %s 失败: %v", path, err)
	}
	return string(data)
}
