package server

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"westy_scan/internal/authz"
	"westy_scan/internal/diff"
	"westy_scan/internal/model"
	"westy_scan/internal/notify"
	"westy_scan/internal/poc"
	"westy_scan/internal/wire"
)

func m6Record() authz.Record {
	now := time.Now()
	return authz.Record{
		ID: "AB-2026-0001", Client: "测试客户",
		Allow: []string{"127.0.0.0/8", "10.0.0.0/24"}, Deny: []string{"10.0.0.1"},
		ValidFrom: now.Add(-time.Hour), ValidTo: now.Add(24 * time.Hour),
		Approver: "李四", Ticket: "SEC-1",
	}
}

func postJSON(t *testing.T, url, token string, body any) *http.Response {
	t.Helper()
	data, _ := json.Marshal(body)
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(data))
	if err != nil {
		t.Fatalf("构造请求失败: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("请求失败: %v", err)
	}
	return resp
}

func getJSON(t *testing.T, url, token string) *http.Response {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, url, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("请求失败: %v", err)
	}
	return resp
}

// 授权书闸门：没有授权书 / 范围不符 → 拒绝创建扫描
func TestScanRequiresValidAuthorization(t *testing.T) {
	srv := New(Options{Token: "admin", Log: quietLogger()})
	defer srv.Close()
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	// 1) 没有授权书 → 拒绝
	resp := postJSON(t, ts.URL+"/api/v1/scans", "admin", wire.ScanSpec{Hosts: []string{"10.0.0.5"}, Ports: []int{80}})
	if resp.StatusCode == http.StatusOK {
		t.Error("未关联授权书时应拒绝创建扫描")
	}
	resp.Body.Close()

	// 2) 授权书不存在 → 拒绝
	resp = postJSON(t, ts.URL+"/api/v1/scans", "admin", wire.ScanSpec{
		Hosts: []string{"10.0.0.5"}, Ports: []int{80}, Authorization: "NOT-EXIST",
	})
	if resp.StatusCode == http.StatusOK {
		t.Error("授权书不存在时应拒绝")
	}
	resp.Body.Close()

	// 3) 登记授权书后，范围内目标可以创建
	if err := srv.CreateAuthorization(m6Record()); err != nil {
		t.Fatalf("登记授权书失败: %v", err)
	}
	resp = postJSON(t, ts.URL+"/api/v1/scans", "admin", wire.ScanSpec{
		Hosts: []string{"10.0.0.5", "127.0.0.1"}, Ports: []int{80}, Authorization: m6Record().ID,
	})
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("范围内目标应允许创建，实际 %d: %s", resp.StatusCode, body)
	}
	var info wire.ScanInfo
	_ = json.NewDecoder(resp.Body).Decode(&info)
	resp.Body.Close()
	if info.Tasks == 0 {
		t.Error("扫描应产生任务")
	}

	// 4) 越界目标（deny 命中）→ 拒绝
	resp = postJSON(t, ts.URL+"/api/v1/scans", "admin", wire.ScanSpec{
		Hosts: []string{"10.0.0.1"}, Ports: []int{80}, Authorization: m6Record().ID,
	})
	if resp.StatusCode == http.StatusOK {
		t.Error("deny 命中的目标应被拒绝")
	}
	resp.Body.Close()

	// 5) 完全无关的目标 → 拒绝
	resp = postJSON(t, ts.URL+"/api/v1/scans", "admin", wire.ScanSpec{
		Hosts: []string{"203.0.113.9"}, Ports: []int{80}, Authorization: m6Record().ID,
	})
	if resp.StatusCode == http.StatusOK {
		t.Error("范围外目标应被拒绝")
	}
	resp.Body.Close()

	// 6) 过期授权书 → 拒绝
	expired := m6Record()
	expired.ID = "AB-EXPIRED"
	expired.ValidFrom = time.Now().Add(-48 * time.Hour)
	expired.ValidTo = time.Now().Add(-time.Hour)
	if err := srv.CreateAuthorization(expired); err == nil {
		t.Error("过期授权书不应被登记")
	}
}

// RBAC：viewer 只读、operator 能建扫描、admin 才能管授权书
func TestRBACRoles(t *testing.T) {
	srv := New(Options{
		Roles: map[string]string{"adm": "admin", "op": "operator", "view": "viewer"},
		Log:   quietLogger(),
	})
	defer srv.Close()
	if err := srv.CreateAuthorization(m6Record()); err != nil {
		t.Fatalf("登记授权书失败: %v", err)
	}
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	spec := wire.ScanSpec{Hosts: []string{"10.0.0.5"}, Ports: []int{80}, Authorization: m6Record().ID}

	// viewer：可以读，不能建扫描，不能管授权书
	if resp := getJSON(t, ts.URL+"/api/v1/stats", "view"); resp.StatusCode != http.StatusOK {
		t.Errorf("viewer 应能读统计，实际 %d", resp.StatusCode)
		resp.Body.Close()
	} else {
		resp.Body.Close()
	}
	if resp := postJSON(t, ts.URL+"/api/v1/scans", "view", spec); resp.StatusCode != http.StatusForbidden {
		t.Errorf("viewer 建扫描应 403，实际 %d", resp.StatusCode)
		resp.Body.Close()
	} else {
		resp.Body.Close()
	}
	if resp := postJSON(t, ts.URL+"/api/v1/authorizations", "view", m6Record()); resp.StatusCode != http.StatusForbidden {
		t.Errorf("viewer 管授权书应 403，实际 %d", resp.StatusCode)
		resp.Body.Close()
	} else {
		resp.Body.Close()
	}

	// operator：能建扫描，不能管授权书
	if resp := postJSON(t, ts.URL+"/api/v1/scans", "op", spec); resp.StatusCode != http.StatusOK {
		t.Errorf("operator 应能建扫描，实际 %d", resp.StatusCode)
		resp.Body.Close()
	} else {
		resp.Body.Close()
	}
	if resp := postJSON(t, ts.URL+"/api/v1/authorizations", "op", m6Record()); resp.StatusCode != http.StatusForbidden {
		t.Errorf("operator 管授权书应 403，实际 %d", resp.StatusCode)
		resp.Body.Close()
	} else {
		resp.Body.Close()
	}

	// admin：全都能
	rec := m6Record()
	rec.ID = "AB-2026-0002"
	if resp := postJSON(t, ts.URL+"/api/v1/authorizations", "adm", rec); resp.StatusCode != http.StatusOK {
		t.Errorf("admin 应能管授权书，实际 %d", resp.StatusCode)
		resp.Body.Close()
	} else {
		resp.Body.Close()
	}

	// 无效 token → 401
	if resp := getJSON(t, ts.URL+"/api/v1/stats", "bogus"); resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("无效 token 应 401，实际 %d", resp.StatusCode)
		resp.Body.Close()
	} else {
		resp.Body.Close()
	}
	// Agent 接口需要 operator 及以上
	if resp := postJSON(t, ts.URL+"/api/v1/agents/pull", "view", wire.PullRequest{AgentID: "a"}); resp.StatusCode != http.StatusForbidden {
		t.Errorf("viewer 调 Agent 接口应 403，实际 %d", resp.StatusCode)
		resp.Body.Close()
	} else {
		resp.Body.Close()
	}
}

// 持久化：重启后任务/资产/漏洞/授权书都还在，且"执行中"的任务回到待执行
func TestPersistenceAcrossRestart(t *testing.T) {
	dir := t.TempDir()

	srv := New(Options{Token: "t", DataDir: dir, Log: quietLogger()})
	if err := srv.CreateAuthorization(m6Record()); err != nil {
		t.Fatalf("登记授权书失败: %v", err)
	}
	info, err := srv.CreateScanAuthorized(wire.ScanSpec{
		ScanID: "scan-persist", Hosts: []string{"10.0.0.5", "10.0.0.6"},
		Ports: []int{80, 443}, JobPorts: 1, Authorization: m6Record().ID,
	})
	if err != nil {
		t.Fatalf("创建扫描失败: %v", err)
	}
	// 领走一个任务（模拟执行中），再汇报资产与漏洞
	jobs := srv.claim("agent-x", 1)
	if len(jobs) != 1 {
		t.Fatalf("应领到 1 个任务")
	}
	srv.ingestAssets("scan-persist", "agent-x", []model.Asset{
		{Host: "10.0.0.5", Port: 80, Service: "http", FoundAt: time.Now()},
	})
	srv.ingestFindings("scan-persist", "agent-x", []poc.Finding{
		findingFor("nacos-unauthorized-user-list", "http://10.0.0.5/nacos"),
	})
	srv.applyOutcome(wire.TaskOutcome{JobID: jobs[0].ID, State: wire.TaskDone})
	srv.Close()

	// 重启
	srv2 := New(Options{Token: "t", DataDir: dir, Log: quietLogger()})
	defer srv2.Close()

	if got := srv2.ScanInfo("scan-persist"); got == nil {
		t.Fatal("重启后扫描视图丢失")
	} else if got.Tasks != info.Tasks {
		t.Errorf("任务数应恢复为 %d，实际 %d", info.Tasks, got.Tasks)
	}
	if n := len(srv2.Assets()); n != 1 {
		t.Errorf("资产应恢复 1 条，实际 %d", n)
	}
	if n := len(srv2.Findings()); n != 1 {
		t.Errorf("漏洞应恢复 1 条，实际 %d", n)
	}
	if n := len(srv2.Authorizations()); n != 1 {
		t.Errorf("授权书应恢复 1 份，实际 %d", n)
	}
	// 重启时"执行中"的任务必须回到待执行（Agent 连接已断，租约无意义）
	var pending, running int
	for _, t2 := range srv2.snapshot().Tasks {
		switch t2.State {
		case wire.TaskPending:
			pending++
		case wire.TaskRunning:
			running++
		}
	}
	if running != 0 {
		t.Errorf("重启后不应有 running 任务，实际 %d", running)
	}
	if pending == 0 {
		t.Error("重启后应有任务可被重新派发")
	}
	// 恢复后还能继续创建扫描（授权书仍有效）
	if _, err := srv2.CreateScanAuthorized(wire.ScanSpec{
		ScanID: "scan-after-restart", Hosts: []string{"10.0.0.9"}, Ports: []int{80},
		Authorization: m6Record().ID,
	}); err != nil {
		t.Errorf("重启后创建扫描失败: %v", err)
	}
}

// 对比接口：两次扫描之间能看出新增漏洞
func TestDiffEndpoint(t *testing.T) {
	srv := New(Options{Token: "t", Log: quietLogger()})
	defer srv.Close()
	if err := srv.CreateAuthorization(m6Record()); err != nil {
		t.Fatalf("登记授权书失败: %v", err)
	}
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	for _, id := range []string{"s1", "s2"} {
		if _, err := srv.CreateScanAuthorized(wire.ScanSpec{
			ScanID: id, Hosts: []string{"10.0.0.5"}, Ports: []int{80}, Authorization: m6Record().ID,
		}); err != nil {
			t.Fatalf("创建 %s 失败: %v", id, err)
		}
	}
	srv.ingestAssets("s1", "a", []model.Asset{{Host: "10.0.0.5", Port: 80, Service: "http", FoundAt: time.Now()}})
	srv.ingestAssets("s2", "a", []model.Asset{
		{Host: "10.0.0.5", Port: 80, Service: "http", FoundAt: time.Now()},
		{Host: "10.0.0.5", Port: 8080, Service: "http", FoundAt: time.Now()},
	})
	srv.ingestFindings("s2", "a", []poc.Finding{
		findingFor("git-config-exposure", "http://10.0.0.5/.git/config"),
	})

	resp := getJSON(t, ts.URL+"/api/v1/scans/diff?scan_id=s2&against=s1", "t")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("对比接口应 200，实际 %d", resp.StatusCode)
	}
	var res struct {
		Summary struct {
			NewAssets   int `json:"new_assets"`
			NewFindings int `json:"new_findings"`
			NewHighRisk int `json:"new_high_risk"`
		} `json:"summary"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		t.Fatalf("解析对比结果失败: %v", err)
	}
	if res.Summary.NewAssets != 1 {
		t.Errorf("应识别出 1 个新增资产，实际 %d", res.Summary.NewAssets)
	}
	if res.Summary.NewFindings != 1 || res.Summary.NewHighRisk != 1 {
		t.Errorf("应识别出 1 个新增高危漏洞，实际 %+v", res.Summary)
	}

	// 缺参数应报错
	resp2 := getJSON(t, ts.URL+"/api/v1/scans/diff?scan_id=s2", "t")
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusBadRequest {
		t.Errorf("缺 against 参数应 400，实际 %d", resp2.StatusCode)
	}
}

// 回归：重复扫到同样的资产/漏洞，不能被 diff 报成"已消失/已修复"
//
// 背景（演示中真实踩到的坑）：聚合表是全局去重的，同一条记录只保留首次出现的样本，
// 其 scan_id 指向第一次。若按 scan_id 判断"本次扫描看到了什么"，
// 第二次扫描就会显示 0 资产 0 漏洞，diff 报出 10 个"已修复"——纯属假信号。
func TestRescanDoesNotReportFixed(t *testing.T) {
	dir := t.TempDir()
	srv := New(Options{Token: "t", DataDir: dir, Log: quietLogger()})
	if err := srv.CreateAuthorization(m6Record()); err != nil {
		t.Fatalf("登记授权书失败: %v", err)
	}
	for _, id := range []string{"s1", "s2"} {
		if _, err := srv.CreateScanAuthorized(wire.ScanSpec{
			ScanID: id, Hosts: []string{"10.0.0.5"}, Ports: []int{80}, Authorization: m6Record().ID,
		}); err != nil {
			t.Fatalf("创建 %s 失败: %v", id, err)
		}
	}
	asset := model.Asset{Host: "10.0.0.5", Port: 80, Service: "http", Product: "nginx", FoundAt: time.Now()}
	finding := findingFor("git-config-exposure", "http://10.0.0.5/.git/config")
	// 两次扫描都观察到同样的资产与漏洞
	for _, id := range []string{"s1", "s2"} {
		srv.ingestAssets(id, "a", []model.Asset{asset})
		srv.ingestFindings(id, "a", []poc.Finding{finding})
	}

	// 1) 第二次扫描自己的计数必须是"这次看到了 1 个"，而不是 0
	if info := srv.ScanInfo("s2"); info == nil {
		t.Fatal("找不到 s2 扫描视图")
	} else if info.Assets != 1 || info.Findings != 1 {
		t.Errorf("s2 应记录观察到 1 资产/1 漏洞，实际 %d/%d", info.Assets, info.Findings)
	}

	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	// 2) diff：没有新增、没有消失、没有修复
	resp := getJSON(t, ts.URL+"/api/v1/scans/diff?scan_id=s2&against=s1", "t")
	var res diff.Result
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		t.Fatalf("解析对比结果失败: %v", err)
	}
	resp.Body.Close()
	if s := res.Summary; s.NewAssets != 0 || s.GoneAssets != 0 || s.NewFindings != 0 || s.FixedFindings != 0 {
		t.Errorf("重复扫描不应产生任何变化，实际 %+v", s)
	}

	// 3) 按扫描过滤的接口也要以"观察到"为准
	assetsResp := getJSON(t, ts.URL+"/api/v1/assets?scan_id=s2", "t")
	var assets []model.Asset
	_ = json.NewDecoder(assetsResp.Body).Decode(&assets)
	assetsResp.Body.Close()
	if len(assets) != 1 {
		t.Errorf("s2 的资产列表应为 1 条，实际 %d", len(assets))
	}
	findResp := getJSON(t, ts.URL+"/api/v1/findings?scan_id=s2", "t")
	var findings []poc.Finding
	_ = json.NewDecoder(findResp.Body).Decode(&findings)
	findResp.Body.Close()
	if len(findings) != 1 {
		t.Errorf("s2 的漏洞列表应为 1 条，实际 %d", len(findings))
	}
	// 4) s2 的报告里必须包含这条漏洞（同样走观察集合）
	rep := getJSON(t, ts.URL+"/api/v1/report?format=markdown&scan_id=s2", "t")
	repBody, _ := io.ReadAll(rep.Body)
	rep.Body.Close()
	if !strings.Contains(string(repBody), "git-config-exposure") {
		t.Error("s2 的报告应包含它自己观察到的漏洞")
	}
	srv.Close()

	// 5) 重启后观察集合仍在（否则重启即产生假"已修复"）
	srv2 := New(Options{Token: "t", DataDir: dir, Log: quietLogger()})
	defer srv2.Close()
	if info := srv2.ScanInfo("s2"); info == nil {
		t.Fatal("重启后 s2 丢失")
	} else if info.Assets != 1 || info.Findings != 1 {
		t.Errorf("重启后 s2 观察计数应为 1/1，实际 %d/%d", info.Assets, info.Findings)
	}
}

// Web UI 与报告导出
func TestWebUIAndReportExport(t *testing.T) {
	srv := New(Options{Token: "t", Log: quietLogger()})
	defer srv.Close()
	if err := srv.CreateAuthorization(m6Record()); err != nil {
		t.Fatalf("登记授权书失败: %v", err)
	}
	if _, err := srv.CreateScanAuthorized(wire.ScanSpec{
		ScanID: "s1", Hosts: []string{"10.0.0.5"}, Ports: []int{80}, Authorization: m6Record().ID,
	}); err != nil {
		t.Fatalf("创建扫描失败: %v", err)
	}
	srv.ingestAssets("s1", "a", []model.Asset{{Host: "10.0.0.5", Port: 80, Service: "http", Product: "nginx", FoundAt: time.Now()}})
	srv.ingestFindings("s1", "a", []poc.Finding{findingFor("git-config-exposure", "http://10.0.0.5/.git/config")})

	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	// UI 页面（静态资源不需要鉴权）
	resp, err := http.Get(ts.URL + "/")
	if err != nil {
		t.Fatalf("获取 UI 失败: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("UI 应 200，实际 %d", resp.StatusCode)
	}
	for _, marker := range []string{"westy_scan 控制台", "/api/v1/scans", "授权书"} {
		if !strings.Contains(string(body), marker) {
			t.Errorf("UI 缺少标记 %q", marker)
		}
	}

	// HTML 报告
	rep := getJSON(t, ts.URL+"/api/v1/report?format=html&scan_id=s1", "t")
	repBody, _ := io.ReadAll(rep.Body)
	rep.Body.Close()
	if rep.StatusCode != http.StatusOK {
		t.Fatalf("报告应 200，实际 %d", rep.StatusCode)
	}
	html := string(repBody)
	for _, marker := range []string{"<!DOCTYPE html>", "漏洞验证结果", "git-config-exposure", "10.0.0.5"} {
		if !strings.Contains(html, marker) {
			t.Errorf("HTML 报告缺少 %q", marker)
		}
	}
	// Markdown 报告
	md := getJSON(t, ts.URL+"/api/v1/report?format=markdown&scan_id=s1", "t")
	mdBody, _ := io.ReadAll(md.Body)
	md.Body.Close()
	if !strings.Contains(string(mdBody), "## 漏洞验证结果") {
		t.Error("Markdown 报告缺少漏洞章节")
	}
}

// 通知：新漏洞达到阈值时触发 webhook
func TestNotifyWebhook(t *testing.T) {
	var got int32
	var lastBody []byte
	receiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&got, 1)
		lastBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer receiver.Close()

	notifier := notify.New(notify.Options{URL: receiver.URL, Format: notify.FormatWeCom})
	srv := New(Options{Token: "t", Log: quietLogger(), Notify: notifier, NotifyMinSeverity: "high"})
	defer srv.Close()

	// 低于阈值：不通知
	lowFinding := findingFor("t-low", "u1")
	lowFinding.Severity = "low"
	srv.ingestFindings("s1", "a", []poc.Finding{lowFinding})
	srv.notifyFindings([]poc.Finding{lowFinding})
	if n := atomic.LoadInt32(&got); n != 0 {
		t.Errorf("低于阈值的漏洞不应通知，实际收到 %d 次", n)
	}

	// 达到阈值：通知，且内容是企微 markdown 结构
	highFinding := findingFor("t-high", "u2")
	highFinding.Severity = "high"
	findings := []poc.Finding{highFinding}
	srv.ingestFindings("s1", "a", findings)
	srv.notifyFindings(findings)
	if n := atomic.LoadInt32(&got); n != 1 {
		t.Fatalf("应收到 1 次通知，实际 %d", n)
	}
	var payload map[string]any
	if err := json.Unmarshal(lastBody, &payload); err != nil {
		t.Fatalf("通知体不是 JSON: %v", err)
	}
	if payload["msgtype"] != "markdown" {
		t.Errorf("企微格式应为 markdown，实际 %v", payload["msgtype"])
	}
	if !strings.Contains(string(lastBody), "t-high") {
		t.Errorf("通知内容应包含模板名: %s", lastBody)
	}
}

// 定时扫描：调度器会按间隔创建新扫描
func TestSchedulerCreatesScans(t *testing.T) {
	srv := New(Options{
		Token: "t", Log: quietLogger(),
		ScheduleEvery: 100 * time.Millisecond,
		ScheduleSpec: &wire.ScanSpec{
			Hosts: []string{"10.0.0.5"}, Ports: []int{80}, Authorization: m6Record().ID,
		},
	})
	defer srv.Close()
	if err := srv.CreateAuthorization(m6Record()); err != nil {
		t.Fatalf("登记授权书失败: %v", err)
	}

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if len(srv.Stats().Scans) >= 2 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if n := len(srv.Stats().Scans); n < 2 {
		t.Fatalf("定时扫描应至少创建 2 次，实际 %d", n)
	}
}
