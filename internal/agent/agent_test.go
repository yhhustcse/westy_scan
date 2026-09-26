package agent

// 本文件只覆盖 internal/agent 这个"分布式执行端"的行为：
// 本地授权闸门、批量上报、断线缓冲与重放、长轮询拉取、鉴权失败的处理。
//
// 全部使用标准库（httptest + testing），不需要任何第三方依赖；
// 临时目录一律用 t.TempDir()，不往工作区写东西。

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"westy_scan/internal/config"
	"westy_scan/internal/model"
	"westy_scan/internal/wire"
)

// ---------------------------------------------------------------------------
// 假 Server：实现 register / pull / report 三个协议端点，报文留在内存里供断言
// ---------------------------------------------------------------------------

// reportCall 记录一次上报请求，以及服务端是否接受了它（返回 200）。
type reportCall struct {
	req      wire.ReportRequest
	accepted bool
}

// pullCall 记录一次拉取请求，以及服务端是否放行（返回 200）；accepted=false 即被 401 拒。
type pullCall struct {
	req      wire.PullRequest
	accepted bool
}

type fakeServer struct {
	token   string // 非空时校验 Bearer token（与 wire.TokenOK 同一套语义）
	agentID string // 服务端"分配"的 agent id

	mu         sync.Mutex
	ts         *httptest.Server
	registers  []wire.RegisterRequest
	pulls      []pullCall
	reports    []reportCall
	failReport bool             // report 一律返回 500，模拟服务端故障
	rejectPull bool             // pull 一律返回 401，模拟 token 过期/失效
	pullJobs   [][]wire.JobSpec // 第 n 次 pull 返回的任务；超出后返回空
	pullWait   time.Duration    // 无任务时服务端停留多久（模拟长轮询）
	onReport   func()           // 收到上报时的回调（用于在"任务执行中"取消 ctx）
}

func newFakeServer(token string) *fakeServer {
	return &fakeServer{token: token, agentID: "server-assigned-agent"}
}

func (f *fakeServer) mux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/agents/register", f.handleRegister)
	mux.HandleFunc("/api/v1/agents/pull", f.handlePull)
	mux.HandleFunc("/api/v1/agents/report", f.handleReport)
	return mux
}

func (f *fakeServer) start(t *testing.T) {
	t.Helper()
	f.ts = httptest.NewServer(f.mux())
	t.Cleanup(f.ts.Close)
}

func (f *fakeServer) startTLS(t *testing.T) {
	t.Helper()
	f.ts = httptest.NewTLSServer(f.mux())
	f.ts.Config.ErrorLog = log.New(io.Discard, "", 0) // 负例会产生 TLS 握手错误，不必打到测试输出
	t.Cleanup(f.ts.Close)
}

// authOK 校验 Bearer token；token 为空表示开发模式（不校验）。
func (f *fakeServer) authOK(w http.ResponseWriter, r *http.Request) bool {
	f.mu.Lock()
	token := f.token
	f.mu.Unlock()
	if wire.TokenOK(r.Header.Get("Authorization"), token) {
		return true
	}
	http.Error(w, "unauthorized", http.StatusUnauthorized)
	return false
}

func (f *fakeServer) handleRegister(w http.ResponseWriter, r *http.Request) {
	var req wire.RegisterRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	f.mu.Lock()
	f.registers = append(f.registers, req)
	f.mu.Unlock()
	if !f.authOK(w, r) {
		return
	}
	writeJSON(w, wire.RegisterResponse{
		AgentID:       f.agentID,
		LeaseSeconds:  5,
		HeartbeatSecs: 1,
		Protocol:      wire.ProtocolVersion,
		ServerVersion: "fake-server",
	})
}

func (f *fakeServer) handlePull(w http.ResponseWriter, r *http.Request) {
	var req wire.PullRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	f.mu.Lock()
	f.pulls = append(f.pulls, pullCall{req: req})
	n := len(f.pulls)
	reject := f.rejectPull
	wait := f.pullWait
	var jobs []wire.JobSpec
	if n-1 < len(f.pullJobs) {
		jobs = f.pullJobs[n-1]
	}
	f.mu.Unlock()

	accepted := f.authOK(w, r)
	if accepted && reject {
		http.Error(w, "token expired", http.StatusUnauthorized)
		accepted = false
	}
	f.mu.Lock()
	f.pulls[n-1].accepted = accepted
	f.mu.Unlock()
	if !accepted {
		return
	}
	// 模拟服务端长轮询：无任务时挂住，直到超时或客户端放弃
	if len(jobs) == 0 && wait > 0 {
		select {
		case <-r.Context().Done():
		case <-time.After(wait):
		}
	}
	writeJSON(w, wire.PullResponse{Jobs: jobs})
}

func (f *fakeServer) handleReport(w http.ResponseWriter, r *http.Request) {
	var req wire.ReportRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	f.mu.Lock()
	f.reports = append(f.reports, reportCall{req: req})
	fail := f.failReport
	hook := f.onReport
	idx := len(f.reports) - 1
	f.mu.Unlock()

	if hook != nil {
		hook()
	}

	authorized := f.authOK(w, r)
	accepted := authorized && !fail
	f.mu.Lock()
	f.reports[idx].accepted = accepted
	f.mu.Unlock()
	if !accepted {
		if authorized {
			http.Error(w, "internal error", http.StatusInternalServerError)
		}
		return
	}
	writeJSON(w, wire.ReportResponse{AcceptedAssets: len(req.Assets), KnownScans: true})
}

func (f *fakeServer) setFailReport(v bool) {
	f.mu.Lock()
	f.failReport = v
	f.mu.Unlock()
}

// setOnReport 注册"收到上报"回调；必须在 Agent 启动前调用。
func (f *fakeServer) setOnReport(fn func()) {
	f.mu.Lock()
	f.onReport = fn
	f.mu.Unlock()
}

func (f *fakeServer) registerCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.registers)
}

func (f *fakeServer) pullCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.pulls)
}

func (f *fakeServer) pullCalls() []pullCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]pullCall(nil), f.pulls...)
}

func (f *fakeServer) allReports() []reportCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]reportCall(nil), f.reports...)
}

// acceptedReports 只返回服务端真正接受（200）的报文。
func (f *fakeServer) acceptedReports() []wire.ReportRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []wire.ReportRequest
	for _, c := range f.reports {
		if c.accepted {
			out = append(out, c.req)
		}
	}
	return out
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func decodeJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	if err := json.NewDecoder(io.LimitReader(r.Body, 4<<20)).Decode(v); err != nil {
		http.Error(w, "bad json: "+err.Error(), http.StatusBadRequest)
		return false
	}
	return true
}

// ---------------------------------------------------------------------------
// 测试用 Agent / 扫描配置
// ---------------------------------------------------------------------------

// testScanConfig 是 Agent 的本地扫描配置模板：与 e2e 里的 agentScanConfig 同一套闸门，
// 但关掉了 POC / 服务识别 / 爬虫，保证单测既不慢也不依赖内置模板。
func testScanConfig(allow, deny []string) config.Config {
	cfg := config.Default()
	cfg.Authorized = true
	cfg.Allow = allow
	cfg.Deny = deny
	cfg.StrictScope = true
	cfg.Concurrency = 8
	cfg.TimeoutSec = 1
	cfg.ServiceDetect = false
	cfg.Crawl = false
	cfg.SanExpand = false
	cfg.UDP = false
	cfg.BlindWebProbes = 10 // 允许对非标准端口盲试 HTTP（httptest 用的是随机端口）
	cfg.POCEnabled = false
	cfg.OutputFormat = "table"
	return cfg
}

// newTestAgent 构造一个指向假 Server 的 Agent（缓冲目录固定落在 t.TempDir() 里）。
func newTestAgent(t *testing.T, f *fakeServer, mutate func(*Config)) *Agent {
	t.Helper()
	cfg := Config{
		ServerURL:  f.ts.URL,
		Token:      f.token,
		AgentID:    "agent-under-test",
		Scan:       testScanConfig([]string{"127.0.0.0/8"}, nil),
		SpoolDir:   filepath.Join(t.TempDir(), "spool"),
		Log:        log.New(io.Discard, "", 0),
		MaxJobs:    2,
		BatchSize:  200,
		FlushEvery: time.Hour,
	}
	if mutate != nil {
		mutate(&cfg)
	}
	ag, err := New(cfg)
	if err != nil {
		t.Fatalf("构造 Agent 失败: %v", err)
	}
	return ag
}

// registerAgent 走一次真实注册流程；Run 在收到注册响应后会把 id 落到 Agent 上，这里复现同一步。
func registerAgent(t *testing.T, ag *Agent) {
	t.Helper()
	reg, err := ag.register(context.Background())
	if err != nil {
		t.Fatalf("注册失败: %v", err)
	}
	if reg.AgentID == "" {
		t.Fatal("服务端未返回 agent_id")
	}
	ag.id = reg.AgentID
}

func testAsset(i int) model.Asset {
	return model.Asset{
		Host: "127.0.0.1", IP: "127.0.0.1", Port: 20000 + i,
		Source: "portscan", FoundAt: time.Now(),
	}
}

// newLoopbackSite 起一个真的 HTTP 站点（在 127.0.0.1 上），返回端口。
func newLoopbackSite(t *testing.T) int {
	t.Helper()
	site := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, "<html><head><title>in-scope</title></head><body>ok</body></html>")
	}))
	t.Cleanup(site.Close)
	_, portStr, err := net.SplitHostPort(strings.TrimPrefix(site.URL, "http://"))
	if err != nil {
		t.Fatalf("解析测试站点地址失败: %v", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("解析测试站点端口失败: %v", err)
	}
	return port
}

// ---------------------------------------------------------------------------
// 1. 本地授权闸门
// ---------------------------------------------------------------------------

// 服务端可以下发任意目标，但 Agent 必须用自己的 allow/deny 复检：
// 越界目标一条资产都不许产生，且要单独上报 rejected 供审计。
func TestAgentLocalScopeGateRejectsOutOfScope(t *testing.T) {
	sitePort := newLoopbackSite(t)

	cases := []struct {
		name         string
		allow        []string
		deny         []string
		host         string
		ports        []int
		wantState    wire.TaskState
		wantRejected bool
		wantAssets   bool
	}{
		{
			name:  "越界目标（不在 allow 内）被本地闸门拦下",
			allow: []string{"127.0.0.0/8"}, host: "192.0.2.77", ports: []int{80},
			wantState: wire.TaskFailed, wantRejected: true, wantAssets: false,
		},
		{
			name:  "命中 deny 规则的目标被本地闸门拦下",
			allow: []string{"127.0.0.0/8"}, deny: []string{"127.0.0.2"},
			host: "127.0.0.2", ports: []int{80},
			wantState: wire.TaskFailed, wantRejected: true, wantAssets: false,
		},
		{
			name:  "范围内目标正常执行并上报资产",
			allow: []string{"127.0.0.0/8"}, host: "127.0.0.1", ports: []int{sitePort},
			wantState: wire.TaskDone, wantRejected: false, wantAssets: true,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeServer("")
			f.start(t)
			ag := newTestAgent(t, f, func(c *Config) {
				c.Scan = testScanConfig(tc.allow, tc.deny)
			})
			registerAgent(t, ag)

			job := wire.JobSpec{ID: "job-gate", ScanID: "scan-gate", Host: tc.host, Ports: tc.ports}
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			ag.runJob(ctx, job)

			reports := f.acceptedReports()
			if len(reports) != 1 {
				t.Fatalf("一个任务应恰好上报一次，实际 %d 次", len(reports))
			}
			rep := reports[0]
			if rep.ScanID != job.ScanID {
				t.Errorf("上报 scan_id = %q，期望 %q", rep.ScanID, job.ScanID)
			}
			if rep.AgentID != ag.id || rep.AgentID == "" {
				t.Errorf("上报 agent_id = %q，期望 %q", rep.AgentID, ag.id)
			}
			if len(rep.Outcomes) != 1 {
				t.Fatalf("应带 1 条任务结果，实际 %d 条", len(rep.Outcomes))
			}
			out := rep.Outcomes[0]
			if out.JobID != job.ID || out.State != tc.wantState {
				t.Errorf("任务结果 = %+v，期望 job_id=%s state=%s", out, job.ID, tc.wantState)
			}

			if tc.wantRejected {
				if !strings.Contains(out.Error, "授权范围") {
					t.Errorf("越界任务必须给出授权范围错误，实际 %q", out.Error)
				}
				if len(rep.Rejected) != 1 || rep.Rejected[0] != job.Host {
					t.Errorf("rejected = %v，期望恰好 [%s]（审计要能看出拒绝了什么）", rep.Rejected, job.Host)
				}
			} else if out.Error != "" || len(rep.Rejected) != 0 {
				t.Errorf("范围内目标不应被判失败: error=%q rejected=%v", out.Error, rep.Rejected)
			}

			// 核心断言：越界时上报的资产数必须为 0
			if !tc.wantAssets {
				if n := len(rep.Assets); n != 0 {
					t.Errorf("越界目标不应产生任何资产，实际 %d 条: %+v", n, rep.Assets)
				}
			} else {
				if len(rep.Assets) == 0 {
					t.Error("范围内目标应上报资产，实际 0 条")
				}
				for _, a := range rep.Assets {
					if a.Host != tc.host {
						t.Errorf("资产不属于本任务目标: %+v", a)
					}
				}
			}
		})
	}
}

// ---------------------------------------------------------------------------
// 2. 批量上报（reportStore）
// ---------------------------------------------------------------------------

// 上报必须"攒批"：够 BatchSize 立刻发，不够就等 FlushEvery；
// 每批条数不得超过阈值，且数据不重不漏。
func TestReportStoreBatchesBySizeAndTime(t *testing.T) {
	cases := []struct {
		name         string
		batchSize    int
		flushEvery   time.Duration
		gap          time.Duration
		adds         int
		wantBatches  []int // 收尾之前的中途批次；nil = 批次划分受调度影响，只断言下限与单批上限
		wantLeftover int   // 收尾报文里应带上的剩余资产
	}{
		{name: "达到批量阈值立即上报", batchSize: 3, flushEvery: time.Hour, adds: 3, wantBatches: []int{3}, wantLeftover: 0},
		{name: "超过阈值时分批上报", batchSize: 3, flushEvery: time.Hour, adds: 7, wantBatches: []int{3, 3}, wantLeftover: 1},
		{name: "按时间间隔触发上报", batchSize: 100, flushEvery: 2 * time.Millisecond, gap: 100 * time.Millisecond, adds: 2, wantLeftover: 0},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeServer("")
			f.start(t)
			ag := newTestAgent(t, f, func(c *Config) {
				c.BatchSize = tc.batchSize
				c.FlushEvery = tc.flushEvery
			})
			registerAgent(t, ag)

			rs := newReportStore(ag, "scan-batch")
			assets := make([]model.Asset, 0, tc.adds)
			for i := 0; i < tc.adds; i++ {
				if i > 0 && tc.gap > 0 {
					time.Sleep(tc.gap)
				}
				a := testAsset(i)
				assets = append(assets, a)
				if err := rs.Add(a); err != nil {
					t.Fatalf("Add 第 %d 条失败: %v", i, err)
				}
			}

			var got []int
			for _, rep := range f.acceptedReports() {
				if len(rep.Assets) > tc.batchSize {
					t.Errorf("单批 %d 条超过批量阈值 %d", len(rep.Assets), tc.batchSize)
				}
				if rep.ScanID != "scan-batch" {
					t.Errorf("批量报文 scan_id = %q，期望 scan-batch", rep.ScanID)
				}
				if rep.AgentID != ag.id || rep.AgentID == "" {
					t.Errorf("批量报文 agent_id = %q，期望 %q", rep.AgentID, ag.id)
				}
				got = append(got, len(rep.Assets))
			}
			if tc.wantBatches != nil {
				if !equalInts(got, tc.wantBatches) {
					t.Errorf("分批结果 = %v，期望 %v", got, tc.wantBatches)
				}
			} else if len(got) == 0 {
				t.Errorf("按时间间隔应至少触发一次中途上报，实际 0 次（批次=%v）", got)
			}

			// 收尾：剩余资产 + 任务结果一起上报
			outcome := wire.TaskOutcome{JobID: "job-batch", Host: "127.0.0.1", State: wire.TaskDone}
			if err := rs.Flush(context.Background(), outcome, nil, nil); err != nil {
				t.Fatalf("收尾上报失败: %v", err)
			}
			reports := f.acceptedReports()
			last := reports[len(reports)-1]
			if len(last.Outcomes) != 1 || last.Outcomes[0].JobID != outcome.JobID {
				t.Errorf("收尾报文缺少任务结果: %+v", last.Outcomes)
			}
			if len(last.Assets) != tc.wantLeftover {
				t.Errorf("收尾报文里剩余资产 = %d 条，期望 %d（前面已分批发完剩下的）", len(last.Assets), tc.wantLeftover)
			}

			// 全部资产不重不漏，且计数正确
			assertNoLossNoDup(t, reports, assets)
			if rs.Total() != tc.adds || rs.Len() != tc.adds {
				t.Errorf("计数错误: Total=%d Len=%d，期望 %d", rs.Total(), rs.Len(), tc.adds)
			}
			if n := len(rs.Assets()); n != tc.adds {
				t.Errorf("内存副本 = %d 条，期望 %d", n, tc.adds)
			}
			if err := rs.Close(); err != nil {
				t.Errorf("Close 应返回 nil，实际 %v", err)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// 3. 断线缓冲与重放（spool）
// ---------------------------------------------------------------------------

// 上报失败必须落盘到 spool 目录；服务端恢复后重放要"不丢不重"。
func TestReportStoreSpoolAndReplay(t *testing.T) {
	t.Run("扫描成功但上报 500：结果落缓冲，恢复后不丢不重", func(t *testing.T) {
		sitePort := newLoopbackSite(t)

		f := newFakeServer("")
		f.start(t)
		ag := newTestAgent(t, f, func(c *Config) {
			c.BatchSize = 1 // 每条资产立即尝试上报 → 更容易触发部分失败
		})
		registerAgent(t, ag)

		f.setFailReport(true) // 服务端故障
		job := wire.JobSpec{ID: "job-spool", ScanID: "scan-spool", Host: "127.0.0.1", Ports: []int{sitePort}}
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		ag.runJob(ctx, job)

		if n := len(f.acceptedReports()); n != 0 {
			t.Errorf("服务端故障期间不应有任何上报被接受，实际 %d 次", n)
		}
		spoolDir := ag.cfg.SpoolDir
		if n := spoolCount(t, spoolDir); n == 0 {
			t.Fatal("上报失败的结果必须写入 spool 目录，实际目录为空")
		}

		// 缓冲内容就是"服务端本该收到的东西"
		spooled := spooledReports(t, spoolDir)
		var want []model.Asset
		sawOutcome := false
		for _, rep := range spooled {
			want = append(want, rep.Assets...)
			if rep.ScanID != job.ScanID {
				t.Errorf("缓冲报文 scan_id = %q，期望 %q", rep.ScanID, job.ScanID)
			}
			if rep.Outcome != nil && rep.Outcome.JobID == job.ID && rep.Outcome.State == wire.TaskDone {
				sawOutcome = true
			}
		}
		if len(want) == 0 {
			t.Fatal("扫描成功却在缓冲里没有任何资产")
		}
		if !sawOutcome {
			t.Error("缓冲里缺少任务完成状态（服务端将永远不知道该任务已结束）")
		}

		// 服务端恢复 → 重放
		f.setFailReport(false)
		ag.replaySpool(ctx)

		if n := spoolCount(t, spoolDir); n != 0 {
			t.Errorf("重放成功后缓冲应被清空，实际还剩 %d 个文件", n)
		}
		reports := f.acceptedReports()
		assertNoLossNoDup(t, reports, want)
		replayedOutcome := false
		for _, rep := range reports {
			for _, o := range rep.Outcomes {
				if o.JobID == job.ID && o.State == wire.TaskDone {
					replayedOutcome = true
				}
			}
		}
		if !replayedOutcome {
			t.Error("重放后仍缺少任务完成状态")
		}
	})

	t.Run("服务端不可达：先落盘，换到可用服务端后重放", func(t *testing.T) {
		f := newFakeServer("")
		f.start(t)
		ag := newTestAgent(t, f, func(c *Config) {
			c.BatchSize = 2
		})
		registerAgent(t, ag)
		f.ts.Close() // 服务端直接下线（连接被拒）

		rs := newReportStore(ag, "scan-down")
		for i := 0; i < 2; i++ {
			if err := rs.Add(testAsset(i)); err != nil {
				t.Fatalf("Add 失败: %v", err)
			}
		}
		outcome := wire.TaskOutcome{JobID: "job-down", Host: "127.0.0.1", State: wire.TaskDone}
		if err := rs.Flush(context.Background(), outcome, nil, nil); err == nil {
			t.Fatal("服务端不可达时上报应返回错误")
		} else if !strings.Contains(err.Error(), "本地缓冲") {
			t.Errorf("上报失败应说明已写入本地缓冲，实际 %v", err)
		}
		spoolDir := ag.cfg.SpoolDir
		if n := spoolCount(t, spoolDir); n != 2 {
			t.Fatalf("应有 2 个缓冲文件（1 批资产 + 1 份收尾），实际 %d 个", n)
		}

		// 服务端还没恢复：重放必须失败并保留缓冲（下次再试，绝不丢数据）
		ag.replaySpool(context.Background())
		if n := spoolCount(t, spoolDir); n != 2 {
			t.Errorf("服务端不可达时重放不应删除缓冲，实际剩 %d 个文件", n)
		}
		if n := len(f.acceptedReports()); n != 0 {
			t.Errorf("服务端不可达时不应有上报被接受，实际 %d 次", n)
		}

		// "服务端恢复"：换一个可用的服务端地址（同一 agent id 继续上报）
		back := newFakeServer("")
		back.start(t)
		ag.cfg.ServerURL = back.ts.URL
		ag.replaySpool(context.Background())

		if n := spoolCount(t, spoolDir); n != 0 {
			t.Errorf("重放成功后缓冲应被清空，实际还剩 %d 个文件", n)
		}
		want := []model.Asset{testAsset(0), testAsset(1)}
		assertNoLossNoDup(t, back.acceptedReports(), want)
	})

	t.Run("ctx 已取消：不重放、不删缓冲", func(t *testing.T) {
		f := newFakeServer("")
		f.start(t)
		ag := newTestAgent(t, f, nil)
		registerAgent(t, ag)
		if err := ag.writeSpool(pendingReport{ScanID: "scan-cancel", Assets: []model.Asset{testAsset(3)}}); err != nil {
			t.Fatalf("写缓冲失败: %v", err)
		}

		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		ag.replaySpool(ctx)

		if n := spoolCount(t, ag.cfg.SpoolDir); n != 1 {
			t.Errorf("ctx 取消后不应删除缓冲文件，实际剩 %d 个", n)
		}
		if n := len(f.acceptedReports()); n != 0 {
			t.Errorf("ctx 取消后不应上报，实际 %d 次", n)
		}
	})

	t.Run("缓冲文件损坏：删除后继续重放其它文件", func(t *testing.T) {
		f := newFakeServer("")
		f.start(t)
		ag := newTestAgent(t, f, nil)
		registerAgent(t, ag)

		if err := ag.writeSpool(pendingReport{ScanID: "scan-corrupt", Assets: []model.Asset{testAsset(7)}}); err != nil {
			t.Fatalf("写缓冲失败: %v", err)
		}
		junk := filepath.Join(ag.cfg.SpoolDir, "report-1-deadbeef.json")
		if err := os.WriteFile(junk, []byte("{ 这不是合法 JSON"), 0o600); err != nil {
			t.Fatalf("写损坏文件失败: %v", err)
		}

		ag.replaySpool(context.Background())

		if _, err := os.Stat(junk); !os.IsNotExist(err) {
			t.Errorf("损坏的缓冲文件应被删除，实际 stat 错误 = %v", err)
		}
		if n := spoolCount(t, ag.cfg.SpoolDir); n != 0 {
			t.Errorf("重放后缓冲目录应为空，实际还剩 %d 个文件", n)
		}
		want := []model.Asset{testAsset(7)}
		assertNoLossNoDup(t, f.acceptedReports(), want)
	})
}

// ---------------------------------------------------------------------------
// 4. 拉任务的长轮询
// ---------------------------------------------------------------------------

func TestAgentPullLongPoll(t *testing.T) {
	t.Run("无任务时带 wait_seconds 挂起，随后能取回任务", func(t *testing.T) {
		job := wire.JobSpec{ID: "job-pull", ScanID: "scan-pull", Host: "192.0.2.99", Ports: []int{80}, CreatedAt: time.Now()}
		f := newFakeServer("")
		f.pullJobs = [][]wire.JobSpec{{}, {job}}
		f.pullWait = 30 * time.Millisecond // 服务端长轮询的"挂住"时间
		f.start(t)
		ag := newTestAgent(t, f, func(c *Config) {
			c.MaxJobs = 3
			c.PullWaitSecs = 7
		})
		registerAgent(t, ag)

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		jobs, err := ag.pull(ctx, ag.cfg.MaxJobs, ag.cfg.PullWaitSecs)
		if err != nil {
			t.Fatalf("第一次拉取失败: %v", err)
		}
		if len(jobs) != 0 {
			t.Errorf("无任务时应返回空列表，实际 %+v", jobs)
		}
		jobs, err = ag.pull(ctx, ag.cfg.MaxJobs, ag.cfg.PullWaitSecs)
		if err != nil {
			t.Fatalf("第二次拉取失败: %v", err)
		}
		if len(jobs) != 1 || jobs[0].ID != job.ID {
			t.Fatalf("第二次应取回任务 %s，实际 %+v", job.ID, jobs)
		}

		pulls := f.pullCalls()
		if len(pulls) != 2 {
			t.Fatalf("应发出 2 次拉取请求，实际 %d 次", len(pulls))
		}
		for i, p := range pulls {
			if p.req.WaitSeconds != 7 {
				t.Errorf("第 %d 次拉取 wait_seconds = %d，期望 7（长轮询，避免空转打爆服务端）", i+1, p.req.WaitSeconds)
			}
			if p.req.MaxJobs != 3 {
				t.Errorf("第 %d 次拉取 max_jobs = %d，期望 3", i+1, p.req.MaxJobs)
			}
			if p.req.AgentID != ag.id || p.req.AgentID == "" {
				t.Errorf("第 %d 次拉取 agent_id = %q，期望 %q", i+1, p.req.AgentID, ag.id)
			}
			if !p.accepted {
				t.Errorf("第 %d 次拉取被服务端拒绝", i+1)
			}
		}
	})

	t.Run("Run 拉到任务后执行、上报，并在空响应后继续拉取", func(t *testing.T) {
		sitePort := newLoopbackSite(t)
		f := newFakeServer("")
		f.pullJobs = [][]wire.JobSpec{{{ID: "job-run", ScanID: "scan-run", Host: "127.0.0.1", Ports: []int{sitePort}}}}
		f.pullWait = 20 * time.Millisecond
		f.start(t)
		ag := newTestAgent(t, f, nil)

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		done := make(chan error, 1)
		go func() { done <- ag.Run(ctx) }()

		waitFor(t, 5*time.Second, "任务结果上报", func() bool { return len(f.acceptedReports()) > 0 })
		// 服务端返回空之后循环必须继续（否则 Agent 拉一次就"死"了）
		waitFor(t, 5*time.Second, "空响应后继续拉取", func() bool { return f.pullCount() >= 2 })
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("ctx 取消不是错误，Run 应返回 nil，实际 %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("Run 未在 ctx 取消后退出")
		}

		reports := f.acceptedReports()
		if len(reports) == 0 {
			t.Fatal("未收到任何上报")
		}
		rep := reports[0]
		if rep.ScanID != "scan-run" || rep.AgentID != f.agentID {
			t.Errorf("上报归属错误: scan_id=%q agent_id=%q", rep.ScanID, rep.AgentID)
		}
		if len(rep.Outcomes) != 1 || rep.Outcomes[0].JobID != "job-run" || rep.Outcomes[0].State != wire.TaskDone {
			t.Errorf("任务结果错误: %+v", rep.Outcomes)
		}
		if len(rep.Assets) == 0 {
			t.Error("范围内目标应上报资产，实际 0 条")
		}
		if n := f.pullCount(); n < 2 {
			t.Errorf("空响应后应继续拉取，实际只拉了 %d 次", n)
		}
	})
}

// ---------------------------------------------------------------------------
// 5. 鉴权失败的处理
// ---------------------------------------------------------------------------

func TestAgentAuthFailure(t *testing.T) {
	t.Run("注册被拒：立即失败、不重试", func(t *testing.T) {
		f := newFakeServer("right-token")
		f.start(t)
		ag := newTestAgent(t, f, func(c *Config) { c.Token = "wrong-token" })

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		start := time.Now()
		err := ag.Run(ctx)
		elapsed := time.Since(start)

		if err == nil {
			t.Fatal("错误 token 注册应失败，实际成功")
		}
		if !strings.Contains(err.Error(), "注册失败") || !strings.Contains(err.Error(), "401") {
			t.Errorf("错误信息应说明注册被拒（401），实际 %v", err)
		}
		if n := f.registerCount(); n != 1 {
			t.Errorf("注册失败只应尝试 1 次（不无限重试），实际 %d 次", n)
		}
		if n := f.pullCount(); n != 0 {
			t.Errorf("注册失败后不应拉取任务，实际 %d 次", n)
		}
		if elapsed > 2*time.Second {
			t.Errorf("鉴权失败应立即返回，实际耗时 %s", elapsed)
		}
	})

	t.Run("拉取被拒：有退避、不崩、可取消退出", func(t *testing.T) {
		// 注册成功、但服务端对拉取返回 401（token 过期/失效）
		f := newFakeServer("t")
		f.rejectPull = true
		f.pullWait = 20 * time.Millisecond
		f.start(t)
		ag := newTestAgent(t, f, nil)

		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() { done <- ag.Run(ctx) }()

		waitFor(t, 3*time.Second, "第一次拉取被拒", func() bool { return f.pullCount() >= 1 })
		// 观察窗口：拉取失败后 Agent 会退避 3s，窗口内不该有第二次请求
		time.Sleep(250 * time.Millisecond)
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("ctx 取消不应让 Run 报错，实际 %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("Run 未在 ctx 取消后退出")
		}

		if n := f.registerCount(); n != 1 {
			t.Errorf("应只注册 1 次（不会因为拉取失败反复重注册），实际 %d 次", n)
		}
		if n := f.pullCount(); n != 1 {
			t.Errorf("鉴权失败应退避重试（3s），250ms 内应只有 1 次请求，实际 %d 次（有打爆服务端的风险）", n)
		}
		if calls := f.pullCalls(); len(calls) > 0 && calls[0].accepted {
			t.Error("测试场景失效：服务端并没有用 401 拒绝这次拉取")
		}
		if n := len(f.allReports()); n != 0 {
			t.Errorf("没有任何任务时不应上报，实际 %d 次", n)
		}
	})
}

// ---------------------------------------------------------------------------
// 追加：请求契约、TLS 校验、构造校验
// ---------------------------------------------------------------------------

// post 是 Agent 与 Server 之间的唯一出口，请求头/错误语义必须稳定。
func TestPostRequestContract(t *testing.T) {
	cases := []struct {
		name    string
		status  int
		body    string
		withOut bool
		wantErr string
	}{
		{name: "正常响应并解析", status: 200, body: `{"jobs":[{"id":"j1","host":"h","ports":[80]}]}`, withOut: true},
		{name: "服务端 500", status: 500, body: "boom", withOut: true, wantErr: "服务端返回 500"},
		{name: "鉴权 401", status: 401, body: "unauthorized", withOut: true, wantErr: "服务端返回 401"},
		{name: "响应体不是合法 JSON", status: 200, body: "not-json", withOut: true, wantErr: "响应解析失败"},
		{name: "out 为空时不解析响应体", status: 200, body: "not-json", withOut: false},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			var mu sync.Mutex
			var gotAuth, gotCT, gotBody string
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				b, _ := io.ReadAll(r.Body)
				mu.Lock()
				gotAuth, gotCT, gotBody = r.Header.Get("Authorization"), r.Header.Get("Content-Type"), string(b)
				mu.Unlock()
				w.WriteHeader(tc.status)
				fmt.Fprint(w, tc.body)
			}))
			defer ts.Close()

			ag, err := New(Config{ServerURL: ts.URL, Token: "tok", Scan: testScanConfig([]string{"127.0.0.0/8"}, nil)})
			if err != nil {
				t.Fatalf("构造 Agent 失败: %v", err)
			}
			var out any
			if tc.withOut {
				out = &wire.PullResponse{}
			}
			err = ag.post(context.Background(), "/api/v1/agents/pull", wire.PullRequest{AgentID: "a1"}, out)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("不应报错，实际 %v", err)
				}
			} else if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("错误 = %v，期望包含 %q", err, tc.wantErr)
			}

			mu.Lock()
			defer mu.Unlock()
			if gotAuth != "Bearer tok" {
				t.Errorf("Authorization = %q，期望 %q", gotAuth, "Bearer tok")
			}
			if gotCT != "application/json" {
				t.Errorf("Content-Type = %q，期望 application/json", gotCT)
			}
			if !strings.Contains(gotBody, `"agent_id":"a1"`) {
				t.Errorf("请求体 = %s，期望包含 agent_id", gotBody)
			}
			if tc.wantErr == "" && tc.withOut {
				resp := out.(*wire.PullResponse)
				if len(resp.Jobs) != 1 || resp.Jobs[0].ID != "j1" {
					t.Errorf("响应未正确解析: %+v", resp.Jobs)
				}
			}
		})
	}
}

// TLS 校验必须真的生效：信任的 CA 能连，不信任的必须连不上。
func TestAgentTLSVerification(t *testing.T) {
	f := newFakeServer("")
	f.startTLS(t)
	caPath := writeServerCA(t, f.ts)

	t.Run("指定 CA 后可以完成注册", func(t *testing.T) {
		ag := newTestAgent(t, f, func(c *Config) { c.TLS = TLSConfig{CAFile: caPath} })
		registerAgent(t, ag)
		if n := f.registerCount(); n != 1 {
			t.Errorf("应完成 1 次注册，实际 %d 次", n)
		}
	})

	t.Run("未信任证书的 HTTPS 服务端必须拒绝", func(t *testing.T) {
		ag := newTestAgent(t, f, nil) // 用系统根证书 → 自签证书不受信
		if _, err := ag.register(context.Background()); err == nil {
			t.Fatal("自签证书不在系统根里，注册应失败（否则 TLS 校验形同虚设）")
		} else if !strings.Contains(err.Error(), "注册失败") {
			t.Errorf("错误信息应包含注册失败，实际 %v", err)
		}
	})
}

// 双向 TLS：客户端证书必须能被加载。证书/私钥读不出来要在构造期就报错（见 NewRejectsInvalidConfig）。
func TestAgentMTLSClientCert(t *testing.T) {
	f := newFakeServer("")
	f.startTLS(t)
	caPath := writeServerCA(t, f.ts)
	certPath, keyPath := writeSelfSignedPair(t)

	ag := newTestAgent(t, f, func(c *Config) {
		c.TLS = TLSConfig{CAFile: caPath, CertFile: certPath, KeyFile: keyPath}
	})
	registerAgent(t, ag)
	if n := f.registerCount(); n != 1 {
		t.Errorf("带客户端证书时应能完成注册，实际 %d 次", n)
	}
}

func TestNewRejectsInvalidConfig(t *testing.T) {
	authorized := testScanConfig([]string{"127.0.0.0/8"}, nil)
	tmp := t.TempDir()
	notADir := filepath.Join(tmp, "not-a-dir")
	if err := os.WriteFile(notADir, []byte("x"), 0o600); err != nil {
		t.Fatalf("准备文件失败: %v", err)
	}

	cases := []struct {
		name string
		cfg  Config
		want string
	}{
		{
			name: "缺少服务端地址",
			cfg:  Config{Scan: authorized},
			want: "缺少 Server 地址",
		},
		{
			name: "未声明本地授权",
			cfg:  Config{ServerURL: "http://127.0.0.1:1"},
			want: "授权",
		},
		{
			name: "CA 文件不存在",
			cfg: Config{
				ServerURL: "http://127.0.0.1:1", Scan: authorized,
				TLS: TLSConfig{CAFile: filepath.Join(tmp, "no-such-ca.pem")},
			},
			want: "读取 CA 失败",
		},
		{
			name: "CA 文件里没有证书",
			cfg: Config{
				ServerURL: "http://127.0.0.1:1", Scan: authorized,
				TLS: TLSConfig{CAFile: notADir},
			},
			want: "不含有效证书",
		},
		{
			name: "客户端证书不存在",
			cfg: Config{
				ServerURL: "http://127.0.0.1:1", Scan: authorized,
				TLS: TLSConfig{CertFile: filepath.Join(tmp, "no.crt"), KeyFile: filepath.Join(tmp, "no.key")},
			},
			want: "加载客户端证书失败",
		},
		{
			name: "缓冲目录无法创建",
			cfg: Config{
				ServerURL: "http://127.0.0.1:1", Scan: authorized,
				SpoolDir: filepath.Join(notADir, "spool"),
			},
			want: "创建缓冲目录失败",
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			ag, err := New(tc.cfg)
			if err == nil {
				t.Fatalf("应返回错误，实际构造成功: %+v", ag)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("错误 = %q，期望包含 %q", err.Error(), tc.want)
			}
		})
	}
}

func TestNewAppliesDefaults(t *testing.T) {
	f := newFakeServer("")
	f.start(t)
	spoolDir := filepath.Join(t.TempDir(), "spool")

	ag, err := New(Config{ServerURL: f.ts.URL, Scan: testScanConfig([]string{"127.0.0.0/8"}, nil), SpoolDir: spoolDir})
	if err != nil {
		t.Fatalf("构造 Agent 失败: %v", err)
	}
	if ag.cfg.MaxJobs != 4 {
		t.Errorf("MaxJobs 默认值 = %d，期望 4", ag.cfg.MaxJobs)
	}
	if ag.cfg.PullWaitSecs != 20 {
		t.Errorf("PullWaitSecs 默认值 = %d，期望 20", ag.cfg.PullWaitSecs)
	}
	if ag.cfg.BatchSize != 200 {
		t.Errorf("BatchSize 默认值 = %d，期望 200", ag.cfg.BatchSize)
	}
	if ag.cfg.FlushEvery != time.Second {
		t.Errorf("FlushEvery 默认值 = %s，期望 1s", ag.cfg.FlushEvery)
	}
	if ag.cfg.Version == "" {
		t.Error("Version 应有默认值")
	}
	if ag.logger == nil {
		t.Error("未提供 Log 时必须回退到丢弃日志，而不是 nil（否则 logf 会 panic）")
	}
	info, err := os.Stat(spoolDir)
	if err != nil || !info.IsDir() {
		t.Errorf("缓冲目录应被自动创建: err=%v", err)
	}
}

// ---------------------------------------------------------------------------
// 追加：执行循环 / 注册 / 缓冲的边界行为
// ---------------------------------------------------------------------------

// 一次拉回多个任务时，ctx 取消后不得再执行剩余任务（否则"停机"会拖到任务跑完）。
func TestAgentRunStopsRemainingJobsAfterCancel(t *testing.T) {
	sitePort := newLoopbackSite(t)
	f := newFakeServer("")
	f.pullWait = 20 * time.Millisecond
	f.pullJobs = [][]wire.JobSpec{{
		{ID: "job-first", ScanID: "scan-cancel", Host: "127.0.0.1", Ports: []int{sitePort}},
		{ID: "job-second", ScanID: "scan-cancel", Host: "192.0.2.77", Ports: []int{80}},
	}}
	f.start(t)
	ag := newTestAgent(t, f, func(c *Config) { c.MaxJobs = 2 })

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var once sync.Once
	f.setOnReport(func() { once.Do(cancel) }) // 第一个任务上报的瞬间取消 ctx

	done := make(chan error, 1)
	go func() { done <- ag.Run(ctx) }()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("ctx 取消不应让 Run 报错，实际 %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Run 未退出（取消后仍在执行任务？）")
	}

	for _, c := range f.allReports() {
		for _, o := range c.req.Outcomes {
			if o.JobID == "job-second" {
				t.Errorf("ctx 取消后不应再执行剩余任务，却上报了 %s", o.JobID)
			}
		}
	}
	if n := f.pullCount(); n != 1 {
		t.Errorf("ctx 取消后不应再拉取任务，实际拉了 %d 次", n)
	}
}

// 扫描配置本身非法（pipeline.New 失败）时，任务必须判失败并上报，而不是静默"完成"。
func TestAgentRunJobReportsPipelineConfigError(t *testing.T) {
	f := newFakeServer("")
	f.start(t)
	ag := newTestAgent(t, f, func(c *Config) {
		c.Scan = testScanConfig([]string{"192.168.1.0/24 非法规则"}, nil)
	})
	registerAgent(t, ag)

	job := wire.JobSpec{ID: "job-badcfg", ScanID: "scan-badcfg", Host: "127.0.0.1", Ports: []int{80}}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ag.runJob(ctx, job)

	reports := f.acceptedReports()
	if len(reports) != 1 {
		t.Fatalf("配置非法也必须上报任务结果，实际 %d 次", len(reports))
	}
	rep := reports[0]
	if len(rep.Outcomes) != 1 || rep.Outcomes[0].State != wire.TaskFailed {
		t.Fatalf("配置非法时任务应判失败，实际 %+v", rep.Outcomes)
	}
	if !strings.Contains(rep.Outcomes[0].Error, "CIDR") {
		t.Errorf("错误信息应说明规则非法，实际 %q", rep.Outcomes[0].Error)
	}
	if len(rep.Assets) != 0 {
		t.Errorf("未执行任何扫描，不应有资产，实际 %d 条", len(rep.Assets))
	}
	if len(rep.Rejected) != 0 {
		t.Errorf("配置非法不是「目标越界」，rejected 应为空，实际 %v", rep.Rejected)
	}
}

// 服务端没返回 agent_id 时注册必须失败（不能带着空 id 继续跑）。
func TestAgentRegisterWithoutAgentID(t *testing.T) {
	f := newFakeServer("")
	f.agentID = ""
	f.start(t)
	ag := newTestAgent(t, f, nil)

	if _, err := ag.register(context.Background()); err == nil {
		t.Fatal("服务端未返回 agent_id 时应报错")
	} else if !strings.Contains(err.Error(), "agent_id") {
		t.Errorf("错误信息应指明缺少 agent_id，实际 %v", err)
	}
}

// 空缓冲不应产生空报文（否则服务端会收到一堆没有任何内容的上报）。
func TestReportStoreFlushOnlySkipsEmptyBuffer(t *testing.T) {
	f := newFakeServer("")
	f.start(t)
	ag := newTestAgent(t, f, nil)
	registerAgent(t, ag)

	rs := newReportStore(ag, "scan-empty")
	if err := rs.flushOnly(context.Background()); err != nil {
		t.Fatalf("空缓冲不应报错，实际 %v", err)
	}
	if n := len(f.allReports()); n != 0 {
		t.Errorf("空缓冲不应发出任何报文，实际 %d 次", n)
	}
}

// 上报失败时如果缓冲不可用，必须如实报错——绝不假装"已经缓冲了"。
func TestAgentReportingWithoutUsableSpool(t *testing.T) {
	t.Run("未配置缓冲目录：直接返回原始错误", func(t *testing.T) {
		f := newFakeServer("")
		f.start(t)
		ag := newTestAgent(t, f, func(c *Config) { c.SpoolDir = "" })
		registerAgent(t, ag)
		f.setFailReport(true)

		rs := newReportStore(ag, "scan-nospool")
		if err := rs.Add(testAsset(0)); err != nil {
			t.Fatalf("Add 失败: %v", err)
		}
		err := rs.Flush(context.Background(), wire.TaskOutcome{JobID: "j", Host: "127.0.0.1", State: wire.TaskDone}, nil, nil)
		if err == nil {
			t.Fatal("上报失败时应返回错误")
		}
		if strings.Contains(err.Error(), "本地缓冲") {
			t.Errorf("未配置缓冲目录时不应声称已写入缓冲，实际 %v", err)
		}
		ag.replaySpool(context.Background()) // 未配置缓冲：静默跳过
		if n := len(f.acceptedReports()); n != 0 {
			t.Errorf("不应有任何上报被接受，实际 %d 次", n)
		}
	})

	t.Run("缓冲目录被删除：写明写缓冲也失败", func(t *testing.T) {
		f := newFakeServer("")
		f.start(t)
		ag := newTestAgent(t, f, nil)
		registerAgent(t, ag)
		if err := os.RemoveAll(ag.cfg.SpoolDir); err != nil {
			t.Fatalf("删除缓冲目录失败: %v", err)
		}
		f.setFailReport(true)

		rs := newReportStore(ag, "scan-norespool")
		if err := rs.Add(testAsset(0)); err != nil {
			t.Fatalf("Add 失败: %v", err)
		}
		err := rs.Flush(context.Background(), wire.TaskOutcome{JobID: "j", Host: "127.0.0.1", State: wire.TaskDone}, nil, nil)
		if err == nil {
			t.Fatal("上报失败且无法落盘时必须返回错误（绝不静默丢数据）")
		}
		if !strings.Contains(err.Error(), "写缓冲也失败") {
			t.Errorf("错误应说明写缓冲也失败，实际 %v", err)
		}
		ag.replaySpool(context.Background()) // 目录不存在：静默返回，不 panic
	})
}

// post 的入参非法时要快速失败（不发请求、不排队）。
func TestPostFailsFastOnBadInput(t *testing.T) {
	f := newFakeServer("")
	f.start(t)
	ag := newTestAgent(t, f, nil)

	if err := ag.post(context.Background(), "/api/v1/agents/pull", make(chan int), nil); err == nil {
		t.Error("无法序列化的请求体应报错")
	}
	if n := f.pullCount(); n != 0 {
		t.Errorf("请求体非法时不应发出请求，实际 %d 次", n)
	}

	bad, err := New(Config{ServerURL: "http://bad host/", Scan: testScanConfig([]string{"127.0.0.0/8"}, nil)})
	if err != nil {
		t.Fatalf("构造 Agent 失败: %v", err)
	}
	if err := bad.post(context.Background(), "/api/v1/agents/pull", wire.PullRequest{AgentID: "a"}, nil); err == nil {
		t.Error("非法的服务端地址应报错")
	}
}

// ---------------------------------------------------------------------------
// 断言辅助
// ---------------------------------------------------------------------------

// assertNoLossNoDup 断言服务端收到的资产与期望集合完全一致：不丢、不重。
func assertNoLossNoDup(t *testing.T, reports []wire.ReportRequest, want []model.Asset) {
	t.Helper()
	counts := map[string]int{}
	for _, rep := range reports {
		for _, a := range rep.Assets {
			counts[a.Key()]++
		}
	}
	for _, w := range want {
		switch counts[w.Key()] {
		case 1:
		case 0:
			t.Errorf("资产 %s 丢失", w.Key())
		default:
			t.Errorf("资产 %s 重复上报 %d 次", w.Key(), counts[w.Key()])
		}
	}
	if len(counts) != len(want) {
		t.Errorf("资产种类 = %d，期望 %d（key=%v）", len(counts), len(want), counts)
	}
}

// spoolCount 统计缓冲目录里待重放的报文文件数。
func spoolCount(t *testing.T, dir string) int {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("读取缓冲目录 %s 失败: %v", dir, err)
	}
	n := 0
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".json") {
			n++
		}
	}
	return n
}

// spooledReports 读出缓冲目录里的全部待重放报文（与 replaySpool 的读取方式一致）。
func spooledReports(t *testing.T, dir string) []pendingReport {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("读取缓冲目录 %s 失败: %v", dir, err)
	}
	var out []pendingReport
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatalf("读取缓冲文件 %s 失败: %v", e.Name(), err)
		}
		var rep pendingReport
		if err := json.Unmarshal(data, &rep); err != nil {
			t.Fatalf("缓冲文件 %s 不是合法报文: %v", e.Name(), err)
		}
		out = append(out, rep)
	}
	return out
}

// waitFor 轮询等待条件成立，避免在测试里写死 sleep。
func waitFor(t *testing.T, timeout time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("等待超时: %s", what)
}

func equalInts(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// writeServerCA 把 httptest TLS 服务端的自签证书写成 PEM，作为 Agent 信任的 CA。
func writeServerCA(t *testing.T, ts *httptest.Server) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ca.pem")
	block := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ts.Certificate().Raw})
	if err := os.WriteFile(path, block, 0o600); err != nil {
		t.Fatalf("写 CA 文件失败: %v", err)
	}
	return path
}

// writeSelfSignedPair 生成一张自签证书与私钥并落盘，返回 (certPath, keyPath)。
func writeSelfSignedPair(t *testing.T) (string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("生成私钥失败: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(20260101),
		Subject:      pkix.Name{CommonName: "westy-agent-test", Organization: []string{"westy_scan test"}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("签发证书失败: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("编码私钥失败: %v", err)
	}
	dir := t.TempDir()
	certPath := filepath.Join(dir, "client.crt")
	keyPath := filepath.Join(dir, "client.key")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatalf("写客户端证书失败: %v", err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatalf("写客户端私钥失败: %v", err)
	}
	return certPath, keyPath
}
