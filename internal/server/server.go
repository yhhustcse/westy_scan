// Package server 实现分布式扫描的编排端（M5）。
//
// 职责：
//   - 任务切片：把 (主机 × 端口) 切成可独立重试的最小单元，用稳定哈希做幂等键；
//   - 租约与重派：任务带租约，Agent 掉线后租约过期自动回到待执行，超过重试上限才判失败；
//   - 结果汇聚：资产按 Key() 去重、漏洞按 (模板, 命中地址) 去重；
//   - 可观测：/healthz、/metrics（Prometheus 文本）、/api/v1/stats。
//
// 安全：所有接口都要 Bearer token（常量时间比较）；**授权的最终判定在 Agent 侧**
// —— 服务端无权把越界目标"授权"给 Agent，Agent 用自己的 allow/deny 再校验一次。
package server

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"westy_scan/internal/audit"
	"westy_scan/internal/authz"
	"westy_scan/internal/diff"
	"westy_scan/internal/model"
	"westy_scan/internal/notify"
	"westy_scan/internal/poc"
	"westy_scan/internal/store"
	"westy_scan/internal/wire"
)

// Options 是服务端参数。
type Options struct {
	Token         string
	LeaseSeconds  int
	MaxTries      int
	ServerVersion string
	Audit         *audit.Logger
	Log           *log.Logger
	SweepEvery    time.Duration

	// M6：平台化
	DataDir           string            // 持久化目录（为空则不落盘）
	Roles             map[string]string // token -> 角色（admin/operator/viewer）
	Notify            *notify.Notifier  // 通知器（nil 表示不通知）
	NotifyMinSeverity string            // 只有不低于该级别的漏洞才通知
	ScheduleEvery     time.Duration     // 定时扫描间隔（0 表示不启用）
	ScheduleSpec      *wire.ScanSpec    // 定时扫描模板（含授权书编号）
}

func (o Options) withDefaults() Options {
	if o.LeaseSeconds <= 0 {
		o.LeaseSeconds = 60
	}
	if o.MaxTries <= 0 {
		o.MaxTries = 3
	}
	if o.ServerVersion == "" {
		o.ServerVersion = "0.1.0"
	}
	if o.SweepEvery <= 0 {
		o.SweepEvery = time.Second
	}
	return o
}

type counters struct {
	jobsDispatched int64
	reports        int64
	assetsNew      int64
	assetsDup      int64
	findingsNew    int64
	rejected       int64
	authFailures   int64
}

// Server 是编排端。
type Server struct {
	opt Options

	mu       sync.Mutex
	tasks    map[string]*wire.Task
	order    []string
	scans    map[string]*wire.ScanInfo
	agents   map[string]*wire.AgentStatus
	seenKey  map[string]bool
	findings map[string]poc.Finding
	// obs 记录"某次扫描实际观察到过哪些资产/漏洞"。
	//
	// 为什么需要它：assets/findings 是全局去重表，同一条记录只保留首次出现的样本，
	// 其上的 scan_id 只表示"首次发现归属"。若用它反推"本次扫描看到了什么"，
	// 重复扫到同一目标会被误判为"未扫到"，diff 于是报出假的"已修复/已消失"。
	obs      map[string]*scanObs
	assets   *store.Memory
	counters counters
	started  time.Time
	wake     chan struct{}
	stop     chan struct{}
	stopOnce sync.Once

	// M6：平台化
	authzRecs map[string]authz.Record
	persist   *persister
	notify    *notify.Notifier
	schedWG   sync.WaitGroup
}

// scanObs 是一次扫描的"观察到过什么"集合（资产键 / 漏洞键）。
// 字段导出是为了能进 state.json 快照。
type scanObs struct {
	Assets   map[string]bool `json:"assets,omitempty"`
	Findings map[string]bool `json:"findings,omitempty"`
}

// New 构造服务端并启动租约清理协程。
func New(opt Options) *Server {
	opt = opt.withDefaults()
	s := &Server{
		opt:       opt,
		tasks:     make(map[string]*wire.Task),
		scans:     make(map[string]*wire.ScanInfo),
		agents:    make(map[string]*wire.AgentStatus),
		seenKey:   make(map[string]bool),
		findings:  make(map[string]poc.Finding),
		obs:       make(map[string]*scanObs),
		assets:    store.NewMemory(),
		authzRecs: make(map[string]authz.Record),
		started:   time.Now(),
		wake:      make(chan struct{}, 1),
		stop:      make(chan struct{}),
		notify:    opt.Notify,
	}
	if opt.Token == "" && len(opt.Roles) == 0 {
		s.logf("警告: 未配置 -token/-role，所有接口处于无鉴权的开发模式")
	}
	if opt.DataDir != "" {
		p, err := newPersister(opt.DataDir)
		if err != nil {
			s.logf("持久化初始化失败（退化为纯内存模式）: %v", err)
		} else {
			s.persist = p
			if err := s.restore(); err != nil {
				s.logf("状态恢复失败（以空状态启动）: %v", err)
			} else {
				s.logf("已从 %s 恢复状态：任务 %d，资产 %d，漏洞 %d，授权书 %d",
					opt.DataDir, len(s.tasks), s.assets.Len(), len(s.findings), len(s.authzRecs))
			}
		}
	}
	go s.sweepLoop()
	if opt.ScheduleEvery > 0 && opt.ScheduleSpec != nil {
		s.startScheduler()
	}
	return s
}

// Close 停止后台协程并落盘。
func (s *Server) Close() {
	s.stopOnce.Do(func() {
		close(s.stop)
		s.schedWG.Wait()
		if s.persist != nil {
			_ = s.persist.saveState(s.snapshot())
			_ = s.persist.Close()
		}
	})
}

func (s *Server) logf(format string, args ...any) {
	if s.opt.Log != nil {
		s.opt.Log.Printf(format, args...)
	}
}

func (s *Server) auditLog(event string, fields map[string]string) {
	if s.opt.Audit != nil {
		s.opt.Audit.Log(event, fields)
	}
}

// CreateScan 按 JobSize 切片并入队，返回扫描视图。
func (s *Server) CreateScan(spec wire.ScanSpec) (*wire.ScanInfo, error) {
	if len(spec.Hosts) == 0 || len(spec.Ports) == 0 {
		return nil, fmt.Errorf("扫描需要至少一台主机与一个端口")
	}
	if spec.ScanID == "" {
		spec.ScanID = "scan-" + wire.JobID("scan", spec.Hosts[0], spec.Ports)[:8] + "-" + time.Now().Format("150405")
	}
	jobSize := spec.JobSize
	if jobSize <= 0 {
		jobSize = 1
	}
	// 端口分片：把端口列表切成若干块，每块一个任务（幂等键含端口集合）。
	// 先把请求里的端口排序：HTTP 调用方传 [443,80] 还是 [80,443] 必须得到同一批任务 ID，
	// 否则"同一个扫描换个端口顺序"就会生成两套任务，幂等与重派语义一起失效。
	sort.Ints(spec.Ports)
	portChunks := chunkPorts(spec.Ports, spec.JobPorts)

	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.scans[spec.ScanID]; exists {
		return nil, fmt.Errorf("扫描 ID 已存在: %s", spec.ScanID)
	}
	info := &wire.ScanInfo{
		ID:        spec.ScanID,
		CreatedAt: time.Now(),
		Hosts:     len(spec.Hosts),
		Ports:     len(spec.Ports),
	}
	// (主机 × 端口分片) 作为一个任务：切片越细，负载越均衡、掉线损失越小。
	for i := 0; i < len(spec.Hosts); i += jobSize {
		end := min(i+jobSize, len(spec.Hosts))
		for _, host := range spec.Hosts[i:end] {
			for _, chunk := range portChunks {
				id := wire.JobID(spec.ScanID, host, chunk)
				if _, ok := s.tasks[id]; ok {
					continue // 幂等：重复入队直接跳过
				}
				task := &wire.Task{
					Spec: wire.JobSpec{
						ID:        id,
						ScanID:    spec.ScanID,
						Host:      host,
						Ports:     append([]int(nil), chunk...),
						CreatedAt: time.Now(),
					},
					State:     wire.TaskPending,
					UpdatedAt: time.Now(),
				}
				s.tasks[id] = task
				s.order = append(s.order, id)
				info.Tasks++
				info.Pending++
			}
		}
	}
	s.scans[spec.ScanID] = info
	s.auditLog("scan_created", map[string]string{
		"scan_id": spec.ScanID,
		"hosts":   itoa(info.Hosts),
		"ports":   itoa(info.Ports),
		"tasks":   itoa(info.Tasks),
	})
	s.signal()
	return info, nil
}

func (s *Server) signal() {
	select {
	case s.wake <- struct{}{}:
	default:
	}
}

// claim 取走若干待执行任务并加租约。
func (s *Server) claim(agentID string, maxJobs int) []wire.JobSpec {
	if maxJobs <= 0 {
		maxJobs = 1
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []wire.JobSpec
	lease := time.Now().Add(time.Duration(s.opt.LeaseSeconds) * time.Second)
	for _, id := range s.order {
		if len(out) >= maxJobs {
			break
		}
		t := s.tasks[id]
		if t == nil || t.State != wire.TaskPending {
			continue
		}
		t.State = wire.TaskRunning
		t.AgentID = agentID
		t.Attempts++
		t.LeaseUntil = lease
		t.UpdatedAt = time.Now()
		if info := s.scans[t.Spec.ScanID]; info != nil {
			info.Pending--
			info.Running++
		}
		out = append(out, t.Spec)
		s.counters.jobsDispatched++
		s.auditLog("job_dispatched", map[string]string{
			"scan_id": t.Spec.ScanID, "job_id": t.Spec.ID, "host": t.Spec.Host, "agent": agentID,
			"attempt": itoa(t.Attempts),
		})
	}
	return out
}

// sweepLoop 周期性回收过期租约：Agent 掉线后任务自动回到待执行。
func (s *Server) sweepLoop() {
	ticker := time.NewTicker(s.opt.SweepEvery)
	defer ticker.Stop()
	for {
		select {
		case <-s.stop:
			return
		case <-ticker.C:
			s.sweep()
		}
	}
}

func (s *Server) sweep() {
	now := time.Now()
	s.mu.Lock()
	var requeued, failed int
	for _, id := range s.order {
		t := s.tasks[id]
		if t == nil || t.State != wire.TaskRunning || t.LeaseUntil.After(now) {
			continue
		}
		info := s.scans[t.Spec.ScanID]
		if t.Attempts >= s.opt.MaxTries {
			t.State = wire.TaskFailed
			t.Error = fmt.Sprintf("租约过期且已达最大重试次数(%d)，判定失败", s.opt.MaxTries)
			failed++
			if info != nil {
				info.Running--
				info.Failed++
			}
		} else {
			t.State = wire.TaskPending
			t.AgentID = ""
			requeued++
			if info != nil {
				info.Running--
				info.Pending++
			}
		}
		t.UpdatedAt = now
	}
	s.mu.Unlock()
	if requeued > 0 || failed > 0 {
		s.logf("租约清理：重派 %d 个任务，判失败 %d 个", requeued, failed)
		s.auditLog("lease_sweep", map[string]string{
			"requeued": itoa(requeued), "failed": itoa(failed),
		})
		s.markDirty()
		s.maybeSaveState()
		if requeued > 0 {
			s.signal()
		}
	}
}

// applyOutcome 处理任务执行结果。
func (s *Server) applyOutcome(o wire.TaskOutcome) {
	var completed *wire.ScanInfo
	s.mu.Lock()
	t := s.tasks[o.JobID]
	if t == nil {
		s.mu.Unlock()
		return
	}
	info := s.scans[t.Spec.ScanID]
	switch o.State {
	case wire.TaskDone:
		if t.State != wire.TaskDone {
			if info != nil {
				if t.State == wire.TaskRunning {
					info.Running--
				} else if t.State == wire.TaskPending {
					info.Pending--
				}
				info.Done++
			}
		}
		t.State = wire.TaskDone
		t.Error = ""
	case wire.TaskFailed:
		if t.Attempts < s.opt.MaxTries {
			// 还能重试：回到待执行，由其它 Agent 接手
			if info != nil {
				if t.State == wire.TaskRunning {
					info.Running--
				} else if t.State == wire.TaskPending {
					info.Pending--
				}
				info.Pending++
			}
			t.State = wire.TaskPending
			t.AgentID = ""
		} else {
			if info != nil {
				if t.State == wire.TaskRunning {
					info.Running--
				}
				info.Failed++
			}
			t.State = wire.TaskFailed
		}
		t.Error = o.Error
	}
	t.UpdatedAt = time.Now()
	if info != nil {
		info.Assets = s.countAssetsForScanLocked(t.Spec.ScanID)
		info.Findings = s.countFindingsForScanLocked(t.Spec.ScanID)
		if info.Done+info.Failed == info.Tasks && info.Tasks > 0 {
			if info.CompletedAt.IsZero() {
				info.CompletedAt = time.Now()
			}
			// 扫描刚完成：出锁后发通知（发 HTTP 不能占着锁）
			cp := *info
			completed = &cp
		}
	}
	s.markDirty()
	s.mu.Unlock()

	if completed != nil {
		s.auditLog("scan_completed", map[string]string{
			"scan_id": completed.ID, "tasks": itoa(completed.Tasks),
			"done": itoa(completed.Done), "failed": itoa(completed.Failed),
			"assets": itoa(completed.Assets), "findings": itoa(completed.Findings),
		})
		s.notifyScanDone(completed)
	}
	s.maybeSaveState()
}

// countAssetsForScanLocked 统计某个扫描的资产数（按 meta.scan_id 归属）。
// countAssetsForScanLocked 返回"该次扫描观察到过"的资产数（不是"首次由它发现"的数量）。
func (s *Server) countAssetsForScanLocked(scanID string) int {
	if o := s.obs[scanID]; o != nil {
		return len(o.Assets)
	}
	return 0
}

// countFindingsForScanLocked 返回"该次扫描观察到过"的漏洞数。
func (s *Server) countFindingsForScanLocked(scanID string) int {
	if o := s.obs[scanID]; o != nil {
		return len(o.Findings)
	}
	return 0
}

// syncScanCountsLocked 把扫描视图上的资产/漏洞计数同步为观察集合的大小。
// 计数是"观察到的数量"，所以在写入集合的同一把锁里就更新，
// 不依赖任务回报路径——否则直连 ingest（测试/导入）时视图会一直显示 0。
func (s *Server) syncScanCountsLocked(scanID string) {
	info := s.scans[scanID]
	o := s.obs[scanID]
	if info == nil || o == nil {
		return
	}
	info.Assets = len(o.Assets)
	info.Findings = len(o.Findings)
}

// obsLocked 取（必要时创建）某次扫描的观察集合。调用方需持有 s.mu。
func (s *Server) obsLocked(scanID string) *scanObs {
	o := s.obs[scanID]
	if o == nil {
		o = &scanObs{Assets: map[string]bool{}, Findings: map[string]bool{}}
		s.obs[scanID] = o
	}
	return o
}

// ObservedAssetKeys / ObservedFindingKeys 导出某次扫描的观察集合（副本，供 diff/报告用）。
func (s *Server) ObservedAssetKeys(scanID string) map[string]bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return copyKeys(s.obs[scanID], func(o *scanObs) map[string]bool { return o.Assets })
}

// ObservedFindingKeys 见 ObservedAssetKeys。
func (s *Server) ObservedFindingKeys(scanID string) map[string]bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return copyKeys(s.obs[scanID], func(o *scanObs) map[string]bool { return o.Findings })
}

func copyKeys(o *scanObs, pick func(*scanObs) map[string]bool) map[string]bool {
	if o == nil {
		return nil
	}
	src := pick(o)
	out := make(map[string]bool, len(src))
	for k, v := range src {
		out[k] = v
	}
	return out
}

// ingestAssets 汇聚资产并去重，返回 (新增, 重复)。
func (s *Server) ingestAssets(scanID, agentID string, assets []model.Asset) (int, int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	added, dup := 0, 0
	o := s.obsLocked(scanID)
	for _, a := range assets {
		a.SetMeta("scan_id", scanID)
		a.SetMeta("agent_id", agentID)
		key := a.Key()
		o.Assets[key] = true // 无论是否首次发现，都算"本次观察到"
		if s.seenKey[key] {
			dup++
			continue
		}
		s.seenKey[key] = true
		if err := s.assets.Add(a); err != nil {
			continue
		}
		s.persistAssetLocked(a) // M6：落盘（追加 JSONL）
		added++
	}
	s.syncScanCountsLocked(scanID)
	if added > 0 {
		s.markDirty()
	}
	return added, dup
}

// ingestFindings 汇聚漏洞结果并去重（键：模板 + 命中地址）。
func (s *Server) ingestFindings(scanID, agentID string, findings []poc.Finding) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	added := 0
	o := s.obsLocked(scanID)
	for _, f := range findings {
		f.ScanID = scanID
		f.AgentID = agentID
		key := diff.FindingKey(f)
		o.Findings[key] = true // 同上：重复命中也是"本次观察到"
		if _, ok := s.findings[key]; ok {
			continue
		}
		s.findings[key] = f
		s.persistFindingLocked(f) // M6：落盘
		added++
	}
	s.syncScanCountsLocked(scanID)
	if added > 0 {
		s.markDirty()
	}
	return added
}

// Assets 返回汇聚后的资产快照。
func (s *Server) Assets() []model.Asset { return s.assets.Assets() }

// Findings 返回汇聚后的漏洞结果（按级别排序）。
func (s *Server) Findings() []poc.Finding {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]poc.Finding, 0, len(s.findings))
	for _, f := range s.findings {
		out = append(out, f)
	}
	return poc.FindingsBySeverity(out)
}

// ScanInfo 返回扫描视图。
func (s *Server) ScanInfo(id string) *wire.ScanInfo {
	s.mu.Lock()
	defer s.mu.Unlock()
	if info := s.scans[id]; info != nil {
		cp := *info
		return &cp
	}
	return nil
}

// Stats 返回整体统计。
func (s *Server) Stats() wire.Stats {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := wire.Stats{
		Protocol:   wire.ProtocolVersion,
		Scans:      make(map[string]*wire.ScanInfo, len(s.scans)),
		Tasks:      map[wire.TaskState]int{},
		Assets:     s.assets.Len(),
		Findings:   len(s.findings),
		UptimeSecs: int64(time.Since(s.started).Seconds()),
	}
	for id, info := range s.scans {
		cp := *info
		st.Scans[id] = &cp
	}
	for _, t := range s.tasks {
		st.Tasks[t.State]++
	}
	for _, a := range s.agents {
		st.Agents = append(st.Agents, *a)
	}
	sort.Slice(st.Agents, func(i, j int) bool { return st.Agents[i].ID < st.Agents[j].ID })
	return st
}

// ---------------- HTTP 层 ----------------

// Handler 返回全部路由。
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	// 探活与指标
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "protocol": wire.ProtocolVersion})
	})
	mux.HandleFunc("/metrics", s.requireRole(roleViewer, func(w http.ResponseWriter, r *http.Request) {
		s.handleMetrics(w)
	}))
	// Agent 接口
	mux.HandleFunc("/api/v1/agents/register", s.requireRole(roleOperator, s.handleRegister))
	mux.HandleFunc("/api/v1/agents/pull", s.requireRole(roleOperator, s.handlePull))
	mux.HandleFunc("/api/v1/agents/report", s.requireRole(roleOperator, s.handleReport))

	// M6 平台接口
	mux.HandleFunc("/api/v1/stats", s.requireRole(roleViewer, func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, s.Stats())
	}))
	mux.HandleFunc("/api/v1/scans", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			s.requireRole(roleViewer, func(w http.ResponseWriter, _ *http.Request) {
				s.handleListScans(w)
			})(w, r)
		case http.MethodPost:
			s.requireRole(roleOperator, s.handleCreateScan)(w, r)
		default:
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "仅支持 GET/POST"})
		}
	})
	mux.HandleFunc("/api/v1/scans/diff", s.requireRole(roleViewer, s.handleDiff))
	mux.HandleFunc("/api/v1/assets", s.requireRole(roleViewer, s.handleAssets))
	mux.HandleFunc("/api/v1/findings", s.requireRole(roleViewer, s.handleFindings))
	mux.HandleFunc("/api/v1/report", s.requireRole(roleViewer, s.handleExportReport))
	mux.HandleFunc("/api/v1/authorizations", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			s.requireRole(roleViewer, func(w http.ResponseWriter, _ *http.Request) {
				s.handleListAuthorizations(w)
			})(w, r)
		case http.MethodPost:
			s.requireRole(roleAdmin, s.handleCreateAuthorization)(w, r)
		default:
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "仅支持 GET/POST"})
		}
	})
	// Web UI（静态页本身不需要鉴权，数据接口才需要）
	mux.HandleFunc("/", s.serveUI)
	return mux
}

func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	var req wire.RegisterRequest
	if err := readJSON(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if req.Protocol != 0 && req.Protocol != wire.ProtocolVersion {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": fmt.Sprintf("协议版本不匹配: agent=%d server=%d", req.Protocol, wire.ProtocolVersion),
		})
		return
	}
	id := strings.TrimSpace(req.AgentID)
	if id == "" {
		id = "agent-" + wire.JobID("agent", req.Hostname, nil)[:8]
	}
	s.mu.Lock()
	s.agents[id] = &wire.AgentStatus{
		ID: id, Version: req.Version, Hostname: req.Hostname,
		LastSeen: time.Now(), LeaseSeconds: s.opt.LeaseSeconds,
	}
	s.mu.Unlock()
	s.auditLog("agent_registered", map[string]string{"agent_id": id, "hostname": req.Hostname, "version": req.Version})
	s.logf("Agent 注册: %s（%s, %s）", id, req.Hostname, req.Version)
	writeJSON(w, http.StatusOK, wire.RegisterResponse{
		AgentID:       id,
		LeaseSeconds:  s.opt.LeaseSeconds,
		HeartbeatSecs: max(5, s.opt.LeaseSeconds/3),
		Protocol:      wire.ProtocolVersion,
		ServerVersion: s.opt.ServerVersion,
		ScopeHint:     "Agent 侧仍需用自己的 allow/deny 做最终校验",
	})
}

func (s *Server) handlePull(w http.ResponseWriter, r *http.Request) {
	var req wire.PullRequest
	if err := readJSON(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if req.AgentID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "缺少 agent_id"})
		return
	}
	s.touchAgent(req.AgentID)
	jobs := s.pullJobs(r.Context(), req)
	writeJSON(w, http.StatusOK, wire.PullResponse{Jobs: jobs})
}

// pullJobs 支持长轮询：没任务时挂起等待，避免 Agent 空转刷接口。
func (s *Server) pullJobs(ctx context.Context, req wire.PullRequest) []wire.JobSpec {
	if jobs := s.claim(req.AgentID, req.MaxJobs); len(jobs) > 0 {
		return jobs
	}
	if req.WaitSeconds <= 0 {
		return nil
	}
	deadline := time.Now().Add(time.Duration(req.WaitSeconds) * time.Second)
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-s.stop:
			return nil
		case <-s.wake:
		case <-time.After(200 * time.Millisecond):
		}
		if jobs := s.claim(req.AgentID, req.MaxJobs); len(jobs) > 0 {
			return jobs
		}
		if time.Now().After(deadline) {
			return nil
		}
	}
}

func (s *Server) handleReport(w http.ResponseWriter, r *http.Request) {
	var req wire.ReportRequest
	if err := readJSON(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if req.AgentID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "缺少 agent_id"})
		return
	}
	s.touchAgent(req.AgentID)

	addedAssets, dup := s.ingestAssets(req.ScanID, req.AgentID, req.Assets)
	addedFindings := s.ingestFindings(req.ScanID, req.AgentID, req.Findings)

	s.mu.Lock()
	s.counters.reports++
	s.counters.assetsNew += int64(addedAssets)
	s.counters.assetsDup += int64(dup)
	s.counters.findingsNew += int64(addedFindings)
	s.counters.rejected += int64(len(req.Rejected))
	agent := s.agents[req.AgentID]
	if agent == nil {
		agent = &wire.AgentStatus{ID: req.AgentID, LastSeen: time.Now()}
		s.agents[req.AgentID] = agent
	}
	agent.AssetsSent += len(req.Assets)
	s.mu.Unlock()

	for _, o := range req.Outcomes {
		s.applyOutcome(o)
		s.mu.Lock()
		if a := s.agents[req.AgentID]; a != nil {
			if o.State == wire.TaskDone {
				a.JobsDone++
			} else {
				a.JobsFailed++
			}
		}
		s.mu.Unlock()
	}
	for _, rj := range req.Rejected {
		s.auditLog("agent_target_rejected", map[string]string{
			"agent_id": req.AgentID, "target": rj,
		})
	}
	// M6：新漏洞按阈值发通知（去重后仍有新增才发）
	if addedFindings > 0 {
		s.notifyFindings(req.Findings)
	}
	s.maybeSaveState()
	if len(req.Findings) > 0 {
		for _, f := range req.Findings {
			s.auditLog("vuln_found", map[string]string{
				"agent_id": req.AgentID, "scan_id": req.ScanID,
				"template": f.TemplateID, "severity": f.Severity, "matched_at": f.MatchedAt,
			})
		}
	}
	s.logf("Agent %s 上报：资产 %d 新增/%d 重复，漏洞 %d 新增，任务结果 %d",
		req.AgentID, addedAssets, dup, addedFindings, len(req.Outcomes))

	writeJSON(w, http.StatusOK, wire.ReportResponse{
		AcceptedAssets:   addedAssets,
		AcceptedFindings: addedFindings,
		Duplicates:       dup,
		KnownScans:       true,
	})
}

func (s *Server) touchAgent(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if a := s.agents[id]; a != nil {
		a.LastSeen = time.Now()
	} else {
		s.agents[id] = &wire.AgentStatus{ID: id, LastSeen: time.Now()}
	}
}

// handleMetrics 输出 Prometheus 文本格式（手写，避免引入客户端库）。
func (s *Server) handleMetrics(w http.ResponseWriter) {
	s.mu.Lock()
	c := s.counters
	st := wire.Stats{Tasks: map[wire.TaskState]int{}}
	for _, t := range s.tasks {
		st.Tasks[t.State]++
	}
	assets := s.assets.Len()
	findings := len(s.findings)
	agents := len(s.agents)
	s.mu.Unlock()

	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	var b strings.Builder
	metric := func(name, help, typ string, value int64) {
		fmt.Fprintf(&b, "# HELP %s %s\n# TYPE %s %s\n%s %d\n", name, help, name, typ, name, value)
	}
	metric("westy_jobs_dispatched_total", "已派发的任务总数", "counter", c.jobsDispatched)
	metric("westy_reports_total", "Agent 上报次数", "counter", c.reports)
	metric("westy_assets_total", "汇聚后的资产条目", "gauge", int64(assets))
	metric("westy_assets_duplicates_total", "被去重丢弃的资产条目", "counter", c.assetsDup)
	metric("westy_findings_total", "汇聚后的漏洞条目", "gauge", int64(findings))
	metric("westy_targets_rejected_total", "被 Agent 授权闸门拦下的目标", "counter", c.rejected)
	metric("westy_auth_failures_total", "鉴权失败次数", "counter", c.authFailures)
	metric("westy_agents_online", "已注册 Agent 数", "gauge", int64(agents))
	metric("westy_tasks_pending", "待执行任务", "gauge", int64(st.Tasks[wire.TaskPending]))
	metric("westy_tasks_running", "执行中任务", "gauge", int64(st.Tasks[wire.TaskRunning]))
	metric("westy_tasks_done", "已完成任务", "gauge", int64(st.Tasks[wire.TaskDone]))
	metric("westy_tasks_failed", "已失败任务", "gauge", int64(st.Tasks[wire.TaskFailed]))
	_, _ = w.Write([]byte(b.String()))
}

func readJSON(r *http.Request, v any) error {
	defer r.Body.Close()
	dec := json.NewDecoder(http.MaxBytesReader(nil, r.Body, 64<<20))
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("请求体解析失败: %w", err)
	}
	return nil
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func itoa(n int) string { return fmt.Sprintf("%d", n) }

// chunkPorts 按 chunkSize 切分端口列表；chunkSize<=0 表示不切分（整份端口一个任务）。
func chunkPorts(ports []int, chunkSize int) [][]int {
	if len(ports) == 0 {
		return [][]int{nil}
	}
	if chunkSize <= 0 || chunkSize >= len(ports) {
		return [][]int{append([]int(nil), ports...)}
	}
	var out [][]int
	for i := 0; i < len(ports); i += chunkSize {
		end := min(i+chunkSize, len(ports))
		out = append(out, append([]int(nil), ports[i:end]...))
	}
	return out
}
