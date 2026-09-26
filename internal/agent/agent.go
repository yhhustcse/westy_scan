// Package agent 实现分布式扫描的执行端（M5）。
//
// 三个必须守住的性质：
//  1. **本地授权闸门**：Agent 用自己的 allow/deny 复检每个目标，Server 无权"授权"越界目标；
//  2. **不丢数据**：上报失败时写入本地磁盘缓冲（spool），恢复后重放；
//  3. **不打扰目标**：所有出网请求仍走 Agent 本地的全局限速与并发收敛。
package agent

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"westy_scan/internal/config"
	"westy_scan/internal/model"
	"westy_scan/internal/pipeline"
	"westy_scan/internal/poc"
	"westy_scan/internal/scope"
	"westy_scan/internal/store"
	"westy_scan/internal/wire"
)

// TLSConfig 是 Agent 侧 TLS 参数。
type TLSConfig struct {
	CAFile             string // 校验服务端证书的 CA（为空则用系统根）
	CertFile, KeyFile  string // 双向 TLS 时的客户端证书
	InsecureSkipVerify bool   // 仅调试用
}

// Config 是 Agent 参数。
type Config struct {
	ServerURL    string
	Token        string
	AgentID      string
	Version      string
	TLS          TLSConfig
	MaxJobs      int           // 每次拉取的任务数
	PullWaitSecs int           // 长轮询等待秒数
	BatchSize    int           // 上报批量条数
	FlushEvery   time.Duration // 上报间隔
	SpoolDir     string        // 断线缓冲目录（为空则不缓冲）
	Scan         config.Config // 扫描配置模板：**本地授权范围**在这里
	Log          *log.Logger
}

func (c Config) withDefaults() Config {
	if c.MaxJobs <= 0 {
		c.MaxJobs = 4
	}
	if c.PullWaitSecs <= 0 {
		c.PullWaitSecs = 20
	}
	if c.BatchSize <= 0 {
		c.BatchSize = 200
	}
	if c.FlushEvery <= 0 {
		c.FlushEvery = time.Second
	}
	if c.Version == "" {
		c.Version = "0.1.0"
	}
	return c
}

// Agent 是执行端。
type Agent struct {
	cfg    Config
	client *http.Client

	mu     sync.Mutex
	spool  []string // 待重放的上报文件名
	id     string
	logger *log.Logger
}

// New 构造 Agent。
func New(cfg Config) (*Agent, error) {
	cfg = cfg.withDefaults()
	if strings.TrimSpace(cfg.ServerURL) == "" {
		return nil, fmt.Errorf("缺少 Server 地址")
	}
	// 本地授权范围必须显式声明，否则拒绝启动（与单机模式同一套闸门）
	if !cfg.Scan.Authorized {
		return nil, fmt.Errorf("Agent 必须声明本地授权（config.scan.authorized=true 或 -authorized）")
	}
	transport := &http.Transport{
		DialContext:         (&net.Dialer{Timeout: 10 * time.Second}).DialContext,
		MaxIdleConns:        8,
		MaxIdleConnsPerHost: 4,
		IdleConnTimeout:     60 * time.Second,
	}
	if cfg.TLS.CAFile != "" || cfg.TLS.CertFile != "" || cfg.TLS.InsecureSkipVerify {
		tlsCfg, err := buildTLS(cfg.TLS)
		if err != nil {
			return nil, err
		}
		transport.TLSClientConfig = tlsCfg
	}
	a := &Agent{
		cfg: cfg,
		client: &http.Client{
			Transport: transport,
			Timeout:   60 * time.Second,
		},
		logger: cfg.Log,
	}
	if a.logger == nil {
		a.logger = log.New(io.Discard, "", 0)
	}
	if cfg.SpoolDir != "" {
		if err := os.MkdirAll(cfg.SpoolDir, 0o755); err != nil {
			return nil, fmt.Errorf("创建缓冲目录失败: %w", err)
		}
	}
	return a, nil
}

func buildTLS(c TLSConfig) (*tls.Config, error) {
	cfg := &tls.Config{InsecureSkipVerify: c.InsecureSkipVerify} //nolint:gosec // 调试开关
	if c.CAFile != "" {
		pem, err := os.ReadFile(c.CAFile)
		if err != nil {
			return nil, fmt.Errorf("读取 CA 失败: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("CA 文件不含有效证书: %s", c.CAFile)
		}
		cfg.RootCAs = pool
	}
	if c.CertFile != "" && c.KeyFile != "" {
		cert, err := tls.LoadX509KeyPair(c.CertFile, c.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("加载客户端证书失败: %w", err)
		}
		cfg.Certificates = []tls.Certificate{cert}
	}
	return cfg, nil
}

func (a *Agent) logf(format string, args ...any) { a.logger.Printf(format, args...) }

// Run 注册并进入拉取/执行/上报循环，直到 ctx 结束。
func (a *Agent) Run(ctx context.Context) error {
	reg, err := a.register(ctx)
	if err != nil {
		return err
	}
	a.id = reg.AgentID
	a.logf("已注册为 %s（服务端 %s，协议 v%d，租约 %ds）", reg.AgentID, reg.ServerVersion, reg.Protocol, reg.LeaseSeconds)

	for ctx.Err() == nil {
		a.replaySpool(ctx)

		jobs, err := a.pull(ctx, a.cfg.MaxJobs, a.cfg.PullWaitSecs)
		if err != nil {
			a.logf("拉取任务失败: %v", err)
			if !sleepCtx(ctx, 3*time.Second) {
				break
			}
			continue
		}
		for _, job := range jobs {
			if ctx.Err() != nil {
				break
			}
			a.runJob(ctx, job)
		}
	}
	a.logf("Agent 退出")
	return nil
}

func (a *Agent) post(ctx context.Context, path string, body any, out any) error {
	data, err := json.Marshal(body)
	if err != nil {
		return err
	}
	url := strings.TrimRight(a.cfg.ServerURL, "/") + path
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if a.cfg.Token != "" {
		req.Header.Set("Authorization", "Bearer "+a.cfg.Token)
	}
	resp, err := a.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	payload, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("服务端返回 %d: %s", resp.StatusCode, strings.TrimSpace(string(payload)))
	}
	if out != nil {
		if err := json.Unmarshal(payload, out); err != nil {
			return fmt.Errorf("响应解析失败: %w", err)
		}
	}
	return nil
}

func (a *Agent) register(ctx context.Context) (*wire.RegisterResponse, error) {
	hostname, _ := os.Hostname()
	req := wire.RegisterRequest{
		AgentID:      a.cfg.AgentID,
		Version:      a.cfg.Version,
		Hostname:     hostname,
		Protocol:     wire.ProtocolVersion,
		Capabilities: []string{"tcp-scan", "service-detect", "http", "crawl", "poc"},
	}
	var out wire.RegisterResponse
	if err := a.post(ctx, "/api/v1/agents/register", req, &out); err != nil {
		return nil, fmt.Errorf("注册失败: %w", err)
	}
	if out.AgentID == "" {
		return nil, fmt.Errorf("服务端未返回 agent_id")
	}
	return &out, nil
}

func (a *Agent) pull(ctx context.Context, maxJobs, waitSecs int) ([]wire.JobSpec, error) {
	var out wire.PullResponse
	err := a.post(ctx, "/api/v1/agents/pull", wire.PullRequest{
		AgentID: a.id, MaxJobs: maxJobs, WaitSeconds: waitSecs,
	}, &out)
	if err != nil {
		return nil, err
	}
	return out.Jobs, nil
}

// runJob 执行一个任务：本地授权复检 → 跑扫描流水线 → 上报。
func (a *Agent) runJob(ctx context.Context, job wire.JobSpec) {
	a.logf("开始任务 %s：%s（%d 个端口）", job.ID, job.Host, len(job.Ports))

	outcome := wire.TaskOutcome{JobID: job.ID, Host: job.Host, State: wire.TaskDone}
	var findings []poc.Finding
	var rejected []string

	// 被本地授权闸门拦下的目标必须单独上报（审计要能看出"Agent 拒绝了什么"）。
	// 判定必须走 errors.Is：以前用错误**文案**匹配，改一个字就静默失效，
	// 而且 DNS 解析失败这类"没被授权书允许"的拒绝原因也进不了 rejected。
	// 三种来源都要认：单个目标越界（scope）、解析失败（scope）、以及"全部目标都被拒"（pipeline）。
	noteRejected := func(err error) {
		if err == nil {
			return
		}
		if errors.Is(err, scope.ErrOutOfScope) ||
			errors.Is(err, scope.ErrResolveFailed) ||
			errors.Is(err, pipeline.ErrAllTargetsRejected) {
			rejected = append(rejected, job.Host)
		}
	}

	cfg := a.cfg.Scan
	cfg.Targets = []string{job.Host}
	// 任务只能扫"服务端下发的这一台主机"：必须清掉配置模板里的 target_file，
	// 否则每个任务都会额外扫描该文件里的目标，且资产会被计到这个 job 的 scan_id 名下
	// —— 那些目标仍在 Agent 授权范围内（不漏授权），但"一个 job = 一台主机"的归属语义会被破坏。
	cfg.TargetFile = ""
	cfg.Ports = joinPorts(job.Ports)
	// Web 种子由本次扫描自己产生，避免把上一个任务的种子带进来
	reporter := newReportStore(a, job.ScanID)

	eng, err := pipeline.New(cfg, reporter, nil, a.logger)
	if err != nil {
		outcome.State = wire.TaskFailed
		outcome.Error = err.Error()
		noteRejected(err)
		a.logf("任务 %s 失败: %v", job.ID, err)
	} else {
		a.logf("任务 %s 本地授权范围: %s", job.ID, eng.Scope().Describe())
		if err := eng.Run(ctx); err != nil {
			outcome.State = wire.TaskFailed
			outcome.Error = err.Error()
			noteRejected(err)
			a.logf("任务 %s 执行失败: %v", job.ID, err)
		}
		findings = eng.Findings()
	}

	// 收尾：把缓冲区里剩下的资产连同任务结果一起上报
	if err := reporter.Flush(ctx, outcome, findings, rejected); err != nil {
		a.logf("任务 %s 上报失败（已写入本地缓冲，稍后重放）: %v", job.ID, err)
		return
	}
	a.logf("任务 %s 完成：资产 %d 条，漏洞 %d 条", job.ID, reporter.Total(), len(findings))
}

type pendingReport struct {
	ScanID   string            `json:"scan_id"`
	Outcome  *wire.TaskOutcome `json:"outcome,omitempty"`
	Assets   []model.Asset     `json:"assets,omitempty"`
	Findings []poc.Finding     `json:"findings,omitempty"`
	Rejected []string          `json:"rejected,omitempty"`
}

// reportStore 实现 store.Store：资产一边产出、一边按条数/时间批量上报。
// 上报失败就落盘缓冲，绝不让"网络抖动"变成"数据丢失"。
type reportStore struct {
	agent  *Agent
	scanID string

	mu     sync.Mutex
	buf    []model.Asset
	last   time.Time
	total  int
	memory *store.Memory
}

func newReportStore(a *Agent, scanID string) *reportStore {
	return &reportStore{agent: a, scanID: scanID, last: time.Now(), memory: store.NewMemory()}
}

// Add 实现 store.Store。
func (r *reportStore) Add(a model.Asset) error {
	_ = r.memory.Add(a)
	r.mu.Lock()
	r.buf = append(r.buf, a)
	r.total++
	needFlush := len(r.buf) >= r.agent.cfg.BatchSize || time.Since(r.last) >= r.agent.cfg.FlushEvery
	r.mu.Unlock()
	if needFlush {
		if err := r.flushOnly(context.Background()); err != nil {
			r.agent.logf("批量上报失败: %v", err)
		}
	}
	return nil
}

// Len 实现 store.Store。
func (r *reportStore) Len() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.total
}

// Assets 实现 store.Store。
func (r *reportStore) Assets() []model.Asset { return r.memory.Assets() }

// Close 实现 store.Store。
func (r *reportStore) Close() error { return nil }

// Total 返回本次任务产出的资产总数。
func (r *reportStore) Total() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.total
}

func (r *reportStore) take() []model.Asset {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := r.buf
	r.buf = nil
	r.last = time.Now()
	return out
}

// flushOnly 只上报已缓冲的资产（中途批量）。
func (r *reportStore) flushOnly(ctx context.Context) error {
	assets := r.take()
	if len(assets) == 0 {
		return nil
	}
	return r.agent.sendReport(ctx, pendingReport{ScanID: r.scanID, Assets: assets})
}

// Flush 收尾上报：剩余资产 + 任务结果 + 漏洞。
func (r *reportStore) Flush(ctx context.Context, outcome wire.TaskOutcome, findings []poc.Finding, rejected []string) error {
	assets := r.take()
	report := pendingReport{
		ScanID:   r.scanID,
		Outcome:  &outcome,
		Assets:   assets,
		Findings: findings,
		Rejected: rejected,
	}
	return r.agent.sendReport(ctx, report)
}

// sendReport 发送一次上报；失败则写盘缓冲。
func (a *Agent) sendReport(ctx context.Context, report pendingReport) error {
	req := wire.ReportRequest{
		AgentID:  a.id,
		ScanID:   report.ScanID,
		Assets:   report.Assets,
		Findings: report.Findings,
		Rejected: report.Rejected,
	}
	if report.Outcome != nil {
		req.Outcomes = []wire.TaskOutcome{*report.Outcome}
	}
	var resp wire.ReportResponse
	if err := a.post(ctx, "/api/v1/agents/report", req, &resp); err != nil {
		if a.cfg.SpoolDir != "" {
			if serr := a.writeSpool(report); serr != nil {
				return fmt.Errorf("%w（写缓冲也失败: %v）", err, serr)
			}
			return fmt.Errorf("%w（已写入本地缓冲）", err)
		}
		return err
	}
	return nil
}

func (a *Agent) writeSpool(report pendingReport) error {
	name := filepath.Join(a.cfg.SpoolDir, fmt.Sprintf("report-%d-%s.json", time.Now().UnixNano(), randSuffix()))
	data, err := json.Marshal(report)
	if err != nil {
		return err
	}
	return os.WriteFile(name, data, 0o600)
}

func randSuffix() string {
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		return "0000"
	}
	return fmt.Sprintf("%x", b)
}

// replaySpool 重放本地缓冲（断线恢复后先补数据，再拉新任务）。
func (a *Agent) replaySpool(ctx context.Context) {
	if a.cfg.SpoolDir == "" {
		return
	}
	entries, err := os.ReadDir(a.cfg.SpoolDir)
	if err != nil {
		return
	}
	var names []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".json") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	for _, name := range names {
		if ctx.Err() != nil {
			return
		}
		path := filepath.Join(a.cfg.SpoolDir, name)
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		var report pendingReport
		if err := json.Unmarshal(data, &report); err != nil {
			a.logf("缓冲文件损坏，已删除: %s", name)
			_ = os.Remove(path)
			continue
		}
		if err := a.sendReportNoSpool(ctx, report); err != nil {
			a.logf("重放缓冲失败（下次再试）: %v", err)
			return
		}
		a.logf("已重放缓冲 %s", name)
		_ = os.Remove(path)
	}
}

// sendReportNoSpool 重放时使用：失败不再写缓冲，避免无限增长。
func (a *Agent) sendReportNoSpool(ctx context.Context, report pendingReport) error {
	req := wire.ReportRequest{
		AgentID: a.id, ScanID: report.ScanID,
		Assets: report.Assets, Findings: report.Findings, Rejected: report.Rejected,
	}
	if report.Outcome != nil {
		req.Outcomes = []wire.TaskOutcome{*report.Outcome}
	}
	return a.post(ctx, "/api/v1/agents/report", req, nil)
}

func joinPorts(ports []int) string {
	parts := make([]string, 0, len(ports))
	for _, p := range ports {
		parts = append(parts, strconv.Itoa(p))
	}
	return strings.Join(parts, ",")
}

func sleepCtx(ctx context.Context, d time.Duration) bool {
	select {
	case <-ctx.Done():
		return false
	case <-time.After(d):
		return true
	}
}
