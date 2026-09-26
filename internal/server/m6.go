package server

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"westy_scan/internal/authz"
	"westy_scan/internal/diff"
	"westy_scan/internal/model"
	"westy_scan/internal/notify"
	"westy_scan/internal/poc"
	"westy_scan/internal/report"
	"westy_scan/internal/wire"
)

// M6：平台化能力 —— RBAC、授权书绑定、Web UI、对比、报告导出、定时扫描、通知。

//go:embed web/*
var webFS embed.FS

// 角色。数字越大权限越高。
type role int

const (
	roleNone role = iota
	roleViewer
	roleOperator
	roleAdmin
)

func parseRole(s string) role {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "admin":
		return roleAdmin
	case "operator":
		return roleOperator
	case "viewer":
		return roleViewer
	default:
		return roleNone
	}
}

func (r role) String() string {
	switch r {
	case roleAdmin:
		return "admin"
	case roleOperator:
		return "operator"
	case roleViewer:
		return "viewer"
	default:
		return "none"
	}
}

// roleOf 解析请求身份。Roles 为空时退回单一 Token（视为 admin）。
func (s *Server) roleOf(r *http.Request) role {
	raw := strings.TrimSpace(r.Header.Get("Authorization"))
	raw = strings.TrimSpace(strings.TrimPrefix(raw, "Bearer "))
	if len(s.opt.Roles) > 0 {
		for token, name := range s.opt.Roles {
			if wire.TokenOK(raw, token) {
				return parseRole(name)
			}
		}
		return roleNone
	}
	if s.opt.Token == "" {
		return roleAdmin // 开发模式：无鉴权
	}
	if wire.TokenOK(raw, s.opt.Token) {
		return roleAdmin
	}
	return roleNone
}

// requireRole 生成带角色校验的处理器。
func (s *Server) requireRole(min role, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		got := s.roleOf(r)
		if got < min {
			s.mu.Lock()
			s.counters.authFailures++
			s.mu.Unlock()
			s.auditLog("auth_denied", map[string]string{
				"remote": r.RemoteAddr, "path": r.URL.Path,
				"role": got.String(), "need": min.String(),
			})
			// HTTP 语义：没有有效身份 → 401（客户端应重新认证）；身份有效但权限不够 → 403
			status := http.StatusForbidden
			if got == roleNone {
				status = http.StatusUnauthorized
			}
			writeJSON(w, status, map[string]string{
				"error": fmt.Sprintf("鉴权/权限校验失败：需要 %s，当前 %s", min, got),
			})
			return
		}
		next(w, r)
	}
}

// ---------------- 授权书 ----------------

// 授权相关的哨兵错误。
//
// 为什么需要：HTTP 处理与授权书导入以前靠 `strings.Contains(err.Error(), "授权书"/"已存在")`
// 来决定状态码（403 还是 400）与去重行为 —— 改一次错误文案就会静默改变 API 语义。
// 现在判定一律走 errors.Is，错误文案只负责给人看。
var (
	// ErrAuthzDenied 覆盖"授权闸门不通过"的所有情况：没给授权书、授权书不存在、
	// 授权书过期/未生效、目标不在授权范围内。HTTP 层据此返回 403。
	ErrAuthzDenied = errors.New("授权校验未通过")
	// ErrAuthzExists 用于授权书导入时的幂等去重（已存在就跳过，不算失败）。
	ErrAuthzExists = errors.New("授权书已存在")
	// ErrScanExists 用于扫描创建的去重（同一个 scan_id 重复创建视为冲突）。
	ErrScanExists = errors.New("扫描 ID 已存在")
)

// CreateAuthorization 登记一份授权书。
func (s *Server) CreateAuthorization(rec authz.Record) error {
	if err := authz.ValidateRecord(rec); err != nil {
		return err
	}
	if _, ok := s.authzRecs[rec.ID]; ok {
		return fmt.Errorf("%w: %s", ErrAuthzExists, rec.ID)
	}
	// 有效期本身也要能通过闸门校验（例如已经是过期的时间段）
	if _, err := authz.NewGuard(rec, time.Now()); err != nil {
		return err
	}
	if rec.CreatedAt.IsZero() {
		rec.CreatedAt = time.Now()
	}
	s.mu.Lock()
	s.authzRecs[rec.ID] = rec
	s.markDirty()
	s.mu.Unlock()
	s.auditLog("authorization_created", map[string]string{
		"id": rec.ID, "client": rec.Client, "allow": strings.Join(rec.Allow, ","),
		"valid_to": rec.ValidTo.Format(time.RFC3339), "approver": rec.Approver, "ticket": rec.Ticket,
	})
	s.maybeSaveState()
	return nil
}

// Authorizations 返回全部授权书。
func (s *Server) Authorizations() []authz.Record {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]authz.Record, 0, len(s.authzRecs))
	for _, rec := range s.authzRecs {
		out = append(out, rec)
	}
	return out
}

// guardFor 取出并校验指定授权书。任何失败都包上 ErrAuthzDenied，
// 便于 HTTP 层用 errors.Is 判定 403，而不用去猜错误文案。
func (s *Server) guardFor(id string) (*authz.Guard, error) {
	if strings.TrimSpace(id) == "" {
		return nil, fmt.Errorf("%w: 创建扫描必须关联有效授权书（authorization 字段），本次未提供", ErrAuthzDenied)
	}
	s.mu.Lock()
	rec, ok := s.authzRecs[id]
	s.mu.Unlock()
	if !ok {
		return nil, fmt.Errorf("%w: 授权书 %s 不存在", ErrAuthzDenied, id)
	}
	g, err := authz.NewGuard(rec, time.Now())
	if err != nil {
		// 过期、未生效、记录非法都归到同一个哨兵
		return nil, fmt.Errorf("%w: %w", ErrAuthzDenied, err)
	}
	return g, nil
}

// CreateScanAuthorized 创建扫描：先过授权书闸门，再切片入队。
func (s *Server) CreateScanAuthorized(spec wire.ScanSpec) (*wire.ScanInfo, error) {
	guard, err := s.guardFor(spec.Authorization)
	if err != nil {
		s.auditLog("scan_denied", map[string]string{
			"reason": err.Error(), "hosts": strings.Join(spec.Hosts, ","),
		})
		return nil, err
	}
	if bad, reason := guard.AllowAll(spec.Hosts); bad != "" {
		err := fmt.Errorf("%w: 目标 %s 不在授权书 %s 范围内：%s", ErrAuthzDenied, bad, spec.Authorization, reason)
		s.auditLog("scan_denied", map[string]string{
			"reason": err.Error(), "authorization": spec.Authorization, "target": bad,
		})
		return nil, err
	}
	info, err := s.CreateScan(spec)
	if err != nil {
		return nil, err
	}
	s.auditLog("scan_authorized", map[string]string{
		"scan_id": info.ID, "authorization": spec.Authorization,
		"operator": spec.Operator, "guard": guard.Describe(),
	})
	s.maybeSaveState()
	return info, nil
}

// ---------------- 定时扫描 ----------------

// EnableSchedule 在运行期启用定时扫描（CLI 创建首个扫描后调用）。
func (s *Server) EnableSchedule(every time.Duration, spec wire.ScanSpec) {
	if every <= 0 {
		return
	}
	s.mu.Lock()
	s.opt.ScheduleEvery = every
	cp := spec
	s.opt.ScheduleSpec = &cp
	s.mu.Unlock()
	s.startScheduler()
}

func (s *Server) startScheduler() {
	s.schedWG.Add(1)
	go func() {
		defer s.schedWG.Done()
		ticker := time.NewTicker(s.opt.ScheduleEvery)
		defer ticker.Stop()
		s.logf("定时扫描已启用：每 %s 一次（授权书 %s）", s.opt.ScheduleEvery, s.opt.ScheduleSpec.Authorization)
		for {
			select {
			case <-s.stop:
				return
			case <-ticker.C:
				spec := *s.opt.ScheduleSpec
				spec.ScanID = "" // 每次都是新扫描，便于按时间对比
				if spec.Operator == "" {
					spec.Operator = "scheduler"
				}
				info, err := s.CreateScanAuthorized(spec)
				if err != nil {
					s.logf("定时扫描创建失败: %v", err)
					s.auditLog("scheduled_scan_failed", map[string]string{"error": err.Error()})
					continue
				}
				s.logf("定时扫描已创建: %s（任务 %d）", info.ID, info.Tasks)
			}
		}
	}()
}

// ---------------- 通知 ----------------

// notifyScanDone 在扫描完成时发通知。
func (s *Server) notifyScanDone(info *wire.ScanInfo) {
	if s.notify == nil || !s.notify.Enabled() || info == nil {
		return
	}
	ev := notify.Event{
		Title:   "westy_scan 扫描完成",
		ScanID:  info.ID,
		Summary: fmt.Sprintf("任务 %d（完成 %d / 失败 %d），资产 %d，漏洞 %d", info.Tasks, info.Done, info.Failed, info.Assets, info.Findings),
		Level:   "info",
	}
	if info.Failed > 0 {
		ev.Level = "warning"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := s.notify.Send(ctx, ev); err != nil {
		s.logf("通知发送失败: %v", err)
	}
}

// notifyFindings 在新漏洞达到阈值时发通知。
func (s *Server) notifyFindings(findings []poc.Finding) {
	if s.notify == nil || !s.notify.Enabled() || len(findings) == 0 {
		return
	}
	var hits []poc.Finding
	for _, f := range findings {
		if poc.SeverityAtLeast(f.Severity, s.opt.NotifyMinSeverity) {
			hits = append(hits, f)
		}
	}
	if len(hits) == 0 {
		return
	}
	ev := notify.Event{
		Title:   fmt.Sprintf("westy_scan 发现 %d 个漏洞", len(hits)),
		Summary: fmt.Sprintf("阈值 %s 及以上", orDefault(s.opt.NotifyMinSeverity, "全部")),
		Level:   "critical",
	}
	for i, f := range hits {
		if i >= 10 {
			ev.Details = append(ev.Details, fmt.Sprintf("…以及另外 %d 条", len(hits)-i))
			break
		}
		// 响应者需要"哪条模板 + 打在哪"，名称可能为空，模板 ID 一定有
		label := f.TemplateID
		if f.Name != "" {
			label = fmt.Sprintf("%s(%s)", f.Name, f.TemplateID)
		}
		ev.Details = append(ev.Details, fmt.Sprintf("[%s] %s → %s", strings.ToUpper(f.Severity), label, f.MatchedAt))
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := s.notify.Send(ctx, ev); err != nil {
		s.logf("漏洞通知发送失败: %v", err)
	}
}

func orDefault(v, def string) string {
	if strings.TrimSpace(v) == "" {
		return def
	}
	return v
}

// ---------------- HTTP 处理器 ----------------

func (s *Server) serveUI(w http.ResponseWriter, r *http.Request) {
	path := "web/index.html"
	if r.URL.Path != "/" && r.URL.Path != "/index.html" {
		path = "web" + strings.TrimPrefix(r.URL.Path, "/")
	}
	data, err := fs.ReadFile(webFS, path)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	switch {
	case strings.HasSuffix(path, ".html"):
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
	case strings.HasSuffix(path, ".js"):
		w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
	case strings.HasSuffix(path, ".css"):
		w.Header().Set("Content-Type", "text/css; charset=utf-8")
	}
	_, _ = w.Write(data)
}

func (s *Server) handleListScans(w http.ResponseWriter) {
	st := s.Stats()
	out := make([]*wire.ScanInfo, 0, len(st.Scans))
	for _, info := range st.Scans {
		out = append(out, info)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleCreateScan(w http.ResponseWriter, r *http.Request) {
	var spec wire.ScanSpec
	if err := readJSON(r, &spec); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if spec.Operator == "" {
		spec.Operator = "api:" + s.roleOf(r).String()
	}
	info, err := s.CreateScanAuthorized(spec)
	if err != nil {
		status := http.StatusBadRequest
		if strings.Contains(err.Error(), "授权书") {
			status = http.StatusForbidden
		}
		writeJSON(w, status, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, info)
}

func (s *Server) handleAssets(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	scanID := q.Get("scan_id")
	host := q.Get("host")
	limit := atoiDefault(q.Get("limit"), 500)

	all := s.Assets()
	if scanID != "" {
		all = diff.AssetsByKeys(all, s.ObservedAssetKeys(scanID))
	}
	out := make([]model.Asset, 0, len(all))
	for _, a := range all {
		if host != "" && !strings.Contains(strings.ToLower(a.Host), strings.ToLower(host)) {
			continue
		}
		out = append(out, a)
		if len(out) >= limit {
			break
		}
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleFindings(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	scanID := q.Get("scan_id")
	minSev := q.Get("min_severity")
	limit := atoiDefault(q.Get("limit"), 500)

	var out []poc.Finding
	obs := map[string]bool(nil)
	if scanID != "" {
		obs = s.ObservedFindingKeys(scanID)
	}
	for _, f := range s.Findings() {
		if scanID != "" && !obs[diff.FindingKey(f)] {
			continue
		}
		if !poc.SeverityAtLeast(f.Severity, minSev) {
			continue
		}
		out = append(out, f)
		if len(out) >= limit {
			break
		}
	}
	writeJSON(w, http.StatusOK, out)
}

// handleDiff 对比两次扫描：?against=<基线扫描ID> 或 &scan_id=<本次>
func (s *Server) handleDiff(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	cur := q.Get("scan_id")
	base := q.Get("against")
	if cur == "" || base == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "需要 scan_id（本次）与 against（基线）两个参数",
		})
		return
	}
	assets := s.Assets()
	findings := s.Findings()
	// 按"该次扫描观察到过的键集合"切片，而不是按记录上的 scan_id（那只是首次发现归属）
	baseAssets := diff.AssetsByKeys(assets, s.ObservedAssetKeys(base))
	baseFindings := diff.FindingsByKeys(findings, s.ObservedFindingKeys(base))
	curAssets := diff.AssetsByKeys(assets, s.ObservedAssetKeys(cur))
	curFindings := diff.FindingsByKeys(findings, s.ObservedFindingKeys(cur))

	res := diff.Compare(baseAssets, curAssets, baseFindings, curFindings)
	res.FromScanID, res.ToScanID = base, cur
	if bi := s.ScanInfo(base); bi != nil {
		res.FromTime = bi.CreatedAt
	}
	if ci := s.ScanInfo(cur); ci != nil {
		res.ToTime = ci.CreatedAt
	}
	writeJSON(w, http.StatusOK, res)
}

func (s *Server) handleListAuthorizations(w http.ResponseWriter) {
	writeJSON(w, http.StatusOK, s.Authorizations())
}

func (s *Server) handleCreateAuthorization(w http.ResponseWriter, r *http.Request) {
	var rec authz.Record
	if err := readJSON(r, &rec); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if err := s.CreateAuthorization(rec); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, rec)
}

// handleExportReport 导出报告：?format=html|markdown|json&scan_id=
func (s *Server) handleExportReport(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	scanID := q.Get("scan_id")
	format := strings.ToLower(q.Get("format"))
	if format == "" {
		format = "html"
	}
	assets := s.Assets()
	findings := s.Findings()
	if scanID != "" {
		// 报告回答的是"这次扫描发现了什么"，同样用观察集合而不是首次发现归属
		assets = diff.AssetsByKeys(assets, s.ObservedAssetKeys(scanID))
		findings = diff.FindingsByKeys(findings, s.ObservedFindingKeys(scanID))
	}
	findings = poc.FindingsBySeverity(findings)

	meta := report.HTMLMeta{ScanID: scanID, GeneratedAt: time.Now()}
	if scanID != "" {
		meta.Title = "扫描报告 " + scanID
	}
	switch format {
	case "json":
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_ = json.NewEncoder(w).Encode(map[string]any{"assets": assets, "findings": findings})
	case "markdown", "md":
		w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
		_ = report.WriteMarkdown(w, assets)
		_ = report.WriteFindingsMarkdown(w, findings)
	default:
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if err := report.WriteHTML(w, assets, findings, meta); err != nil {
			s.logf("生成 HTML 报告失败: %v", err)
		}
	}
}

func atoiDefault(s string, def int) int {
	if strings.TrimSpace(s) == "" {
		return def
	}
	n, err := strconv.Atoi(s)
	if err != nil || n <= 0 {
		return def
	}
	return n
}
