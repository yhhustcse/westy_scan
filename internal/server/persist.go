package server

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
	"westy_scan/internal/jsonutil"

	"westy_scan/internal/authz"
	"westy_scan/internal/diff"
	"westy_scan/internal/model"
	"westy_scan/internal/poc"
	"westy_scan/internal/wire"
)

// 持久化策略（零依赖）：
//   - 任务/扫描/Agent/授权书这类"小状态"：整体快照写到 state.json（临时文件 + 原子重命名）；
//   - 资产/漏洞这类"会不断增长的数据"：追加写 JSONL，避免每次全量重写；
//   - 恢复时以结果为准重建任务计数，不盲信快照里的计数（防半途崩溃导致的状态不一致）。
//
// 真正的生产环境应该换 Postgres（接口已抽象好），但"重启不丢"这条底线用标准库就能守住。
type snapshot struct {
	SavedAt  time.Time                    `json:"saved_at"`
	Tasks    []*wire.Task                 `json:"tasks"`
	Scans    map[string]*wire.ScanInfo    `json:"scans"`
	Agents   map[string]*wire.AgentStatus `json:"agents"`
	Authz    map[string]authz.Record      `json:"authorizations"`
	Obs      map[string]*scanObs          `json:"observed"`
	Counters counters                     `json:"counters"`
}

type persister struct {
	dir       string
	statePath string

	mu        sync.Mutex
	assetFile *os.File
	findFile  *os.File
	assetEnc  *json.Encoder
	findEnc   *json.Encoder
	dirty     bool
	lastSave  time.Time
	saveEvery time.Duration
}

func newPersister(dir string) (*persister, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("创建数据目录失败: %w", err)
	}
	p := &persister{
		dir:       dir,
		statePath: filepath.Join(dir, "state.json"),
		saveEvery: 2 * time.Second,
	}
	var err error
	if p.assetFile, err = os.OpenFile(filepath.Join(dir, "assets.jsonl"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644); err != nil {
		return nil, err
	}
	if p.findFile, err = os.OpenFile(filepath.Join(dir, "findings.jsonl"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644); err != nil {
		_ = p.assetFile.Close()
		return nil, err
	}
	p.assetEnc = json.NewEncoder(p.assetFile)
	p.findEnc = json.NewEncoder(p.findFile)
	return p, nil
}

// appendAsset 追加一条资产。写盘失败只记录 dirty，由后台/收尾统一重试整体快照。
func (p *persister) appendAsset(a model.Asset) {
	p.mu.Lock()
	defer p.mu.Unlock()
	_ = p.assetEnc.Encode(a)
}

func (p *persister) appendFinding(f poc.Finding) {
	p.mu.Lock()
	defer p.mu.Unlock()
	_ = p.findEnc.Encode(f)
}

// markDirty 标记"小状态"有变化，由 maybeSave 做去抖落盘。
func (p *persister) markDirty() {
	p.mu.Lock()
	p.dirty = true
	p.mu.Unlock()
}

func (p *persister) maybeSave(s *snapshot) {
	p.mu.Lock()
	if !p.dirty || time.Since(p.lastSave) < p.saveEvery {
		p.mu.Unlock()
		return
	}
	p.dirty = false
	p.mu.Unlock()
	_ = p.saveState(s)
}

func (p *persister) saveState(s *snapshot) error {
	if s == nil {
		return nil
	}
	s.SavedAt = time.Now()
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	tmp := p.statePath + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	if err := os.Rename(tmp, p.statePath); err != nil {
		return err
	}
	p.mu.Lock()
	p.lastSave = time.Now()
	p.mu.Unlock()
	return nil
}

func (p *persister) loadState() (*snapshot, error) {
	data, err := os.ReadFile(p.statePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var snap snapshot
	if err := jsonutil.Unmarshal(data, &snap); err != nil {
		return nil, err
	}
	return &snap, nil
}

// loadJSONL 逐行读取；损坏的行跳过而不是整体失败（数据尽量保住）。
func loadJSONL[T any](path string) ([]T, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()
	var out []T
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var item T
		if err := json.Unmarshal(line, &item); err != nil {
			continue
		}
		out = append(out, item)
	}
	return out, sc.Err()
}

func (p *persister) loadAssets() ([]model.Asset, error) {
	return loadJSONL[model.Asset](filepath.Join(p.dir, "assets.jsonl"))
}

func (p *persister) loadFindings() ([]poc.Finding, error) {
	return loadJSONL[poc.Finding](filepath.Join(p.dir, "findings.jsonl"))
}

func (p *persister) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	var firstErr error
	if p.assetFile != nil {
		if err := p.assetFile.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
		p.assetFile = nil
	}
	if p.findFile != nil {
		if err := p.findFile.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
		p.findFile = nil
	}
	return firstErr
}

// restore 从磁盘恢复状态。
//
// 关键保持一致性的处理：重启时"运行中"的任务一律回到待执行 ——
// 因为它们的 Agent 连接已经断了，租约无法续期。
func (s *Server) restore() error {
	snap, err := s.persist.loadState()
	if err != nil {
		return err
	}
	if snap != nil {
		for _, t := range snap.Tasks {
			if t == nil || t.Spec.ID == "" {
				continue
			}
			if t.State == wire.TaskRunning {
				t.State = wire.TaskPending
				t.AgentID = ""
			}
			s.tasks[t.Spec.ID] = t
			s.order = append(s.order, t.Spec.ID)
		}
		sort.Slice(s.order, func(i, j int) bool {
			a, b := s.tasks[s.order[i]], s.tasks[s.order[j]]
			if a == nil || b == nil {
				return false
			}
			return a.Spec.CreatedAt.Before(b.Spec.CreatedAt)
		})
		for id, info := range snap.Scans {
			cp := *info
			s.scans[id] = &cp
		}
		for id, a := range snap.Agents {
			cp := *a
			s.agents[id] = &cp
		}
		for id, rec := range snap.Authz {
			s.authzRecs[id] = rec
		}
		// 观察集合：先吃快照，后面再用 JSONL 里的记录补齐/覆盖，
		// 这样即使快照比 JSONL 旧（快照是去抖写的），也不会漏掉扫描归属。
		for id, o := range snap.Obs {
			if o == nil {
				continue
			}
			dst := s.obsLocked(id)
			for k := range o.Assets {
				dst.Assets[k] = true
			}
			for k := range o.Findings {
				dst.Findings[k] = true
			}
		}
		s.counters = snap.Counters
		// 用任务实际状态重建扫描计数，避免半途崩溃留下的脏计数
		for _, info := range s.scans {
			info.Tasks, info.Done, info.Failed, info.Running, info.Pending = 0, 0, 0, 0, 0
		}
		for _, t := range s.tasks {
			info := s.scans[t.Spec.ScanID]
			if info == nil {
				continue
			}
			info.Tasks++
			switch t.State {
			case wire.TaskDone:
				info.Done++
			case wire.TaskFailed:
				info.Failed++
			case wire.TaskRunning:
				info.Running++
			default:
				info.Pending++
			}
		}
	}

	assets, err := s.persist.loadAssets()
	if err != nil {
		return err
	}
	for _, a := range assets {
		key := a.Key()
		if a.MetaValue("scan_id") != "" {
			s.obsLocked(a.MetaValue("scan_id")).Assets[key] = true
		}
		if s.seenKey[key] {
			continue
		}
		s.seenKey[key] = true
		_ = s.assets.Add(a)
	}
	findings, err := s.persist.loadFindings()
	if err != nil {
		return err
	}
	for _, f := range findings {
		s.findings[diff.FindingKey(f)] = f
		if f.ScanID != "" {
			s.obsLocked(f.ScanID).Findings[diff.FindingKey(f)] = true
		}
	}
	for _, info := range s.scans {
		info.Assets = s.countAssetsForScanLocked(info.ID)
		info.Findings = s.countFindingsForScanLocked(info.ID)
	}
	return nil
}

// snapshot 生成当前状态快照。
func (s *Server) snapshot() *snapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	snap := &snapshot{
		Scans:    make(map[string]*wire.ScanInfo, len(s.scans)),
		Agents:   make(map[string]*wire.AgentStatus, len(s.agents)),
		Authz:    make(map[string]authz.Record, len(s.authzRecs)),
		Obs:      make(map[string]*scanObs, len(s.obs)),
		Counters: s.counters,
	}
	for id, o := range s.obs {
		if o == nil {
			continue
		}
		cp := &scanObs{Assets: make(map[string]bool, len(o.Assets)), Findings: make(map[string]bool, len(o.Findings))}
		for k := range o.Assets {
			cp.Assets[k] = true
		}
		for k := range o.Findings {
			cp.Findings[k] = true
		}
		snap.Obs[id] = cp
	}
	for _, id := range s.order {
		if t := s.tasks[id]; t != nil {
			cp := *t
			snap.Tasks = append(snap.Tasks, &cp)
		}
	}
	for id, info := range s.scans {
		cp := *info
		snap.Scans[id] = &cp
	}
	for id, a := range s.agents {
		cp := *a
		snap.Agents[id] = &cp
	}
	for id, rec := range s.authzRecs {
		snap.Authz[id] = rec
	}
	return snap
}

// persistAsset / persistFinding 在聚合时顺手落盘。
func (s *Server) persistAssetLocked(a model.Asset) {
	if s.persist != nil {
		s.persist.appendAsset(a)
	}
}

func (s *Server) persistFindingLocked(f poc.Finding) {
	if s.persist != nil {
		s.persist.appendFinding(f)
	}
}

func (s *Server) markDirty() {
	if s.persist != nil {
		s.persist.markDirty()
	}
}

func (s *Server) maybeSaveState() {
	if s.persist != nil {
		s.persist.maybeSave(s.snapshot())
	}
}
