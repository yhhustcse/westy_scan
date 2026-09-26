// Package store 提供结果存储抽象。
//
// 为什么要有接口：单机模式用"内存 + JSONL 落盘"就够，
// 分布式模式下换成数据库或远端 Sink 时，流水线代码一行都不用改。
package store

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"

	"westy_scan/internal/model"
)

// Store 是结果落地接口，实现必须并发安全。
type Store interface {
	Add(model.Asset) error
	Len() int
	Assets() []model.Asset
	Close() error
}

// Memory 是带去重的内存存储。
type Memory struct {
	mu    sync.Mutex
	seen  map[string]bool
	items []model.Asset
}

// NewMemory 构造内存存储。
func NewMemory() *Memory {
	return &Memory{seen: make(map[string]bool)}
}

// Add 写入一条资产，重复键会被忽略（返回 nil）。
func (m *Memory) Add(a model.Asset) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := a.Key()
	if m.seen[key] {
		return nil
	}
	m.seen[key] = true
	m.items = append(m.items, a)
	return nil
}

// Len 返回已存储资产数量。
func (m *Memory) Len() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.items)
}

// Assets 返回资产快照。
func (m *Memory) Assets() []model.Asset {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]model.Asset, len(m.items))
	copy(out, m.items)
	return out
}

// Close 实现 Store。
func (m *Memory) Close() error { return nil }

// JSONL 以 JSON Lines 格式流式落盘，适合大规模结果与后续再处理。
type JSONL struct {
	mu   sync.Mutex
	file *os.File
	enc  *json.Encoder
	seen map[string]bool
	n    int
}

// NewJSONL 打开（或创建）结果文件。
func NewJSONL(path string) (*JSONL, error) {
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, err
		}
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return nil, err
	}
	return &JSONL{file: f, enc: json.NewEncoder(f), seen: make(map[string]bool)}, nil
}

// Add 追加一条资产。
//
// 注意顺序：**先写成功再标记 seen**。反过来（先标记）在 Encode 失败时会
// 让这个 key 永远处于"已见过"状态——重试会静默返回 nil、数据永不落盘，
// 属于最隐蔽的一类数据丢失。
func (j *JSONL) Add(a model.Asset) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	key := a.Key()
	if j.seen[key] {
		return nil
	}
	if err := j.enc.Encode(a); err != nil {
		return err
	}
	j.seen[key] = true
	j.n++
	return nil
}

// Len 返回写入条数。
func (j *JSONL) Len() int {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.n
}

// Assets 流式存储不保留全量数据，返回 nil。
func (j *JSONL) Assets() []model.Asset { return nil }

// Close 关闭文件。
func (j *JSONL) Close() error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.file == nil {
		return nil
	}
	err := j.file.Close()
	j.file = nil
	return err
}

// Multi 把一条资产同时写进多个存储。
type Multi struct {
	stores []Store
}

// NewMulti 组合存储。
func NewMulti(stores ...Store) *Multi {
	return &Multi{stores: stores}
}

// Add 广播写入；返回第一个错误，但会尝试写完所有目标。
func (m *Multi) Add(a model.Asset) error {
	var firstErr error
	for _, s := range m.stores {
		if err := s.Add(a); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// Len 返回第一个存储的计数（通常是有去重语义的那个）。
func (m *Multi) Len() int {
	if len(m.stores) == 0 {
		return 0
	}
	return m.stores[0].Len()
}

// Assets 返回第一个非空存储的全量快照。
func (m *Multi) Assets() []model.Asset {
	for _, s := range m.stores {
		if items := s.Assets(); items != nil {
			return items
		}
	}
	return nil
}

// Close 关闭全部存储。
func (m *Multi) Close() error {
	var firstErr error
	for _, s := range m.stores {
		if err := s.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}
