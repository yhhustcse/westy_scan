package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"westy_scan/internal/model"
)

// loadJSONL 逐行读取落盘文件，断言每行都是合法 JSON 对象，
// 返回解析出的资产列表（行数即有效条目数）。
func loadJSONL(t *testing.T, path string) []model.Asset {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("读取落盘文件失败: %v", err)
	}
	if len(raw) == 0 {
		return nil
	}
	text := strings.TrimSuffix(string(raw), "\n")
	lines := strings.Split(text, "\n")
	out := make([]model.Asset, 0, len(lines))
	for i, ln := range lines {
		if strings.TrimSpace(ln) == "" {
			t.Fatalf("第 %d 行为空行，JSONL 应一行一条记录", i+1)
		}
		var a model.Asset
		if err := json.Unmarshal([]byte(ln), &a); err != nil {
			t.Fatalf("第 %d 行不是合法 JSON: %v（行内容 %q）", i+1, err, ln)
		}
		out = append(out, a)
	}
	return out
}

func countLines(t *testing.T, path string) int {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("读取文件失败: %v", err)
	}
	if len(raw) == 0 {
		return 0
	}
	return len(strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n"))
}

func tempFile(t *testing.T, name string) string {
	t.Helper()
	return filepath.Join(t.TempDir(), name)
}

// ---------------------------------------------------------------- Memory

// TestMemoryAddDeduplicates 固化 Memory 的去重语义：
// 相同 Key() 重复 Add 返回 nil（不报错），Len/Assets 只保留第一次。
func TestMemoryAddDeduplicates(t *testing.T) {
	t.Parallel()

	dup := model.Asset{Host: "10.0.0.1", Port: 80, Service: "http"}
	m := NewMemory()

	if err := m.Add(dup); err != nil {
		t.Fatalf("首次 Add 应成功，得到 %v", err)
	}
	// 同键不同内容：应被忽略（返回 nil，且不覆盖首条）。
	longer := dup
	longer.Service = "http"
	longer.Title = "should-be-ignored"
	if err := m.Add(longer); err != nil {
		t.Fatalf("重复键 Add 应返回 nil（静默去重），得到 %v", err)
	}
	if got := m.Len(); got != 1 {
		t.Fatalf("重复键去重后 Len 应为 1，得到 %d", got)
	}
	items := m.Assets()
	if len(items) != 1 {
		t.Fatalf("Assets 应只有 1 条，得到 %d", len(items))
	}
	if items[0].Title != "" {
		t.Fatalf("重复键不应覆盖首条记录，Title 被改成了 %q", items[0].Title)
	}
}

// TestMemoryKeySemantics 固化 Asset.Key() 的三级优先级：
// URL > tcp|host|port > host|host。
func TestMemoryKeySemantics(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name     string
		assets   []model.Asset
		wantLen  int
		wantKeys []string
	}{
		{
			name: "same_key_de_duplicated",
			assets: []model.Asset{
				{Host: "a.example.com", Port: 443},
				{Host: "a.example.com", Port: 443, Banner: "nginx"},
			},
			wantLen:  1,
			wantKeys: []string{"tcp|a.example.com|443"},
		},
		{
			name: "url_takes_priority_over_port",
			assets: []model.Asset{
				{Host: "a.example.com", Port: 80, URL: "http://a.example.com/"},
				{Host: "a.example.com", Port: 80},
			},
			wantLen:  2,
			wantKeys: []string{"url|http://a.example.com/", "tcp|a.example.com|80"},
		},
		{
			name: "host_only_asset",
			assets: []model.Asset{
				{Host: "b.example.com"},
				{Host: "b.example.com"},
			},
			wantLen:  1,
			wantKeys: []string{"host|b.example.com"},
		},
		{
			name: "distinct_ports_are_distinct",
			assets: []model.Asset{
				{Host: "c.example.com", Port: 22},
				{Host: "c.example.com", Port: 80},
				{Host: "c.example.com", Port: 443},
			},
			wantLen: 3,
			wantKeys: []string{
				"tcp|c.example.com|22",
				"tcp|c.example.com|80",
				"tcp|c.example.com|443",
			},
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			m := NewMemory()
			for i, a := range tc.assets {
				if err := m.Add(a); err != nil {
					t.Fatalf("第 %d 次 Add 失败: %v", i, err)
				}
			}
			if got := m.Len(); got != tc.wantLen {
				t.Fatalf("Len = %d，期望 %d", got, tc.wantLen)
			}
			items := m.Assets()
			if len(items) != tc.wantLen {
				t.Fatalf("Assets 长度 = %d，期望 %d", len(items), tc.wantLen)
			}
			for i, want := range tc.wantKeys {
				if got := items[i].Key(); got != want {
					t.Fatalf("第 %d 条 Key = %q，期望 %q", i, got, want)
				}
			}
		})
	}
}

// TestMemoryAssetsIsSnapshot 验证 Assets() 返回的是副本，改动它不影响内部状态。
func TestMemoryAssetsIsSnapshot(t *testing.T) {
	t.Parallel()

	m := NewMemory()
	if err := m.Add(model.Asset{Host: "10.1.1.1", Port: 8080}); err != nil {
		t.Fatal(err)
	}
	snap := m.Assets()
	snap[0].Host = "mutated"
	snap[0].Port = 1
	if got := m.Assets()[0]; got.Host != "10.1.1.1" || got.Port != 8080 {
		t.Fatalf("Assets() 未返回副本，内部数据被外部修改: %+v", got)
	}
	if err := m.Close(); err != nil {
		t.Fatalf("Memory.Close 应返回 nil，得到 %v", err)
	}
}

// TestMemoryConcurrentAdd 并发写同一批键：去重必须精确，-race 检验并发安全。
func TestMemoryConcurrentAdd(t *testing.T) {
	t.Parallel()

	const (
		goroutines = 32
		keys       = 8
	)
	m := NewMemory()

	var wg sync.WaitGroup
	errCh := make(chan error, goroutines*keys)
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < keys; i++ {
				if err := m.Add(model.Asset{Host: "10.0.0.1", Port: 1000 + i}); err != nil {
					errCh <- err
					return
				}
			}
		}(g)
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Fatalf("并发 Add 返回错误: %v", err)
	}
	if got := m.Len(); got != keys {
		t.Fatalf("并发去重后 Len = %d，期望 %d", got, keys)
	}
	// 并发读也不能 race/panic。
	if got := len(m.Assets()); got != keys {
		t.Fatalf("并发后 Assets 长度 = %d，期望 %d", got, keys)
	}
}

// ---------------------------------------------------------------- JSONL

// TestJSONLAddWritesOneJSONObjectPerLine 验证落盘格式：Add 一条 = 文件里恰好一行合法 JSON。
func TestJSONLAddWritesOneJSONObjectPerLine(t *testing.T) {
	t.Parallel()

	path := tempFile(t, "assets.jsonl")
	s, err := NewJSONL(path)
	if err != nil {
		t.Fatalf("NewJSONL 失败: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })

	if got := countLines(t, path); got != 0 {
		t.Fatalf("新建文件应为空，实际有 %d 行", got)
	}

	asset := model.Asset{
		Host:       "www.example.com",
		IP:         "93.184.216.34",
		Port:       443,
		Scheme:     "https",
		URL:        "https://www.example.com/",
		Service:    "https",
		Product:    "nginx",
		Version:    "1.25.3",
		StatusCode: 200,
		Title:      "Example Domain",
		Products:   []string{"nginx"},
		Evidence:   []string{"banner match"},
		Meta:       map[string]string{"source": "unit"},
	}
	if err := s.Add(asset); err != nil {
		t.Fatalf("Add 失败: %v", err)
	}
	if got := countLines(t, path); got != 1 {
		t.Fatalf("Add 一条后应恰好 1 行，实际 %d 行", got)
	}
	if got := s.Len(); got != 1 {
		t.Fatalf("Len = %d，期望 1", got)
	}

	items := loadJSONL(t, path)
	if len(items) != 1 {
		t.Fatalf("解析出 %d 条记录，期望 1", len(items))
	}
	got := items[0]
	if got.Key() != asset.Key() {
		t.Fatalf("落盘后 Key = %q，期望 %q", got.Key(), asset.Key())
	}
	if got.Title != asset.Title || got.Product != asset.Product || got.Version != asset.Version {
		t.Fatalf("字段丢失: %+v", got)
	}
	if got.StatusCode != 200 || len(got.Evidence) != 1 || got.Meta["source"] != "unit" {
		t.Fatalf("嵌套/切片字段丢失: %+v", got)
	}
}

// TestJSONLCloseFlushesAndErrorsAfterClose 验证 Close 后内容完整可读，
// 且关闭后 Add 返回错误而非 panic。
func TestJSONLCloseFlushesAndErrorsAfterClose(t *testing.T) {
	t.Parallel()

	path := tempFile(t, "close.jsonl")
	s, err := NewJSONL(path)
	if err != nil {
		t.Fatalf("NewJSONL 失败: %v", err)
	}
	for i := 0; i < 5; i++ {
		if err := s.Add(model.Asset{Host: "10.0.0.1", Port: 9000 + i}); err != nil {
			t.Fatalf("第 %d 次 Add 失败: %v", i, err)
		}
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close 失败: %v", err)
	}
	if items := loadJSONL(t, path); len(items) != 5 {
		t.Fatalf("Close 后应能完整读回 5 条，实际 %d 条", len(items))
	}
	if got := s.Assets(); got != nil {
		t.Fatalf("JSONL.Assets 应返回 nil（流式存储不留全量），得到 %v", got)
	}
	if err := s.Add(model.Asset{Host: "10.0.0.2"}); err == nil {
		t.Fatal("Close 后 Add 应返回错误（写已关闭的文件），实际返回 nil")
	}
}

// TestJSONLCloseIsIdempotent 验证重复 Close 不报错，且不丢已写内容。
func TestJSONLCloseIsIdempotent(t *testing.T) {
	t.Parallel()

	path := tempFile(t, "idem.jsonl")
	s, err := NewJSONL(path)
	if err != nil {
		t.Fatalf("NewJSONL 失败: %v", err)
	}
	if err := s.Add(model.Asset{Host: "h1", Port: 1}); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if err := s.Close(); err != nil {
			t.Fatalf("第 %d 次 Close 应返回 nil，得到 %v", i+1, err)
		}
	}
	if items := loadJSONL(t, path); len(items) != 1 {
		t.Fatalf("重复 Close 后应有 1 条记录，实际 %d 条", len(items))
	}
	if got := s.Len(); got != 1 {
		t.Fatalf("Close 后 Len 应保留计数，得到 %d", got)
	}
}

// TestJSONLDeduplicates 固化 JSONL 去重语义：同键不写第二行。
func TestJSONLDeduplicates(t *testing.T) {
	t.Parallel()

	path := tempFile(t, "dedup.jsonl")
	s, err := NewJSONL(path)
	if err != nil {
		t.Fatalf("NewJSONL 失败: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })

	dup := model.Asset{Host: "dup.example.com", Port: 80}
	for i := 0; i < 4; i++ {
		if err := s.Add(dup); err != nil {
			t.Fatalf("重复 Add 应返回 nil，得到 %v", err)
		}
	}
	if err := s.Add(model.Asset{Host: "dup.example.com", Port: 81}); err != nil {
		t.Fatal(err)
	}
	if got := s.Len(); got != 2 {
		t.Fatalf("Len = %d，期望 2", got)
	}
	if got := countLines(t, path); got != 2 {
		t.Fatalf("去重后文件应恰好 2 行，实际 %d 行", got)
	}
}

// TestJSONLFailedEncodeMarksKeySeen 记录一个真实行为（潜在 bug）：
// Add 在 Encode 失败时仍把 key 记入 seen 并返回错误，因此重试同一键会静默返回 nil 且永不落盘。
func TestJSONLFailedEncodeMarksKeySeen(t *testing.T) {
	t.Parallel()

	path := tempFile(t, "fail.jsonl")
	s, err := NewJSONL(path)
	if err != nil {
		t.Fatalf("NewJSONL 失败: %v", err)
	}
	asset := model.Asset{Host: "fail.example.com", Port: 22}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if err := s.Add(asset); err == nil {
		t.Fatal("向已关闭文件 Add 应报错")
	}
	if got := s.Len(); got != 0 {
		t.Fatalf("写失败不应增加计数，得到 Len = %d", got)
	}
	// 重试语义（曾经这里是"静默返回 nil、数据永不落盘"的数据丢失 bug）：
	// 写失败时**不能**把这个 key 标记为 seen，否则重试会被当成重复而直接丢弃。
	// 现在要求：重试仍然报错（文件依旧关闭），但 key 没有被污染。
	if err := s.Add(asset); err == nil {
		t.Fatal("文件仍处于关闭状态，重试应当继续报错，而不是静默成功")
	}
	if got := s.Len(); got != 0 {
		t.Fatalf("重试未真正写入，Len 应为 0，得到 %d", got)
	}
	if s.seen[asset.Key()] {
		t.Fatal("写失败不应把 key 标记为 seen —— 那会让后续重试永久静默丢弃该资产")
	}
}

// TestNewJSONLCreatesParentDir 验证父目录会被自动创建。
func TestNewJSONLCreatesParentDir(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "nested", "deeper", "out.jsonl")
	s, err := NewJSONL(path)
	if err != nil {
		t.Fatalf("NewJSONL 应自动创建父目录，却失败: %v", err)
	}
	defer func() { _ = s.Close() }()
	if err := s.Add(model.Asset{Host: "x", Port: 1}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("文件未创建: %v", err)
	}
}

// TestNewJSONLInvalidPathErrors 验证无法打开目标路径时返回错误。
func TestNewJSONLInvalidPathErrors(t *testing.T) {
	t.Parallel()

	// 以目录本身作为文件路径：OpenFile 必然失败。
	dir := t.TempDir()
	if s, err := NewJSONL(filepath.Join(dir, "sub") + string(os.PathSeparator)); err == nil {
		_ = s.Close()
		t.Fatal("把目录当文件打开应返回错误，实际成功")
	}
}

// TestJSONLConcurrentAdd 并发写：去重精确 + 文件行数一致 + -race 无竞争。
func TestJSONLConcurrentAdd(t *testing.T) {
	t.Parallel()

	const (
		goroutines = 32
		keys       = 8
	)
	path := tempFile(t, "concurrent.jsonl")
	s, err := NewJSONL(path)
	if err != nil {
		t.Fatalf("NewJSONL 失败: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })

	var wg sync.WaitGroup
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < keys; i++ {
				_ = s.Add(model.Asset{Host: "10.9.9.9", Port: 2000 + i})
			}
		}()
	}
	wg.Wait()

	if got := s.Len(); got != keys {
		t.Fatalf("并发去重后 Len = %d，期望 %d", got, keys)
	}
	if got := countLines(t, path); got != keys {
		t.Fatalf("并发后文件行数 = %d，期望 %d（行可能交错损坏）", got, keys)
	}
	if got := len(loadJSONL(t, path)); got != keys {
		t.Fatalf("并发后解析出的记录数 = %d，期望 %d", got, keys)
	}
}

// ---------------------------------------------------------------- Multi

// fakeStore 是可编排的测试替身：记录调用次数并可控地返回错误。
type fakeStore struct {
	name string

	mu        sync.Mutex
	adds      []model.Asset
	addErr    error
	closeErr  error
	closeCall int
	items     []model.Asset
}

func (f *fakeStore) Add(a model.Asset) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.adds = append(f.adds, a)
	return f.addErr
}

func (f *fakeStore) Len() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.adds)
}

func (f *fakeStore) Assets() []model.Asset {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.items
}

func (f *fakeStore) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closeCall++
	return f.closeErr
}

func (f *fakeStore) addCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.adds)
}

// TestMultiAddBroadcastsEvenWhenOneFails 固化语义：
// 返回第一个错误，但所有 sink 都会被尝试写入。
func TestMultiAddBroadcastsEvenWhenOneFails(t *testing.T) {
	t.Parallel()

	boom := errors.New("sink down")
	first := &fakeStore{name: "first", addErr: boom}
	second := &fakeStore{name: "second"}
	third := &fakeStore{name: "third", addErr: errors.New("another")}

	m := NewMulti(first, second, third)
	got := m.Add(model.Asset{Host: "10.0.0.1", Port: 80})
	if !errors.Is(got, boom) {
		t.Fatalf("应返回第一个错误 %v，实际 %v", boom, got)
	}
	for _, s := range []*fakeStore{first, second, third} {
		if s.addCount() != 1 {
			t.Fatalf("sink %s 应收到 1 次 Add，实际 %d 次（失败不应阻断后续 sink）", s.name, s.addCount())
		}
	}
}

// TestMultiAddToMemoryAndJSONL 真实组合：内存 + 落盘同时写入，两侧都可读。
func TestMultiAddToMemoryAndJSONL(t *testing.T) {
	t.Parallel()

	path := tempFile(t, "multi.jsonl")
	j, err := NewJSONL(path)
	if err != nil {
		t.Fatalf("NewJSONL 失败: %v", err)
	}
	mem := NewMemory()
	m := NewMulti(mem, j)
	t.Cleanup(func() { _ = m.Close() })

	assets := []model.Asset{
		{Host: "a.example.com", Port: 80},
		{Host: "a.example.com", Port: 443},
		{Host: "a.example.com", Port: 80}, // 重复，两个 sink 都应去重
	}
	for _, a := range assets {
		if err := m.Add(a); err != nil {
			t.Fatalf("Multi.Add 失败: %v", err)
		}
	}
	if got := m.Len(); got != 2 {
		t.Fatalf("Multi.Len 应取第一个 store 的计数 2，得到 %d", got)
	}
	if got := mem.Len(); got != 2 {
		t.Fatalf("Memory.Len = %d，期望 2", got)
	}
	if got := j.Len(); got != 2 {
		t.Fatalf("JSONL.Len = %d，期望 2", got)
	}
	if err := m.Close(); err != nil {
		t.Fatalf("Multi.Close 失败: %v", err)
	}
	if items := loadJSONL(t, path); len(items) != 2 {
		t.Fatalf("落盘应有 2 条，实际 %d 条", len(items))
	}
	if got := len(m.Assets()); got != 2 {
		t.Fatalf("Multi.Assets 应返回 Memory 快照（2 条），得到 %d", got)
	}
}

// TestMultiLenAndAssetsEmpty 固化空 Multi 与 Assets 回退语义。
func TestMultiLenAndAssetsEmpty(t *testing.T) {
	t.Parallel()

	empty := NewMulti()
	if got := empty.Len(); got != 0 {
		t.Fatalf("空 Multi.Len 应为 0，得到 %d", got)
	}
	if got := empty.Assets(); got != nil {
		t.Fatalf("空 Multi.Assets 应为 nil，得到 %v", got)
	}
	if err := empty.Add(model.Asset{Host: "noop"}); err != nil {
		t.Fatalf("空 Multi.Add 应为 nil，得到 %v", err)
	}
	if err := empty.Close(); err != nil {
		t.Fatalf("空 Multi.Close 应为 nil，得到 %v", err)
	}

	// Assets 跳过返回 nil 的 sink（JSONL 语义），取第一个非 nil 快照。
	streamOnly := &fakeStore{name: "stream"} // items == nil
	snapshot := NewMemory()
	if err := snapshot.Add(model.Asset{Host: "h", Port: 1}); err != nil {
		t.Fatal(err)
	}
	multi := NewMulti(streamOnly, snapshot)
	if got := multi.Len(); got != 0 {
		t.Fatalf("Multi.Len 只看第一个 store，应为 0，得到 %d", got)
	}
	got := multi.Assets()
	if len(got) != 1 || got[0].Host != "h" {
		t.Fatalf("Multi.Assets 应回退到第一个非 nil 快照，得到 %+v", got)
	}
}

// TestMultiCloseAttemptsAllStores 固化语义：Close 遍历所有 store 并返回第一个错误。
func TestMultiCloseAttemptsAllStores(t *testing.T) {
	t.Parallel()

	boom := errors.New("close failed")
	first := &fakeStore{name: "first", closeErr: boom}
	second := &fakeStore{name: "second"}
	m := NewMulti(first, second)

	if got := m.Close(); !errors.Is(got, boom) {
		t.Fatalf("Multi.Close 应返回第一个错误 %v，实际 %v", boom, got)
	}
	if first.closeCall != 1 || second.closeCall != 1 {
		t.Fatalf("所有 store 都应被 Close，实际 first=%d second=%d", first.closeCall, second.closeCall)
	}
}

// TestMultiConcurrentAdd 并发经 Multi 写多个真实 sink，-race 下检验整体并发安全。
func TestMultiConcurrentAdd(t *testing.T) {
	t.Parallel()

	const (
		goroutines = 16
		keys       = 8
	)
	path := tempFile(t, "multi-concurrent.jsonl")
	j, err := NewJSONL(path)
	if err != nil {
		t.Fatalf("NewJSONL 失败: %v", err)
	}
	m := NewMulti(NewMemory(), j)
	t.Cleanup(func() { _ = m.Close() })

	var wg sync.WaitGroup
	errCh := make(chan error, goroutines)
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < keys; i++ {
				if err := m.Add(model.Asset{Host: "10.5.5.5", Port: 3000 + i}); err != nil {
					errCh <- err
					return
				}
			}
		}()
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Fatalf("并发 Multi.Add 失败: %v", err)
	}
	if got := m.Len(); got != keys {
		t.Fatalf("并发后 Multi.Len = %d，期望 %d", got, keys)
	}
	if got := j.Len(); got != keys {
		t.Fatalf("并发后 JSONL.Len = %d，期望 %d", got, keys)
	}
	if got := countLines(t, path); got != keys {
		t.Fatalf("并发后文件行数 = %d，期望 %d", got, keys)
	}
}

// TestStoreInterfaceSatisfied 编译期确认实现满足 Store 接口。
func TestStoreInterfaceSatisfied(t *testing.T) {
	t.Parallel()

	var _ Store = NewMemory()
	var _ Store = &JSONL{}
	var _ Store = NewMulti()
	var _ Store = (*Memory)(nil)
}

// TestMemoryAddManyKeepsOrderAndCount 大量顺序写入时计数与顺序必须稳定。
func TestMemoryAddManyKeepsOrderAndCount(t *testing.T) {
	t.Parallel()

	const n = 500
	m := NewMemory()
	for i := 0; i < n; i++ {
		if err := m.Add(model.Asset{Host: fmt.Sprintf("h%d.example.com", i), Port: 80}); err != nil {
			t.Fatalf("第 %d 次 Add 失败: %v", i, err)
		}
	}
	if got := m.Len(); got != n {
		t.Fatalf("Len = %d，期望 %d", got, n)
	}
	items := m.Assets()
	if len(items) != n {
		t.Fatalf("Assets 长度 = %d，期望 %d", len(items), n)
	}
	if items[0].Host != "h0.example.com" || items[n-1].Host != fmt.Sprintf("h%d.example.com", n-1) {
		t.Fatalf("顺序被破坏：首条 %q 末条 %q", items[0].Host, items[n-1].Host)
	}
}
