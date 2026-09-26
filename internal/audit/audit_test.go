package audit

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// readEvents 读取审计文件，断言 JSONL 结构，返回按行解析出的事件。
func readEvents(t *testing.T, path string) []Event {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("读取审计文件失败: %v", err)
	}
	if len(raw) == 0 {
		return nil
	}
	if bytes.HasPrefix(raw, []byte{0xEF, 0xBB, 0xBF}) {
		t.Fatal("审计文件不应带 UTF-8 BOM（会破坏 SIEM 逐行解析）")
	}
	lines := strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n")
	out := make([]Event, 0, len(lines))
	for i, ln := range lines {
		if strings.TrimSpace(ln) == "" {
			t.Fatalf("第 %d 行为空行，审计日志必须一行一个 JSON 对象", i+1)
		}
		var ev Event
		if err := json.Unmarshal([]byte(ln), &ev); err != nil {
			t.Fatalf("第 %d 行不是合法 JSON 对象: %v（行内容 %q）", i+1, err, ln)
		}
		out = append(out, ev)
	}
	return out
}

// parseTime 校验 Event.Time 是否为 RFC3339 格式。
func parseTime(s string) (time.Time, error) {
	return time.Parse(time.RFC3339, s)
}

// TestOpenWritesOneJSONObjectPerLine 验证 Log 的落盘格式与字段一致性。
func TestOpenWritesOneJSONObjectPerLine(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l, err := Open(path)
	if err != nil {
		t.Fatalf("Open 失败: %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })

	rounds := []struct {
		event  string
		fields map[string]string
	}{
		{event: "scan.start", fields: map[string]string{"target": "10.0.0.1", "operator": "alice"}},
		{event: "scan.done", fields: map[string]string{"target": "10.0.0.2", "assets": "17"}},
		{event: "authz.deny", fields: map[string]string{"reason": "out of scope"}},
	}
	for _, r := range rounds {
		l.Log(r.event, r.fields)
	}
	if err := l.Close(); err != nil {
		t.Fatalf("Close 失败: %v", err)
	}

	events := readEvents(t, path)
	if len(events) != len(rounds) {
		t.Fatalf("应有 %d 行事件，实际 %d 行", len(rounds), len(events))
	}
	for i, r := range rounds {
		got := events[i]
		if got.Event != r.event {
			t.Fatalf("第 %d 条 event = %q，期望 %q", i+1, got.Event, r.event)
		}
		if len(got.Fields) != len(r.fields) {
			t.Fatalf("第 %d 条 fields = %v，期望 %v", i+1, got.Fields, r.fields)
		}
		for k, v := range r.fields {
			if got.Fields[k] != v {
				t.Fatalf("第 %d 条 fields[%q] = %q，期望 %q", i+1, k, got.Fields[k], v)
			}
		}
		if _, err := parseTime(got.Time); err != nil {
			t.Fatalf("第 %d 条 time = %q 不是 RFC3339 时间: %v", i+1, got.Time, err)
		}
	}
}

// TestLogFieldsAreVerbatim 固化当前行为：Log 原样写入 fields，不做大小写归一化
// （文档注释声称"键统一小写"，实现并未处理 —— 用本测试把真实语义钉住）。
func TestLogFieldsAreVerbatim(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "case.jsonl")
	l, err := Open(path)
	if err != nil {
		t.Fatalf("Open 失败: %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })

	l.Log("Authz.Deny", map[string]string{"TargetHost": "example.com", "MixedCase": "V"})
	events := readEvents(t, path)
	if len(events) != 1 {
		t.Fatalf("应有 1 条事件，实际 %d", len(events))
	}
	if events[0].Event != "Authz.Deny" {
		t.Fatalf("event 名不应被改写，得到 %q", events[0].Event)
	}
	if _, ok := events[0].Fields["TargetHost"]; !ok {
		t.Fatalf("fields 键被改写了: %v", events[0].Fields)
	}
	if events[0].Fields["MixedCase"] != "V" {
		t.Fatalf("fields 值被改写了: %v", events[0].Fields)
	}
}

// TestLogNilFieldsOmitsKey 固化 Event.Fields 的 omitempty 行为。
func TestLogNilFieldsOmitsKey(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "nil-fields.jsonl")
	l, err := Open(path)
	if err != nil {
		t.Fatalf("Open 失败: %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })
	l.Log("noop", nil)

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("读取失败: %v", err)
	}
	if strings.Contains(string(raw), `"fields"`) {
		t.Fatalf("nil fields 应被 omitempty 省略，实际内容 %q", strings.TrimSpace(string(raw)))
	}
	var ev Event
	if err := json.Unmarshal(bytes.TrimSpace(raw), &ev); err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if ev.Fields != nil {
		t.Fatalf("反序列化后 Fields 应为 nil，得到 %v", ev.Fields)
	}
}

// TestOpenAppendsToExistingFile 验证 O_APPEND 语义：重开同一文件不截断历史。
func TestOpenAppendsToExistingFile(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "append.jsonl")

	l1, err := Open(path)
	if err != nil {
		t.Fatalf("首次 Open 失败: %v", err)
	}
	l1.Log("first", map[string]string{"n": "1"})
	if err := l1.Close(); err != nil {
		t.Fatalf("Close 失败: %v", err)
	}

	l2, err := Open(path)
	if err != nil {
		t.Fatalf("二次 Open 失败: %v", err)
	}
	l2.Log("second", map[string]string{"n": "2"})
	if err := l2.Close(); err != nil {
		t.Fatalf("Close 失败: %v", err)
	}

	events := readEvents(t, path)
	if len(events) != 2 {
		t.Fatalf("追加写后应有 2 条事件，实际 %d 条（历史被截断了？）", len(events))
	}
	if events[0].Event != "first" || events[1].Event != "second" {
		t.Fatalf("顺序错误: %q / %q", events[0].Event, events[1].Event)
	}
}

// TestOpenCreatesParentDir 验证父目录自动创建。
func TestOpenCreatesParentDir(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "logs", "deep", "audit.jsonl")
	l, err := Open(path)
	if err != nil {
		t.Fatalf("Open 应自动创建父目录，却失败: %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })
	l.Log("created", nil)
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("审计文件未创建: %v", err)
	}
}

// TestOpenInvalidPathErrors 目标路径不可写时必须返回错误。
func TestOpenInvalidPathErrors(t *testing.T) {
	t.Parallel()

	// 以目录本身作为文件路径。
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "adir"), 0o755); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "adir") + string(os.PathSeparator)
	l, err := Open(p)
	if err == nil {
		_ = l.Close()
		t.Fatal("把目录当审计文件打开应返回错误，实际成功")
	}
	if l != nil {
		t.Fatalf("出错时应返回 nil logger，得到 %+v", l)
	}
}

// TestNopLoggerOnEmptyPath 固化 Open("") 的 Nop 语义。
func TestNopLoggerOnEmptyPath(t *testing.T) {
	t.Parallel()

	l, err := Open("")
	if err != nil {
		t.Fatalf("Open(\"\") 应返回 Nop logger，得到错误 %v", err)
	}
	l.Log("ignored", map[string]string{"a": "b"}) // 不应 panic
	if err := l.Close(); err != nil {
		t.Fatalf("Nop logger Close 应为 nil，得到 %v", err)
	}
	// Nop logger 未持有文件：Close 幂等。
	if err := l.Close(); err != nil {
		t.Fatalf("Nop logger 重复 Close 应为 nil，得到 %v", err)
	}
}

// TestNilReceiverLogAndClose 固化 nil 接收者语义（不 panic）。
func TestNilReceiverLogAndClose(t *testing.T) {
	t.Parallel()

	var l *Logger
	l.Log("event", map[string]string{"k": "v"})
	if err := l.Close(); err != nil {
		t.Fatalf("nil Logger.Close 应为 nil，得到 %v", err)
	}
}

// TestCloseIsIdempotentAndLogAfterCloseIsNoop 固化 Close 幂等 + 关闭后写入被静默丢弃。
func TestCloseIsIdempotentAndLogAfterCloseIsNoop(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "closed.jsonl")
	l, err := Open(path)
	if err != nil {
		t.Fatalf("Open 失败: %v", err)
	}
	l.Log("before", map[string]string{"n": "1"})
	if err := l.Close(); err != nil {
		t.Fatalf("首次 Close 失败: %v", err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("读取失败: %v", err)
	}

	l.Log("after", map[string]string{"n": "2"}) // enc==nil，应为 no-op
	for i := 0; i < 3; i++ {
		if err := l.Close(); err != nil {
			t.Fatalf("第 %d 次重复 Close 应为 nil，得到 %v", i+2, err)
		}
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("读取失败: %v", err)
	}
	if !bytes.Equal(before, after) {
		t.Fatalf("Close 后 Log 应为 no-op，文件却从 %q 变成 %q", before, after)
	}
	if events := readEvents(t, path); len(events) != 1 || events[0].Event != "before" {
		t.Fatalf("应只有 1 条 before 事件，得到 %+v", events)
	}
}

// TestConcurrentLog 并发写审计：行数精确、每行合法、-race 无竞争。
func TestConcurrentLog(t *testing.T) {
	t.Parallel()

	const (
		goroutines = 16
		perG       = 8
		want       = goroutines * perG
	)
	path := filepath.Join(t.TempDir(), "concurrent.jsonl")
	l, err := Open(path)
	if err != nil {
		t.Fatalf("Open 失败: %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })

	// 所有 goroutine 共享同一个只读 map，考察 Fields 是否被并发改写。
	shared := map[string]string{"operator": "bob", "tool": "westy"}
	var wg sync.WaitGroup
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < perG; i++ {
				l.Log(fmt.Sprintf("evt.%d.%d", g, i), shared)
			}
		}(g)
	}
	wg.Wait()
	if err := l.Close(); err != nil {
		t.Fatalf("Close 失败: %v", err)
	}

	events := readEvents(t, path)
	if len(events) != want {
		t.Fatalf("应有 %d 行事件，实际 %d 行（并发写交错或丢失）", want, len(events))
	}
	seen := make(map[string]bool, want)
	for _, ev := range events {
		if seen[ev.Event] {
			t.Fatalf("事件 %q 重复写入", ev.Event)
		}
		seen[ev.Event] = true
		if ev.Fields["operator"] != "bob" || ev.Fields["tool"] != "westy" {
			t.Fatalf("事件 %q 的 fields 丢失: %v", ev.Event, ev.Fields)
		}
	}
	for g := 0; g < goroutines; g++ {
		for i := 0; i < perG; i++ {
			if !seen[fmt.Sprintf("evt.%d.%d", g, i)] {
				t.Fatalf("事件 evt.%d.%d 丢失", g, i)
			}
		}
	}
}
