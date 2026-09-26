// Package audit 写审计日志。
//
// 渗透测试框架必须"可自证清白"：谁、在什么时间、对哪个目标、
// 依据哪份授权做了哪些动作。审计日志用 JSONL 追加写，天然可被 SIEM 采集。
package audit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Event 是一条审计记录。
type Event struct {
	Time   string            `json:"time"`
	Event  string            `json:"event"`
	Fields map[string]string `json:"fields,omitempty"`
}

// Logger 是并发安全的审计日志写入器。零值/Nop 表示不写文件。
type Logger struct {
	mu  sync.Mutex
	enc *json.Encoder
	f   *os.File
}

// Open 打开审计文件；path 为空时返回不做任何事的 Nop logger。
func Open(path string) (*Logger, error) {
	if path == "" {
		return &Logger{}, nil
	}
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, err
		}
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return nil, err
	}
	return &Logger{f: f, enc: json.NewEncoder(f)}, nil
}

// Log 记一条事件。fields 的键**原样写入**（不归一化大小写）——
// 采集方按写入的键检索，需要统一键名请在调用点统一，不要指望这里改。
func (l *Logger) Log(event string, fields map[string]string) {
	if l == nil || l.enc == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	_ = l.enc.Encode(Event{
		Time:   time.Now().Format(time.RFC3339),
		Event:  event,
		Fields: fields,
	})
}

// Close 关闭文件。
func (l *Logger) Close() error {
	if l == nil || l.f == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	err := l.f.Close()
	l.f = nil
	l.enc = nil
	return err
}
