// Package wire 定义 Server 与 Agent 之间的协议消息。
//
// 为什么不是 gRPC/protobuf：本项目的硬约束是**零第三方依赖、隔离网可编译**。
// gRPC 要拉 google.golang.org/grpc + protobuf（还有 protoc 代码生成），
// Postgres 也要驱动 —— 一旦引入，"拷源码进内网就能编"这条底线就没了。
//
// 因此这里用标准库实现等价能力：**JSON over HTTP/1.1**，语义与 gRPC 四类流一一对应：
//
//	注册     POST /api/v1/agents/register
//	拉任务   POST /api/v1/agents/pull      （长轮询，等价于任务下发流）
//	上报     POST /api/v1/agents/report    （批量，等价于资产/结果上报流）
//	控制     GET  /api/v1/stats  /healthz  /metrics
//
// 消息类型与 gRPC 方案完全一致，将来要换传输层，只需替换 client/server 的收发实现。
package wire

import (
	"crypto/subtle"
	"sort"
	"strings"
	"time"

	"westy_scan/internal/model"
	"westy_scan/internal/poc"
)

// ProtocolVersion 用于 Server/Agent 版本兼容检查。
const ProtocolVersion = 1

// JobSpec 是一个可独立重试的最小扫描单元。
//
// 幂等键 = ID：由 (IP + 端口集合 + 扫描 ID 的稳定哈希) 生成，
// 因此"Agent 掉线重连后重复拉取同一个任务"不会产生重复数据。
type JobSpec struct {
	ID        string    `json:"id"`
	ScanID    string    `json:"scan_id"`
	Host      string    `json:"host"`
	IP        string    `json:"ip,omitempty"`
	Ports     []int     `json:"ports"`
	CreatedAt time.Time `json:"created_at"`
}

// TaskState 是服务端任务状态。
type TaskState string

const (
	TaskPending TaskState = "pending"
	TaskRunning TaskState = "running"
	TaskDone    TaskState = "done"
	TaskFailed  TaskState = "failed"
)

// Task 是服务端的任务视图（含租约信息）。
type Task struct {
	Spec       JobSpec   `json:"spec"`
	State      TaskState `json:"state"`
	AgentID    string    `json:"agent_id,omitempty"`
	Attempts   int       `json:"attempts"`
	LeaseUntil time.Time `json:"lease_until,omitempty"`
	Error      string    `json:"error,omitempty"`
	UpdatedAt  time.Time `json:"updated_at"`
}

// AgentStatus 是 Agent 的注册与心跳信息。
type AgentStatus struct {
	ID           string    `json:"id"`
	Version      string    `json:"version,omitempty"`
	Hostname     string    `json:"hostname,omitempty"`
	LastSeen     time.Time `json:"last_seen"`
	LeaseSeconds int       `json:"lease_seconds,omitempty"`
	JobsDone     int       `json:"jobs_done"`
	JobsFailed   int       `json:"jobs_failed"`
	AssetsSent   int       `json:"assets_sent"`
}

// RegisterRequest / RegisterResponse
type RegisterRequest struct {
	AgentID      string   `json:"agent_id,omitempty"` // 空表示由服务端分配
	Version      string   `json:"version"`
	Hostname     string   `json:"hostname,omitempty"`
	Protocol     int      `json:"protocol"`
	Capabilities []string `json:"capabilities,omitempty"`
}

type RegisterResponse struct {
	AgentID       string `json:"agent_id"`
	LeaseSeconds  int    `json:"lease_seconds"`
	HeartbeatSecs int    `json:"heartbeat_seconds"`
	Protocol      int    `json:"protocol"`
	ServerVersion string `json:"server_version"`
	ScopeHint     string `json:"scope_hint,omitempty"` // 仅供提示：Agent 仍以自己的授权配置为准
}

// PullRequest / PullResponse
type PullRequest struct {
	AgentID     string `json:"agent_id"`
	MaxJobs     int    `json:"max_jobs,omitempty"`
	WaitSeconds int    `json:"wait_seconds,omitempty"` // 长轮询等待（无任务时挂起）
}

type PullResponse struct {
	Jobs []JobSpec `json:"jobs"`
}

// TaskOutcome 是单个任务的执行结果。
type TaskOutcome struct {
	JobID string    `json:"job_id"`
	State TaskState `json:"state"` // done / failed
	Error string    `json:"error,omitempty"`
	Host  string    `json:"host,omitempty"`
}

// ReportRequest 是批量上报（资产 + 漏洞 + 任务结果）。
type ReportRequest struct {
	AgentID  string        `json:"agent_id"`
	ScanID   string        `json:"scan_id,omitempty"`
	Outcomes []TaskOutcome `json:"outcomes,omitempty"`
	Assets   []model.Asset `json:"assets,omitempty"`
	Findings []poc.Finding `json:"findings,omitempty"`
	Rejected []string      `json:"rejected,omitempty"` // 被 Agent 本地授权闸门拦下的目标（审计用）
}

type ReportResponse struct {
	AcceptedAssets   int  `json:"accepted_assets"`
	AcceptedFindings int  `json:"accepted_findings"`
	Duplicates       int  `json:"duplicates"`
	KnownScans       bool `json:"known_scan"`
}

// ScanSpec 是"创建一次扫描"的输入（服务端切片用）。
type ScanSpec struct {
	ScanID  string   `json:"scan_id,omitempty"`
	Hosts   []string `json:"hosts"`
	Ports   []int    `json:"ports"`
	JobSize int      `json:"job_size,omitempty"` // 每个任务包含多少台主机（默认 1）
	// JobPorts 是**端口分片大小**：把端口列表切成多个任务（默认 0 = 全部端口一个任务）。
	// 切片越细，负载越均衡、Agent 掉线时损失越小，但任务调度开销略高。
	JobPorts int `json:"job_ports,omitempty"`
	MaxTries int `json:"max_tries,omitempty"`
	// Authorization 是**授权书编号**（M6）：没有有效授权书就不允许创建扫描。
	Authorization string `json:"authorization,omitempty"`
	Operator      string `json:"operator,omitempty"`
}

// ScanInfo 是扫描任务的生命周期视图。
type ScanInfo struct {
	ID          string    `json:"id"`
	CreatedAt   time.Time `json:"created_at"`
	Hosts       int       `json:"hosts"`
	Ports       int       `json:"ports"`
	Tasks       int       `json:"tasks"`
	Done        int       `json:"done"`
	Failed      int       `json:"failed"`
	Running     int       `json:"running"`
	Pending     int       `json:"pending"`
	Assets      int       `json:"assets"`
	Findings    int       `json:"findings"`
	CompletedAt time.Time `json:"completed_at,omitempty"`
}

// Stats 是服务端整体统计。
type Stats struct {
	Protocol   int                  `json:"protocol"`
	Scans      map[string]*ScanInfo `json:"scans"`
	Tasks      map[TaskState]int    `json:"tasks"`
	Agents     []AgentStatus        `json:"agents"`
	Assets     int                  `json:"assets"`
	Findings   int                  `json:"findings"`
	UptimeSecs int64                `json:"uptime_seconds"`
	Extra      map[string]int       `json:"extra,omitempty"`
}

// TokenOK 校验 Bearer token，用常量时间比较避免时序侧信道。
//
// 两个细节都是踩过坑才写对的：
//  1. **先 TrimSpace 再 TrimPrefix**：反过来的话 `"  Bearer xxx"`（前导空格，
//     某些客户端/网关会加上）会剥不掉前缀导致合法请求被拒，而 `"Bearer  xxx"`（多余空格）却能过 —— 不一致且危险；
//  2. `subtle.ConstantTimeCompare` 只在**长度相等**时才是常量时间，长度不同会立刻返回 0。
//     这让"token 长度"成为可观测信息；要彻底消除需要先哈希到定长再比较，
//     当前实现选择的是"长度不敏感于内容"这一层的保护（短 token 本身也不该用）。
func TokenOK(got, want string) bool {
	if want == "" {
		return true // 未配置 token：开发模式（服务端会打警告）
	}
	got = strings.TrimSpace(got)
	got = strings.TrimSpace(strings.TrimPrefix(got, "Bearer "))
	return subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1
}

// JobID 生成幂等任务 ID。
//
// 幂等键的语义是"同一次扫描的同一台主机的同一组端口"，因此要把输入**规范化**：
//   - 各字段用**长度前缀**编码，避免分隔符歧义（`("a|b","c")` 与 `("a","b|c")` 不能撞车）；
//   - 端口**排序 + 去重**：`[80,443]`、`[443,80]`、`[443,80,443]` 必须得到同一个键。
//     否则同一个任务会因为请求里的顺序或重复而生成多个 ID，去重与掉线重派一起失效。
func JobID(scanID, host string, ports []int) string {
	var sb strings.Builder
	writePart := func(s string) {
		sb.WriteString(itoa(len(s)))
		sb.WriteString(":")
		sb.WriteString(s)
	}
	writePart(scanID)
	writePart(host)
	sorted := append([]int(nil), ports...)
	sort.Ints(sorted)
	for i, p := range sorted {
		if i > 0 && sorted[i-1] == p {
			continue // 重复端口不参与哈希
		}
		if i > 0 {
			sb.WriteString(",")
		}
		sb.WriteString(itoa(p))
	}
	return shortHash(sb.String())
}
