// Package authz 实现"授权书绑定"（M6）。
//
// 这是把合规从"流程要求"变成"系统强制"的关键一环：
// **没有有效授权书，就没有扫描任务**。授权书记录了
//   - 委托方与授权书编号（审计可追溯到纸面文件）；
//   - 允许的目标范围（CIDR/域名，含明确的 deny）；
//   - 有效期（过期即拒绝，不依赖人工记时间）；
//   - 审批人与工单号。
//
// 服务端在创建扫描时逐目标校验；Agent 侧还会用自己的 allow/deny 再校验一次。
// 两层闸门是刻意的：服务端防"越权下发"，Agent 防"配置漂移"。
package authz

import (
	"fmt"
	"strings"
	"time"

	"westy_scan/internal/scope"
)

// Record 是一份授权书。
type Record struct {
	ID        string    `json:"id"`             // 授权书编号（如 AB-2026-0142）
	Client    string    `json:"client"`         // 委托方
	Allow     []string  `json:"allow"`          // 允许范围（CIDR/域名）
	Deny      []string  `json:"deny,omitempty"` // 明确排除
	ValidFrom time.Time `json:"valid_from"`
	ValidTo   time.Time `json:"valid_to"`
	Approver  string    `json:"approver,omitempty"` // 审批人
	Ticket    string    `json:"ticket,omitempty"`   // 工单/合同号
	Note      string    `json:"note,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

// Expired 判断授权书在给定时间是否已过期。
func (r Record) Expired(at time.Time) bool {
	if r.ValidTo.IsZero() {
		return false // 未设置截止时间视为长期有效（但仍需 allow 非空）
	}
	return at.After(r.ValidTo)
}

// NotYetValid 判断是否还没到生效时间。
func (r Record) NotYetValid(at time.Time) bool {
	return !r.ValidFrom.IsZero() && at.Before(r.ValidFrom)
}

// ValidateRecord 做静态校验（创建授权书时调用）。
func ValidateRecord(r Record) error {
	if strings.TrimSpace(r.ID) == "" {
		return fmt.Errorf("授权书编号不能为空")
	}
	if strings.TrimSpace(r.Client) == "" {
		return fmt.Errorf("委托方不能为空")
	}
	if len(r.Allow) == 0 {
		return fmt.Errorf("必须至少给出一条允许范围（allow）")
	}
	if !r.ValidTo.IsZero() && !r.ValidFrom.IsZero() && r.ValidTo.Before(r.ValidFrom) {
		return fmt.Errorf("有效期非法：截止时间早于生效时间")
	}
	for _, rule := range append(append([]string{}, r.Allow...), r.Deny...) {
		if _, err := scope.ParseRule(rule); err != nil {
			return fmt.Errorf("授权范围规则非法 %q: %w", rule, err)
		}
	}
	return nil
}

// Guard 是授权书自己的范围闸门（复用 scope 的规则语义）。
type Guard struct {
	record Record
	sc     *scope.Scope
}

// NewGuard 构造闸门；构造时会做有效期与静态校验。
func NewGuard(r Record, now time.Time) (*Guard, error) {
	if err := ValidateRecord(r); err != nil {
		return nil, err
	}
	if r.NotYetValid(now) {
		return nil, fmt.Errorf("授权书 %s 尚未生效（自 %s 起）", r.ID, r.ValidFrom.Format(time.RFC3339))
	}
	if r.Expired(now) {
		return nil, fmt.Errorf("授权书 %s 已过期（%s 截止），拒绝扫描", r.ID, r.ValidTo.Format(time.RFC3339))
	}
	// authorized=true：范围判定由 allow/deny 完成，这里不重复"是否授权"的判断
	sc, err := scope.New(r.Allow, r.Deny, 1<<20, true, true)
	if err != nil {
		return nil, err
	}
	return &Guard{record: r, sc: sc}, nil
}

// Allow 判断单个目标是否在授权范围内。
func (g *Guard) Allow(target string) (bool, string) {
	host, ok, reason := g.sc.Check(target)
	if !ok {
		return false, reason
	}
	if host == "" {
		return false, "空目标"
	}
	return true, ""
}

// AllowAll 校验一批目标，返回第一个越界的目标与原因（全部通过时返回空）。
func (g *Guard) AllowAll(targets []string) (string, string) {
	for _, t := range targets {
		if ok, reason := g.Allow(t); !ok {
			return t, reason
		}
	}
	return "", ""
}

// Record 返回授权书副本。
func (g *Guard) Record() Record { return g.record }

// Describe 生成可读摘要（写审计用）。
func (g *Guard) Describe() string {
	return fmt.Sprintf("authz=%s client=%s allow=%v deny=%v valid_to=%s approver=%s ticket=%s",
		g.record.ID, g.record.Client, g.record.Allow, g.record.Deny,
		formatTime(g.record.ValidTo), g.record.Approver, g.record.Ticket)
}

func formatTime(t time.Time) string {
	if t.IsZero() {
		return "长期"
	}
	return t.Format("2006-01-02")
}
