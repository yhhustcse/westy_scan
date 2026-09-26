// Package diff 计算两次扫描之间的资产/漏洞变化（M6）。
//
// 为什么这是平台化的核心功能之一：渗透测试不是一次性动作。
// 甲方真正关心的是"**这次比上次多了什么**"——新增的端口、新上线的站点、
// 新出现的漏洞，才是需要马上处置的东西。没有 diff，报告就只是一堆快照。
package diff

import (
	"sort"
	"strconv"
	"strings"
	"time"

	"westy_scan/internal/model"
	"westy_scan/internal/poc"
)

// Result 是两次扫描的对比结果。
type Result struct {
	FromScanID string    `json:"from_scan_id,omitempty"`
	ToScanID   string    `json:"to_scan_id,omitempty"`
	FromTime   time.Time `json:"from_time,omitempty"`
	ToTime     time.Time `json:"to_time,omitempty"`

	NewAssets     []model.Asset `json:"new_assets,omitempty"`
	GoneAssets    []model.Asset `json:"gone_assets,omitempty"`
	ChangedAssets []Changed     `json:"changed_assets,omitempty"`

	NewFindings   []poc.Finding `json:"new_findings,omitempty"`
	FixedFindings []poc.Finding `json:"fixed_findings,omitempty"`

	Summary Summary `json:"summary"`
}

// Changed 描述同一个键上的属性变化（例如服务版本变了、标题变了）。
type Changed struct {
	Key    string            `json:"key"`
	Host   string            `json:"host"`
	Port   int               `json:"port,omitempty"`
	Before map[string]string `json:"before"`
	After  map[string]string `json:"after"`
}

// Summary 是便于展示与告警的汇总。
type Summary struct {
	NewAssets     int `json:"new_assets"`
	GoneAssets    int `json:"gone_assets"`
	ChangedAssets int `json:"changed_assets"`
	NewFindings   int `json:"new_findings"`
	FixedFindings int `json:"fixed_findings"`
	// NewHighRisk 是新增的高危及以上漏洞数量（通知/告警优先看这个）
	NewHighRisk int `json:"new_high_risk"`
}

// Empty 表示没有任何变化。
func (r Result) Empty() bool {
	return r.Summary.NewAssets == 0 && r.Summary.GoneAssets == 0 &&
		r.Summary.ChangedAssets == 0 && r.Summary.NewFindings == 0 && r.Summary.FixedFindings == 0
}

// Assets 对比两组资产。old 是基线，cur 是本次。
func Assets(old, cur []model.Asset) Result {
	res := Result{}
	oldMap := indexAssets(old)
	curMap := indexAssets(cur)

	for key, a := range curMap {
		prev, ok := oldMap[key]
		if !ok {
			res.NewAssets = append(res.NewAssets, a)
			continue
		}
		if ch, changed := compareAsset(prev, a); changed {
			res.ChangedAssets = append(res.ChangedAssets, ch)
		}
	}
	for key, a := range oldMap {
		if _, ok := curMap[key]; !ok {
			res.GoneAssets = append(res.GoneAssets, a)
		}
	}
	sortAssets(res.NewAssets)
	sortAssets(res.GoneAssets)
	sort.Slice(res.ChangedAssets, func(i, j int) bool { return res.ChangedAssets[i].Key < res.ChangedAssets[j].Key })
	res.Summary.NewAssets = len(res.NewAssets)
	res.Summary.GoneAssets = len(res.GoneAssets)
	res.Summary.ChangedAssets = len(res.ChangedAssets)
	return res
}

// Findings 对比两组漏洞（键：模板 + 命中地址）。
func Findings(old, cur []poc.Finding) Result {
	return FindingsInto(Result{}, old, cur)
}

// FindingsInto 在已有结果上追加漏洞对比（便于先比资产再比漏洞）。
func FindingsInto(res Result, old, cur []poc.Finding) Result {
	oldMap := indexFindings(old)
	curMap := indexFindings(cur)
	for key, f := range curMap {
		if _, ok := oldMap[key]; !ok {
			res.NewFindings = append(res.NewFindings, f)
			if rank(f.Severity) >= rank(poc.SeverityHigh) {
				res.Summary.NewHighRisk++
			}
		}
	}
	for key, f := range oldMap {
		if _, ok := curMap[key]; !ok {
			res.FixedFindings = append(res.FixedFindings, f)
		}
	}
	sortFindings(res.NewFindings)
	sortFindings(res.FixedFindings)
	res.Summary.NewFindings = len(res.NewFindings)
	res.Summary.FixedFindings = len(res.FixedFindings)
	return res
}

// Compare 一次性对比资产与漏洞。
func Compare(oldAssets, curAssets []model.Asset, oldFindings, curFindings []poc.Finding) Result {
	res := Assets(oldAssets, curAssets)
	return FindingsInto(res, oldFindings, curFindings)
}

// FindingKey 是漏洞的稳定标识（模板 + 命中地址）。
//
// 服务端汇聚去重、按扫描切片、diff 索引全部用它，保证"去重"和"归属"是同一套语义。
func FindingKey(f poc.Finding) string { return f.TemplateID + "|" + f.MatchedAt }

// AssetsByKeys / FindingsByKeys 按"某次扫描观察到过的键集合"切片。
//
// 为什么不能按记录上的 scan_id 过滤：聚合结果里同一条资产/漏洞只保留**首次**出现的记录，
// 第二次扫描重新观察到它时不会产生新记录，记录上的 scan_id 仍指向第一次。
// 用 scan_id 过滤就会把"这次也扫到了"误判成"这次没扫到"，
// 于是 diff 把长期存在的资产/漏洞报成"已消失/已修复"——这是会误导处置决策的假信号。
func AssetsByKeys(all []model.Asset, keys map[string]bool) []model.Asset {
	if len(keys) == 0 {
		return nil
	}
	out := make([]model.Asset, 0, len(keys))
	for _, a := range all {
		if keys[a.Key()] {
			out = append(out, a)
		}
	}
	return out
}

// FindingsByKeys 见 AssetsByKeys。
func FindingsByKeys(all []poc.Finding, keys map[string]bool) []poc.Finding {
	if len(keys) == 0 {
		return nil
	}
	out := make([]poc.Finding, 0, len(keys))
	for _, f := range all {
		if keys[FindingKey(f)] {
			out = append(out, f)
		}
	}
	return out
}

// FilterByScanID 按记录上的 scan_id 过滤（"首次由哪次扫描发现"）。
//
// 注意它回答的是"首次发现归属"，不是"这次扫描看到了什么"；
// 后者要用 AssetsByKeys/FindingsByKeys 配合服务端的观察集合。
func FilterByScanID(assets []model.Asset, findings []poc.Finding, scanID string) ([]model.Asset, []poc.Finding) {
	var as []model.Asset
	for _, a := range assets {
		if a.MetaValue("scan_id") == scanID {
			as = append(as, a)
		}
	}
	var fs []poc.Finding
	for _, f := range findings {
		if f.ScanID == scanID {
			fs = append(fs, f)
		}
	}
	return as, fs
}

func indexAssets(list []model.Asset) map[string]model.Asset {
	out := make(map[string]model.Asset, len(list))
	for _, a := range list {
		out[a.Key()] = a
	}
	return out
}

func indexFindings(list []poc.Finding) map[string]poc.Finding {
	out := make(map[string]poc.Finding, len(list))
	for _, f := range list {
		out[FindingKey(f)] = f
	}
	return out
}

// compareAsset 只比较"有运维意义"的字段，避免 found_at/证据这类噪声触发变化告警。
func compareAsset(before, after model.Asset) (Changed, bool) {
	ch := Changed{
		Key:    after.Key(),
		Host:   after.Host,
		Port:   after.Port,
		Before: map[string]string{},
		After:  map[string]string{},
	}
	fields := []struct {
		name string
		get  func(model.Asset) string
	}{
		{"service", func(a model.Asset) string { return a.Service }},
		{"product", func(a model.Asset) string { return a.Product }},
		{"version", func(a model.Asset) string { return a.Version }},
		{"title", func(a model.Asset) string { return a.Title }},
		{"status", func(a model.Asset) string { return itoa(a.StatusCode) }},
		{"server", func(a model.Asset) string { return a.Server }},
		{"favicon", func(a model.Asset) string { return itoa64(a.FaviconHash) }},
		{"cdn", func(a model.Asset) string { return a.CDN }},
	}
	for _, f := range fields {
		b, a := f.get(before), f.get(after)
		if b != a {
			ch.Before[f.name] = b
			ch.After[f.name] = a
		}
	}
	if len(ch.Before) == 0 {
		return Changed{}, false
	}
	return ch, true
}

func rank(sev string) int {
	switch strings.ToLower(strings.TrimSpace(sev)) {
	case poc.SeverityCritical:
		return 5
	case poc.SeverityHigh:
		return 4
	case poc.SeverityMedium:
		return 3
	case poc.SeverityLow:
		return 2
	case poc.SeverityInfo:
		return 1
	}
	return 0
}

func sortAssets(list []model.Asset) {
	sort.Slice(list, func(i, j int) bool {
		if list[i].Host != list[j].Host {
			return list[i].Host < list[j].Host
		}
		return list[i].Port < list[j].Port
	})
}

func sortFindings(list []poc.Finding) {
	sort.Slice(list, func(i, j int) bool {
		if list[i].Severity != list[j].Severity {
			return rank(list[i].Severity) > rank(list[j].Severity)
		}
		return list[i].MatchedAt < list[j].MatchedAt
	})
}

func itoa(n int) string {
	if n == 0 {
		return ""
	}
	return strconv.Itoa(n)
}

func itoa64(n int32) string {
	if n == 0 {
		return ""
	}
	return strconv.FormatInt(int64(n), 10)
}
