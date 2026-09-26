package diff

import (
	"testing"
	"time"

	"westy_scan/internal/model"
	"westy_scan/internal/poc"
)

func asset(host string, port int, service, version string) model.Asset {
	return model.Asset{
		Host: host, Port: port, Service: service, Version: version,
		Source: "portscan", FoundAt: time.Now(),
	}
}

func finding(tpl, matchedAt, sev string) poc.Finding {
	return poc.Finding{TemplateID: tpl, MatchedAt: matchedAt, Severity: sev, FoundAt: time.Now()}
}

func TestAssetDiff(t *testing.T) {
	old := []model.Asset{
		asset("a", 80, "http", "1.0"),
		asset("a", 443, "http", "1.0"),
		asset("b", 22, "ssh", "9.0"),
	}
	cur := []model.Asset{
		asset("a", 80, "http", "1.0"),    // 未变
		asset("a", 443, "http", "2.0"),   // 版本变化
		asset("c", 3306, "mysql", "8.0"), // 新增
	}

	res := Assets(old, cur)
	if res.Summary.NewAssets != 1 || res.Summary.GoneAssets != 1 || res.Summary.ChangedAssets != 1 {
		t.Fatalf("对比结果错误: %+v", res.Summary)
	}
	if res.NewAssets[0].Host != "c" {
		t.Errorf("新增资产错误: %+v", res.NewAssets)
	}
	if res.GoneAssets[0].Host != "b" {
		t.Errorf("消失资产错误: %+v", res.GoneAssets)
	}
	ch := res.ChangedAssets[0]
	if ch.Host != "a" || ch.Port != 443 {
		t.Errorf("变化资产定位错误: %+v", ch)
	}
	if ch.Before["version"] != "1.0" || ch.After["version"] != "2.0" {
		t.Errorf("版本变化未识别: %+v", ch)
	}
	if res.Empty() {
		t.Error("有变化时 Empty 应为 false")
	}
}

func TestAssetDiffIgnoresNoise(t *testing.T) {
	old := []model.Asset{asset("a", 80, "http", "1.0")}
	cur := []model.Asset{asset("a", 80, "http", "1.0")}
	// found_at 不同不应触发"变化"
	cur[0].FoundAt = time.Now().Add(time.Hour)
	cur[0].Banner = "不同的 banner（噪声字段）"
	res := Assets(old, cur)
	if !res.Empty() {
		t.Errorf("噪声字段不应触发变化: %+v", res.Summary)
	}
}

func TestFindingDiff(t *testing.T) {
	old := []poc.Finding{
		finding("git-config-exposure", "http://a/.git/config", "high"),
		finding("swagger-ui-exposure", "http://a/swagger-ui.html", "low"),
	}
	cur := []poc.Finding{
		finding("git-config-exposure", "http://a/.git/config", "high"),             // 仍在
		finding("docker-api-unauthorized-version", "http://a/version", "critical"), // 新增高危
	}
	res := Findings(old, cur)
	if res.Summary.NewFindings != 1 || res.Summary.FixedFindings != 1 {
		t.Fatalf("漏洞对比错误: %+v", res.Summary)
	}
	if res.Summary.NewHighRisk != 1 {
		t.Errorf("新增高危计数错误: %+v", res.Summary)
	}
	if res.NewFindings[0].TemplateID != "docker-api-unauthorized-version" {
		t.Errorf("新增漏洞错误: %+v", res.NewFindings)
	}
	if res.FixedFindings[0].TemplateID != "swagger-ui-exposure" {
		t.Errorf("已修复漏洞错误: %+v", res.FixedFindings)
	}
}

func TestCompareAndFilterByScanID(t *testing.T) {
	scanA := []model.Asset{{Host: "a", Port: 80, Meta: map[string]string{"scan_id": "s1"}}}
	scanB := []model.Asset{{Host: "a", Port: 80, Meta: map[string]string{"scan_id": "s2"}}}
	findingsA := []poc.Finding{{TemplateID: "t", MatchedAt: "u", ScanID: "s1", Severity: "high"}}

	as, fs := FilterByScanID(append(scanA, scanB...), findingsA, "s1")
	if len(as) != 1 || len(fs) != 1 {
		t.Fatalf("按 scan_id 过滤错误: %d 资产 %d 漏洞", len(as), len(fs))
	}

	res := Compare(scanA, scanB, findingsA, nil)
	if res.Summary.NewFindings != 0 || res.Summary.FixedFindings != 1 {
		t.Errorf("对比应识别出漏洞消失: %+v", res.Summary)
	}
}

func TestSeverityRankingInSummary(t *testing.T) {
	cur := []poc.Finding{
		finding("a", "u1", "medium"),
		finding("b", "u2", "high"),
		finding("c", "u3", "critical"),
		finding("d", "u4", "info"),
	}
	res := Findings(nil, cur)
	if res.Summary.NewFindings != 4 {
		t.Fatalf("新增漏洞数错误: %+v", res.Summary)
	}
	if res.Summary.NewHighRisk != 2 {
		t.Errorf("高危及以上应为 2（high+critical），实际 %d", res.Summary.NewHighRisk)
	}
	// 排序：critical 在前
	if res.NewFindings[0].Severity != "critical" {
		t.Errorf("应按严重级别排序: %+v", res.NewFindings)
	}
}
