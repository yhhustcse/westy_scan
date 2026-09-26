// Package model 定义整个扫描框架共享的数据模型。
//
// 设计原则：所有模块之间只通过本包的类型通信。
// 这样单机 CLI、分布式 Server/Agent、可插拔模块可以共用同一份契约，
// 后续把本地 channel 换成 gRPC 流也不影响任何扫描逻辑。
package model

import (
	"fmt"
	"strings"
	"time"
)

// Host 是一条待扫描目标，是流水线的第一等公民。
type Host struct {
	Input string `json:"input"`        // 用户原始输入，便于回溯
	Host  string `json:"host"`         // 归一化后的主机名或 IP
	IP    string `json:"ip,omitempty"` // 解析结果（DNS 只解析一次）
	Ports []int  `json:"ports,omitempty"`
}

// TLSInfo 记录证书信息，用于资产测绘与证书到期提醒。
type TLSInfo struct {
	Subject   string    `json:"subject,omitempty"`
	Issuer    string    `json:"issuer,omitempty"`
	NotBefore time.Time `json:"not_before,omitempty"`
	NotAfter  time.Time `json:"not_after,omitempty"`
	DNSNames  []string  `json:"dns_names,omitempty"`
	Serial    string    `json:"serial,omitempty"`
	Expired   bool      `json:"expired,omitempty"`
}

// Asset 是框架的核心输出单元：一条"可观测的攻击面事实"。
//
// 它刻意不做强类型分层（没有严格的 Domain/Port/URL 三种结构体），
// 因为渗透前期信息收集阶段资产是会不断"生长"的：
// 一个 IP 先有端口，端口上长出服务，服务上长出 URL，URL 上再长出端点。
// 用同一个结构体 + Source/Depth 字段表达血缘关系，序列化与去重都更简单。
type Asset struct {
	Input      string   `json:"input,omitempty"`   // 来源输入，便于回溯
	Host       string   `json:"host"`              // 主机名或 IP
	IP         string   `json:"ip,omitempty"`      //
	Port       int      `json:"port,omitempty"`    //
	Scheme     string   `json:"scheme,omitempty"`  // http / https
	URL        string   `json:"url,omitempty"`     //
	Service    string   `json:"service,omitempty"` // 服务/协议指纹，如 http、ssh、redis
	Product    string   `json:"product,omitempty"` // 主产品名，如 OpenSSH、MySQL
	Version    string   `json:"version,omitempty"` // 产品版本，如 9.6p1、8.0.35
	Products   []string `json:"products,omitempty"`
	Title      string   `json:"title,omitempty"`
	StatusCode int      `json:"status_code,omitempty"`
	Server     string   `json:"server,omitempty"`
	Banner     string   `json:"banner,omitempty"`
	TLS        *TLSInfo `json:"tls,omitempty"`
	Depth      int      `json:"depth,omitempty"`      // 爬虫深度
	Source     string   `json:"source,omitempty"`     // 产出该资产的模块
	Confidence string   `json:"confidence,omitempty"` // high / medium / low
	Evidence   []string `json:"evidence,omitempty"`   // 判定依据，用于人工复核与误报复盘
	// FaviconHash 是 favicon 的 mmh3 哈希（Shodan 约定的 base64 形式，见 internal/favhash）。
	FaviconHash int32  `json:"favicon_hash,omitempty"`
	CDN         string `json:"cdn,omitempty"`
	WAF         string `json:"waf,omitempty"`
	BehindCDN   bool   `json:"behind_cdn,omitempty"` // 真实 IP 可能被隐藏
	OriginNote  string `json:"origin_note,omitempty"`
	// 攻击面输入清单（M3）：参数名与表单结构，直接对应 M4 注入类模板的输入面
	Params  []string          `json:"params,omitempty"`
	Forms   []Form            `json:"forms,omitempty"`
	Meta    map[string]string `json:"meta,omitempty"`
	FoundAt time.Time         `json:"found_at"`
}

// Form 是页面里发现的表单结构（action 已解析为绝对地址）。
type Form struct {
	Action string   `json:"action,omitempty"`
	Method string   `json:"method,omitempty"`
	Fields []string `json:"fields,omitempty"`
}

// 置信度等级。含义：
//
//	high   —— 协议握手解析出的结构化结果（如 MySQL 握手包里的版本号）
//	medium —— 特征串 / Banner 正则命中（如 Server: nginx）
//	low    —— 仅凭端口推断（如 3389 就认为是 RDP）
const (
	ConfidenceHigh   = "high"
	ConfidenceMedium = "medium"
	ConfidenceLow    = "low"
)

func confidenceRank(level string) int {
	switch level {
	case ConfidenceHigh:
		return 3
	case ConfidenceMedium:
		return 2
	case ConfidenceLow:
		return 1
	default:
		return 0
	}
}

// RaiseConfidence 只在等级更高时提升置信度，避免"端口猜测"覆盖"握手实证"。
func (a *Asset) RaiseConfidence(level string) {
	if confidenceRank(level) > confidenceRank(a.Confidence) {
		a.Confidence = level
	}
}

// AddEvidence 记录判定依据（自动去重）。
func (a *Asset) AddEvidence(items ...string) {
	for _, it := range items {
		it = strings.TrimSpace(it)
		if it == "" {
			continue
		}
		dup := false
		for _, old := range a.Evidence {
			if old == it {
				dup = true
				break
			}
		}
		if !dup {
			a.Evidence = append(a.Evidence, it)
		}
	}
}

// Identify 一次写入服务/产品/版本/置信度/依据。
// 已存在的更强结论不会被覆盖：服务名与主产品只在为空时写入，
// 置信度只升不降（握手解析结果因此不会被后续的端口猜测冲淡）。
func (a *Asset) Identify(service, product, version, confidence, evidence string) {
	if service != "" && a.Service == "" {
		a.Service = service
	}
	if product != "" {
		a.AddProduct(product)
		if a.Product == "" {
			a.Product = product
		}
	}
	if version != "" && a.Version == "" {
		a.Version = version
	}
	a.RaiseConfidence(confidence)
	a.AddEvidence(evidence)
}

// Key 是资产的去重键。同一条事实只允许进入存储一次。
func (a Asset) Key() string {
	switch {
	case a.URL != "":
		return "url|" + a.URL
	case a.Port > 0:
		return fmt.Sprintf("tcp|%s|%d", a.Host, a.Port)
	default:
		return "host|" + a.Host
	}
}

// SetMeta 写入扩展字段，自动初始化 map。
func (a *Asset) SetMeta(k, v string) {
	if v == "" {
		return
	}
	if a.Meta == nil {
		a.Meta = make(map[string]string)
	}
	a.Meta[k] = v
}

// MetaValue 读取扩展字段。
func (a Asset) MetaValue(k string) string {
	if a.Meta == nil {
		return ""
	}
	return a.Meta[k]
}

// AddProduct 追加产品指纹，自动去重。
func (a *Asset) AddProduct(products ...string) {
	for _, p := range products {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		dup := false
		for _, old := range a.Products {
			if strings.EqualFold(old, p) {
				dup = true
				break
			}
		}
		if !dup {
			a.Products = append(a.Products, p)
		}
	}
}

// IsWeb 表示该资产是否值得做 Web 层探测与爬取。
func (a Asset) IsWeb() bool {
	if a.URL != "" || a.Scheme != "" {
		return true
	}
	if strings.EqualFold(a.Service, "http") || strings.EqualFold(a.Service, "https") {
		return true
	}
	if strings.HasPrefix(strings.ToUpper(a.Banner), "HTTP/") {
		return true
	}
	return false
}
