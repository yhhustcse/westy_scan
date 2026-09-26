// Package cdn 做 CDN / WAF 的**被动识别**。
//
// 设计原则：只观察已有数据（CNAME 链、响应头、Set-Cookie），绝不为了识别而发送
// 触发型 payload —— 那既会污染目标日志，也会被 WAF 记为攻击行为。
//
// 识别出来的价值有两个：
//  1. "真实 IP 可能被隐藏" —— 直接影响后续渗透策略（不能拿 CDN 边缘 IP 当目标）；
//  2. 关联分析 —— 同一 CDN 厂商/节点下的资产往往属于同一业务方。
//
// 局限（写在前面，避免过度自信）：本包只做特征匹配，不做 IP 段归属判断；
// 未命中不等于没有 CDN，只等于"没有可用证据"。
package cdn

import (
	"net/http"
	"strings"
)

// Kind 常量。
const (
	KindCDN  = "cdn"
	KindWAF  = "waf"
	KindBoth = "both"
)

// Detection 是一次识别的结果。
type Detection struct {
	CDN       string
	WAF       string
	BehindCDN bool
	Evidence  []string
}

// Empty 表示什么都没识别出来。
func (d Detection) Empty() bool { return d.CDN == "" && d.WAF == "" }

// cnameSuffix 是 CNAME 后缀 → 厂商。
// CNAME 是**最强证据**：它直接说明流量被谁接管。
var cnameSuffixes = []struct {
	suffix string
	name   string
}{
	{".cloudflare.net", "Cloudflare"},
	{".cloudflare.com", "Cloudflare"},
	{".akamaiedge.net", "Akamai"},
	{".akamai.net", "Akamai"},
	{".akamaitechnologies.com", "Akamai"},
	{".edgekey.net", "Akamai"},
	{".edgesuite.net", "Akamai"},
	{".fastly.net", "Fastly"},
	{".fastlylb.net", "Fastly"},
	{".cloudfront.net", "AWS CloudFront"},
	{".azureedge.net", "Azure CDN"},
	{".azurefd.net", "Azure Front Door"},
	{".trafficmanager.net", "Azure Traffic Manager"},
	{".kunlun.com", "阿里云 CDN"},
	{".kunlungr.com", "阿里云 CDN"},
	{".alikunlun.com", "阿里云 CDN"},
	{".alikunlun.net", "阿里云 CDN"},
	{".cdngslb.com", "阿里云 CDN"},
	{".alicdn.com", "阿里云 CDN"},
	{".dnsv1.com", "腾讯云 CDN"},
	{".tcdn.qq.com", "腾讯云 CDN"},
	{".wscdns.com", "网宿科技"},
	{".wscloudcdn.com", "网宿科技"},
	{".lxdns.com", "网宿科技"},
	{".chinacache.com", "蓝汛"},
	{".ccgslb.com", "蓝汛"},
	{".bdydns.com", "百度云加速"},
	{".yunjiasu-cdn.net", "百度云加速"},
	{".hwcdn.net", "华为云 CDN"},
	{".cdnhwc1.com", "华为云 CDN"},
	{".incapdns.net", "Imperva Incapsula"},
	{".impervadns.net", "Imperva Incapsula"},
	{".sucuri.net", "Sucuri"},
	{".stackpathdns.com", "StackPath"},
	{".kxcdn.com", "KeyCDN"},
	{".cachefly.net", "CacheFly"},
	{".cdnsun.net", "CDN77"},
}

// headerRule 是响应头特征。Contains 为空表示"该头存在即命中"。
var headerRules = []struct {
	header   string
	contains string
	name     string
	kind     string
}{
	// Cloudflare
	{"cf-ray", "", "Cloudflare", KindBoth},
	{"cf-cache-status", "", "Cloudflare", KindCDN},
	{"server", "cloudflare", "Cloudflare", KindBoth},
	// AWS
	{"x-amz-cf-id", "", "AWS CloudFront", KindCDN},
	{"x-amz-cf-pop", "", "AWS CloudFront", KindCDN},
	{"x-cache", "cloudfront", "AWS CloudFront", KindCDN},
	// Fastly
	{"x-served-by", "cache-", "Fastly", KindCDN},
	{"x-cache", "fastly", "Fastly", KindCDN},
	{"x-fastly-request-id", "", "Fastly", KindCDN},
	// Akamai
	{"x-akamai-transformed", "", "Akamai", KindCDN},
	{"x-akamai-request-id", "", "Akamai", KindCDN},
	{"x-check-cacheable", "", "Akamai", KindCDN},
	// Azure
	{"x-azure-ref", "", "Azure Front Door", KindCDN},
	{"x-msedge-ref", "", "Azure Front Door", KindCDN},
	// 阿里云
	{"ali-swift-global-savetime", "", "阿里云 CDN", KindCDN},
	{"eagleid", "", "阿里云 CDN", KindCDN},
	{"x-cache", "kunlun", "阿里云 CDN", KindCDN},
	// 网宿
	{"x-ws-request-id", "", "网宿科技", KindCDN},
	{"x-ws-request-gid", "", "网宿科技", KindCDN},
	{"via", "wscloudcdn", "网宿科技", KindCDN},
	// 百度云加速
	{"server", "yunjiasu", "百度云加速", KindBoth},
	{"x-cache", "yunjiasu", "百度云加速", KindCDN},
	// Sucuri
	{"x-sucuri-id", "", "Sucuri", KindBoth},
	{"x-sucuri-cache", "", "Sucuri", KindCDN},
	// Imperva
	{"x-iinfo", "", "Imperva Incapsula", KindBoth},
	{"x-cdn", "incapsula", "Imperva Incapsula", KindBoth},
	{"server", "incapsula", "Imperva Incapsula", KindBoth},
	// WAF 特征
	{"server", "big-ip", "F5 BIG-IP", KindWAF}, // F5 的 Server 头通常是 "BIG-IP"
	{"server", "bigip", "F5 BIG-IP", KindWAF},  // 少数实现写成 BigIP
	{"server", "mod_security", "ModSecurity", KindWAF},
	{"server", "safedog", "安全狗", KindWAF},
	{"server", "wzws", "网防G01", KindWAF},
	{"x-protected-by", "waf", "未知 WAF", KindWAF},
}

// cookieRule 是 Set-Cookie 前缀特征。
var cookieRules = []struct {
	prefix string
	name   string
	kind   string
}{
	{"__cfduid", "Cloudflare", KindBoth},
	{"cf_clearance", "Cloudflare", KindWAF},
	{"__cf_bm", "Cloudflare", KindWAF},
	{"incap_ses_", "Imperva Incapsula", KindBoth},
	{"visid_incap_", "Imperva Incapsula", KindBoth},
	{"nlbi_", "Imperva Incapsula", KindWAF},
	{"bigipserver", "F5 BIG-IP", KindWAF},
	{"ak_bmsc", "Akamai Bot Manager", KindWAF},
	{"bm_sv", "Akamai Bot Manager", KindWAF},
	{"sucuri_cloudproxy_uuid", "Sucuri", KindBoth},
	{"wzws_sessionid", "网防G01", KindWAF},
	{"hwwafsesid", "华为云 WAF", KindWAF},
	{"hwwafsestime", "华为云 WAF", KindWAF},
}

// Detect 依据 CNAME、响应头、Cookie 名字做被动识别。
//
// cname 传 net.LookupCNAME 的结果（可能为空）；cookieNames 传 CookieNames(headers) 的结果。
func Detect(cname string, headers http.Header, cookieNames []string) Detection {
	d := Detection{}
	host := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(cname), "."))

	for _, p := range cnameSuffixes {
		if strings.HasSuffix(host, p.suffix) {
			d.apply(p.name, KindCDN, "cname:"+p.suffix)
			d.BehindCDN = true
			break
		}
	}

	if headers != nil {
		for _, r := range headerRules {
			v := strings.ToLower(headers.Get(r.header))
			if v == "" {
				continue
			}
			if r.contains != "" && !strings.Contains(v, r.contains) {
				continue
			}
			d.apply(r.name, r.kind, "header:"+r.header)
			if r.kind != KindWAF {
				d.BehindCDN = true
			}
		}
	}

	for _, c := range cookieNames {
		lc := strings.ToLower(strings.TrimSpace(c))
		if lc == "" {
			continue
		}
		for _, cr := range cookieRules {
			if strings.HasPrefix(lc, cr.prefix) {
				d.apply(cr.name, cr.kind, "cookie:"+cr.prefix)
				if cr.kind != KindWAF {
					d.BehindCDN = true
				}
			}
		}
	}
	return d
}

// apply 写入识别结果：同一字段只保留第一个命中的厂商（先到先得，CNAME 优先）。
func (d *Detection) apply(name, kind, evidence string) {
	if name == "" {
		return
	}
	if kind == KindCDN || kind == KindBoth {
		if d.CDN == "" {
			d.CDN = name
		}
	}
	if kind == KindWAF || kind == KindBoth {
		if d.WAF == "" {
			d.WAF = name
		}
	}
	for _, e := range d.Evidence {
		if e == evidence {
			return
		}
	}
	d.Evidence = append(d.Evidence, evidence)
}

// CookieNames 从 Set-Cookie 头里提取 Cookie 名（只要名字部分）。
func CookieNames(h http.Header) []string {
	if h == nil {
		return nil
	}
	raw := h.Values("Set-Cookie")
	out := make([]string, 0, len(raw))
	for _, line := range raw {
		for _, part := range strings.Split(line, ",") {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			eq := strings.IndexByte(part, '=')
			if eq <= 0 {
				continue
			}
			name := strings.TrimSpace(part[:eq])
			if name == "" || strings.ContainsAny(name, " ;") {
				continue
			}
			out = append(out, name)
		}
	}
	return out
}

// OriginHint 返回给报告用的一句话提示（不主动绕过 WAF，只提示后续人工方向）。
func (d Detection) OriginHint() string {
	if !d.BehindCDN {
		return ""
	}
	return "流量经 " + firstNonEmpty(d.CDN, d.WAF) + " 转发，边缘 IP 不代表源站；" +
		"源站确认需在授权范围内通过证书 SAN、历史解析记录或业务侧配合完成，本工具不主动绕过 WAF"
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return "CDN"
}
