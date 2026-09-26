package poc

import (
	"crypto/rand"
	"encoding/hex"
	"regexp"
	"strconv"
	"strings"
)

// 变量渲染：把模板里的 {{Var}} 替换成实际值。
//
// 支持的变量（与 nuclei 常用集合对齐）：
//
//	BaseURL    scheme://host[:port]      RootURL   scheme://host
//	Hostname   host（不含端口）           Host      同 Hostname
//	Port       端口                       Scheme    http/https
//	Path       资产已知路径               IP        解析到的 IP
//	randstr / randstr_1 / randstr_2      每次请求独立的随机串（用于回显验证）
//	oob / oob_url / oob_host             外带验证用的一次性地址（仅启用 OOB 时存在）
//
// 未知变量**保持原样**并且不报错 —— 这样模板里的其它 {{...}}（例如 JS 模板语法）
// 不会被误替换；同时编译期会警告"模板里出现了无来源的变量"。

var reVar = regexp.MustCompile(`\{\{\s*([A-Za-z0-9_.\-]+)\s*\}\}`)

// Vars 是一次渲染可用的变量集合。
type Vars map[string]string

// Lookup 允许大小写不敏感地取变量（nuclei 模板大小写并不统一）。
func (v Vars) Lookup(name string) (string, bool) {
	if val, ok := v[name]; ok {
		return val, true
	}
	for k, val := range v {
		if strings.EqualFold(k, name) {
			return val, true
		}
	}
	return "", false
}

// Render 用变量集合渲染字符串。
func Render(s string, vars Vars) string {
	if !strings.Contains(s, "{{") {
		return s
	}
	return reVar.ReplaceAllStringFunc(s, func(match string) string {
		sub := reVar.FindStringSubmatch(match)
		if len(sub) != 2 {
			return match
		}
		if val, ok := vars.Lookup(sub[1]); ok {
			return val
		}
		return match // 未知变量保持原样
	})
}

// UnknownVars 返回模板里出现的、变量集合中没有的变量名（用于编译期告警）。
// 动态变量（randstr/oob 等）由引擎注入，因此调用方应传入完整集合。
func UnknownVars(text string, vars Vars) []string {
	var out []string
	seen := map[string]bool{}
	for _, m := range reVar.FindAllStringSubmatch(text, -1) {
		if len(m) != 2 {
			continue
		}
		name := m[1]
		if _, ok := vars.Lookup(name); ok {
			continue
		}
		if seen[name] {
			continue
		}
		seen[name] = true
		out = append(out, name)
	}
	return out
}

// RandStr 生成指定长度的随机小写十六进制串（用于回显验证与 OOB token）。
func RandStr(n int) string {
	if n <= 0 {
		n = 8
	}
	buf := make([]byte, (n+1)/2)
	if _, err := rand.Read(buf); err != nil {
		// crypto/rand 失败属于系统级异常，退化成固定串也比 panic 好，
		// 但必须让它显眼：调用方会在证据里看到它。
		return strings.Repeat("0", n)
	}
	return hex.EncodeToString(buf)[:n]
}

// itoa 内部使用，避免到处 import strconv。
func itoa(n int) string { return strconv.Itoa(n) }
