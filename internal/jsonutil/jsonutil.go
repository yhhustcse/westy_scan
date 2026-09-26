// Package jsonutil 提供"容忍 Windows 工具产物"的 JSON 解析。
//
// 背景：Windows 上的 PowerShell（`Set-Content -Encoding UTF8`）与记事本默认会写
// **带 BOM 的 UTF-8**，而 Go 的 encoding/json 遇到 BOM 会直接报
// `invalid character '\ufeff' looking for beginning of value`。
// 这个工具的配置文件、授权书、模板、指纹规则都可能是人手写的，
// 在 Windows 上"用记事本存一下就打不开"是不能接受的，所以统一在这里剥掉 BOM。
package jsonutil

import (
	"bytes"
	"encoding/json"
)

// bom 是 UTF-8 BOM（EF BB BF）。
var bom = []byte{0xEF, 0xBB, 0xBF}

// StripBOM 去掉开头的 UTF-8 BOM（没有则原样返回，不复制）。
func StripBOM(data []byte) []byte {
	if bytes.HasPrefix(data, bom) {
		return data[len(bom):]
	}
	return data
}

// Unmarshal 先剥 BOM 再解析。
func Unmarshal(data []byte, v any) error {
	return json.Unmarshal(StripBOM(data), v)
}
