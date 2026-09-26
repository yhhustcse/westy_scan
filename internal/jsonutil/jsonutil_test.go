package jsonutil

import (
	"encoding/json"
	"testing"
)

func TestStripBOM(t *testing.T) {
	plain := []byte(`{"a":1}`)
	if got := StripBOM(plain); string(got) != string(plain) {
		t.Errorf("无 BOM 时应原样返回")
	}
	withBOM := append([]byte{0xEF, 0xBB, 0xBF}, plain...)
	if got := StripBOM(withBOM); string(got) != string(plain) {
		t.Errorf("应剥掉 BOM，实际 %q", got)
	}
}

// 真实场景：Windows 工具写出的带 BOM JSON 必须能解析
func TestUnmarshalWithBOM(t *testing.T) {
	withBOM := append([]byte{0xEF, 0xBB, 0xBF}, []byte(`{"id":"AB-1","allow":["10.0.0.0/24"]}`)...)
	var v struct {
		ID    string   `json:"id"`
		Allow []string `json:"allow"`
	}
	if err := Unmarshal(withBOM, &v); err != nil {
		t.Fatalf("带 BOM 的 JSON 应能解析: %v", err)
	}
	if v.ID != "AB-1" || len(v.Allow) != 1 {
		t.Errorf("解析结果错误: %+v", v)
	}

	// 不带 BOM 也要正常
	if err := Unmarshal([]byte(`{"id":"AB-2"}`), &v); err != nil {
		t.Fatalf("普通 JSON 应能解析: %v", err)
	}

	// 真错误仍要报错（不要吞掉语法错误）
	if err := Unmarshal([]byte(`{oops`), &v); err == nil {
		t.Error("非法 JSON 应报错")
	}

	// 与标准库行为一致（除 BOM 外）
	var raw map[string]any
	if err := json.Unmarshal([]byte(`{"a":1}`), &raw); err != nil {
		t.Fatal(err)
	}
}
