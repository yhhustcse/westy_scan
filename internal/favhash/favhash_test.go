package favhash

import (
	"encoding/base64"
	"strings"
	"testing"
)

// MurmurHash3 x86_32 的已知向量（与 python-mmh3 对齐）。
// mmh3.hash("foo") 是社区文档里最常被引用的样例值。
func TestMMH3KnownVectors(t *testing.T) {
	cases := []struct {
		in   string
		want int32
	}{
		{"", 0},
		{"foo", -156908512},
		{"hello", 613153351},
	}
	for _, c := range cases {
		if got := MMH3([]byte(c.in)); got != c.want {
			t.Errorf("MMH3(%q) = %d, 期望 %d", c.in, got, c.want)
		}
	}
}

// 同一份输入必须稳定（favicon 指纹的全部价值建立在可复现上）
func TestMMH3Stable(t *testing.T) {
	data := []byte{0x00, 0x00, 0x01, 0x00, 0x7f, 0x80, 0xff, 0xfe, 0x42}
	first := MMH3(data)
	for i := 0; i < 10; i++ {
		if got := MMH3(data); got != first {
			t.Fatalf("第 %d 次结果不一致: %d != %d", i, got, first)
		}
	}
}

// 小改动应当产生不同的哈希（避免实现退化成常量函数）
func TestMMH3Sensitive(t *testing.T) {
	a := MMH3([]byte("favicon-bytes-a"))
	b := MMH3([]byte("favicon-bytes-b"))
	if a == b {
		t.Errorf("不同输入得到相同哈希 %d", a)
	}
}

// base64 包装必须复刻 Python base64.encodebytes：76 字符换行 + 结尾换行
func TestBase64LinesConvention(t *testing.T) {
	// 少于 76 字符：单行 + 结尾换行
	got := Base64Lines([]byte("foo"), 76)
	if got != "Zm9v\n" {
		t.Errorf("Base64Lines(foo) = %q, 期望 %q", got, "Zm9v\n")
	}

	// 空输入：Python 的 encodebytes(b"") 返回 b""（无换行）
	if got := Base64Lines(nil, 76); got != "" {
		t.Errorf("空输入应返回空串，实际 %q", got)
	}

	// 超过 76 字符：每行 76 字符，最后一行也带换行
	raw := make([]byte, 200)
	for i := range raw {
		raw[i] = byte(i)
	}
	enc := Base64Lines(raw, 76)
	lines := strings.Split(strings.TrimSuffix(enc, "\n"), "\n")
	if len(lines) < 3 {
		t.Fatalf("200 字节 base64 应至少 3 行，实际 %d 行", len(lines))
	}
	for i, l := range lines {
		if i < len(lines)-1 && len(l) != 76 {
			t.Errorf("第 %d 行长度 %d，期望 76", i, len(l))
		}
		if len(l) > 76 {
			t.Errorf("第 %d 行超长: %d", i, len(l))
		}
	}
	if !strings.HasSuffix(enc, "\n") {
		t.Error("结尾必须有换行（Shodan 约定）")
	}

	// 与标准库 base64 的内容必须一致（只差换行）
	plain := base64.StdEncoding.EncodeToString(raw)
	if strings.ReplaceAll(enc, "\n", "") != plain {
		t.Error("去掉换行后应与标准 base64 相同")
	}
}

func TestShodanVsRawHash(t *testing.T) {
	fav := []byte{0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x10, 0x10}
	shodan := ShodanHash(fav)
	raw := RawHash(fav)
	if shodan == raw {
		t.Error("base64 与原始字节两种约定不应得到同一结果")
	}
	// Shodan 约定 = 对 base64 文本取 mmh3，这里显式复算一遍
	if want := MMH3([]byte(Base64Lines(fav, 76))); shodan != want {
		t.Errorf("ShodanHash 与定义不符: %d != %d", shodan, want)
	}
	if want := MMH3(fav); raw != want {
		t.Errorf("RawHash 与定义不符: %d != %d", raw, want)
	}
}

// base64 的 padding 与短输入也不能出错
func TestBase64LinesShortInputs(t *testing.T) {
	for _, n := range []int{1, 2, 3, 4, 5, 56, 57, 58, 200} {
		data := make([]byte, n)
		enc := Base64Lines(data, 76)
		if !strings.HasSuffix(enc, "\n") {
			t.Errorf("n=%d 缺少结尾换行", n)
		}
		// 行数应等于 ceil(base64 长度 / 76)
		encLen := len(base64.StdEncoding.EncodeToString(data))
		wantLines := (encLen + 75) / 76
		if got := strings.Count(enc, "\n"); got != wantLines {
			t.Errorf("n=%d 换行数 %d，期望 %d（base64 长度 %d）", n, got, wantLines, encLen)
		}
		// 去掉换行后必须与标准 base64 一致
		if strings.ReplaceAll(enc, "\n", "") != base64.StdEncoding.EncodeToString(data) {
			t.Errorf("n=%d 内容与标准 base64 不一致", n)
		}
	}
}
