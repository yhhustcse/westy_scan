package portscan

import (
	"context"
	"testing"
	"time"

	"westy_scan/internal/scope"
)

func benchScope(b *testing.B) *scope.Scope {
	b.Helper()
	sc, err := scope.New([]string{"127.0.0.1/32"}, nil, 16, false, true)
	if err != nil {
		b.Fatalf("构造 Scope 失败: %v", err)
	}
	return sc
}

// closedPorts 返回一段大概率全部关闭的本地端口，用来测量扫描引擎自身开销
// （不依赖任何外部目标，CI 里也能跑）。
func closedPorts(n int) []int {
	ports := make([]int, 0, n)
	for p := 20000; p < 20000+n; p++ {
		ports = append(ports, p)
	}
	return ports
}

// BenchmarkConnectScanLocalhost1000 测 1000 个端口（本机，绝大多数为关闭状态）的扫描吞吐。
// 注意：这测的是"扫描引擎 + 本地 TCP 栈"的上限，不是真实网络的吞吐；
// 真实网络的瓶颈通常在 RTT 与丢包，见 docs/benchmark.md。
func BenchmarkConnectScanLocalhost1000(b *testing.B) {
	sc := benchScope(b)
	ports := closedPorts(1000)
	ctx := context.Background()
	scanner := ConnectScanner{}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		start := time.Now()
		open := 0
		for range scanner.Scan(ctx, sc, []string{"127.0.0.1"}, ports, Options{
			Timeout:     2 * time.Second,
			Concurrency: 200,
			Banner:      false,
		}) {
			open++
		}
		elapsed := time.Since(start).Seconds()
		if elapsed > 0 {
			b.ReportMetric(float64(len(ports))/elapsed, "ports/s")
		}
		if open > 0 {
			b.Logf("本机 20000-20999 段意外出现 %d 个开放端口，吞吐数字会偏低", open)
		}
	}
}

func BenchmarkBuildSYNPacket(b *testing.B) {
	src := []byte{10, 0, 0, 5}
	dst := []byte{10, 0, 0, 9}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := buildSYNPacket(src, dst, 40000, 445, 12345); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkParseIPv4TCP(b *testing.B) {
	pkt, err := buildSYNPacket([]byte{10, 0, 0, 5}, []byte{10, 0, 0, 9}, 40000, 445, 1)
	if err != nil {
		b.Fatal(err)
	}
	pkt[33] = tcpFlagSYN | tcpFlagACK
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := parseIPv4TCP(pkt); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkScopeGuard 衡量授权闸门自身的开销（含缓存命中的 DNS 解析路径）。
func BenchmarkScopeGuard(b *testing.B) {
	sc := benchScope(b)
	ctx := context.Background()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, _, err := sc.Guard(ctx, "127.0.0.1"); err != nil {
			b.Fatal(err)
		}
	}
}
