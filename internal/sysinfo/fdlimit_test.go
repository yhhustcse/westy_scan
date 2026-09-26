package sysinfo

import (
	"runtime"
	"testing"
)

// TestFDSoftLimitNeverPanics 固化"任何平台都必须安全返回"的契约：
// 该函数在启动路径上被调用，不能 panic，也不能出现越界/负值语义错误。
func TestFDSoftLimitNeverPanics(t *testing.T) {
	t.Parallel()

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("FDSoftLimit 不应 panic，却 panic 了: %v", r)
		}
	}()

	limit, ok := FDSoftLimit()
	if ok {
		if limit == 0 {
			t.Fatalf("ok=true 时 limit 不应为 0（0 表示无限制，与 ok=true 语义矛盾）")
		}
		t.Logf("检测到 fd 软上限: %d", limit)
		return
	}
	// 降级路径（Windows/非 Unix）：必须报告"不可用"，且 limit 为 0 而非垃圾值。
	if limit != 0 {
		t.Fatalf("ok=false 时 limit 应为 0，得到 %d", limit)
	}
	t.Logf("平台 %s 无 RLIMIT_NOFILE，走降级路径（limit=0, ok=false）", runtime.GOOS)
}

// TestFDSoftLimitIsStable 同一进程内重复调用必须给出一致结果（无随机/竞态）。
func TestFDSoftLimitIsStable(t *testing.T) {
	t.Parallel()

	first, firstOK := FDSoftLimit()
	for i := 0; i < 20; i++ {
		limit, ok := FDSoftLimit()
		if ok != firstOK {
			t.Fatalf("第 %d 次调用 ok 从 %v 变为 %v", i+2, firstOK, ok)
		}
		if limit != first {
			t.Fatalf("第 %d 次调用 limit 从 %d 变为 %d", i+2, first, limit)
		}
	}
}

// TestFDSoftLimitConcurrent 并发调用：-race 下检验无共享状态问题。
func TestFDSoftLimitConcurrent(t *testing.T) {
	t.Parallel()

	const goroutines = 16
	results := make(chan struct {
		limit uint64
		ok    bool
	}, goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			l, ok := FDSoftLimit()
			results <- struct {
				limit uint64
				ok    bool
			}{l, ok}
		}()
	}
	first := <-results
	for i := 1; i < goroutines; i++ {
		got := <-results
		if got != first {
			t.Fatalf("并发调用结果不一致: %+v vs %+v", got, first)
		}
	}
}

// TestPlatformSpecificExpectation 断言当前平台的具体语义：
// Windows 属于 !linux && !darwin，必须走降级路径返回 (0,false)。
func TestPlatformSpecificExpectation(t *testing.T) {
	t.Parallel()

	limit, ok := FDSoftLimit()
	switch runtime.GOOS {
	case "linux", "darwin":
		if !ok {
			t.Fatalf("%s 上应能取到 RLIMIT_NOFILE，却返回 ok=false", runtime.GOOS)
		}
		if limit < 64 {
			t.Logf("警告：fd 软上限异常偏低: %d", limit)
		}
	default:
		if ok {
			t.Fatalf("%s 上无 RLIMIT_NOFILE 概念，应返回 ok=false，却得到 (%d, true)", runtime.GOOS, limit)
		}
		if limit != 0 {
			t.Fatalf("%s 降级路径应返回 limit=0，得到 %d", runtime.GOOS, limit)
		}
	}
}
