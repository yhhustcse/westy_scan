package ratelimit

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// waitResult 在给定超时内尝试取一个令牌。
// 返回 nil 表示取到令牌，否则返回 ctx 的错误（通常是 context.DeadlineExceeded）。
func waitResult(l *Limiter, d time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), d)
	defer cancel()
	return l.Wait(ctx)
}

// waitOne 在给定超时内取一个令牌，返回是否成功。
func waitOne(l *Limiter, d time.Duration) bool { return waitResult(l, d) == nil }

// 经实测（见测试内的耗时断言）固化的语义：
//   - New(perSecond>0) 的桶**初始为空**，第一个令牌要等一个补充周期 (1s/perSecond)；
//   - 桶容量 = perSecond，但补充速率恒为每秒 perSecond 个（桶满则丢弃）；
//   - 因此"一次能连续取到几个令牌"取决于已经积攒了多久，最多 perSecond 个。
//
// ⚠️ 测试策略（这条是被 CI 打脸后才写下的）：
// **凡是"精确条数"的断言，一律用注入时钟 newWithTicks，不碰真实 ticker。**
// 原因：原来的写法是"sleep 一会儿让桶灌满 → 断言恰好能取到 perSecond 个 → 断言下一个取不到"，
// 而补充是真实 ticker 在跑 —— 只要某次调度跨过一个补充间隔（CI 上跑 -race 就会），
// 断言就随机失败。这类"测试与时钟赛跑"的问题在本地快机器上完全看不出来，
// 一到慢机器就变成随机红。真实时钟只保留一处 smoke 测试（TestNewUsesRealTicker）。
//
// fillBucket 把桶灌满：推入**恰好 cap 个**补充信号，并轮询等待它们真的进了桶。
//
// 为什么必须"恰好 cap 个"（这里踩过一次）：多推的信号虽然会因为桶满被丢弃，
// 但**已在途**的信号（后台协程已从 channel 收到、正等着往桶里放）会在测试取走令牌后
// 立刻补上一个 —— 于是"取空后不该再有令牌"的断言会随机失败。
// 灌满即停，才能保证"没有余量、也没有在途"。
//
// 用轮询而不是 sleep：睡眠是"猜时间"，轮询是"等事实"。
func fillBucket(t *testing.T, l *Limiter, ticks chan<- time.Time) {
	t.Helper()
	want := cap(l.tokens)
	for i := 0; i < want; i++ {
		select {
		case ticks <- time.Now():
		case <-time.After(2 * time.Second):
			t.Fatal("推送补充信号超时：后台协程没有在消费时钟 channel")
		}
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if len(l.tokens) == want {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("桶未在 2 秒内被灌满：len=%d want=%d", len(l.tokens), want)
}

// TestNewNonPositiveIsUnlimited 固化 New(perSecond<=0) 的语义：
// 返回的限速器不做任何限制，Wait 立即成功。
func TestNewNonPositiveIsUnlimited(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name      string
		perSecond int
	}{
		{name: "zero", perSecond: 0},
		{name: "negative", perSecond: -1},
		{name: "very_negative", perSecond: -1000},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			l := New(tc.perSecond)
			t.Cleanup(l.Stop)

			for i := 0; i < 100; i++ {
				ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
				err := l.Wait(ctx)
				cancel()
				if err != nil {
					t.Fatalf("New(%d) 应不限速，第 %d 次 Wait 却返回 %v", tc.perSecond, i, err)
				}
			}
		})
	}
}

// TestNilLimiterAndZeroValue 固化 nil 接收者与零值 Limiter 的语义（均不阻塞）。
func TestNilLimiterAndZeroValue(t *testing.T) {
	t.Parallel()

	var nilL *Limiter
	if err := nilL.Wait(context.Background()); err != nil {
		t.Fatalf("nil Limiter.Wait 应返回 nil，得到 %v", err)
	}
	nilL.Stop() // 不应 panic

	var zero Limiter
	for i := 0; i < 50; i++ {
		if err := zero.Wait(context.Background()); err != nil {
			t.Fatalf("零值 Limiter 第 %d 次 Wait 应成功，得到 %v", i, err)
		}
	}
	zero.Stop() // stop 为 nil，不应 panic
}

// TestNewUsesRealTicker 是唯一一处依赖真实时钟的测试：证明 New 真的接了一个 ticker，
// 并且首个令牌**不是瞬发**的。上下界都放得很宽（只为抓"瞬发"和"永不补充"两种极端），
// 精确行为由注入时钟的测试负责 —— 这样它不会因为 CI 慢而红。
func TestNewUsesRealTicker(t *testing.T) {
	t.Parallel()

	const perSecond = 5 // 真实补充间隔 200ms
	l := New(perSecond)
	t.Cleanup(l.Stop)

	if err := waitResult(l, 20*time.Millisecond); err != context.DeadlineExceeded {
		t.Fatalf("新建限速器的桶应为空，Wait 却返回 %v", err)
	}

	start := time.Now()
	if err := waitResult(l, 5*time.Second); err != nil {
		t.Fatalf("等待补充周期后应能取到令牌，实际返回 %v", err)
	}
	elapsed := time.Since(start)
	if elapsed < 50*time.Millisecond {
		t.Fatalf("首个令牌仅用 %v 就拿到，远快于补充间隔 200ms：令牌被瞬发", elapsed)
	}
	if elapsed > 3*time.Second {
		t.Fatalf("首个令牌耗时 %v，远超补充间隔 200ms（ticker 可能没接上）", elapsed)
	}
}

// TestBurstIsCappedByCapacity 固化容量语义：**无论灌多少补充信号**，
// 最多只能连续取到 perSecond 个（桶不会超过容量），取空后立即再取必然失败。
//
// 用注入时钟：灌 10 个信号（> 容量 3），取空后没有新信号 → 下一个必然取不到。
// 这一步不依赖任何真实时间，因此在任何机器上都确定。
func TestBurstIsCappedByCapacity(t *testing.T) {
	t.Parallel()

	const perSecond = 3
	ticks := make(chan time.Time)
	l := newWithTicks(perSecond, ticks)
	t.Cleanup(l.Stop)

	fillBucket(t, l, ticks) // 灌满；多余信号不存在，取空后不可能再冒出令牌

	got := 0
	for i := 0; i < perSecond+5; i++ {
		if !waitOne(l, 50*time.Millisecond) {
			break
		}
		got++
	}
	if got != perSecond {
		t.Fatalf("桶容量应为 %d，实际连续取到 %d 个", perSecond, got)
	}
	// 桶已空，且没有新的补充信号：这里**不可能**再取到令牌（不是"50ms 内大概取不到"）。
	if waitOne(l, 50*time.Millisecond) {
		t.Fatal("桶被取空后不应再发令牌")
	}
}

// TestEmptyBucketBlocksUntilRefill 验证桶空后 Wait 会阻塞，直到**新的补充信号到达**才返回。
// 用注入时钟：阻塞与唤醒都由测试自己控制，没有"等大概多久"的猜测。
func TestEmptyBucketBlocksUntilRefill(t *testing.T) {
	t.Parallel()

	ticks := make(chan time.Time)
	l := newWithTicks(2, ticks)
	t.Cleanup(l.Stop)

	// 空桶：Wait 必须阻塞（用 50ms 窗口证明它没有立刻返回）
	if waitOne(l, 50*time.Millisecond) {
		t.Fatal("空桶不应立刻发令牌")
	}

	// 手动送来一个令牌：阻塞中的 Wait 必须马上返回
	done := make(chan bool, 1)
	go func() { done <- waitOne(l, 2*time.Second) }()
	select {
	case ticks <- time.Now():
	case <-time.After(2 * time.Second):
		t.Fatal("推送补充信号超时")
	}
	select {
	case ok := <-done:
		if !ok {
			t.Fatal("补充信号到达后 Wait 应成功")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("补充信号到达后 Wait 未返回")
	}

	// 再次取空，确认没有残留令牌
	if waitOne(l, 50*time.Millisecond) {
		t.Fatal("桶应已抽空，却仍能取到令牌")
	}
}

// TestStopIsIdempotentAndHaltsRefill 验证 Stop 可重复调用，且停止后不再补充令牌。
func TestStopIsIdempotentAndHaltsRefill(t *testing.T) {
	t.Parallel()

	const perSecond = 10 // 间隔 100ms
	l := New(perSecond)

	if !waitOne(l, 2*time.Second) {
		t.Fatal("Stop 前应能取到令牌")
	}
	l.Stop()
	l.Stop() // 幂等，不应 panic

	// 后台补充协程已退出：再等 300ms（3 个补充周期）也拿不到令牌。
	time.Sleep(300 * time.Millisecond)
	if err := waitResult(l, 20*time.Millisecond); err != context.DeadlineExceeded {
		t.Fatalf("Stop 后不应再有令牌补充，Wait 返回 %v", err)
	}
}

// TestWaitContextCancelled 验证 ctx 取消能及时打断 Wait（无令牌时）。
// 用注入时钟：桶里永远不会有令牌，所以"Wait 返回 Canceled"这件事没有第二个可能。
func TestWaitContextCancelled(t *testing.T) {
	t.Parallel()

	ticks := make(chan time.Time) // 从不推送：桶保持为空
	l := newWithTicks(2, ticks)
	t.Cleanup(l.Stop)

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(20 * time.Millisecond)
		cancel()
	}()
	start := time.Now()
	if err := l.Wait(ctx); err != context.Canceled {
		t.Fatalf("ctx 取消时 Wait 应返回 context.Canceled，实际返回 %v", err)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("Wait 未及时响应取消，耗时 %v", elapsed)
	}
}

// TestConcurrentWaitOnEmptyBucketGrantsNothing 并发抢一个**永远为空**的桶：
// 一个都不应放行；-race 同时检验并发安全。
// 用注入时钟（从不推送）→ "0 个放行"是确定事实，与机器快慢无关。
func TestConcurrentWaitOnEmptyBucketGrantsNothing(t *testing.T) {
	t.Parallel()

	const waiters = 32
	ticks := make(chan time.Time) // 从不推送
	l := newWithTicks(1, ticks)
	t.Cleanup(l.Stop)

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	var granted int64
	var wg sync.WaitGroup
	ready := make(chan struct{}, waiters)
	start := make(chan struct{})
	for i := 0; i < waiters; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ready <- struct{}{}
			<-start // 所有 goroutine 同时开抢
			if l.Wait(ctx) == nil {
				atomic.AddInt64(&granted, 1)
			}
		}()
	}
	for i := 0; i < waiters; i++ {
		<-ready
	}
	close(start)
	wg.Wait()

	if got := atomic.LoadInt64(&granted); got != 0 {
		t.Fatalf("300ms 窗口内空桶放行了 %d 个令牌（速率 1/s），限速失效", got)
	}
}

// TestConcurrentWaitDoesNotOversell 并发抢一个刚灌满的桶：
// 放行数必须**恰好**等于桶容量（并发下既不吞令牌，也不超发）。
//
// 用注入时钟：灌满后不再推送任何信号，于是"80ms 窗口内不可能多出一个令牌"
// 是确定事实 —— 原来的写法靠 sleep 1.2s 等真实 ticker，窗口相位随机，
// 有相当概率撞上下一个补充周期而误报超发。
func TestConcurrentWaitDoesNotOversell(t *testing.T) {
	t.Parallel()

	const (
		capacity = 3
		waiters  = 48
	)
	ticks := make(chan time.Time)
	l := newWithTicks(capacity, ticks)
	t.Cleanup(l.Stop)

	fillBucket(t, l, ticks) // 灌满（恰好 cap 个，无在途信号）

	ctx, cancel := context.WithTimeout(context.Background(), 80*time.Millisecond)
	defer cancel()

	var granted int64
	var wg sync.WaitGroup
	ready := make(chan struct{}, waiters)
	start := make(chan struct{})
	for i := 0; i < waiters; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ready <- struct{}{}
			<-start
			for l.Wait(ctx) == nil {
				atomic.AddInt64(&granted, 1)
			}
		}()
	}
	for i := 0; i < waiters; i++ {
		<-ready
	}
	close(start)
	wg.Wait()

	got := atomic.LoadInt64(&granted)
	if got < capacity {
		t.Fatalf("桶里有 %d 个令牌，并发下只放行 %d 个（令牌被吞）", capacity, got)
	}
	if got > capacity {
		t.Fatalf("并发下放行 %d 个令牌，超过桶容量 %d（80ms 内不足一个补充周期 333ms）", got, capacity)
	}
}

// TestConcurrentWaitAcrossLimiters 多类限速器（限速 / 不限速 / nil）并发使用，-race 检验无共享状态问题。
func TestConcurrentWaitAcrossLimiters(t *testing.T) {
	t.Parallel()

	const workers = 8
	unlimited := New(0)
	limiters := []*Limiter{New(1000), unlimited, nil}
	for _, l := range limiters {
		if l != nil {
			t.Cleanup(l.Stop)
		}
	}

	var wg sync.WaitGroup
	for _, l := range limiters {
		l := l
		for w := 0; w < workers; w++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for i := 0; i < 20; i++ {
					if l == nil {
						if err := l.Wait(context.Background()); err != nil {
							t.Errorf("nil 限速器 Wait 应返回 nil，得到 %v", err)
						}
						continue
					}
					_ = waitResult(l, 200*time.Millisecond)
				}
			}()
		}
	}
	wg.Wait()
}
