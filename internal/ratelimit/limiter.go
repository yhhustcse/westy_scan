// Package ratelimit 提供全局令牌桶限速。
//
// 渗透测试框架最容易出事的地方就是"一上来把目标打挂"。
// 因此限速不是可选项，而是所有出网动作的必经之路：
// 端口扫描、HTTP 探测、爬虫都共享同一个 Limiter 实例。
package ratelimit

import (
	"context"
	"sync"
	"time"
)

// Limiter 是一个简单的令牌桶：每秒补充 perSecond 个令牌。
// 零值（tokens == nil）等价于不限速，便于在测试中省略。
type Limiter struct {
	tokens chan struct{}
	stop   chan struct{}
	ticker *time.Ticker // 仅 New 创建时有值；注入时钟时为 nil
	once   sync.Once
}

// New 创建限速器。perSecond <= 0 表示不限速。
func New(perSecond int) *Limiter {
	if perSecond <= 0 {
		return &Limiter{}
	}
	interval := time.Second / time.Duration(perSecond)
	if interval <= 0 {
		interval = time.Millisecond
	}
	t := time.NewTicker(interval)
	l := newWithTicks(perSecond, t.C)
	l.ticker = t
	return l
}

// newWithTicks 与 New 行为相同，但补充信号取自给定的 channel。
//
// 存在的理由很具体：令牌"何时到达"原本只由真实 ticker 决定，于是测试里
// "取空桶后不应立刻再发令牌"这类断言必须和真实时钟赛跑 —— 在慢机器（CI 上跑 -race）
// 上一旦某次调度跨过一个补充间隔，测试就会随机失败。把时钟注入进来以后，
// 这些断言变成完全确定的：没人往 channel 里发信号，就绝不可能有新令牌。
//
// perSecond 同时决定桶容量（与 New 一致）。
func newWithTicks(perSecond int, ticks <-chan time.Time) *Limiter {
	l := &Limiter{
		tokens: make(chan struct{}, perSecond),
		stop:   make(chan struct{}),
	}
	go func() {
		for {
			select {
			case <-l.stop:
				return
			case <-ticks:
				select {
				case l.tokens <- struct{}{}:
				default: // 桶满则丢弃，保持恒定速率而非突发
				}
			}
		}
	}()
	return l
}

// Wait 阻塞直到获得一个令牌或 ctx 结束。
func (l *Limiter) Wait(ctx context.Context) error {
	if l == nil || l.tokens == nil {
		return nil
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-l.tokens:
		return nil
	}
}

// Stop 释放后台协程（以及真实 ticker）。
func (l *Limiter) Stop() {
	if l == nil {
		return
	}
	l.once.Do(func() {
		if l.stop != nil {
			close(l.stop)
		}
		if l.ticker != nil {
			l.ticker.Stop()
		}
	})
}
