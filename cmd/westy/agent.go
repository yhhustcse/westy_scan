package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"westy_scan/internal/agent"
	"westy_scan/internal/config"
)

// runAgent 是 `westy agent` 子命令：执行端。
//
// 扫描行为（端口、并发、限速、爬虫、模板…）来自配置文件，命令行只覆盖与
// "分布式身份/连接"相关的参数 —— 这样 Agent 的扫描策略由运维统一管理，
// 而授权范围始终在 Agent 本地配置里，Server 无法代它授权。
func runAgent(args []string) error {
	fs := flag.NewFlagSet("westy agent", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	var (
		serverURL = fs.String("server", "", "Server 地址，如 http://127.0.0.1:8899（必填）")
		token     = fs.String("token", "", "与 Server 约定的鉴权 token")
		agentID   = fs.String("id", "", "Agent ID（默认由服务端分配）")
		spool     = fs.String("spool", "out/agent-spool", "断线时的本地缓冲目录（空表示不缓冲）")
		cfgPath   = fs.String("config", "", "扫描配置文件（与单机模式同一份 JSON）")
		maxJobs   = fs.Int("max-jobs", 4, "每次拉取的任务数")
		waitSecs  = fs.Int("pull-wait", 20, "长轮询等待秒数")
		batchSize = fs.Int("batch", 200, "上报批量条数")

		authorized = fs.Bool("authorized", false, "声明本地已获得授权（也可写在配置里）")
		allow      = fs.String("allow", "", "本地授权范围 allow（逗号分隔；强烈建议显式配置）")
		deny       = fs.String("deny", "", "本地授权范围 deny（逗号分隔，优先级最高）")
		strict     = fs.Bool("strict-scope", true, "严格模式：必须配置 allow")

		caFile     = fs.String("tls-ca", "", "校验服务端证书的 CA 文件")
		clientCert = fs.String("tls-cert", "", "双向 TLS 客户端证书")
		clientKey  = fs.String("tls-key", "", "双向 TLS 客户端私钥")
		insecure   = fs.Bool("tls-insecure", false, "跳过服务端证书校验（仅调试）")
	)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(*serverURL) == "" {
		return fmt.Errorf("必须指定 -server")
	}

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	if *authorized {
		cfg.Authorized = true
	}
	if v := splitComma(*allow); len(v) > 0 {
		cfg.Allow = append(cfg.Allow, v...)
	}
	if v := splitComma(*deny); len(v) > 0 {
		cfg.Deny = append(cfg.Deny, v...)
	}
	cfg.StrictScope = *strict || cfg.StrictScope
	if !cfg.Authorized {
		return fmt.Errorf("Agent 必须声明本地授权：-authorized 或配置文件 authorized=true")
	}

	ag, err := agent.New(agent.Config{
		ServerURL: *serverURL,
		Token:     *token,
		AgentID:   *agentID,
		Version:   version,
		TLS: agent.TLSConfig{
			CAFile: *caFile, CertFile: *clientCert, KeyFile: *clientKey,
			InsecureSkipVerify: *insecure,
		},
		MaxJobs: *maxJobs, PullWaitSecs: *waitSecs, BatchSize: *batchSize,
		SpoolDir: *spool,
		Scan:     cfg,
		Log:      loggerFor(),
	})
	if err != nil {
		return err
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	loggerFor().Printf("Agent 启动：server=%s 本地授权范围=%v 严格模式=%v 缓冲目录=%s",
		*serverURL, cfg.Allow, cfg.StrictScope, *spool)
	return ag.Run(ctx)
}

func splitComma(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		if p := strings.TrimSpace(part); p != "" {
			out = append(out, p)
		}
	}
	return out
}
