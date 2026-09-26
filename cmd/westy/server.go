package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
	"westy_scan/internal/jsonutil"

	"westy_scan/internal/audit"
	"westy_scan/internal/authz"
	"westy_scan/internal/notify"
	"westy_scan/internal/report"
	"westy_scan/internal/server"
	"westy_scan/internal/target"
	"westy_scan/internal/wire"
)

// runServer 是 `westy server` 子命令：编排端。
func runServer(args []string) error {
	fs := flag.NewFlagSet("westy server", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	var (
		listen    = fs.String("listen", "127.0.0.1:8899", "监听地址")
		token     = fs.String("token", "", "Agent 鉴权 token（为空则开发模式，会打印警告）")
		tlsCert   = fs.String("tls-cert", "", "服务端证书（配合 -tls-key 启用 HTTPS）")
		tlsKey    = fs.String("tls-key", "", "服务端私钥")
		auditFile = fs.String("audit", "out/server-audit.jsonl", "服务端审计日志 JSONL")
		targets   = fs.String("targets", "", "启动时创建一次扫描：目标（逗号分隔，支持域名/IP/CIDR）")
		ports     = fs.String("ports", "common", "启动时创建扫描：端口表达式")
		jobSize   = fs.Int("job-size", 1, "每个任务包含的主机数")
		jobPorts  = fs.Int("job-ports", 0, "端口分片大小（0=全部端口一个任务；切片越细越均衡、掉线损失越小）")
		lease     = fs.Int("lease", 60, "任务租约秒数（Agent 掉线后多久重派）")
		maxTries  = fs.Int("max-tries", 3, "单任务最大重试次数")
		runFor    = fs.Duration("run-for", 0, "运行指定时长后退出（0 表示常驻）")
		reportTo  = fs.String("report", "", "退出时把资产/漏洞报告写到文件（默认标准输出）")
		format    = fs.String("format", "table", "报告格式：table|markdown|json")

		// M6：平台化
		dataDir   = fs.String("data-dir", "out/server-data", "持久化目录（空字符串=纯内存，重启丢状态）")
		rolesFlag = fs.String("roles", "", "角色 token 映射，如 admin=tok1,operator=tok2,viewer=tok3")
		authzFile = fs.String("authz-file", "", "启动时导入授权书 JSON（数组，文件里没有的不会覆盖）")
		authzRef  = fs.String("authorization", "", "创建扫描所用授权书编号（与 -targets 配合，必填）")
		schedule  = fs.Duration("schedule", 0, "定时扫描间隔（0=不启用；需要 -targets 与 -authorization）")
		notifyURL = fs.String("notify-url", "", "通知 webhook 地址（企微/钉钉/Slack 机器人或自建网关）")
		notifyFmt = fs.String("notify-format", "json", "通知格式：json|wecom|dingtalk|slack")
		notifyMin = fs.String("notify-min-severity", "high", "只通知不低于该级别的漏洞")
	)
	if err := fs.Parse(args); err != nil {
		return err
	}

	aud, err := audit.Open(*auditFile)
	if err != nil {
		return err
	}
	defer aud.Close()

	roles, err := parseRoles(*rolesFlag)
	if err != nil {
		return err
	}

	srv := server.New(server.Options{
		Token: *token, LeaseSeconds: *lease, MaxTries: *maxTries,
		ServerVersion: version, Audit: aud, Log: loggerFor(),
		DataDir:           *dataDir,
		Roles:             roles,
		Notify:            notify.New(notify.Options{URL: *notifyURL, Format: notify.Format(*notifyFmt)}),
		NotifyMinSeverity: *notifyMin,
	})
	defer srv.Close()

	// 导入授权书
	if strings.TrimSpace(*authzFile) != "" {
		recs, err := loadAuthorizations(*authzFile)
		if err != nil {
			return err
		}
		imported := 0
		for _, rec := range recs {
			if err := srv.CreateAuthorization(rec); err != nil {
				if strings.Contains(err.Error(), "已存在") {
					continue
				}
				return fmt.Errorf("导入授权书 %s 失败: %w", rec.ID, err)
			}
			imported++
		}
		fmt.Fprintf(os.Stderr, "[server] 授权书导入完成：新增 %d 份（文件 %s）\n", imported, *authzFile)
	}

	// 可选：启动时直接下发一次扫描（必须关联授权书）
	if strings.TrimSpace(*targets) != "" {
		if strings.TrimSpace(*authzRef) == "" {
			return fmt.Errorf("创建扫描必须用 -authorization 指定授权书编号（这是合规闸门：没有授权书不允许扫描）")
		}
		hosts, portList, err := parseScanTargets(*targets, *ports)
		if err != nil {
			return err
		}
		spec := wire.ScanSpec{
			Hosts: hosts, Ports: portList, JobSize: *jobSize, JobPorts: *jobPorts,
			Authorization: *authzRef, Operator: "cli",
		}
		info, err := srv.CreateScanAuthorized(spec)
		if err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "[server] 已创建扫描 %s：主机 %d，端口 %d，任务 %d（授权书 %s）\n",
			info.ID, info.Hosts, info.Ports, info.Tasks, *authzRef)

		// 定时扫描由服务端自己创建（每分钟/每小时的周期性资产变更巡检）
		if *schedule > 0 {
			srv.EnableSchedule(*schedule, spec)
			fmt.Fprintf(os.Stderr, "[server] 已启用定时扫描：每 %s 一次（授权书 %s）\n", *schedule, *authzRef)
		}
	}

	httpSrv := &http.Server{
		Addr:              *listen,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		// 长轮询需要较长的写超时
		WriteTimeout: 10 * time.Minute,
		IdleTimeout:  2 * time.Minute,
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if *runFor > 0 {
		var stop context.CancelFunc
		ctx, stop = context.WithTimeout(ctx, *runFor)
		defer stop()
	}

	go func() {
		var serveErr error
		if *tlsCert != "" && *tlsKey != "" {
			fmt.Fprintf(os.Stderr, "[server] HTTPS 监听 %s\n", *listen)
			serveErr = httpSrv.ListenAndServeTLS(*tlsCert, *tlsKey)
		} else {
			fmt.Fprintf(os.Stderr, "[server] HTTP 监听 %s（生产环境建议配合 TLS/双向 TLS）\n", *listen)
			serveErr = httpSrv.ListenAndServe()
		}
		if serveErr != nil && serveErr != http.ErrServerClosed {
			fmt.Fprintf(os.Stderr, "[server] 监听退出: %v\n", serveErr)
		}
	}()

	<-ctx.Done()
	shutdownCtx, cancelShutdown := context.WithTimeout(context.Background(), 5*time.Second)
	_ = httpSrv.Shutdown(shutdownCtx)
	cancelShutdown()

	st := srv.Stats()
	fmt.Fprintf(os.Stderr, "[server] 退出：任务 %v，资产 %d，漏洞 %d，Agent %d\n",
		st.Tasks, st.Assets, st.Findings, len(st.Agents))
	for _, info := range st.Scans {
		fmt.Fprintf(os.Stderr, "[server] 扫描 %s：任务 %d（完成 %d/失败 %d），资产 %d，漏洞 %d\n",
			info.ID, info.Tasks, info.Done, info.Failed, info.Assets, info.Findings)
	}

	return writeServerReport(*reportTo, *format, srv)
}

func writeServerReport(path, format string, srv *server.Server) error {
	var w *os.File = os.Stdout
	if path != "" {
		f, err := os.Create(path)
		if err != nil {
			return err
		}
		defer f.Close()
		w = f
	}
	assets := srv.Assets()
	findings := srv.Findings()
	switch format {
	case "json":
		return report.WriteJSON(w, assets)
	case "markdown":
		if err := report.WriteMarkdown(w, assets); err != nil {
			return err
		}
		return report.WriteFindingsMarkdown(w, findings)
	default:
		if err := report.WriteTable(w, assets); err != nil {
			return err
		}
		fmt.Fprintln(w)
		return report.WriteFindings(w, findings)
	}
}

// parseRoles 解析 "admin=tok1,operator=tok2" 形式的角色映射。
func parseRoles(spec string) (map[string]string, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return nil, nil
	}
	out := map[string]string{}
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		kv := strings.SplitN(part, "=", 2)
		if len(kv) != 2 {
			return nil, fmt.Errorf("角色映射格式应为 role=token，实际 %q", part)
		}
		role := strings.ToLower(strings.TrimSpace(kv[0]))
		token := strings.TrimSpace(kv[1])
		switch role {
		case "admin", "operator", "viewer":
		default:
			return nil, fmt.Errorf("未知角色 %q（可选 admin/operator/viewer）", role)
		}
		if token == "" {
			return nil, fmt.Errorf("角色 %s 的 token 为空", role)
		}
		out[token] = role
	}
	return out, nil
}

// loadAuthorizations 读取授权书 JSON（数组或单对象）。
func loadAuthorizations(path string) ([]authz.Record, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("读取授权书文件失败: %w", err)
	}
	data = jsonutil.StripBOM(data)
	trimmed := strings.TrimSpace(string(data))
	if strings.HasPrefix(trimmed, "[") {
		var recs []authz.Record
		if err := jsonutil.Unmarshal(data, &recs); err != nil {
			return nil, fmt.Errorf("解析授权书失败: %w", err)
		}
		return recs, nil
	}
	var rec authz.Record
	if err := jsonutil.Unmarshal(data, &rec); err != nil {
		return nil, fmt.Errorf("解析授权书失败: %w", err)
	}
	return []authz.Record{rec}, nil
}

// parseScanTargets 复用单机版的目标/端口解析逻辑。
func parseScanTargets(targets, ports string) ([]string, []int, error) {
	hosts, err := target.ParseAll([]string{targets}, 4096)
	if err != nil {
		return nil, nil, err
	}
	if len(hosts) == 0 {
		return nil, nil, fmt.Errorf("未从 %q 解析出任何目标", targets)
	}
	out := make([]string, 0, len(hosts))
	for _, h := range hosts {
		out = append(out, h.Host)
	}
	portList, err := target.ParsePorts(ports)
	if err != nil {
		return nil, nil, err
	}
	return out, portList, nil
}
