package pipeline

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"westy_scan/internal/audit"
	"westy_scan/internal/config"
	"westy_scan/internal/favhash"
	"westy_scan/internal/model"
	"westy_scan/internal/store"
)

var testFavicon = []byte{0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x10, 0x10, 0x00, 0x00}

// selfSignedCert 生成一张带多个 SAN 的自签证书，用于验证证书联动。
func selfSignedCert(t *testing.T, dnsNames []string, ips []net.IP) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("生成私钥失败: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(20260101),
		Subject:               pkix.Name{CommonName: "westy-test", Organization: []string{"westy_scan test"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:              dnsNames,
		IPAddresses:           ips,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("签发证书失败: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func readAudit(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("读取审计日志失败: %v", err)
	}
	return string(data)
}

// TestPipelineM2WebAndSAN 覆盖 M2 三条链路：
//  1. favicon 抓取 + mmh3 哈希（Shodan 约定）；
//  2. CDN/WAF 被动识别（响应头特征）；
//  3. 证书 SAN 联动：越界域名被审计拦截，范围内域名被扩展。
func TestPipelineM2WebAndSAN(t *testing.T) {
	cert := selfSignedCert(t,
		[]string{"localhost", "out-of-scope.example"},
		[]net.IP{net.ParseIP("127.0.0.1")},
	)

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// 模拟经 Cloudflare 转发的站点（被动识别只看这些特征）
		w.Header().Set("CF-RAY", "7a1b2c3d4e5f-LAX")
		w.Header().Set("Server", "cloudflare")
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><head><title>Westy M2</title>
			<link rel="icon" href="/favicon.ico"></head><body>m2</body></html>`)
	})
	mux.HandleFunc("/favicon.ico", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/x-icon")
		_, _ = w.Write(testFavicon)
	})

	srv := httptest.NewUnstartedServer(mux)
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	srv.StartTLS()
	defer srv.Close()

	_, portStr, err := net.SplitHostPort(strings.TrimPrefix(srv.URL, "https://"))
	if err != nil {
		t.Fatalf("解析测试服务地址失败: %v", err)
	}

	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	aud, err := audit.Open(auditPath)
	if err != nil {
		t.Fatalf("打开审计失败: %v", err)
	}
	defer aud.Close()

	mem := store.NewMemory()
	cfg := config.Default()
	cfg.Targets = []string{"127.0.0.1"}
	cfg.Ports = portStr
	cfg.Allow = []string{"127.0.0.1/32", "localhost"} // out-of-scope.example 故意不放进来
	cfg.StrictScope = true
	cfg.Authorized = true
	cfg.Concurrency = 8
	cfg.TimeoutSec = 3
	cfg.ServiceDetect = false
	cfg.Crawl = false
	cfg.SanExpand = true
	cfg.SanMaxHosts = 5
	cfg.UDP = false
	cfg.BlindWebProbes = 10

	eng, err := New(cfg, mem, aud, log.New(io.Discard, "", 0))
	if err != nil {
		t.Fatalf("构造流水线失败: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := eng.Run(ctx); err != nil {
		t.Fatalf("流水线运行失败: %v", err)
	}
	aud.Close()

	var web *model.Asset
	for _, a := range mem.Assets() {
		if a.URL != "" && strings.HasPrefix(a.URL, "https://") {
			cp := a
			web = &cp
		}
	}
	if web == nil {
		t.Fatalf("未发现 HTTPS 资产，实际资产: %+v", mem.Assets())
	}

	// 1) favicon 哈希
	wantHash := favhash.ShodanHash(testFavicon)
	if web.FaviconHash != wantHash {
		t.Errorf("favicon 哈希 = %d，期望 %d（meta=%v）", web.FaviconHash, wantHash, web.Meta)
	}
	// 2) CDN/WAF
	if web.CDN != "Cloudflare" {
		t.Errorf("CDN 未识别: %q（evidence=%v）", web.CDN, web.Evidence)
	}
	if !web.BehindCDN || web.OriginNote == "" {
		t.Errorf("应标记 BehindCDN 并给出源站提示: behind=%v note=%q", web.BehindCDN, web.OriginNote)
	}
	// 3) 证书信息与 SAN
	if web.TLS == nil || len(web.TLS.DNSNames) == 0 {
		t.Fatalf("证书 SAN 未采集: %+v", web.TLS)
	}

	// 4) SAN 联动：越界域名必须被拦截并留痕
	logText := readAudit(t, auditPath)
	if !strings.Contains(logText, "san_rejected") || !strings.Contains(logText, "out-of-scope.example") {
		t.Errorf("越界 SAN 未被审计拦截:\n%s", logText)
	}
	if !strings.Contains(logText, "cdn_detected") {
		t.Errorf("缺少 CDN 识别审计事件:\n%s", logText)
	}
	// localhost 在 allow 内，应被纳入扩展（added>=1）
	if !strings.Contains(logText, "san_expand_done") {
		t.Errorf("缺少 SAN 联动完成事件:\n%s", logText)
	}
	// 绝不允许出现对越界域名的扫描动作。
	//
	// 必须**逐行**判断：越界域名本身一定会出现在 san_rejected 的 reason 里，
	// 而 san_asset 事件可能来自合法域名（例如 allow 内的 localhost）。
	// 若用"整份日志里分别 Contains 两个串"的写法，只要合法扩展产出过一条资产事件，
	// 就会把"合法扩展 + 越界被拒"误判成"越界被扫描" —— CI 上就是这么红的。
	for _, line := range strings.Split(logText, "\n") {
		if strings.Contains(line, `"event":"san_asset"`) && strings.Contains(line, "out-of-scope.example") {
			t.Errorf("越界域名被扫描了（严重问题）:\n%s", line)
		}
	}
}

// SAN 关闭时不应产生任何联动行为
func TestPipelineSANDisabled(t *testing.T) {
	cert := selfSignedCert(t, []string{"localhost"}, []net.IP{net.ParseIP("127.0.0.1")})
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, "<html><title>t</title></html>")
	})
	srv := httptest.NewUnstartedServer(mux)
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	srv.StartTLS()
	defer srv.Close()
	_, portStr, _ := net.SplitHostPort(strings.TrimPrefix(srv.URL, "https://"))

	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	aud, _ := audit.Open(auditPath)
	mem := store.NewMemory()
	cfg := config.Default()
	cfg.Targets = []string{"127.0.0.1"}
	cfg.Ports = portStr
	cfg.Allow = []string{"127.0.0.1/32", "localhost"}
	cfg.StrictScope = true
	cfg.Authorized = true
	cfg.TimeoutSec = 3
	cfg.ServiceDetect = false
	cfg.SanExpand = false
	cfg.BlindWebProbes = 10

	eng, err := New(cfg, mem, aud, log.New(io.Discard, "", 0))
	if err != nil {
		t.Fatalf("构造流水线失败: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := eng.Run(ctx); err != nil {
		t.Fatalf("运行失败: %v", err)
	}
	aud.Close()
	if strings.Contains(readAudit(t, auditPath), "san_expand_done") {
		t.Error("SanExpand=false 时不应出现 SAN 联动事件")
	}
}
