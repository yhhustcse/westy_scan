# westy_scan 常用任务（Linux/macOS；Windows 请用 scripts/*.ps1）

BIN := bin/westy

.PHONY: build test vet fmt demo rules clean

build:
	go build -trimpath -ldflags "-s -w" -o $(BIN) ./cmd/westy

test:
	go test ./... -count=1 -race

vet:
	go vet ./...

fmt:
	gofmt -l -w cmd internal   # 注意：不要对仓库根跑，会走进 .tools/go 的工具链源码

# 规则库体检：规模 + 质量门禁 + 金丝雀全命中 + 干净站点零误报
rules: build
	@echo "指纹规则数：" && ./$(BIN) -list-rules | grep -c '"name"'
	@echo "漏洞模板数：" && ./$(BIN) -list-templates 2>/dev/null | grep -c '"id"'
	go test ./internal/fingerprint/ ./internal/poc/ -count=1 -v | tail -40
	@echo "金丝雀验收请跑：python3 scripts/fake-services.py & ./$(BIN) -target 127.0.0.1 ... （见 README 第 10 步）"

demo: build
	@echo "本地闭环演示：扫描本机 127.0.0.1/32"
	./$(BIN) -target 127.0.0.1 -allow 127.0.0.1/32 -authorized -strict-scope \
		-ports "common" -crawl -format table -o out/demo.jsonl -v

clean:
	rm -rf bin out
