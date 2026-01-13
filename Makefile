PWD := $(dir $(abspath $(firstword $(MAKEFILE_LIST))))
REPORT_DIR := test/reports/sast

.PHONY: sast-gosec sast-govulncheck sast test

.IGNORE: sast-gosec sast-govulncheck

sast-gosec:
	@docker run --rm -it -v "$(PWD)":/workspace -w /workspace securego/gosec:2.22.11 -out $(REPORT_DIR)/gosec.txt ./...
	@echo "SAST gosec completed"

sast-govulncheck:
	@docker run --rm -v "$(PWD)":/app -w /app golang:1.25.5 go mod download && go install golang.org/x/vuln/cmd/govulncheck@latest && govulncheck ./... >$(REPORT_DIR)/govulncheck.txt
	@echo "SAST govulncheck completed"

sast: sast-gosec sast-govulncheck
	@echo "SAST completed"

test:
	go test ./...