PWD := $(dir $(abspath $(firstword $(MAKEFILE_LIST))))

sast-gosec:
	docker run --rm -it \
	-v "$(PWD)":/workspace -w /workspace \
	securego/gosec:latest \
	-out gosec-report.txt ./...
# 	-fmt=json -out gosec-report.json ./...

sast-govulncheck:
	docker run --rm -v "$(PWD)":/app -w /app golang:1.25 \
	go mod download && go install golang.org/x/vuln/cmd/govulncheck@latest && \
	govulncheck ./... > govulncheck-report.txt
# 	govulncheck -json ./... > govulncheck-report.json

sast: sast-gosec sast-govulncheck
	@echo "SAST completed: reports saved to gosec-report.json and govulncheck-report.json"