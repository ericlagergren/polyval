#!/usr/bin/env bash

set -xeuo pipefail

go run asm.go \
	-out out/polyval_amd64.s \
	-stubs out/stub_amd64.go \
	-pkg polyval
gofmt -s -w out/*.go
asmfmt -w out/*.s
mv out/* ../
export CGO_ENABLED=1
export GOARCH=amd64
go test github.com/ericlagergren/polyval \
	-v \
	-vet all \
	-failfast \
	-count 1 \
	"${@}"
