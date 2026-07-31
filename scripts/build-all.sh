#!/bin/sh
# Produce CGO-disabled binaries for every supported runtime platform. Linux
# outputs are fully static; macOS still links platform system libraries.
set -eu

output_dir=${1:-dist}
mkdir -p "$output_dir"

build() {
	goos=$1
	goarch=$2
	output="$output_dir/agent-guard_${goos}_${goarch}"
	(
		CGO_ENABLED=0 \
			GOOS=$goos \
			GOARCH=$goarch \
			GOTOOLCHAIN=local \
			go build -mod=vendor -trimpath -o "$output" ./cmd/agent-guard
	)
}

build darwin arm64
build linux amd64
build linux arm64
