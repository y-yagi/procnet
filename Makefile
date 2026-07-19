# procnet Makefile
#
# Two build flavors:
#   make build        - default binary, /proc-based attribution only (no toolchain needed)
#   make build-ebpf   - binary with the eBPF hybrid attribution compiled in
#
# The eBPF flavor needs a one-time toolchain: clang, llvm-strip, bpftool
# (linux-tools-$(uname -r)), and the libbpf CO-RE headers. `make build-ebpf`
# pulls the headers (make bpf-headers) and generates vmlinux.h (make vmlinux)
# automatically; see their targets for the prerequisites.

BINARY   := procnet
PKG      := ./cmd/procnet
EBPF_DIR := internal/ebpf
BPF_DIR  := $(EBPF_DIR)/bpf
KERNEL   := $(shell uname -r)

# bpftool used to dump the kernel BTF. The distro's /usr/sbin/bpftool is a
# wrapper that needs the kernel-matched linux-tools package; if that's
# missing, point this at any working bpftool (any recent version can dump
# the running kernel's BTF), e.g. make vmlinux BPFTOOL=$HOME/.local/bin/bpftool
BPFTOOL ?= bpftool

# libbpf CO-RE headers attribute.bpf.c includes, vendored into $(BPF_DIR).
LIBBPF_HEADERS := bpf_helpers.h bpf_helper_defs.h bpf_core_read.h bpf_tracing.h bpf_endian.h
VENDORED       := $(addprefix $(BPF_DIR)/,$(LIBBPF_HEADERS))

.PHONY: all build build-ebpf generate vmlinux bpf-headers \
        test test-ebpf test-ebpf-integration fmt vet check clean clean-ebpf help

all: build

## build: default binary (/proc-only attribution, no eBPF toolchain required)
build:
	go build -o $(BINARY) $(PKG)

## build-ebpf: binary with eBPF hybrid attribution (generates code first)
build-ebpf: generate
	go build -tags ebpf_generated -o $(BINARY) $(PKG)

## generate: run bpf2go (needs vendored headers + vmlinux.h)
generate: bpf-headers $(BPF_DIR)/vmlinux.h
	go generate ./$(EBPF_DIR)

## vmlinux: dump the running kernel's BTF to $(BPF_DIR)/vmlinux.h via bpftool
vmlinux: $(BPF_DIR)/vmlinux.h

$(BPF_DIR)/vmlinux.h:
	@command -v $(BPFTOOL) >/dev/null 2>&1 || { \
		echo "ERROR: bpftool ($(BPFTOOL)) not found. Install: sudo apt install linux-tools-$(KERNEL)"; exit 1; }
	@$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@ 2>/dev/null; \
	if [ ! -s $@ ]; then \
		rm -f $@; \
		echo "ERROR: $(BPFTOOL) produced no output -- the kernel-specific bpftool is missing."; \
		echo "       Install it (sudo apt install linux-tools-$(KERNEL) / linux-tools-generic),"; \
		echo "       or point make at a working one: make $@ BPFTOOL=/path/to/bpftool"; \
		exit 1; \
	fi
	@echo "generated $@ ($$(wc -l < $@) lines)"

## bpf-headers: vendor libbpf CO-RE headers into $(BPF_DIR) (no sudo required)
bpf-headers:
	@mkdir -p $(BPF_DIR)
	@missing=0; for h in $(LIBBPF_HEADERS); do [ -f $(BPF_DIR)/$$h ] || missing=1; done; \
	if [ $$missing -eq 0 ]; then echo "libbpf headers already vendored in $(BPF_DIR)"; exit 0; fi; \
	if [ -d /usr/include/bpf ]; then \
		for h in $(LIBBPF_HEADERS); do cp /usr/include/bpf/$$h $(BPF_DIR)/; done; \
		echo "vendored libbpf headers from /usr/include/bpf"; \
	else \
		tmp=$$(mktemp -d); \
		( cd $$tmp && apt-get download libbpf-dev >/dev/null 2>&1 && dpkg-deb -x libbpf-dev_*.deb x ) || \
			{ echo "ERROR: could not obtain libbpf-dev; install it: sudo apt install libbpf-dev"; rm -rf $$tmp; exit 1; }; \
		for h in $(LIBBPF_HEADERS); do cp $$tmp/x/usr/include/bpf/$$h $(BPF_DIR)/; done; \
		echo "vendored libbpf headers via apt-get download"; \
		rm -rf $$tmp; \
	fi

## test: run all unit tests (default build tags)
test:
	go test ./...

## test-ebpf: run unit tests with the eBPF code compiled in (needs generate first)
test-ebpf: generate
	go test -tags ebpf_generated ./...

## test-ebpf-integration: load the real eBPF program (needs root + BTF kernel)
test-ebpf-integration: generate
	@echo "Requires root; run: sudo go test -tags 'ebpf_generated ebpf_integration' ./$(EBPF_DIR)/..."
	sudo go test -tags 'ebpf_generated ebpf_integration' ./$(EBPF_DIR)/...

## fmt: check formatting (fails if any file needs gofmt)
fmt:
	@out=$$(gofmt -l .); if [ -n "$$out" ]; then echo "needs gofmt:"; echo "$$out"; exit 1; fi

## vet: go vet
vet:
	go vet ./...

## check: fmt + vet + build + test (the default-flavor gate)
check: fmt vet build test

## clean: remove the built binary
clean:
	rm -f $(BINARY)

## clean-ebpf: remove binary + all generated/regeneration-only eBPF artifacts
clean-ebpf: clean
	rm -f $(EBPF_DIR)/attribute_bpfel.go $(EBPF_DIR)/attribute_bpfel.o
	rm -f $(BPF_DIR)/vmlinux.h $(VENDORED)

## help: list targets
help:
	@grep -E '^## ' $(MAKEFILE_LIST) | sed 's/^## /  /'
