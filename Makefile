GO_RUN = go run github.com/cilium/ebpf/cmd/bpf2go
GO_MOD_TIDY = go mod tidy
GO_BUILD = go build
TARGET = arm64
PACKAGE = main


BPF_FILE = bpf.c

# TYPE = -type trace_event -type trace_config
TYPE = -type config_t -type dex_event_data_t -type method_event_data_t

HEADERS = headers
VMLINUX_HEADERS = vmlinux/$(TARGET)

BPF_OUTPUT = bpf
BINARY_NAME = eBPFDexDumper

ANDROID_NDK_ROOT = /home/lleaves/android-ndk-r25c

## Android
CC = "${ANDROID_NDK_ROOT}/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android33-clang"
CXX = "${ANDROID_NDK_ROOT}/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android33-clang++"
GOOS = android
GOARCH = $(TARGET)
CGO_ENABLED = 1

all: bpf genbtf tidy build

bpf:
	$(GO_RUN) -go-package $(PACKAGE) --target=$(TARGET) $(TYPE) $(BPF_OUTPUT) $(BPF_FILE) -- -I$(HEADERS) -I$(VMLINUX_HEADERS)

tidy:
	$(GO_MOD_TIDY)

build: tidy
	CC=$(CC) CXX=$(CXX) GOOS=$(GOOS) GOARCH=$(GOARCH) CGO_ENABLED=$(CGO_ENABLED) $(GO_BUILD) -buildvcs=false

genbtf: bpf
	@echo "Generating minimal BTFs with bpftool (requires assets/*.btf)"
	@# Ensure bpftool binary exists in assets directory
	@if [ ! -x assets/bpftool ]; then echo "Error: assets/bpftool not found or not executable"; exit 1; fi
	@# Generate minimal BTFs for known kernels using compiled BPF object
	@obj_file=$(BPF_OUTPUT)_$(TARGET)_bpfel.o; \
	if [ ! -f $$obj_file ]; then echo "Error: $$obj_file not found. Run 'make bpf' first."; exit 1; fi; \
	if [ -f assets/a12-5.10-arm64.btf ]; then \
	  echo "- a12-5.10-arm64_min.btf"; \
	  assets/bpftool gen min_core_btf assets/a12-5.10-arm64.btf assets/a12-5.10-arm64_min.btf $$obj_file || exit 1; \
	fi; \
	if [ -f assets/rock5b-5.10-f9d1b1529-arm64.btf ]; then \
	  echo "- rock5b-5.10-arm64_min.btf"; \
	  assets/bpftool gen min_core_btf assets/rock5b-5.10-f9d1b1529-arm64.btf assets/rock5b-5.10-arm64_min.btf $$obj_file || exit 1; \
	fi

clean:
	rm -f $(BPF_OUTPUT)_$(TARGET)_bpfel.go $(BPF_OUTPUT)_$(TARGET)_bpfel.o $(BINARY_NAME) assets/*_min.btf

.PHONY: all bpf genbtf tidy build clean
