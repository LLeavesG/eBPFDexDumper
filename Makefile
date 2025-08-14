GO_RUN = go run github.com/cilium/ebpf/cmd/bpf2go
GO_MOD_TIDY = go mod tidy
GO_BUILD = go build
TARGET = arm64
PACKAGE = main


BPF_FILE = bpf.c

# TYPE = -type trace_event -type trace_config
TYPE = -type config_t -type event_data_t -type method_event_data_t

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

all: bpf tidy build

bpf:
	$(GO_RUN) -go-package $(PACKAGE) --target=$(TARGET) $(TYPE) $(BPF_OUTPUT) $(BPF_FILE) -- -I$(HEADERS) -I$(VMLINUX_HEADERS)

tidy:
	$(GO_MOD_TIDY)

build: tidy
	CC=$(CC) CXX=$(CXX) GOOS=$(GOOS) GOARCH=$(GOARCH) CGO_ENABLED=$(CGO_ENABLED) $(GO_BUILD) -buildvcs=false

clean:
	rm -f $(BPF_OUTPUT)_$(TARGET)_bpfel.go $(BPF_OUTPUT)_$(TARGET)_bpfel.o $(BINARY_NAME)

.PHONY: all bpf tidy build clean