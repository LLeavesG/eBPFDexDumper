# eBPFDexDumper

[![Language](https://img.shields.io/badge/Language-Go-blue.svg)](https://golang.org/)
[![Platform](https://img.shields.io/badge/Platform-Android-green.svg)](https://android.com/)

[English](README.md) | [中文](README_CN.md)

Android in-memory DEX dumper powered by eBPF technology.

## Features
- **Undetectable**: Uses eBPF uprobes for stealth operation
- **Passive dump**: Non-intrusive memory analysis
- **Real-time tracing**: Optional method execution monitoring
- **Automatic fixing**: Built-in DEX file repair functionality

**Showcase**: https://blog.lleavesg.top/article/eBPFDexDumper

## Supported Environment
- **Tested on**: Android 13 (Pixel 6)
- **Architecture**: ARM64
- **Requirements**: Root permission required

**Note**: On other Android versions you may need minor adjustments and rebuild.

## Prerequisites
Before dumping, it's recommended to remove the app's OAT optimization output to avoid `cdex` or empty results. You can do this manually, or let the tool remove it automatically with `--clean-oat`:
- Find base path: `pm path <package>`
- Remove oat folder: delete the app's `oat/` directory under `/data/app/.../<package>/`

Root permission is typically required to attach uprobes and read target memory.

## Usage

### Command Syntax
```
eBPFDexDumper [command] [options]
```

**Available Commands:**
- `dump` - Start eBPF-based DEX dumper
- `fix` - Fix dumped DEX files in a directory

### `dump` Command
Attach uprobes to libart and stream DEX/method events. You must provide either `--uid` or `--name` to filter the target app.

**Options:**
- `--uid, -u <uid>` - Filter by UID (alternative to `--name`) (default: 0)
- `--name, -n <package>` - Android package name to derive UID (alternative to `--uid`)
- `--libart, -l <path>` - Path to libart.so (default: `/apex/com.android.art/lib64/libart.so`)
- `--out, -o, --output <dir>` - Output directory on device (required)
- `--trace, -t` - Print executed methods in real time during dumping (default: false)
- `--clean-oat, -c` - Remove `/data/app/.../oat` folders of target app(s) before dumping (default: false)
- `--execute-offset <value>` - Manual offset for art::interpreter::Execute function (hex value, e.g. 0x12345) (default: 0) (If not specified, it will be auto-found)
- `--nterp-offset <value>` - Manual offset for ExecuteNterpImpl function (hex value, e.g. 0x12345) (default: 0) (If not specified, it will be auto-found)

**Examples:**
```bash
# Filter by UID
./eBPFDexDumper dump -u 10244 -o /data/local/tmp/out

# Filter by package name (UID auto-resolved)
./eBPFDexDumper dump -n com.example.app -o /data/local/tmp/out

# Enable realtime method trace output
./eBPFDexDumper dump -n com.example.app -o /data/local/tmp/out -t

# Custom libart path
./eBPFDexDumper dump -u 10244 -l /apex/com.android.art/lib64/libart.so -o /sdcard/dex_out

# Auto-remove oat to improve completeness
./eBPFDexDumper dump -n com.example.app -o /data/local/tmp/out -c

# Use manual offsets for specific ART versions
./eBPFDexDumper dump -n com.example.app -o /data/local/tmp/out --execute-offset 0x12345 --nterp-offset 0x67890
```

**Output Files:**
- **DEX files**: `dex_<begin>_<size>.dex` saved under the output directory
- **Method bytecode JSON**: `dex_<begin>_<size>_code.json` saved on shutdown (SIGINT/SIGTERM) or normal exit

### `fix` Command
Scan a directory for dumped DEX files and fix headers/structures for readability.

**Options:**
- `--dir, -d <dir>` - Directory containing dumped DEX files (required)

**Example:**
```bash
./eBPFDexDumper fix -d /data/local/tmp/out
```

## Installation & Build

### Requirements
- **Go 1.19+** for building the application
- **Android NDK** for cross-compilation
- **Android device** with ARM64 architecture
- **Root access** on the target Android device

### Build Instructions
1. **Clone the repository:**
   ```bash
   git clone https://github.com/LLeavesG/eBPFDexDumper.git
   cd eBPFDexDumper
   ```

2. **Adjust NDK path if necessary**, then build:
   ```bash
   make
   ```

3. **Push to Android device:**
   ```bash
   adb push eBPFDexDumper /data/local/tmp/
   adb shell chmod +x /data/local/tmp/eBPFDexDumper
   ```

## Troubleshooting

### Common Issues

**1. UID but not PID**
You need to specify the app's uid using -u, not pid, or directly use -n to specify the package name.
Don't use -u to specify the app's pid.

**2. Binary Not Found**
```bash
# Verify file was pushed correctly
adb shell ls -la /data/local/tmp/eBPFDexDumper

# Ensure execute permissions
adb shell chmod +x /data/local/tmp/eBPFDexDumper
```

**3. Empty or Incomplete DEX Files**
- Use `--clean-oat` flag to remove OAT optimization
- Ensure the target app is actively running
- Try manual offset values for your specific Android version

**4. Cannot Find libart.so**
```bash
# Find libart.so location on your device
adb shell find /apex -name "libart.so" 2>/dev/null
adb shell find /system -name "libart.so" 2>/dev/null
```

## References
- [cilium/ebpf](https://github.com/cilium/ebpf) - eBPF library for Go
- [ebpfmanager](https://github.com/gojue/ebpfmanager) - Go + eBPF Manager Library
- [null-luo/btrace](https://github.com/null-luo/btrace) - Binary tracing tools
- [ART Internal Structure](https://evilpan.com/2021/12/26/art-internal/)
- [Android Runtime Analysis](https://zhuanlan.zhihu.com/p/523692715)
- [DEX File Format](https://blog.csdn.net/weixin_47668107/article/details/114251185)
- [Android Security Research](https://juejin.cn/post/7045575502991458340)
- [eBPF on Android](https://juejin.cn/post/7384992816906747913)
- [Advanced Obfuscation Techniques](https://blog.quarkslab.com/dji-the-art-of-obfuscation.html)
- [eBPF Documentation](https://blog.seeflower.dev/archives/84/#title-7)

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.


## Disclaimer

This tool is intended for educational and defensive security research purposes only. Users are responsible for ensuring compliance with applicable laws and regulations.