# eBPFDexDumper

[![Language](https://img.shields.io/badge/Language-Go-blue.svg)](https://golang.org/)
[![Platform](https://img.shields.io/badge/Platform-Android-green.svg)](https://android.com/)

[中文](README.md) | [English](README_en.md)

Android in-memory DEX dumper powered by eBPF technology.

## Features
- **Undetectable**: Uses eBPF uprobes for stealth operation
- **Passive dump**: Non-intrusive memory analysis
- **Real-time tracing**: Optional method execution monitoring
- **Automatic fixing**: Built-in DEX file repair functionality
- **High performance**: Lock-free caching and optimized string processing
- **Simplified operation**: Smart defaults, dump and fix in one command

**Showcase**: https://blog.lleavesg.top/article/eBPFDexDumper

## Supported Environment
- **Tested on**: Android 13 (Pixel 6)
- **Architecture**: ARM64
- **Requirements**: Root permission required

**Note**: On other Android versions you may need minor adjustments and rebuild.

## Prerequisites
The tool automatically removes the app's OAT optimization output to avoid `cdex` or empty results. For manual operation:
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
- `--out, -o, --output <dir>` - Output directory on device (default: `/data/local/tmp/dex_out`)
- `--trace, -t` - Print executed methods in real time during dumping (default: false)
- `--clean-oat, -c` - Remove `/data/app/.../oat` folders of target app(s) before dumping (default: **true**)
- `--auto-fix, -f` - Automatically fix DEX files after dumping (default: **true**)
- `--no-clean-oat` - Disable automatic OAT cleaning
- `--no-auto-fix` - Disable automatic DEX fixing
- `--execute-offset <value>` - Manual offset for art::interpreter::Execute function (hex value, e.g. 0x12345)
- `--nterp-offset <value>` - Manual offset for ExecuteNterpImpl function (hex value, e.g. 0x12345)

**Examples:**
```bash
# Simplest usage - just specify package name, auto dump+clean-oat+fix
./eBPFDexDumper dump -n com.example.app

# Filter by UID
./eBPFDexDumper dump -u 10244

# Enable realtime method trace output
./eBPFDexDumper dump -n com.example.app -t

# Custom output directory
./eBPFDexDumper dump -n com.example.app -o /sdcard/dex_out

# Disable auto-fix (dump only)
./eBPFDexDumper dump -n com.example.app --no-auto-fix

# Disable auto clean-oat
./eBPFDexDumper dump -n com.example.app --no-clean-oat

# Use manual offsets for specific ART versions
./eBPFDexDumper dump -n com.example.app --execute-offset 0x12345 --nterp-offset 0x67890
```

**Output Files:**
- **DEX files**: `dex_<begin>_<size>.dex` saved under the output directory
- **Method bytecode JSON**: `dex_<begin>_<size>_code.json` saved on shutdown (SIGINT/SIGTERM) or normal exit
- **Fixed DEX files**: `fix/dex_<begin>_<size>_fix.dex` saved in `fix` subdirectory after auto-fix

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

### 高版本Android中libart.so去除符号后如何寻找函数正确的偏移
脱壳工具可以自己寻找NterpExecuteImpl函数的偏移，方法是通过字节码匹配实现
```
F0 0B 40 D1 1F 02 40 B9 FF 83 02 D1 E8 27 00 6D EA 2F 01 6D EC 37 02 6D EE 3F 03 6D F3 53 04 A9 F5 5B 05 A9 F7 63 06 A9 F9 6B 07 A9 FB 73 08 A9 FD 7B 09 A9 16 08 40 F9
```

而对于Execute函数，需要在IDA中打开libart.so，搜索字符串"Interpreting"，然后查看哪些函数引用了这个字符串，通常会有两个函数引用它，而其中一个函数的传入参数数量为6，那么这个函数就是我们要找的Execute函数
![alt text](img/image.png)
![alt text](img/image1.png)


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
- Ensure the target app is actively running (tool has `--clean-oat` enabled by default)
- If issue persists, try manual offset values
- Check if you have sufficient permissions to read target process memory

**4. Cannot Find libart.so**
```bash
# Find libart.so location on your device
adb shell find /apex -name "libart.so" 2>/dev/null
adb shell find /system -name "libart.so" 2>/dev/null
```

## References
- [cilium/ebpf](https://github.com/cilium/ebpf) - eBPF library for Go
- [ebpfmanager](https://github.com/gojue/ebpfmanager) - Go + eBPF Manager Library
- [stackplz](https://github.com/SeeFlowerX/stackplz) - StackPlz eBPF Tools
- [eDBG](https://github.com/ShinoLeah/eDBG) - eDBG eBPF Debugger
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