# eBPF-DexDumper
Android in-memory DEX dumper powered by eBPF.

- Undetectable
- Passive dump

Showcase: https://blog.lleavesg.top/article/eBPFDexDumper

## Supported Environment
- Tested on Android 13 (Pixel 6)
- Built for `arm64`

Note: on other Android versions you may need minor adjustments and rebuild.

Before dumping, it’s recommended to remove the app’s oat optimization output to avoid `cdex` or empty results. You can do this manually, or let the tool remove it automatically with `--clean-oat`:
- Find base path: `pm path <package>`
- Remove oat folder: delete the app’s `oat/` directory under `/data/app/.../<package>/`

Root permission is typically required to attach uprobes and read target memory.

## Usage

Top-level:
```
eBPFDexDumper [command] [options]
```

Commands:
- `dump`: Start eBPF-based DEX dumper
- `fix`: Fix dumped DEX files in a directory

### dump
Attach uprobes to libart and stream DEX/method events. You must provide either `--uid` or `--name` to filter the target app.

Options:
- `--uid, -u <uid>`: Filter by UID (alternative to `--name`).
- `--name, -n <package>`: Android package name to derive UID (alternative to `--uid`).
- `--libart, -l <path>`: Path to `libart.so` on device. Default: `/apex/com.android.art/lib64/libart.so`.
- `--out, -o, --output <dir>`: Output directory on device (required).
- `--trace, -t`: Realtime print of executed methods during dumping (optional; off by default).
- `--clean-oat, -c`: Remove `/data/app/.../oat` of the target app(s) before dumping (optional; off by default).

Examples:
```
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
```

Outputs:
- DEX files: `dex_<begin>_<size>.dex` saved under the output directory.
- Method bytecode JSON: `dex_<begin>_<size>_code.json` saved on shutdown (SIGINT/SIGTERM) or normal exit.

### fix
Scan a directory for dumped DEX files and fix headers/structures for readability.

Options:
- `--dir, -d <dir>`: Directory containing dumped DEX files (required).

Example:
```
./eBPFDexDumper fix -d /data/local/tmp/out
```

## Build
Adjust NDK path if necessary, then:
```
make
```

## References
https://github.com/cilium/ebpf

https://github.com/null-luo/btrace

https://blog.seeflower.dev/archives/84/#title-7

https://evilpan.com/2021/12/26/art-internal/

https://zhuanlan.zhihu.com/p/523692715

https://blog.csdn.net/weixin_47668107/article/details/114251185

https://juejin.cn/post/7045575502991458340

https://juejin.cn/post/7384992816906747913

https://blog.quarkslab.com/dji-the-art-of-obfuscation.html
