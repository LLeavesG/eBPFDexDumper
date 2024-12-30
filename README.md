# eBPF-DexDumper
Android dexDumper based on eBPF
Show: https://blog.lleavesg.top/article/eBPFDexDumper

## Usage

ps: uid means filter uid

```
Usage: ./eBPFDexDumper <uid> <pathToLibart> <offsetExecute(hex)> <offsetExecuteNterpImpl(hex)> <offsetVerifyClass(hex)> <outputPath>
Example ( if Auto get offset ): ./eBPFDexDumper 10244 /apex/com.android.art/lib64/libart.so 0 0 0 /data/local/tmp/dexfile
Example (if get offset failed): ./eBPFDexDumper 10244 /apex/com.android.art/lib64/libart.so 0x473E48 0x473E48 0x3D9F18 /data/local/tmp/dexfile
```
![image](https://github.com/user-attachments/assets/43e9d9ac-c56c-4dd7-9349-8d4fed1b6207)
![image](https://github.com/user-attachments/assets/565d1761-baa2-42cc-99c6-47eae703fee1)


## Complie
fix ndk path and make

```
make
```
