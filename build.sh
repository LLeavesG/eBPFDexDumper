export ANDROID_NDK_ROOT=/home/lleaves/android-ndk-r25c/

export PATH=/usr/local/go/bin:$ANDROID_NDK_ROOT/toolchains/llvm/prebuilt/linux-x86_64/bin:$PATH
make && adb push eBPFDexDumper /data/local/tmp/
adb shell "su -c 'chmod +x /data/local/tmp/eBPFDexDumper'"