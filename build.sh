export ANDROID_NDK_ROOT=/home/lleaves/android-ndk-r25c/

export PATH=$ANDROID_NDK_ROOT/toolchains/llvm/prebuilt/linux-x86_64/bin:$PATH
make && adb push eBPFDexDumper /data/local/tmp/