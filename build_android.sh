#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ANDROID_MAIN="${ANDROID_BUILD_TOP:-$HOME/android-main}"

if [ ! -d "$ANDROID_MAIN" ]; then
    echo "Error: Android source tree not found at $ANDROID_MAIN" >&2
    exit 1
fi

TARGET_ARG="${1:-all}"
shift 2>/dev/null || true

stage_jni_libs() {
    local ARCH_TRIPLE="$1"
    local ABI_NAME="$2"
    local REL_DIR="$SCRIPT_DIR/target/$ARCH_TRIPLE/release"
    local JNI_DIR="$SCRIPT_DIR/android/app/src/main/jniLibs/$ABI_NAME"

    mkdir -p "$JNI_DIR"
    cp -f "$REL_DIR/libquic_tcp.so" "$REL_DIR/libquic_to_tcp.so"
    cp -f "$REL_DIR/libquic_tcp.so" "$REL_DIR/libtcp_to_quic.so"
    cp -f "$REL_DIR/libquic_to_tcp.so" "$JNI_DIR/libquic_to_tcp.so"
    cp -f "$REL_DIR/libtcp_to_quic.so" "$JNI_DIR/libtcp_to_quic.so"
}

build_armv7() {
    echo "=== Building quic-tcp for Android merioth (armv7-linux-androideabi) ==="
    local TOOLCHAIN_DIR="$SCRIPT_DIR/.toolchain"

    export PATH="$TOOLCHAIN_DIR/bin:$ANDROID_MAIN/prebuilts/rust-toolchain/linux-x86/1.96.0/bin:$PATH"
    export CC_armv7_linux_androideabi="arm-linux-androideabi-clang"
    export AR_armv7_linux_androideabi="arm-linux-androideabi-ar"
    export CXX_armv7_linux_androideabi="arm-linux-androideabi-clang++"
    export CARGO_TARGET_ARMV7_LINUX_ANDROIDEABI_LINKER="arm-linux-androideabi-clang"
    export CARGO_TARGET_ARMV7_LINUX_ANDROIDEABI_RUSTFLAGS="-C panic=abort"
    export ANDROID_NDK_HOME="$TOOLCHAIN_DIR/ndk"
    export BORING_BSSL_SYSROOT="$TOOLCHAIN_DIR/sysroot"

    cargo build --release --target armv7-linux-androideabi "$@"
    stage_jni_libs "armv7-linux-androideabi" "armeabi-v7a"

    echo "=== armv7-linux-androideabi Binaries & Shared Libraries: ==="
    file "$SCRIPT_DIR/target/armv7-linux-androideabi/release/tcp-to-quic" \
         "$SCRIPT_DIR/target/armv7-linux-androideabi/release/quic-to-tcp" \
         "$SCRIPT_DIR/target/armv7-linux-androideabi/release/rendezvous-server" \
         "$SCRIPT_DIR/target/armv7-linux-androideabi/release/libquic_to_tcp.so" \
         "$SCRIPT_DIR/target/armv7-linux-androideabi/release/libtcp_to_quic.so"
}

build_arm64() {
    echo "=== Building quic-tcp for Android yogi/yoga (aarch64-linux-android) ==="
    local TOOLCHAIN_DIR="$SCRIPT_DIR/.toolchain/aarch64"

    export PATH="$TOOLCHAIN_DIR/bin:$ANDROID_MAIN/prebuilts/rust-toolchain/linux-x86/1.96.0/bin:$PATH"
    export CC_aarch64_linux_android="aarch64-linux-android-clang"
    export AR_aarch64_linux_android="aarch64-linux-android-ar"
    export CXX_aarch64_linux_android="aarch64-linux-android-clang++"
    export CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER="aarch64-linux-android-clang"
    export CARGO_TARGET_AARCH64_LINUX_ANDROID_RUSTFLAGS="-C panic=abort -Z branch-protection=bti"
    export ANDROID_NDK_HOME="$TOOLCHAIN_DIR/ndk"
    export BORING_BSSL_SYSROOT="$TOOLCHAIN_DIR/sysroot"

    cargo build --release --target aarch64-linux-android "$@"
    stage_jni_libs "aarch64-linux-android" "arm64-v8a"

    echo "=== aarch64-linux-android Binaries & Shared Libraries: ==="
    file "$SCRIPT_DIR/target/aarch64-linux-android/release/tcp-to-quic" \
         "$SCRIPT_DIR/target/aarch64-linux-android/release/quic-to-tcp" \
         "$SCRIPT_DIR/target/aarch64-linux-android/release/rendezvous-server" \
         "$SCRIPT_DIR/target/aarch64-linux-android/release/libquic_to_tcp.so" \
         "$SCRIPT_DIR/target/aarch64-linux-android/release/libtcp_to_quic.so"
}

package_single_apk() {
    local VARIANT_NAME="$1"
    local MANIFEST_FILE="$2"
    local OUT_APK="$3"

    local SDK_TOOLS="$ANDROID_MAIN/prebuilts/sdk/tools/linux/bin"
    local ANDROID_JAR="$ANDROID_MAIN/prebuilts/sdk/34/public/android.jar"
    local APP_SRC="$SCRIPT_DIR/android/app/src/main"
    local WORK_DIR="$SCRIPT_DIR/android/build/work_$VARIANT_NAME"

    rm -rf "$WORK_DIR"
    mkdir -p "$WORK_DIR/compiled_res" "$WORK_DIR/gen" "$WORK_DIR/classes" "$WORK_DIR/dex" "$WORK_DIR/apk_root"

    "$SDK_TOOLS/aapt2" compile --dir "$APP_SRC/res" -o "$WORK_DIR/compiled_res/res.zip"
    "$SDK_TOOLS/aapt2" link \
        -I "$ANDROID_JAR" \
        --manifest "$MANIFEST_FILE" \
        --java "$WORK_DIR/gen" \
        -o "$WORK_DIR/unaligned.apk" \
        "$WORK_DIR/compiled_res/res.zip"

    javac --release 11 \
        -cp "$ANDROID_JAR" \
        -d "$WORK_DIR/classes" \
        "$WORK_DIR/gen/com/quictcp/app/R.java" \
        "$APP_SRC/java/com/quictcp/app/QuicToTcpLib.java" \
        "$APP_SRC/java/com/quictcp/app/TcpToQuicLib.java" \
        "$APP_SRC/java/com/quictcp/app/ProxyConfig.java" \
        "$APP_SRC/java/com/quictcp/app/ProxyForegroundService.java" \
        "$APP_SRC/java/com/quictcp/app/MainActivity.java"

    local CLASS_FILES=()
    while IFS= read -r -d '' f; do
        CLASS_FILES+=("$f")
    done < <(find "$WORK_DIR/classes" -name "*.class" -print0)

    java -cp "$ANDROID_MAIN/prebuilts/r8/r8.jar" com.android.tools.r8.D8 \
        --lib "$ANDROID_JAR" \
        --min-api 26 \
        --output "$WORK_DIR/dex" \
        "${CLASS_FILES[@]}"

    cp "$WORK_DIR/dex/classes.dex" "$WORK_DIR/apk_root/classes.dex"
    mkdir -p "$WORK_DIR/apk_root/lib"
    cp -r "$APP_SRC/jniLibs/"* "$WORK_DIR/apk_root/lib/"

    (
        cd "$WORK_DIR/apk_root"
        zip -q "$WORK_DIR/unaligned.apk" classes.dex
        zip -q -0 -r "$WORK_DIR/unaligned.apk" lib
    )

    "$SDK_TOOLS/zipalign" -f -p 4 "$WORK_DIR/unaligned.apk" "$OUT_APK"

    local KEYSTORE="$SCRIPT_DIR/android/build/debug.keystore"
    if [ ! -f "$KEYSTORE" ]; then
        keytool -genkeypair \
            -keystore "$KEYSTORE" \
            -storepass android \
            -keypass android \
            -alias androiddebugkey \
            -keyalg RSA \
            -keysize 2048 \
            -validity 10000 \
            -dname "CN=Android Debug,O=Android,C=US" >/dev/null 2>&1
    fi

    java -jar "$ANDROID_MAIN/prebuilts/sdk/tools/linux/lib/apksigner.jar" sign \
        --ks "$KEYSTORE" \
        --ks-pass pass:android \
        --key-pass pass:android \
        "$OUT_APK"

    echo "[+] Built & signed APK ($VARIANT_NAME): $OUT_APK ($(du -h "$OUT_APK" | cut -f1))"
}

build_apks() {
    echo "=== Building Android Phone & Watch APKs ==="
    mkdir -p "$SCRIPT_DIR/android/build"

    package_single_apk \
        "phone" \
        "$SCRIPT_DIR/android/app/src/main/AndroidManifest.xml" \
        "$SCRIPT_DIR/android/build/quic-tcp-phone.apk"

    package_single_apk \
        "watch" \
        "$SCRIPT_DIR/android/app/src/watch/AndroidManifest.xml" \
        "$SCRIPT_DIR/android/build/quic-tcp-watch.apk"

    cp -f "$SCRIPT_DIR/android/build/quic-tcp-phone.apk" "$SCRIPT_DIR/android/build/quic-tcp-universal.apk"
}

echo "=== Using Android Tree at $ANDROID_MAIN ==="

case "$TARGET_ARG" in
    yogi|yoga|arm64|aarch64)
        build_arm64 "$@"
        ;;
    merioth|arm|armv7)
        build_armv7 "$@"
        ;;
    apk)
        build_apks
        ;;
    all)
        build_armv7 "$@"
        build_arm64 "$@"
        build_apks
        ;;
    *)
        echo "Unknown target: $TARGET_ARG (expected: merioth, yogi, yoga, apk, or all)" >&2
        exit 1
        ;;
esac
