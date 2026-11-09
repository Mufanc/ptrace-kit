# ART JNI integration test

Requires an AArch64 Android device or emulator, ADB, and an existing JDK, Android
SDK build-tools, and NDK. The test starts its own `app_process64` child with CheckJNI;
it does not install an APK or change device configuration.

The Java fixture passes strings to a native method that publishes their references,
the JNIEnv address, and a completion flag address. It keeps the references live
until the test sets the flag.

The test exercises UTF-16 reads across the 4 KiB stack buffer boundary and
checks register restoration before letting the native method return to Java.
A failed assertion kills and reaps the fixture.

## Build and run

Set `JAVA_HOME`, `ANDROID_HOME`, and `ANDROID_NDK_HOME` for existing installations.
Adjust the build-tools version and NDK host directory for your machine.

```sh
mkdir -p target/jni-fixture
"$JAVA_HOME/bin/javac" --release 8 -d target/jni-fixture tests/fixtures/jni/PtraceKitJniFixture.java
"$ANDROID_HOME/build-tools/36.0.0/d8" --output target/jni-fixture target/jni-fixture/PtraceKitJniFixture.class
jni_clang="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/darwin-x86_64/bin/aarch64-linux-android35-clang"
"${jni_clang}++" -shared -fPIC -nostdlib++ -Wall -Wextra -Werror -o target/jni-fixture/libfixture.so tests/fixtures/jni/fixture.cpp
CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER="$jni_clang" cargo test --all-features --no-run
adb shell mkdir -p /data/local/tmp/ptrace-kit-tests/jni
adb push target/jni-fixture/classes.dex target/jni-fixture/libfixture.so /data/local/tmp/ptrace-kit-tests/jni/
```

Push the executable reported by Cargo for `tests/jni_android.rs` to
`/data/local/tmp/ptrace-kit-tests/jni-tests`, then run:

```sh
adb shell 'chmod 700 /data/local/tmp/ptrace-kit-tests/jni-tests && timeout 45s /data/local/tmp/ptrace-kit-tests/jni-tests --nocapture'
```
