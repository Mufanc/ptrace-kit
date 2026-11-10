# Remote dynamic loading test

Build two versions of the same shared object with an AArch64 Android NDK
compiler. Set `dlfcn_clang` to the path of the compiler, for example
`aarch64-linux-android35-clang` in the NDK toolchain.

```sh
mkdir -p target/dlfcn-fixture
for version in 1 2; do
    "$dlfcn_clang" -shared -fPIC -Wl,-soname,libptrace_kit_reload.so \
        -DFIXTURE_VERSION="$version" tests/fixtures/dlfcn/fixture.c \
        -o "target/dlfcn-fixture/v$version.so"
done
adb shell mkdir -p /data/local/tmp/ptrace-kit-tests/dlfcn
adb push target/dlfcn-fixture/v1.so target/dlfcn-fixture/v2.so /data/local/tmp/ptrace-kit-tests/dlfcn/
CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER="$dlfcn_clang" cargo test --features dlfcn --test remote_call --no-run
```

Push the reported test executable to the Android target and run it with
`--exact reloads_a_shared_object_from_a_descriptor`.
