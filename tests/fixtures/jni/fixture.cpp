#include <jni.h>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <sys/prctl.h>
#include <unistd.h>

extern "C" JNIEXPORT void JNICALL
Java_PtraceKitJniFixture_hold(JNIEnv* env, jclass, jstring value, jstring empty,
                              jstring long_value, jstring malformed) {
    if (prctl(PR_SET_DUMPABLE, 1) != 0) {
        std::abort();
    }

    volatile uint64_t done = 0;

    std::printf("JNI_READY %d %zu %zu %zu %zu %zu %zu\n", getpid(),
                reinterpret_cast<uintptr_t>(env), reinterpret_cast<uintptr_t>(value),
                reinterpret_cast<uintptr_t>(empty), reinterpret_cast<uintptr_t>(long_value),
                reinterpret_cast<uintptr_t>(malformed), reinterpret_cast<uintptr_t>(&done));
    std::fflush(stdout);

    while (done == 0) {
        usleep(1000);
    }

    if (env->ExceptionCheck()) {
        env->ExceptionDescribe();
        std::abort();
    }
}
