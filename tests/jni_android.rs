#![cfg(feature = "jni")]

use nix::libc::PTRACE_EVENT_STOP;
use ptrace_kit::jni::{JniError, JniNativeInterface};
use ptrace_kit::remote::CallOptions;
use ptrace_kit::{Pid, Signal, Tracee, WaitStatus};
use std::io::{BufRead, BufReader};
use std::mem::offset_of;
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

const FIXTURE_DIR: &str = "/data/local/tmp/ptrace-kit-tests/jni";

struct Fixture(Child);

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn strings_in_real_art_vm() {
    let mut fixture = Fixture(
        Command::new("/system/bin/app_process64")
            .env("CLASSPATH", format!("{FIXTURE_DIR}/classes.dex"))
            .args([
                "-Xcheck:jni",
                FIXTURE_DIR,
                "PtraceKitJniFixture",
                &format!("{FIXTURE_DIR}/libfixture.so"),
            ])
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("build and deploy tests/fixtures/jni first"),
    );
    let mut stdout = BufReader::new(fixture.0.stdout.take().unwrap());
    let mut line = String::new();
    loop {
        line.clear();
        assert_ne!(
            stdout.read_line(&mut line).unwrap(),
            0,
            "ART fixture exited before readiness"
        );
        if line.starts_with("JNI_READY ") {
            break;
        }
    }
    let values: Vec<usize> = line
        .split_whitespace()
        .skip(1)
        .map(|part| part.parse().unwrap())
        .collect();
    let [pid, env, original_string, empty, long, malformed, done] = values[..] else {
        panic!("bad readiness record: {line}");
    };
    assert_eq!(pid, fixture.0.id() as usize);
    let mut tracee = Tracee::seize(Pid::from_raw(pid as i32)).unwrap();
    tracee.interrupt().unwrap();
    assert!(matches!(
        tracee
            .wait(Instant::now() + Duration::from_secs(5))
            .unwrap(),
        WaitStatus::PtraceEvent(_, Signal::SIGTRAP, PTRACE_EVENT_STOP)
    ));
    let orig = tracee.read_regs().unwrap();
    let fpr = tracee.read_fp_regs().unwrap();
    let options = CallOptions {
        return_address: orig.sp(),
        deadline: Instant::now() + Duration::from_secs(20),
    };
    // The native fixture keeps the JNIEnv and input strings live on the seized thread.
    unsafe {
        assert!(
            tracee
                .call_remote_jni(
                    env,
                    offset_of!(JniNativeInterface, GetVersion),
                    &[],
                    options,
                    None
                )
                .unwrap()
                > 0
        );
        assert!(matches!(
            tracee.call_remote_jni(
                env,
                offset_of!(JniNativeInterface, GetVersion),
                &[0; 8],
                options,
                None
            ),
            Err(JniError::Core(_))
        ));
        assert_eq!(
            tracee
                .read_jstring(env, original_string, options, None)
                .unwrap()
                .as_deref(),
            Some("初始\0🙂")
        );
        assert_eq!(
            tracee
                .read_jstring(env, empty, options, None)
                .unwrap()
                .as_deref(),
            Some("")
        );
        assert!(
            tracee
                .read_jstring(env, 0, options, None)
                .unwrap()
                .is_none()
        );
        assert!(matches!(
            tracee.read_jstring(env, malformed, options, None),
            Err(JniError::Utf16(_))
        ));

        // The surrogate pair spans two 4 KiB reads and is decoded after reassembly.
        let expected = format!("{}🙂tail", "x".repeat(2047));
        assert_eq!(
            tracee
                .read_jstring(env, long, options, None)
                .unwrap()
                .as_deref(),
            Some(expected.as_str())
        );
    }
    let restored = tracee.read_regs().unwrap();
    for index in 0..31 {
        assert_eq!(
            restored.register(index).unwrap(),
            orig.register(index).unwrap()
        );
    }
    assert_eq!(
        (restored.pc(), restored.sp(), restored.pstate()),
        (orig.pc(), orig.sp(), orig.pstate())
    );
    assert_eq!(tracee.read_fp_regs().unwrap(), fpr);
    tracee.write_u64(done, 1).unwrap();
    tracee.detach(None).unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(status) = fixture.0.try_wait().unwrap() {
            assert!(status.success(), "ART fixture failed: {status}");
            break;
        }
        assert!(Instant::now() < deadline, "ART fixture did not resume");
        thread::sleep(Duration::from_millis(10));
    }
    line.clear();
    stdout.read_line(&mut line).unwrap();
    assert_eq!(line.trim(), "JNI_FIXTURE_FINISHED");
}
