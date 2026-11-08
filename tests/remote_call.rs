use nix::errno::Errno;
use nix::libc::{self, PTRACE_EVENT_STOP};
use nix::sys::signal;
use nix::sys::wait;
use ptrace_kit::remote::{
    CallOptions, Recovery, RemoteCallError, RemoteCallRecoveryError, StopAction,
};
use ptrace_kit::{Error, FpRegSet, Pid, RegSet, RemoteAddress, Signal, Tracee, WaitStatus};
use std::arch::naked_asm;
use std::time::{Duration, Instant};

struct Child(Pid);

impl Drop for Child {
    fn drop(&mut self) {
        let _ = signal::kill(self.0, Signal::SIGKILL);
        while let Err(Errno::EINTR) = wait::waitpid(self.0, None) {}
    }
}

impl Child {
    fn paused() -> Self {
        // The fork child uses only async-signal-safe syscalls and never returns to Rust.
        let pid = unsafe { libc::fork() };
        if pid == 0 {
            loop {
                unsafe {
                    libc::pause();
                }
            }
        }
        assert!(pid > 0);
        Self(Pid::from_raw(pid))
    }

    fn stopped(&self) -> Tracee {
        let mut tracee = Tracee::seize(self.0).unwrap();
        tracee.interrupt().unwrap();
        assert!(matches!(
            tracee
                .wait(Instant::now() + Duration::from_secs(2))
                .unwrap(),
            WaitStatus::PtraceEvent(_, Signal::SIGTRAP, PTRACE_EVENT_STOP)
        ));
        tracee
    }
}

#[unsafe(naked)]
unsafe extern "C" fn sum8() -> u64 {
    naked_asm!(
        "add x0, x0, x1",
        "add x0, x0, x2",
        "add x0, x0, x3",
        "add x0, x0, x4",
        "add x0, x0, x5",
        "add x0, x0, x6",
        "add x0, x0, x7",
        "mov x19, #0x1234",
        "movi v0.16b, #0x5a",
        "mov x9, #0x10",
        "msr fpsr, x9",
        "ret"
    );
}

#[unsafe(naked)]
unsafe extern "C" fn fault() -> u64 {
    naked_asm!(
        "mov x19, #0x5678",
        "movi v0.16b, #0x77",
        "mov x9, #0",
        "ldr x0, [x9]",
        "ret"
    );
}

#[unsafe(naked)]
unsafe extern "C" fn spin() -> u64 {
    naked_asm!("mov x19, #0x5678", "movi v0.16b, #0x77", "2: b 2b");
}

#[unsafe(naked)]
unsafe extern "C" fn signal_self() -> u64 {
    // getpid(), then tgkill(pid, pid, SIGUSR1), then return 77.
    naked_asm!(
        "mov x8, #172",
        "svc #0",
        "mov x1, x0",
        "mov x2, #10",
        "mov x8, #131",
        "svc #0",
        "mov x0, #77",
        "ret"
    );
}

#[unsafe(naked)]
unsafe extern "C" fn exit_self() -> u64 {
    naked_asm!("mov x0, #17", "mov x8, #93", "svc #0", "brk #0");
}

fn call_options(orig: &RegSet, timeout: Duration) -> CallOptions {
    CallOptions {
        return_address: orig.sp(),
        deadline: Instant::now() + timeout,
    }
}

fn assert_restored(tracee: &Tracee, orig: &RegSet, fpr: &FpRegSet) {
    let current = tracee.read_regs().unwrap();
    for index in 0..31 {
        assert_eq!(
            current.register(index).unwrap(),
            orig.register(index).unwrap(),
            "x{index}"
        );
    }
    assert_eq!(current.pc(), orig.pc());
    assert_eq!(current.sp(), orig.sp());
    assert_eq!(current.pstate(), orig.pstate());
    assert_eq!(&tracee.read_fp_regs().unwrap(), fpr);
}

#[test]
fn remote_call_returns_and_restores_registers() {
    let child = Child::paused();
    let mut tracee = child.stopped();
    let orig = tracee.read_regs().unwrap();
    let fpr = tracee.read_fp_regs().unwrap();
    let options = call_options(&orig, Duration::from_secs(2));
    // These functions and eight register arguments are valid in the forked target;
    // the stack is writable and its address is a non-executable return sentinel.
    let result = unsafe {
        tracee.call_remote(
            sum8 as *const () as RemoteAddress,
            &[1, 2, 3, 4, 5, 6, 7, 8],
            options,
            None,
        )
    }
    .unwrap();
    assert_eq!(result, 36);
    assert_restored(&tracee, &orig, &fpr);

    for (function, args, expected) in [
        (
            libc::getpid as *const () as RemoteAddress,
            Vec::new(),
            child.0.as_raw() as u64,
        ),
        (
            libc::strlen as *const () as RemoteAddress,
            vec![c"ptrace-kit".as_ptr() as u64],
            10,
        ),
    ] {
        let value = unsafe {
            tracee.call_remote(
                function,
                &args,
                call_options(&orig, Duration::from_secs(2)),
                None,
            )
        }
        .unwrap();
        assert_eq!(value, expected);
        assert_restored(&tracee, &orig, &fpr);
    }

    let invalid =
        unsafe { tracee.call_remote(sum8 as *const () as RemoteAddress, &[0; 9], options, None) }
            .unwrap_err();
    assert!(matches!(
        invalid,
        RemoteCallError::Call {
            cause: Error::InvalidArgument(_),
            recovery: Recovery::Unchanged
        }
    ));
    assert_restored(&tracee, &orig, &fpr);

    let expired = unsafe {
        tracee.call_remote(
            sum8 as *const () as RemoteAddress,
            &[],
            call_options(&orig, Duration::ZERO),
            None,
        )
    }
    .unwrap_err();
    assert!(matches!(
        expired,
        RemoteCallError::Call {
            cause: Error::Timeout(_),
            recovery: Recovery::Unchanged
        }
    ));
    assert_restored(&tracee, &orig, &fpr);
    tracee.detach(None).unwrap();
}

#[test]
fn remote_call_recovers_from_fault_and_abort() {
    let child = Child::paused();
    let mut tracee = child.stopped();
    let orig = tracee.read_regs().unwrap();
    let fpr = tracee.read_fp_regs().unwrap();
    {
        let function = fault as *const () as RemoteAddress;
        let error = unsafe {
            tracee.call_remote(
                function,
                &[],
                call_options(&orig, Duration::from_millis(50)),
                Some(&mut |_| panic!("faults do not enter stop policy")),
            )
        }
        .unwrap_err();
        let RemoteCallError::Call {
            cause: Error::Execution(reason),
            recovery: Recovery::Restored,
        } = &error
        else {
            panic!("expected an execution error: {error}");
        };
        assert!(reason.contains("unexpected SIGSEGV"));
        assert!(reason.contains("pc=0x"));
        assert!(reason.contains("fault_address=0x0,"));
        assert!(reason.contains(&format!("return_address={:#x}", orig.sp())));
        assert!(reason.contains("si_code="));
        assert_restored(&tracee, &orig, &fpr);

        // A subsequent call verifies that fault recovery leaves the handle usable.
        assert_eq!(
            unsafe {
                tracee.call_remote(
                    sum8 as *const () as RemoteAddress,
                    &[42, 0, 0, 0, 0, 0, 0, 0],
                    call_options(&orig, Duration::from_secs(2)),
                    None,
                )
            }
            .unwrap(),
            42
        );
        assert_restored(&tracee, &orig, &fpr);
    }

    let error = unsafe {
        tracee.call_remote(
            signal_self as *const () as RemoteAddress,
            &[],
            call_options(&orig, Duration::from_secs(2)),
            None,
        )
    }
    .unwrap_err();
    assert!(
        matches!(
            error,
            RemoteCallError::Call {
                cause: Error::Execution(_),
                recovery: Recovery::Restored
            }
        ),
        "{error}"
    );
    assert_restored(&tracee, &orig, &fpr);

    let mut stops = 0;
    let error = unsafe {
        tracee.call_remote(
            signal_self as *const () as RemoteAddress,
            &[],
            call_options(&orig, Duration::from_secs(2)),
            Some(&mut |status| {
                assert!(matches!(status, WaitStatus::Stopped(_, Signal::SIGUSR1)));
                stops += 1;
                StopAction::Abort
            }),
        )
    }
    .unwrap_err();
    assert_eq!(stops, 1);
    assert!(
        matches!(
            error,
            RemoteCallError::Call {
                cause: Error::Execution(_),
                recovery: Recovery::Restored
            }
        ),
        "{error}"
    );
    assert_restored(&tracee, &orig, &fpr);

    let result = unsafe {
        tracee.call_remote(
            signal_self as *const () as RemoteAddress,
            &[],
            call_options(&orig, Duration::from_secs(2)),
            Some(&mut |status| {
                assert!(matches!(status, WaitStatus::Stopped(_, Signal::SIGUSR1)));
                StopAction::Resume(None)
            }),
        )
    }
    .unwrap();
    assert_eq!(result, 77);
    assert_restored(&tracee, &orig, &fpr);
    tracee.detach(None).unwrap();
}

#[test]
fn remote_call_reports_unrecoverable_target_exit() {
    let child = Child::paused();
    let mut tracee = child.stopped();
    let orig = tracee.read_regs().unwrap();
    let error = unsafe {
        tracee.call_remote(
            exit_self as *const () as RemoteAddress,
            &[],
            call_options(&orig, Duration::from_secs(2)),
            None,
        )
    }
    .unwrap_err();
    assert!(
        matches!(
            error,
            RemoteCallError::Call {
                cause: Error::Execution(_),
                recovery: Recovery::Failed(RemoteCallRecoveryError::NotStopped)
            }
        ),
        "{error}"
    );
    // call_remote consumed the exit event and reaped the child.
    std::mem::forget(child);
    assert!(matches!(tracee.read_regs(), Err(Error::IllegalState(_))));
}

#[test]
fn remote_call_leaves_timed_out_target_running() {
    for function in [
        spin as *const () as RemoteAddress,
        libc::pause as *const () as RemoteAddress,
    ] {
        let child = Child::paused();
        let mut tracee = child.stopped();
        let orig = tracee.read_regs().unwrap();
        let started = Instant::now();
        let error = unsafe {
            tracee.call_remote(
                function,
                &[],
                call_options(&orig, Duration::from_millis(50)),
                None,
            )
        }
        .unwrap_err();
        assert!(
            matches!(
                error,
                RemoteCallError::Call {
                    cause: Error::Timeout(_),
                    recovery: Recovery::Failed(RemoteCallRecoveryError::NotStopped)
                }
            ),
            "{error}"
        );
        assert!(started.elapsed() < Duration::from_secs(2));
        // No interrupt or return event is pending; cleanup belongs to the caller.
        assert!(matches!(
            tracee.wait(Instant::now()),
            Err(Error::Timeout(_))
        ));
    }
}
