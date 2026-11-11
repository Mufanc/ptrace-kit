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

#[cfg(feature = "ipc")]
#[test]
fn channel_belongs_to_the_session_that_created_it() {
    use ptrace_kit::ipc::IpcError;
    use std::os::fd::IntoRawFd;

    let child = Child::paused();
    let other_child = Child::paused();
    let mut tracee = child.stopped().with_timeout(Duration::from_secs(2));
    let mut other = other_child.stopped();
    let options = call_options(&tracee.read_regs().unwrap(), Duration::from_secs(2));
    let fd_count = || {
        std::fs::read_dir(format!("/proc/{}/fd", child.0))
            .unwrap()
            .count()
    };
    let before = fd_count();
    let channel = unsafe { tracee.create_channel(options.return_address, None) }.unwrap();
    assert_eq!(fd_count(), before + 1);
    let (channel, error) = unsafe { other.close_channel(channel, options, None) }.unwrap_err();
    assert!(matches!(error, IpcError::Core(Error::InvalidArgument(_))));
    let channel = channel.unwrap();
    assert_eq!(fd_count(), before + 1);

    let expired = CallOptions {
        deadline: Instant::now(),
        ..options
    };
    let (channel, error) =
        unsafe { Tracee::close_channel(&mut tracee, channel, expired, None) }.unwrap_err();
    assert!(matches!(
        error,
        IpcError::Call(RemoteCallError::Call {
            recovery: Recovery::Unchanged,
            ..
        })
    ));
    let channel = channel.unwrap();
    assert_eq!(fd_count(), before + 1);
    unsafe { tracee.close_channel(channel, options.return_address, None) }.unwrap();
    assert_eq!(fd_count(), before);

    let channel = unsafe { tracee.create_channel(options.return_address, None) }.unwrap();
    tracee.detach(None).unwrap();
    let mut reattached = child.stopped();
    let (channel, error) = unsafe { reattached.close_channel(channel, options, None) }.unwrap_err();
    assert!(matches!(error, IpcError::Core(Error::InvalidArgument(_))));
    let (local, remote) = channel.unwrap().into_parts().unwrap();
    // Ownership was handed off from the original session for manual cleanup.
    assert_eq!(
        unsafe {
            reattached.call_remote(
                libc::close as *const () as RemoteAddress,
                &[remote.into_raw_fd() as u64],
                options,
                None,
            )
        }
        .unwrap(),
        0
    );
    drop(local);
    assert_eq!(fd_count(), before);
    reattached.detach(None).unwrap();
    other.detach(None).unwrap();
}

#[cfg(feature = "ipc")]
#[test]
fn hands_off_channel_endpoints() {
    use nix::sys::socket::{self, MsgFlags};
    use std::os::fd::{AsRawFd, IntoRawFd};

    let child = Child::paused();
    let mut tracee = child.stopped().with_timeout(Duration::from_secs(2));
    let return_address = tracee.read_regs().unwrap().sp();
    let channel = unsafe { tracee.create_channel(return_address, None) }.unwrap();
    let (local, remote) = channel.into_parts().unwrap();
    let receiver = tracee.duplicate_fd(remote.as_raw_fd()).unwrap();

    // The test owns the child, whose exit releases the handed-off remote endpoint.
    let remote_number = remote.into_raw_fd();
    assert!(remote_number >= 0);
    tracee.detach(None).unwrap();
    assert_eq!(
        socket::send(
            local.as_raw_fd(),
            b"payload",
            MsgFlags::MSG_DONTWAIT | MsgFlags::MSG_NOSIGNAL
        )
        .unwrap(),
        7
    );
    let mut payload = [0; 7];
    assert_eq!(
        socket::recv(receiver.as_raw_fd(), &mut payload, MsgFlags::MSG_DONTWAIT).unwrap(),
        payload.len()
    );
    assert_eq!(&payload, b"payload");
}

#[cfg(feature = "ipc")]
#[test]
fn installs_descriptors_and_rejects_a_poisoned_channel() {
    use nix::libc::{F_GETFD, FD_CLOEXEC, RTLD_DEFAULT};
    use ptrace_kit::ipc::IpcError;
    use std::fs::File;
    use std::os::fd::{AsFd, AsRawFd};
    use std::sync::atomic::AtomicU8;

    static READ_BUFFER: AtomicU8 = AtomicU8::new(0xff);

    let child = Child::paused();
    let mut tracee = child.stopped().with_timeout(Duration::from_secs(2));
    let return_address = tracee.read_regs().unwrap().sp();
    let fd_count = || {
        std::fs::read_dir(format!("/proc/{}/fd", child.0))
            .unwrap()
            .count()
    };
    let before = fd_count();
    let local = File::open("/dev/zero").unwrap();
    let mut channel = unsafe { tracee.create_channel(return_address, None) }.unwrap();

    // The forked child inherits the same libc mappings.
    let read = unsafe { libc::dlsym(RTLD_DEFAULT, c"read".as_ptr()) } as RemoteAddress;
    let fcntl = unsafe { libc::dlsym(RTLD_DEFAULT, c"fcntl".as_ptr()) } as RemoteAddress;
    let recvmsg = unsafe { libc::dlsym(RTLD_DEFAULT, c"recvmsg".as_ptr()) } as RemoteAddress;
    let close = unsafe { libc::dlsym(RTLD_DEFAULT, c"close".as_ptr()) } as RemoteAddress;
    assert!(read != 0 && fcntl != 0 && recvmsg != 0 && close != 0);

    for _ in 0..2 {
        let remote_fd =
            unsafe { tracee.install_fd(&mut channel, local.as_fd(), return_address, None) }
                .unwrap();
        let number = remote_fd.as_raw_fd() as u64;
        let address = READ_BUFFER.as_ptr() as RemoteAddress;
        tracee.write_all(address, &[0xff]).unwrap();
        let count =
            unsafe { tracee.call_remote(read, &[number, address as u64, 1], return_address, None) }
                .unwrap();
        let mut byte = [0xff];
        tracee.read_exact(address, &mut byte).unwrap();
        assert_eq!((count, byte), (1, [0]));
        let flags =
            unsafe { tracee.call_remote(fcntl, &[number, F_GETFD as u64], return_address, None) }
                .unwrap();
        assert_eq!(flags as i32, FD_CLOEXEC);
        assert_eq!(fd_count(), before + 2);

        let expired = CallOptions {
            return_address,
            deadline: Instant::now(),
        };
        let (returned_fd, error) =
            unsafe { Tracee::close_fd(&mut tracee, remote_fd, expired, None) }.unwrap_err();
        assert!(matches!(
            error,
            IpcError::Call(RemoteCallError::Call {
                cause: Error::Timeout(_),
                recovery: Recovery::Unchanged,
            })
        ));
        let remote_fd = returned_fd.unwrap();
        assert_eq!(remote_fd.as_raw_fd() as u64, number);
        assert_eq!(fd_count(), before + 2);
        unsafe { tracee.close_fd(remote_fd, return_address, None) }.unwrap();
        assert_eq!(fd_count(), before + 1);
    }

    let remote_fd =
        unsafe { tracee.install_fd(&mut channel, local.as_fd(), return_address, None) }.unwrap();
    let number = remote_fd.as_raw_fd() as u64;
    let original = tracee.read_u64(close).unwrap();
    // Return -1 from close and keep the descriptor open for test cleanup.
    tracee.write_u64(close, 0xd65f_03c0_9280_0000).unwrap();
    let failed = unsafe { tracee.close_fd(remote_fd, return_address, None) };
    tracee.write_u64(close, original).unwrap();
    assert!(matches!(
        failed,
        Err((None, IpcError::Core(Error::Execution(_))))
    ));
    assert_eq!(
        unsafe { tracee.call_remote(close, &[number], return_address, None) }.unwrap(),
        0
    );
    assert_eq!(fd_count(), before + 1);

    let original = tracee.read_u64(recvmsg).unwrap();
    // Make recvmsg return -1 without reading the packet in the child.
    tracee.write_u64(recvmsg, 0xd65f_03c0_9280_0000).unwrap();
    let failed = unsafe { tracee.install_fd(&mut channel, local.as_fd(), return_address, None) };
    tracee.write_u64(recvmsg, original).unwrap();
    assert!(matches!(failed, Err(IpcError::Core(Error::Execution(_)))));
    assert!(matches!(
        unsafe { tracee.install_fd(&mut channel, local.as_fd(), return_address, None) },
        Err(IpcError::Core(Error::IllegalState(_)))
    ));
    let (channel, error) = channel.into_parts().unwrap_err();
    assert!(matches!(error, Error::IllegalState(_)));
    unsafe { tracee.close_channel(channel, return_address, None) }.unwrap();
    assert_eq!(fd_count(), before);
    tracee.detach(None).unwrap();
}

#[cfg(feature = "dlfcn")]
#[test]
fn reloads_a_shared_object_from_a_descriptor() {
    use ptrace_kit::dlfcn::DlfcnError;
    use std::fs::File;
    use std::io::{BufRead, BufReader};
    use std::os::fd::AsFd;
    use std::process::{Command, Stdio};

    const FIXTURE_DIR: &str = "/data/local/tmp/ptrace-kit-tests/dlfcn";

    let mut process = Command::new("/system/bin/sh")
        .args(["-c", "echo ready; read line"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let child = Child(Pid::from_raw(process.id() as i32));
    let mut ready = String::new();
    BufReader::new(process.stdout.take().unwrap())
        .read_line(&mut ready)
        .unwrap();
    assert_eq!(ready.trim(), "ready");

    let mut tracee = child.stopped().with_timeout(Duration::from_secs(2));
    let return_address = tracee.read_regs().unwrap().sp();
    let loader = tracee.dynamic_loader().unwrap();
    let mut channel = unsafe { tracee.create_channel(return_address, None) }.unwrap();

    for version in [1, 2] {
        let file = File::open(format!("{FIXTURE_DIR}/v{version}.so"))
            .expect("build and deploy tests/fixtures/dlfcn first");
        let fd =
            unsafe { tracee.install_fd(&mut channel, file.as_fd(), return_address, None) }.unwrap();
        let handle = unsafe {
            loader.dlopen_fd(
                &mut tracee,
                &fd,
                "libptrace_kit_reload.so",
                return_address,
                None,
            )
        }
        .unwrap();
        unsafe { tracee.close_fd(fd, return_address, None) }.unwrap();
        assert!(matches!(
            unsafe { loader.dlsym(&mut tracee, handle, "missing_symbol", return_address, None) },
            Err(DlfcnError::Core(Error::Execution(_)))
        ));
        assert!(matches!(
            unsafe {
                loader.dlsym(
                    &mut tracee,
                    handle,
                    "fixture_version\0ignored",
                    return_address,
                    None,
                )
            },
            Err(DlfcnError::Core(Error::InvalidArgument(_)))
        ));
        let symbol =
            unsafe { loader.dlsym(&mut tracee, handle, "fixture_version", return_address, None) }
                .unwrap();
        assert_eq!(
            unsafe { tracee.call_remote(symbol, &[], return_address, None) }.unwrap(),
            version
        );
        unsafe { loader.dlclose(&mut tracee, handle, return_address, None) }.unwrap();
    }

    unsafe { tracee.close_channel(channel, return_address, None) }.unwrap();
    tracee.detach(None).unwrap();
}

#[test]
fn remote_call_returns_and_restores_registers() {
    let child = Child::paused();
    let mut tracee = child.stopped().with_timeout(Duration::from_secs(2));
    let orig = tracee.read_regs().unwrap();
    let fpr = tracee.read_fp_regs().unwrap();
    let return_address = orig.sp();
    // These functions and eight register arguments are valid in the forked target;
    // the stack is writable and its address is a non-executable return sentinel.
    let result = unsafe {
        tracee.call_remote(
            sum8 as *const () as RemoteAddress,
            &[1, 2, 3, 4, 5, 6, 7, 8],
            return_address,
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
        let value = unsafe { tracee.call_remote(function, &args, return_address, None) }.unwrap();
        assert_eq!(value, expected);
        assert_restored(&tracee, &orig, &fpr);
    }

    let invalid = unsafe {
        tracee.call_remote(
            sum8 as *const () as RemoteAddress,
            &[0; 9],
            return_address,
            None,
        )
    }
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
        Tracee::call_remote(
            &mut tracee,
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
