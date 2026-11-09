//! Explicit control of one traced thread. Drop does not resume or detach it.

use crate::constants::{NT_PRFPREG, NT_PRSTATUS, PTRACE_INTERRUPT, PTRACE_SEIZE};
use crate::{Error, FpRegSet, Pid, RegSet, Signal, WaitStatus};
use nix::errno::Errno;
use nix::libc::{self, PTRACE_GETREGSET, PTRACE_SETREGSET, c_int, iovec, user_regs_struct};
use nix::sys::ptrace;
use nix::sys::wait::{self, WaitPidFlag};
use std::marker::PhantomData;
use std::rc::Rc;
use std::thread;
use std::time::{Duration, Instant};

mod timeout;

pub use timeout::TraceeWithTimeout;

#[derive(Debug)]
pub struct Tracee {
    tid: Pid,
    attached: bool,
    // Ptrace operations must stay on the tracer thread that seized the target.
    _thread_pin: PhantomData<Rc<()>>,
}

impl Tracee {
    /// Establishes tracing without sending SIGSTOP or waiting for a stop.
    pub fn seize(tid: Pid) -> Result<Self, Error> {
        if tid.as_raw() <= 0 {
            return Err(Error::InvalidArgument(format!(
                "TID {tid} must be positive"
            )));
        }

        request(tid, PTRACE_SEIZE, 0, 0)?;

        Ok(Self {
            tid,
            attached: true,
            _thread_pin: PhantomData,
        })
    }

    pub fn tid(&self) -> Pid {
        self.tid
    }

    pub(crate) fn active_target(&self) -> Result<Pid, Error> {
        if !self.attached {
            return Err(Error::IllegalState(format!(
                "tracee {} is detached or exited",
                self.tid
            )));
        }

        Ok(self.tid)
    }

    pub fn interrupt(&mut self) -> Result<(), Error> {
        request(self.active_target()?, PTRACE_INTERRUPT, 0, 0)?;
        Ok(())
    }

    /// A timeout leaves the target in its current state; it does not cancel execution.
    pub fn wait(&mut self, deadline: Instant) -> Result<WaitStatus, Error> {
        let tid = self.active_target()?;

        loop {
            match wait::waitpid(tid, Some(WaitPidFlag::__WALL | WaitPidFlag::WNOHANG)) {
                Ok(WaitStatus::StillAlive) | Err(Errno::EINTR) => {}
                Ok(status) => {
                    if matches!(status, WaitStatus::Exited(..) | WaitStatus::Signaled(..)) {
                        self.attached = false;
                    }

                    return Ok(status);
                }
                Err(source) => {
                    return Err(Error::System {
                        reason: format!("waitpid tid={tid}"),
                        source,
                    });
                }
            }

            let remaining = deadline.saturating_duration_since(Instant::now());

            if remaining.is_zero() {
                return Err(Error::Timeout(format!("waiting for tracee {tid}")));
            }

            thread::sleep(remaining.min(Duration::from_millis(1)));
        }
    }

    pub fn resume(&mut self, signal: Option<Signal>) -> Result<(), Error> {
        ptrace::cont(self.active_target()?, signal).map_err(|source| Error::System {
            reason: format!("PTRACE_CONT tid={}, signal={signal:?}", self.tid),
            source,
        })?;

        Ok(())
    }

    /// Requires a ptrace stop. Failure preserves the attached handle for retry.
    pub fn detach(&mut self, signal: Option<Signal>) -> Result<(), Error> {
        ptrace::detach(self.active_target()?, signal).map_err(|source| Error::System {
            reason: format!("PTRACE_DETACH tid={}, signal={signal:?}", self.tid),
            source,
        })?;
        self.attached = false;

        Ok(())
    }

    pub fn read_regs(&self) -> Result<RegSet, Error> {
        let mut regs = RegSet::default();
        let mut iov = iovec {
            iov_base: (&mut regs.0 as *mut user_regs_struct).cast(),
            iov_len: size_of::<user_regs_struct>(),
        };

        self.regset_io(PTRACE_GETREGSET, NT_PRSTATUS, &mut iov)?;

        if iov.iov_len != size_of::<user_regs_struct>() {
            return Err(Error::Io(format!(
                "tracee {} returned {} register bytes, expected {}",
                self.tid,
                iov.iov_len,
                size_of::<user_regs_struct>()
            )));
        }

        Ok(regs)
    }

    pub fn write_regs(&mut self, regs: &RegSet) -> Result<(), Error> {
        let mut iov = iovec {
            iov_base: (&regs.0 as *const user_regs_struct).cast_mut().cast(),
            iov_len: size_of::<user_regs_struct>(),
        };

        self.regset_io(PTRACE_SETREGSET, NT_PRSTATUS, &mut iov)
    }

    pub fn read_fp_regs(&self) -> Result<FpRegSet, Error> {
        let mut regs = FpRegSet::default();
        let mut iov = iovec {
            iov_base: (&mut regs as *mut FpRegSet).cast(),
            iov_len: size_of::<FpRegSet>(),
        };

        self.regset_io(PTRACE_GETREGSET, NT_PRFPREG, &mut iov)?;

        if iov.iov_len != size_of::<FpRegSet>() {
            return Err(Error::Io(format!(
                "tracee {} returned {} floating-point register bytes, expected {}",
                self.tid,
                iov.iov_len,
                size_of::<FpRegSet>()
            )));
        }

        Ok(regs)
    }

    pub fn write_fp_regs(&mut self, regs: &FpRegSet) -> Result<(), Error> {
        let mut iov = iovec {
            iov_base: (regs as *const FpRegSet).cast_mut().cast(),
            iov_len: size_of::<FpRegSet>(),
        };

        self.regset_io(PTRACE_SETREGSET, NT_PRFPREG, &mut iov)
    }

    fn regset_io(&self, operation: c_int, note: usize, iov: &mut iovec) -> Result<(), Error> {
        request(
            self.active_target()?,
            operation,
            note,
            iov as *mut iovec as usize,
        )
    }
}

fn request(tid: Pid, request: c_int, address: usize, data: usize) -> Result<(), Error> {
    let reason = match request {
        PTRACE_SEIZE => "PTRACE_SEIZE",
        PTRACE_INTERRUPT => "PTRACE_INTERRUPT",
        PTRACE_GETREGSET => "PTRACE_GETREGSET",
        PTRACE_SETREGSET => "PTRACE_SETREGSET",
        _ => "ptrace",
    };

    // Pointer arguments refer to live buffers for the duration of the synchronous syscall.
    Errno::result(unsafe { libc::ptrace(request, tid.as_raw(), address, data) }).map_err(
        |source| Error::System {
            reason: format!("{reason} tid={tid}"),
            source,
        },
    )?;

    Ok(())
}
