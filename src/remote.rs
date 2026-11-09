//! Synchronous AArch64 remote calls with up to eight integer/pointer arguments.

use crate::{Error, FpRegSet, RegSet, RemoteAddress, Signal, Tracee, WaitStatus};
use nix::sys::ptrace;
use std::fmt::{self, Display, Formatter};
use std::time::Instant;

#[derive(Clone, Copy, Debug)]
pub struct CallOptions {
    pub return_address: RemoteAddress,
    pub deadline: Instant,
}

#[derive(Clone, Copy, Debug)]
pub enum StopAction {
    Resume(Option<Signal>),
    Abort,
}

#[derive(Debug)]
pub enum Recovery {
    Unchanged,
    Restored,
    Failed(RemoteCallRecoveryError),
}

#[derive(Debug, thiserror::Error)]
pub enum RemoteCallRecoveryError {
    NotStopped,
    Registers {
        gpr: Option<Error>,
        fpr: Option<Error>,
    },
}

impl Display for RemoteCallRecoveryError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotStopped => write!(
                f,
                "target is not confirmed stopped; registers were not restored"
            ),
            Self::Registers { gpr, fpr } => {
                write!(f, "failed to restore registers")?;

                if let Some(error) = gpr {
                    write!(f, "; GPR: {error}")?;
                }

                if let Some(error) = fpr {
                    write!(f, "; FPR: {error}")?;
                }

                Ok(())
            }
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum RemoteCallError {
    #[error("remote call: {cause}; {recovery}")]
    Call {
        #[source]
        cause: Error,
        recovery: Recovery,
    },
    #[error("remote call returned, but recovery failed: {cause}")]
    Recovery {
        #[source]
        cause: RemoteCallRecoveryError,
    },
}

impl RemoteCallError {
    pub(crate) fn unchanged(cause: Error) -> Self {
        Self::Call {
            cause,
            recovery: Recovery::Unchanged,
        }
    }
}

impl Display for Recovery {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Recovery::Unchanged => write!(f, "target state unchanged"),
            Recovery::Restored => write!(f, "registers restored, target stopped"),
            Recovery::Failed(error) => {
                write!(f, "recovery failed, target state unknown: {error}")
            }
        }
    }
}

impl Tracee {
    /// Runs a function, consumes its wait events, and restores GPR and FPSIMD state.
    /// Registers are restored only after a confirmed ptrace stop. Without one,
    /// recovery fails without interrupting or writing registers to the target.
    /// With no stop callback, unexpected stops abort the call and trigger recovery.
    ///
    /// # Safety
    /// The target must be in a ptrace stop with exclusive event consumption. The
    /// function, arguments, stack, and target state must permit the requested call.
    /// `return_address` must fault on instruction fetch with SIGSEGV. Calls may
    /// change target memory, locks, resources, and TLS; those effects are not undone.
    /// Live SVE/SME state is unsupported. The stop callback must not panic and must
    /// return promptly. Fault signals abort the call without invoking the callback.
    pub unsafe fn call_remote(
        &mut self,
        function: RemoteAddress,
        args: &[u64],
        options: CallOptions,
        mut on_stop: Option<&mut dyn FnMut(WaitStatus) -> StopAction>,
    ) -> Result<u64, RemoteCallError> {
        let orig = self.read_regs().map_err(RemoteCallError::unchanged)?;
        let entry = prepare_regs(&orig, function, args, options.return_address)
            .map_err(RemoteCallError::unchanged)?;

        unsafe { self.call_remote_with_regs(&orig, &entry, options.deadline, &mut on_stop) }
    }

    /// `orig` must match the current GPRs. `entry` must describe a valid remote call
    /// as required by `call_remote`, with its return marker in LR.
    pub(crate) unsafe fn call_remote_with_regs(
        &mut self,
        orig: &RegSet,
        entry: &RegSet,
        deadline: Instant,
        on_stop: &mut Option<&mut dyn FnMut(WaitStatus) -> StopAction>,
    ) -> Result<u64, RemoteCallError> {
        let function = entry.pc();
        let return_address = entry.lr();
        let fpr_orig = self.read_fp_regs().map_err(RemoteCallError::unchanged)?;

        if Instant::now() >= deadline {
            return Err(RemoteCallError::unchanged(Error::Timeout(format!(
                "remote call tid={}, function={function:#x}",
                self.tid()
            ))));
        }

        let mut stopped = true;
        let result = (|| {
            self.write_regs(entry)?;
            self.resume(None)?;
            stopped = false;

            loop {
                let status = self.wait(deadline)?;

                stopped = is_stop(status);

                match status {
                    WaitStatus::Stopped(_, Signal::SIGSEGV) => {
                        let regs = self.read_regs()?;
                        let info = ptrace::getsiginfo(self.active_target()?).map_err(|source| {
                            Error::System {
                                reason: format!("PTRACE_GETSIGINFO tid={}", self.tid()),
                                source,
                            }
                        })?;
                        // si_addr is the fault-address union member for kernel SIGSEGV.
                        let address = unsafe { info.si_addr() } as RemoteAddress;

                        if regs.pc() == return_address
                            && info.si_code > 0
                            && address == return_address
                        {
                            return Ok(regs.return_value());
                        }

                        return Err(Error::Execution(format!(
                            "remote call tid={} unexpected SIGSEGV: pc={:#x}, fault_address={address:#x}, return_address={:#x}, si_code={}",
                            self.tid(),
                            regs.pc(),
                            return_address,
                            info.si_code
                        )));
                    }
                    WaitStatus::Stopped(
                        _,
                        Signal::SIGBUS | Signal::SIGILL | Signal::SIGFPE | Signal::SIGSYS,
                    )
                    | WaitStatus::Exited(..)
                    | WaitStatus::Signaled(..) => {
                        return Err(Error::Execution(format!(
                            "remote call tid={} stopped with {status:?}",
                            self.tid()
                        )));
                    }
                    _ if !stopped => {
                        return Err(Error::Execution(format!(
                            "remote call tid={} stopped with {status:?}",
                            self.tid()
                        )));
                    }
                    _ => {}
                }

                let action = match on_stop.as_mut() {
                    Some(handler) => handler(status),
                    None => default_stop(status),
                };

                if Instant::now() >= deadline {
                    return Err(Error::Timeout(format!(
                        "remote call tid={}, function={function:#x}",
                        self.tid()
                    )));
                }

                match action {
                    StopAction::Resume(signal) => {
                        self.resume(signal)?;
                        stopped = false;
                    }
                    StopAction::Abort => {
                        return Err(Error::Execution(format!(
                            "remote call tid={} aborted by stop policy at {status:?}",
                            self.tid()
                        )));
                    }
                }
            }
        })();
        let recovery = self.recover_call(stopped, orig, &fpr_orig);

        match (result, recovery) {
            (Ok(value), Ok(())) => Ok(value),
            (Err(cause), Ok(())) => Err(RemoteCallError::Call {
                cause,
                recovery: Recovery::Restored,
            }),
            (Err(cause), Err(error)) => Err(RemoteCallError::Call {
                cause,
                recovery: Recovery::Failed(error),
            }),
            (Ok(_), Err(cause)) => Err(RemoteCallError::Recovery { cause }),
        }
    }

    fn recover_call(
        &mut self,
        stopped: bool,
        orig: &RegSet,
        fpr_orig: &FpRegSet,
    ) -> Result<(), RemoteCallRecoveryError> {
        if !stopped {
            return Err(RemoteCallRecoveryError::NotStopped);
        }

        let res_gpr = self.write_regs(orig);
        let res_fpr = self.write_fp_regs(fpr_orig);

        if res_gpr.is_err() || res_fpr.is_err() {
            return Err(RemoteCallRecoveryError::Registers {
                gpr: res_gpr.err(),
                fpr: res_fpr.err(),
            });
        }

        Ok(())
    }
}

fn default_stop(_status: WaitStatus) -> StopAction {
    StopAction::Abort
}

fn is_stop(status: WaitStatus) -> bool {
    matches!(
        status,
        WaitStatus::Stopped(..) | WaitStatus::PtraceEvent(..) | WaitStatus::PtraceSyscall(..)
    )
}

/// Returns a modified snapshot; the caller controls execution and restores the original.
/// This prepares general-purpose registers only and does not execute the function.
pub fn prepare_regs(
    orig: &RegSet,
    function: RemoteAddress,
    args: &[u64],
    return_address: RemoteAddress,
) -> Result<RegSet, Error> {
    if args.len() > 8
        || function == 0
        || !function.is_multiple_of(4)
        || return_address == 0
        || function == return_address
    {
        return Err(Error::InvalidArgument(format!(
            "remote call function={function:#x}, return_address={return_address:#x}, argument_count={}",
            args.len()
        )));
    }

    let mut regs = orig.clone();

    regs.set_pc(function);
    regs.set_sp(orig.sp() & !0xf);
    regs.set_lr(return_address);

    for (index, &arg) in args.iter().enumerate() {
        regs.set_register(index, arg)?;
    }

    Ok(regs)
}

#[cfg(test)]
mod tests {
    use super::{Recovery, RemoteCallError, RemoteCallRecoveryError};
    use crate::{Error, RegSet};
    use nix::errno::Errno;
    use std::error::Error as StdError;

    #[test]
    fn recovery_errors_display_each_failed_register_set() {
        for (gpr, fpr) in [(true, false), (false, true), (true, true)] {
            let error = RemoteCallRecoveryError::Registers {
                gpr: gpr.then(|| Error::System {
                    reason: "restore GPR".into(),
                    source: Errno::EIO,
                }),
                fpr: fpr.then(|| Error::System {
                    reason: "restore FPR".into(),
                    source: Errno::ESRCH,
                }),
            };
            let error = RemoteCallError::Recovery { cause: error };
            let message = error.to_string();
            assert_eq!(message.contains("GPR: system error: restore GPR"), gpr);
            assert_eq!(message.contains("FPR: system error: restore FPR"), fpr);
            assert!(error.source().unwrap().is::<RemoteCallRecoveryError>());
        }
    }

    #[test]
    fn call_failure_keeps_primary_source_and_recovery_context() {
        let error = RemoteCallError::Call {
            cause: Error::Timeout("remote function".into()),
            recovery: Recovery::Failed(RemoteCallRecoveryError::Registers {
                gpr: Some(Error::System {
                    reason: "restore GPR".into(),
                    source: Errno::EIO,
                }),
                fpr: None,
            }),
        };
        let source = error.source().unwrap().downcast_ref::<Error>().unwrap();
        assert!(matches!(source, Error::Timeout(_)));
        assert!(error.to_string().contains("restore GPR"));
    }

    #[test]
    fn prepares_call_without_modifying_snapshot() {
        let mut orig = RegSet::default();
        orig.set_pc(0x1000);
        orig.set_sp(0x2007);
        orig.set_lr(0x3000);
        let regs = super::prepare_regs(&orig, 0x4000, &[u64::MAX, 42], 0x5000).unwrap();
        assert_eq!((regs.pc(), regs.sp(), regs.lr()), (0x4000, 0x2000, 0x5000));
        assert_eq!(regs.register(0).unwrap(), u64::MAX);
        assert_eq!(regs.register(1).unwrap(), 42);
        assert_eq!((orig.pc(), orig.sp(), orig.lr()), (0x1000, 0x2007, 0x3000));
        assert!(super::prepare_regs(&orig, 0x4000, &[0; 9], 0x5000).is_err());
        assert!(super::prepare_regs(&orig, 3, &[], 0x5000).is_err());
        assert!(super::prepare_regs(&orig, 0x4000, &[], 0x4000).is_err());
        assert!(orig.register(31).is_err());
        assert!(orig.set_register(31, 0).is_err());
    }
}
