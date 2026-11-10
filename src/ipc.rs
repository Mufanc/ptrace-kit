//! File descriptor operations across processes.

use crate::maps::{MapPermissions, Maps};
use crate::remote::{self, CallOptions, Recovery, RemoteCallError, StopAction};
use crate::{Error, RemoteAddress, Tracee, WaitStatus};
use nix::errno::Errno;
use nix::libc::{self, AF_UNIX, SOCK_CLOEXEC, SOCK_SEQPACKET, SYS_pidfd_getfd, SYS_pidfd_open};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::rc::Rc;

/// An IPC channel bound to the tracee session that created it.
/// Use [`Tracee::close_channel`] before detaching to release the target endpoint.
pub struct IpcChannel {
    session: Rc<()>,
    local: Option<OwnedFd>,
    remote: RawFd,
    close: RemoteAddress,
}

#[derive(Debug, thiserror::Error)]
pub enum IpcError {
    #[error(transparent)]
    Core(#[from] Error),
    #[error(transparent)]
    Call(#[from] RemoteCallError),
    #[error("channel setup failed: {cause}. Target descriptor cleanup failed: {cleanup}")]
    SetupCleanup {
        #[source]
        cause: Box<IpcError>,
        cleanup: Box<IpcError>,
    },
}

impl Tracee {
    /// Duplicates an open target descriptor into the calling process.
    ///
    /// Both descriptors refer to the same open file description. The caller owns
    /// the local copy, and the target keeps its descriptor open. The traced thread
    /// must be the thread group leader. Kernel permission checks apply.
    pub fn duplicate_fd(&self, remote_fd: RawFd) -> Result<OwnedFd, Error> {
        let tid = self.active_target()?;

        if remote_fd < 0 {
            return Err(Error::InvalidArgument(format!(
                "remote fd {remote_fd} must be nonnegative"
            )));
        }

        let pidfd = Errno::result(unsafe { libc::syscall(SYS_pidfd_open, tid.as_raw(), 0) })
            .map_err(|source| Error::system(format!("pidfd_open tid={tid}"), source))?;
        let pidfd = unsafe { OwnedFd::from_raw_fd(pidfd as RawFd) };
        let fd = Errno::result(unsafe {
            libc::syscall(SYS_pidfd_getfd, pidfd.as_raw_fd(), remote_fd, 0)
        })
        .map_err(|source| {
            Error::system(format!("pidfd_getfd tid={tid}, fd={remote_fd}"), source)
        })?;

        Ok(unsafe { OwnedFd::from_raw_fd(fd as RawFd) })
    }

    /// Creates an IPC channel between the caller and the target.
    /// The traced thread must be the thread group leader.
    /// A setup failure can leave descriptors open in the target.
    ///
    /// # Safety
    /// The safety conditions of [`Self::call_remote`] apply. The target's libc
    /// mappings must remain stable, and its stack must have room for the two
    /// returned descriptors and the called functions' frames.
    pub unsafe fn create_channel(
        &mut self,
        options: CallOptions,
        mut on_stop: Option<&mut dyn FnMut(WaitStatus) -> StopAction>,
    ) -> Result<IpcChannel, IpcError> {
        let maps = Maps::scan(self.active_target()?)?;
        let mut libc = maps.mapped_file("libc.so")?;
        let socketpair_fn = libc.resolve_symbol("socketpair")?;
        let close_fn = libc.resolve_symbol("close")?;

        for address in [socketpair_fn, close_fn] {
            if !maps
                .find(address)
                .is_some_and(|entry| entry.perms.contains(MapPermissions::EXECUTE))
            {
                return Err(Error::IllegalState(format!(
                    "libc.so address {address:#x} is not executable"
                ))
                .into());
            }
        }

        let orig = self.read_regs().map_err(RemoteCallError::unchanged)?;
        let buffer =
            remote::reserve_stack(orig.sp(), size_of::<[RawFd; 2]>(), align_of::<[RawFd; 2]>())?;
        let args = [
            AF_UNIX as u64,
            (SOCK_SEQPACKET | SOCK_CLOEXEC) as u64,
            0,
            buffer as u64,
        ];
        let mut entry = remote::prepare_regs(&orig, socketpair_fn, &args, options.return_address)
            .map_err(RemoteCallError::unchanged)?;

        // Validate the cleanup call before socketpair opens any descriptors.
        remote::prepare_regs(&orig, close_fn, &[], options.return_address)
            .map_err(RemoteCallError::unchanged)?;
        entry.set_sp(buffer);

        let status =
            unsafe { self.call_remote_with_regs(&orig, &entry, options.deadline, &mut on_stop) }?
                as i32;

        if status != 0 {
            return Err(Error::Execution(format!("target socketpair returned {status}")).into());
        }

        let mut pair = [0; size_of::<[RawFd; 2]>()];

        self.read_exact(buffer, &mut pair)?;

        let local_fd = RawFd::from_le_bytes(pair[..size_of::<RawFd>()].try_into().unwrap());
        let remote = RawFd::from_le_bytes(pair[size_of::<RawFd>()..].try_into().unwrap());

        let local = match self.duplicate_fd(local_fd) {
            Ok(local) => local,
            Err(cause) => {
                return Err(unsafe {
                    self.cleanup_channel_setup(
                        cause.into(),
                        &[local_fd, remote],
                        close_fn,
                        options,
                        &mut on_stop,
                    )
                });
            }
        };

        if let Err(cause) =
            unsafe { self.close_remote_fd(close_fn, local_fd, options, &mut on_stop) }
        {
            return Err(unsafe {
                self.cleanup_channel_setup(cause, &[remote], close_fn, options, &mut on_stop)
            });
        }

        Ok(IpcChannel {
            session: Rc::clone(&self.ipc_session),
            local: Some(local),
            remote,
            close: close_fn,
        })
    }

    /// Releases a channel using the tracee session that created it.
    /// The handle remains usable if the call fails before execution begins.
    /// After an attempted remote close, the handle is invalidated to prevent retries.
    ///
    /// # Safety
    /// The safety conditions of [`Self::call_remote`] apply. The target must still
    /// own the channel endpoint, and its libc must still be mapped at the same address.
    pub unsafe fn close_channel(
        &mut self,
        channel: &mut IpcChannel,
        options: CallOptions,
        mut on_stop: Option<&mut dyn FnMut(WaitStatus) -> StopAction>,
    ) -> Result<(), IpcError> {
        if !Rc::ptr_eq(&self.ipc_session, &channel.session) {
            return Err(Error::InvalidArgument(
                "IPC channel belongs to another tracee session".into(),
            )
            .into());
        }

        self.active_target()?;

        if channel.local.is_none() {
            return Err(Error::IllegalState("IPC channel is closed".into()).into());
        }

        let result =
            unsafe { self.close_remote_fd(channel.close, channel.remote, options, &mut on_stop) };

        if !matches!(
            &result,
            Err(IpcError::Call(RemoteCallError::Call {
                recovery: Recovery::Unchanged,
                ..
            }))
        ) {
            drop(channel.local.take());
        }

        result
    }

    unsafe fn close_remote_fd(
        &mut self,
        close: RemoteAddress,
        fd: RawFd,
        options: CallOptions,
        on_stop: &mut Option<&mut dyn FnMut(WaitStatus) -> StopAction>,
    ) -> Result<(), IpcError> {
        let status = unsafe {
            self.call_remote(
                close,
                &[fd as u64],
                options,
                match on_stop.as_mut() {
                    Some(handler) => Some(&mut **handler),
                    None => None,
                },
            )
        }? as i32;

        if status != 0 {
            return Err(Error::Execution(format!("target close fd={fd} returned {status}")).into());
        }

        Ok(())
    }

    unsafe fn cleanup_channel_setup(
        &mut self,
        cause: IpcError,
        fds: &[RawFd],
        close: RemoteAddress,
        options: CallOptions,
        on_stop: &mut Option<&mut dyn FnMut(WaitStatus) -> StopAction>,
    ) -> IpcError {
        if matches!(
            &cause,
            IpcError::Call(
                RemoteCallError::Recovery { .. }
                    | RemoteCallError::Call {
                        recovery: Recovery::Failed(_),
                        ..
                    }
            )
        ) {
            return cause;
        }

        for &fd in fds {
            if let Err(cleanup) = unsafe { self.close_remote_fd(close, fd, options, on_stop) } {
                return IpcError::SetupCleanup {
                    cause: Box::new(cause),
                    cleanup: Box::new(cleanup),
                };
            }
        }

        cause
    }
}
