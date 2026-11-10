//! File descriptor operations across processes.

mod message;

use self::message::ReceiveBuffer;
use crate::maps::{MapPermissions, Maps};
use crate::remote::{self, CallOptions, Recovery, RemoteCallError, StopAction};
use crate::{Error, RemoteAddress, Tracee, WaitStatus};
use nix::errno::Errno;
use nix::libc::{
    self, AF_UNIX, MSG_CMSG_CLOEXEC, MSG_DONTWAIT, SOCK_CLOEXEC, SOCK_SEQPACKET, SYS_pidfd_getfd,
    SYS_pidfd_open,
};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, IntoRawFd, OwnedFd, RawFd};
use std::rc::Rc;
use std::time::Instant;

/// An IPC channel bound to the tracee session that created it.
/// Use [`Tracee::close_channel`] before detaching to release the target endpoint.
pub struct IpcChannel {
    recvmsg: RemoteAddress,
    poisoned: bool,
    local: Option<OwnedFd>,
    remote: RemoteFd,
}

impl IpcChannel {
    fn local_fd(&self) -> Result<BorrowedFd<'_>, Error> {
        self.local
            .as_ref()
            .map(AsFd::as_fd)
            .ok_or_else(|| Error::IllegalState("IPC channel is closed".into()))
    }
}

/// A descriptor owned by the target process. Close it with [`Tracee::close_fd`].
/// Dropping the handle leaves the descriptor open in the target.
#[derive(Debug)]
pub struct RemoteFd {
    session: Rc<()>,
    fd: RawFd,
    close: RemoteAddress,
}

impl RemoteFd {
    fn new(session: &Rc<()>, fd: RawFd, close: RemoteAddress) -> Self {
        Self {
            session: Rc::clone(session),
            fd,
            close,
        }
    }
}

impl AsRawFd for RemoteFd {
    /// Returns the descriptor number in the target's descriptor table.
    fn as_raw_fd(&self) -> RawFd {
        self.fd
    }
}

impl IntoRawFd for RemoteFd {
    /// Returns the descriptor number and transfers responsibility for closing
    /// it in the target process to the caller.
    fn into_raw_fd(self) -> RawFd {
        self.fd
    }
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

impl IpcError {
    fn can_retry_close(&self) -> bool {
        matches!(
            self,
            Self::Call(RemoteCallError::Call {
                recovery: Recovery::Unchanged,
                ..
            })
        )
    }
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
        let recvmsg_fn = libc.resolve_symbol("recvmsg")?;

        for address in [socketpair_fn, close_fn, recvmsg_fn] {
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
            recvmsg: recvmsg_fn,
            poisoned: false,
            local: Some(local),
            remote: RemoteFd::new(&self.ipc_session, remote, close_fn),
        })
    }

    /// Copies a local descriptor into the target with close-on-exec set.
    /// A failure after sending poisons the channel and can leave a descriptor
    /// open in the target. Close the channel and create a new one to continue.
    ///
    /// # Safety
    /// The safety conditions of [`Self::call_remote`] apply. The target must still
    /// own the channel endpoint, its libc mappings must remain stable, and its
    /// stack must have room for recvmsg and its buffers.
    pub unsafe fn install_fd(
        &mut self,
        channel: &mut IpcChannel,
        fd: BorrowedFd<'_>,
        options: CallOptions,
        mut on_stop: Option<&mut dyn FnMut(WaitStatus) -> StopAction>,
    ) -> Result<RemoteFd, IpcError> {
        self.verify_fd_session(&channel.remote)?;

        let local = channel.local_fd()?;

        if channel.poisoned {
            return Err(Error::IllegalState("IPC channel is poisoned".into()).into());
        }

        let orig = self.read_regs().map_err(RemoteCallError::unchanged)?;
        let buffer = remote::reserve_stack(
            orig.sp(),
            size_of::<ReceiveBuffer>(),
            align_of::<ReceiveBuffer>(),
        )?;
        let remote = channel.remote.as_raw_fd();
        let flags = MSG_CMSG_CLOEXEC | MSG_DONTWAIT;
        let args = [remote as u64, buffer as u64, flags as u64];
        let mut entry = remote::prepare_regs(&orig, channel.recvmsg, &args, options.return_address)
            .map_err(RemoteCallError::unchanged)?;
        let mut message = ReceiveBuffer::encode(buffer);

        entry.set_sp(buffer);

        if Instant::now() >= options.deadline {
            return Err(RemoteCallError::unchanged(Error::Timeout("install fd".into())).into());
        }

        self.write_all(buffer, &message)?;

        let sent = message::send_fd(local, fd)?;

        // An unconfirmed transfer may leave a descriptor queued for the next receive.
        channel.poisoned = true;

        if sent != 1 {
            return Err(Error::Io(format!("sendmsg sent {sent} bytes for one descriptor")).into());
        }

        let received =
            unsafe { self.call_remote_with_regs(&orig, &entry, options.deadline, &mut on_stop) }?
                as isize;

        if received != 1 {
            return Err(Error::Execution(format!("target recvmsg returned {received}")).into());
        }

        self.read_exact(buffer, &mut message)?;

        let fd = ReceiveBuffer::decode_fd(&message)?;

        channel.poisoned = false;

        Ok(RemoteFd::new(&self.ipc_session, fd, channel.remote.close))
    }

    /// Closes a target descriptor owned by this tracee session.
    /// An error returns the handle only if the remote close did not execute.
    ///
    /// # Safety
    /// The safety conditions of [`Self::call_remote`] apply. The target must still
    /// own this descriptor, and its libc must still be mapped at the same address.
    pub unsafe fn close_fd(
        &mut self,
        fd: RemoteFd,
        options: CallOptions,
        mut on_stop: Option<&mut dyn FnMut(WaitStatus) -> StopAction>,
    ) -> Result<(), (Option<RemoteFd>, IpcError)> {
        if let Err(error) = self.verify_fd_session(&fd) {
            return Err((Some(fd), error.into()));
        }

        unsafe { self.close_remote_fd(fd.close, fd.as_raw_fd(), options, &mut on_stop) }
            .map_err(|error| (error.can_retry_close().then_some(fd), error))
    }

    /// Releases a channel using the tracee session that created it.
    /// The local endpoint is released when the target descriptor is invalidated.
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
        self.verify_fd_session(&channel.remote)?;
        channel.local_fd()?;

        let number = channel.remote.as_raw_fd();
        let result =
            unsafe { self.close_remote_fd(channel.remote.close, number, options, &mut on_stop) };

        if !result.as_ref().is_err_and(IpcError::can_retry_close) {
            drop(channel.local.take());
        }

        result
    }

    fn verify_fd_session(&self, fd: &RemoteFd) -> Result<(), Error> {
        if !Rc::ptr_eq(&self.ipc_session, &fd.session) {
            return Err(Error::InvalidArgument(
                "remote descriptor belongs to another tracee session".into(),
            ));
        }

        // Report a detached session before entering the remote-call path.
        self.active_target()?;

        Ok(())
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
