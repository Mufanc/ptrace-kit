#[cfg(feature = "ipc")]
use crate::ipc::{IpcChannel, IpcError, RemoteFd};
#[cfg(feature = "jni")]
use crate::jni::JniError;
use crate::remote::{CallOptions, RemoteCallError, StopAction};
use crate::{Error, RemoteAddress, Tracee, WaitStatus};
use std::ops::{Deref, DerefMut};
#[cfg(feature = "ipc")]
use std::os::fd::BorrowedFd;
use std::time::{Duration, Instant};

/// Owns a [`Tracee`] and applies a caller-configured timeout per operation.
///
/// Use [`Tracee::wait`] or the corresponding `Tracee` call method with an explicit
/// deadline to share a budget across operations.
#[derive(Debug)]
pub struct TraceeWithTimeout {
    tracee: Tracee,
    timeout: Duration,
}

impl Tracee {
    /// Wraps this tracee with a default timeout for waits and remote calls.
    pub fn with_timeout(self, timeout: Duration) -> TraceeWithTimeout {
        TraceeWithTimeout {
            tracee: self,
            timeout,
        }
    }
}

impl TraceeWithTimeout {
    fn deadline(&self) -> Result<Instant, Error> {
        Instant::now().checked_add(self.timeout).ok_or_else(|| {
            Error::InvalidArgument(format!(
                "timeout {:?} exceeds the Instant range",
                self.timeout
            ))
        })
    }

    fn call_options(&self, return_address: RemoteAddress) -> Result<CallOptions, Error> {
        Ok(CallOptions {
            return_address,
            deadline: self.deadline()?,
        })
    }

    /// Waits for a trace event using the configured timeout.
    pub fn wait(&mut self) -> Result<WaitStatus, Error> {
        let deadline = self.deadline()?;

        self.tracee.wait(deadline)
    }

    /// Executes a remote function using the configured timeout.
    ///
    /// # Safety
    /// The safety conditions of [`Tracee::call_remote`] apply.
    pub unsafe fn call_remote(
        &mut self,
        function: RemoteAddress,
        args: &[u64],
        return_address: RemoteAddress,
        on_stop: Option<&mut dyn FnMut(WaitStatus) -> StopAction>,
    ) -> Result<u64, RemoteCallError> {
        let options = self
            .call_options(return_address)
            .map_err(RemoteCallError::unchanged)?;

        unsafe { self.tracee.call_remote(function, args, options, on_stop) }
    }

    /// Creates an IPC channel with one timeout budget for the entire setup.
    ///
    /// # Safety
    /// The safety conditions of [`Tracee::create_channel`] apply.
    #[cfg(feature = "ipc")]
    pub unsafe fn create_channel(
        &mut self,
        return_address: RemoteAddress,
        on_stop: Option<&mut dyn FnMut(WaitStatus) -> StopAction>,
    ) -> Result<IpcChannel, IpcError> {
        let options = self.call_options(return_address)?;

        unsafe { self.tracee.create_channel(options, on_stop) }
    }

    /// Closes an IPC channel using the configured timeout.
    ///
    /// # Safety
    /// The safety conditions of [`Tracee::close_channel`] apply.
    #[cfg(feature = "ipc")]
    pub unsafe fn close_channel(
        &mut self,
        channel: &mut IpcChannel,
        return_address: RemoteAddress,
        on_stop: Option<&mut dyn FnMut(WaitStatus) -> StopAction>,
    ) -> Result<(), IpcError> {
        let options = self.call_options(return_address)?;

        unsafe { self.tracee.close_channel(channel, options, on_stop) }
    }

    /// Installs a descriptor using the configured timeout.
    ///
    /// # Safety
    /// The safety conditions of [`Tracee::install_fd`] apply.
    #[cfg(feature = "ipc")]
    pub unsafe fn install_fd(
        &mut self,
        channel: &mut IpcChannel,
        fd: BorrowedFd<'_>,
        return_address: RemoteAddress,
        on_stop: Option<&mut dyn FnMut(WaitStatus) -> StopAction>,
    ) -> Result<RemoteFd, IpcError> {
        let options = self.call_options(return_address)?;

        unsafe { self.tracee.install_fd(channel, fd, options, on_stop) }
    }

    /// Closes a target descriptor using the configured timeout.
    /// An error returns the handle only if the remote close did not execute.
    ///
    /// # Safety
    /// The safety conditions of [`Tracee::close_fd`] apply.
    #[cfg(feature = "ipc")]
    pub unsafe fn close_fd(
        &mut self,
        fd: RemoteFd,
        return_address: RemoteAddress,
        on_stop: Option<&mut dyn FnMut(WaitStatus) -> StopAction>,
    ) -> Result<(), (Option<RemoteFd>, IpcError)> {
        let options = match self.call_options(return_address) {
            Ok(options) => options,
            Err(error) => return Err((Some(fd), error.into())),
        };

        unsafe { self.tracee.close_fd(fd, options, on_stop) }
    }

    /// Executes a remote JNI function using the configured timeout.
    ///
    /// # Safety
    /// The safety conditions of [`Tracee::call_remote_jni`] apply.
    #[cfg(feature = "jni")]
    pub unsafe fn call_remote_jni(
        &mut self,
        env: RemoteAddress,
        byte_offset: usize,
        args: &[u64],
        return_address: RemoteAddress,
        on_stop: Option<&mut dyn FnMut(WaitStatus) -> StopAction>,
    ) -> Result<u64, JniError> {
        let options = self.call_options(return_address)?;

        unsafe {
            self.tracee
                .call_remote_jni(env, byte_offset, args, options, on_stop)
        }
    }

    /// Reads a Java string with one timeout budget for the entire read.
    ///
    /// # Safety
    /// The safety conditions of [`Tracee::read_jstring`] apply.
    #[cfg(feature = "jni")]
    pub unsafe fn read_jstring(
        &mut self,
        env: RemoteAddress,
        reference: RemoteAddress,
        return_address: RemoteAddress,
        on_stop: Option<&mut dyn FnMut(WaitStatus) -> StopAction>,
    ) -> Result<Option<String>, JniError> {
        let options = self.call_options(return_address)?;

        unsafe { self.tracee.read_jstring(env, reference, options, on_stop) }
    }
}

impl Deref for TraceeWithTimeout {
    type Target = Tracee;

    fn deref(&self) -> &Self::Target {
        &self.tracee
    }
}

impl DerefMut for TraceeWithTimeout {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.tracee
    }
}
