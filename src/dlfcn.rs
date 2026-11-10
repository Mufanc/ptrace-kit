//! Dynamic library operations in a traced process.
//!
//! Library and symbol names must not contain NUL bytes.

use crate::ipc::RemoteFd;
use crate::maps::{MapPermissions, Maps};
use crate::remote::{self, CallOptions, RemoteCallError, StopAction};
use crate::{Error, RemoteAddress, Tracee, WaitStatus};
use nix::libc::RTLD_NOW;
use std::mem::{self, offset_of};
use std::os::fd::{AsRawFd, RawFd};
use std::rc::Rc;

pub use crate::tracee::timeout::DynamicLoaderWithTimeout;

const ANDROID_DLEXT_USE_LIBRARY_FD: u64 = 0x10;

#[repr(C)]
struct DlextInfo {
    flags: u64,
    reserved_addr: RemoteAddress,
    reserved_size: usize,
    relro_fd: RawFd,
    library_fd: RawFd,
    library_fd_offset: i64,
    library_namespace: RemoteAddress,
}

const _: () = {
    assert!(offset_of!(DlextInfo, library_fd) == 28);
    assert!(size_of::<DlextInfo>() == 48);
};

#[derive(Debug, thiserror::Error)]
pub enum DlfcnError {
    #[error(transparent)]
    Core(#[from] Error),
    #[error(transparent)]
    Call(#[from] RemoteCallError),
}

/// Resolved libdl entry points bound to one tracee session.
/// Recreate the loader after an exec or a change to the target's libdl mappings.
#[derive(Debug)]
pub struct DynamicLoader {
    session: Rc<()>,
    dlopen_ext: RemoteAddress,
    dlsym: RemoteAddress,
    dlclose: RemoteAddress,
}

impl Tracee {
    /// Resolves the target's libdl entry points for repeated use.
    pub fn dynamic_loader(&self) -> Result<DynamicLoader, Error> {
        let maps = Maps::scan(self.active_target()?)?;
        let mut libdl = maps.mapped_file("libdl.so")?;
        let mut resolve = |symbol: &str| {
            let address = libdl.resolve_symbol(symbol)?;

            if !maps
                .find(address)
                .is_some_and(|entry| entry.perms.contains(MapPermissions::EXECUTE))
            {
                return Err(Error::IllegalState(format!(
                    "libdl.so:{symbol} address {address:#x} is not executable"
                )));
            }

            Ok(address)
        };

        Ok(DynamicLoader {
            session: Rc::clone(&self.ipc_session),
            dlopen_ext: resolve("android_dlopen_ext")?,
            dlsym: resolve("dlsym")?,
            dlclose: resolve("dlclose")?,
        })
    }

    unsafe fn call_dlfcn_with_stack<const N: usize>(
        &mut self,
        function: RemoteAddress,
        prefix: &[u8],
        name: &str,
        args: impl FnOnce(RemoteAddress) -> [u64; N],
        options: CallOptions,
        mut on_stop: Option<&mut dyn FnMut(WaitStatus) -> StopAction>,
    ) -> Result<u64, DlfcnError> {
        if name.as_bytes().contains(&0) {
            return Err(
                Error::InvalidArgument("library or symbol name contains NUL".into()).into(),
            );
        }

        let scratch = [prefix, name.as_bytes(), b"\0"].concat();
        let orig = self.read_regs().map_err(RemoteCallError::unchanged)?;
        let stack = remote::reserve_stack(orig.sp(), scratch.len(), align_of::<DlextInfo>())?;
        let mut entry = remote::prepare_regs(&orig, function, &args(stack), options.return_address)
            .map_err(RemoteCallError::unchanged)?;

        entry.set_sp(stack);
        self.write_all(stack, &scratch)?;

        Ok(unsafe { self.call_remote_with_regs(&orig, &entry, options.deadline, &mut on_stop) }?)
    }
}

impl DynamicLoader {
    /// Loads a shared object from an installed fd with `RTLD_NOW` and returns
    /// an opaque loader handle. The caller can close the fd after loading.
    /// The target linker selects its namespace using the return address.
    ///
    /// # Safety
    /// The safety conditions of [`Tracee::call_remote`] apply. The cached libdl
    /// mappings must remain valid, and the fd must still refer to the intended ELF.
    /// The target must have stack space for the loader and its arguments and be
    /// in a state that permits running constructors.
    pub unsafe fn dlopen_fd(
        &self,
        tracee: &mut Tracee,
        fd: &RemoteFd,
        name: &str,
        options: CallOptions,
        on_stop: Option<&mut dyn FnMut(WaitStatus) -> StopAction>,
    ) -> Result<RemoteAddress, DlfcnError> {
        self.verify_session(tracee)?;
        tracee.verify_fd_session(fd)?;

        let info = DlextInfo {
            flags: ANDROID_DLEXT_USE_LIBRARY_FD,
            reserved_addr: 0,
            reserved_size: 0,
            relro_fd: 0,
            library_fd: fd.as_raw_fd(),
            library_fd_offset: 0,
            library_namespace: 0,
        };
        // The AArch64 layout has no padding. All fields are initialized scalars.
        let info: [u8; size_of::<DlextInfo>()] = unsafe { mem::transmute(info) };
        let handle = unsafe {
            tracee.call_dlfcn_with_stack(
                self.dlopen_ext,
                &info,
                name,
                |address| {
                    [
                        (address + info.len()) as u64,
                        RTLD_NOW as u64,
                        address as u64,
                    ]
                },
                options,
                on_stop,
            )
        }? as RemoteAddress;

        if handle == 0 {
            return Err(Error::Execution(format!("android_dlopen_ext failed for {name:?}")).into());
        }

        Ok(handle)
    }

    /// Looks up a nonnull symbol address using a target library handle.
    ///
    /// # Safety
    /// The safety conditions of [`Tracee::call_remote`] apply. The cached libdl
    /// mappings must remain valid, and the handle must identify a loaded library
    /// in the target. The target needs stack space for the name and the lookup.
    pub unsafe fn dlsym(
        &self,
        tracee: &mut Tracee,
        handle: RemoteAddress,
        name: &str,
        options: CallOptions,
        on_stop: Option<&mut dyn FnMut(WaitStatus) -> StopAction>,
    ) -> Result<RemoteAddress, DlfcnError> {
        self.verify_session(tracee)?;

        let address = unsafe {
            tracee.call_dlfcn_with_stack(
                self.dlsym,
                &[],
                name,
                |address| [handle as u64, address as u64],
                options,
                on_stop,
            )
        }? as RemoteAddress;

        if address == 0 {
            return Err(Error::Execution(format!("dlsym failed for {name:?}")).into());
        }

        Ok(address)
    }

    /// Releases one loader reference to a target library.
    ///
    /// # Safety
    /// The safety conditions of [`Tracee::call_remote`] apply. The cached libdl
    /// mappings and target library handle must remain valid. No thread may use
    /// code or data that can be unloaded, and the target must be ready to run
    /// the library's destructors.
    pub unsafe fn dlclose(
        &self,
        tracee: &mut Tracee,
        handle: RemoteAddress,
        options: CallOptions,
        on_stop: Option<&mut dyn FnMut(WaitStatus) -> StopAction>,
    ) -> Result<(), DlfcnError> {
        self.verify_session(tracee)?;

        let status =
            unsafe { tracee.call_remote(self.dlclose, &[handle as u64], options, on_stop) }? as i32;

        if status != 0 {
            return Err(Error::Execution(format!("dlclose returned {status}")).into());
        }

        Ok(())
    }

    fn verify_session(&self, tracee: &Tracee) -> Result<(), Error> {
        if !Rc::ptr_eq(&self.session, &tracee.ipc_session) {
            return Err(Error::InvalidArgument(
                "dynamic loader belongs to another tracee session".into(),
            ));
        }

        Ok(())
    }
}
