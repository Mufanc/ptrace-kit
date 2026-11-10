//! Remote JNI calls and Java string reads.

use crate::remote::{self, CallOptions, RemoteCallError, StopAction};
use crate::{Error, RemoteAddress, Tracee, WaitStatus};
use std::mem::offset_of;
use std::string::FromUtf16Error;

pub use jni_sys::JNINativeInterface__1_6 as JniNativeInterface;

const STACK_BUFFER_SIZE: usize = 4 * 1024;

fn function_slot(table: RemoteAddress, byte_offset: usize) -> Result<RemoteAddress, Error> {
    if table == 0 || !byte_offset.is_multiple_of(size_of::<usize>()) {
        return Err(Error::InvalidArgument(format!(
            "invalid JNI table={table:#x}, byte_offset={byte_offset}"
        )));
    }

    table.checked_add(byte_offset).ok_or_else(|| {
        Error::InvalidArgument(format!(
            "JNI table={table:#x}, byte_offset={byte_offset} overflows"
        ))
    })
}

#[derive(Debug, thiserror::Error)]
pub enum JniError {
    #[error(transparent)]
    Core(#[from] Error),
    #[error(transparent)]
    Call(#[from] RemoteCallError),
    #[error("Java string contains unpaired UTF-16 surrogates: {0}")]
    Utf16(#[from] FromUtf16Error),
}

impl Tracee {
    fn jni_function(&self, env: RemoteAddress, byte_offset: usize) -> Result<RemoteAddress, Error> {
        if env == 0 {
            return Err(Error::InvalidArgument("JNIEnv must be nonnull".into()));
        }

        let table = self.read_u64(env)? as RemoteAddress;
        let function = self.read_u64(function_slot(table, byte_offset)?)? as RemoteAddress;

        if function == 0 {
            return Err(Error::IllegalState(format!(
                "null JNI function env={env:#x}, byte_offset={byte_offset}"
            )));
        }

        Ok(function)
    }

    /// Calls a JNI table entry, prepending JNIEnv to at most seven arguments.
    ///
    /// `byte_offset` is the byte offset of the function field from the start of the
    /// [`JniNativeInterface`] table. For example, use `offset_of!(JniNativeInterface, GetVersion)`
    /// to call `GetVersion`.
    ///
    /// # Safety
    /// The safety conditions of [`Self::call_remote`] apply. `env` must be a valid
    /// JNIEnv for the traced thread in native state, outside a JNI critical region.
    /// The offset and arguments must match a non-variadic JNI function with integer
    /// or pointer arguments and an integer, pointer, or void return type. The
    /// function must be permitted in the thread's current exception state, and
    /// object references must be valid.
    pub unsafe fn call_remote_jni(
        &mut self,
        env: RemoteAddress,
        byte_offset: usize,
        args: &[u64],
        options: CallOptions,
        on_stop: Option<&mut dyn FnMut(WaitStatus) -> StopAction>,
    ) -> Result<u64, JniError> {
        if args.len() > 7 {
            return Err(Error::InvalidArgument(format!(
                "JNI call accepts at most 7 arguments, got {}",
                args.len()
            ))
            .into());
        }

        let function = self.jni_function(env, byte_offset)?;
        let mut full_args = [0; 8];

        full_args[0] = env as u64;
        full_args[1..args.len() + 1].copy_from_slice(args);

        // The caller supplies the JNI signature, references, and target execution preconditions.
        Ok(unsafe { self.call_remote(function, &full_args[..args.len() + 1], options, on_stop) }?)
    }

    /// Reads a Java string through a 4 KiB buffer on the target stack.
    /// Null maps to `None`. Unpaired UTF-16 surrogates return an error.
    ///
    /// # Safety
    /// The safety conditions of [`Self::call_remote_jni`] apply to the calls made here.
    /// A nonnull reference must be a valid jstring. The target must have no pending exception.
    /// The target must have room below its current SP for the buffer and the JNI call's frames.
    pub unsafe fn read_jstring(
        &mut self,
        env: RemoteAddress,
        reference: RemoteAddress,
        options: CallOptions,
        mut on_stop: Option<&mut dyn FnMut(WaitStatus) -> StopAction>,
    ) -> Result<Option<String>, JniError> {
        if reference == 0 {
            return Ok(None);
        }

        let length = unsafe {
            self.call_remote_jni(
                env,
                offset_of!(JniNativeInterface, GetStringLength),
                &[reference as u64],
                options,
                match on_stop.as_mut() {
                    Some(handler) => Some(&mut **handler),
                    None => None,
                },
            )
        }? as i32;

        let length = usize::try_from(length)
            .map_err(|_| Error::Execution(format!("GetStringLength returned {length}")))?;

        if length == 0 {
            return Ok(Some(String::new()));
        }

        let orig = self.read_regs()?;
        let buffer_address =
            remote::reserve_stack(orig.sp(), STACK_BUFFER_SIZE, align_of::<u16>())?;
        let mut buffer = vec![0; length * size_of::<u16>()];

        for (index, chunk) in buffer.chunks_mut(STACK_BUFFER_SIZE).enumerate() {
            let start = index * (STACK_BUFFER_SIZE / size_of::<u16>());
            let count = chunk.len() / size_of::<u16>();
            let function =
                self.jni_function(env, offset_of!(JniNativeInterface, GetStringRegion))?;
            let args = [
                env as u64,
                reference as u64,
                start as u64,
                count as u64,
                buffer_address as u64,
            ];
            let mut entry = remote::prepare_regs(&orig, function, &args, options.return_address)
                .map_err(RemoteCallError::unchanged)?;

            entry.set_sp(buffer_address);

            unsafe { self.call_remote_with_regs(&orig, &entry, options.deadline, &mut on_stop) }?;

            // Success restores orig for the next chunk. Copy before the stack is reused.
            self.read_exact(buffer_address, chunk)?;
        }

        let units: Vec<u16> = buffer
            .chunks_exact(2)
            .map(|bytes| u16::from_le_bytes([bytes[0], bytes[1]]))
            .collect();

        Ok(Some(String::from_utf16(&units)?))
    }
}

#[cfg(test)]
mod tests {
    use crate::RemoteAddress;

    #[test]
    fn validates_table_offsets() {
        assert_eq!(super::function_slot(0x1000, 8).unwrap(), 0x1008);
        assert!(super::function_slot(0, 8).is_err());
        assert!(super::function_slot(0x1000, 1).is_err());
        assert!(super::function_slot(RemoteAddress::MAX - 7, 8).is_err());
    }
}
