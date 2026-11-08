//! UAPI constants missing from the Android libc bindings.

use nix::libc::c_int;

pub(crate) const PTRACE_SEIZE: c_int = 0x4206;
pub(crate) const PTRACE_INTERRUPT: c_int = 0x4207;
pub(crate) const NT_PRSTATUS: usize = 1;
