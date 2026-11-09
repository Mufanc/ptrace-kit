//! A toolkit for interacting with processes through ptrace.
//!
//! Supports Android on AArch64.
//!
//! Callers own stop policies, symbol resolution, scratch memory, and event consumption.

mod constants;

pub mod error;
#[cfg(feature = "jni")]
pub mod jni;
pub mod memory;
pub mod regs;
pub mod remote;
pub mod tracee;

pub use error::Error;
pub use nix::sys::signal::Signal;
pub use nix::sys::wait::WaitStatus;
pub use nix::unistd::Pid;
pub use regs::{FpRegSet, RegSet};
pub use tracee::{Tracee, TraceeWithTimeout};

/// An address in the target process.
pub type RemoteAddress = usize;
