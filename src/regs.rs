//! AArch64 general-purpose and floating-point/SIMD register snapshots.

use crate::{Error, RemoteAddress};
use nix::libc::user_regs_struct;

#[derive(Clone, Debug)]
pub struct RegSet(pub(crate) user_regs_struct);

impl Default for RegSet {
    fn default() -> Self {
        Self(user_regs_struct {
            regs: [0; 31],
            sp: 0,
            pc: 0,
            pstate: 0,
        })
    }
}

impl RegSet {
    pub fn pc(&self) -> RemoteAddress {
        self.0.pc as RemoteAddress
    }
    pub fn set_pc(&mut self, value: RemoteAddress) {
        self.0.pc = value as u64;
    }
    pub fn sp(&self) -> RemoteAddress {
        self.0.sp as RemoteAddress
    }
    pub fn set_sp(&mut self, value: RemoteAddress) {
        self.0.sp = value as u64;
    }
    pub fn lr(&self) -> RemoteAddress {
        self.0.regs[30] as RemoteAddress
    }
    pub fn set_lr(&mut self, value: RemoteAddress) {
        self.0.regs[30] = value as u64;
    }
    pub fn fp(&self) -> RemoteAddress {
        self.0.regs[29] as RemoteAddress
    }
    pub fn pstate(&self) -> u64 {
        self.0.pstate
    }
    pub fn return_value(&self) -> u64 {
        self.0.regs[0]
    }

    pub fn register(&self, index: usize) -> Result<u64, Error> {
        self.0.regs.get(index).copied().ok_or_else(|| {
            Error::InvalidArgument(format!("register index {index} is outside 0..31"))
        })
    }

    pub fn set_register(&mut self, index: usize, value: u64) -> Result<(), Error> {
        let register = self.0.regs.get_mut(index).ok_or_else(|| {
            Error::InvalidArgument(format!("register index {index} is outside 0..31"))
        })?;

        *register = value;
        Ok(())
    }
}

/// The NT_PRFPREG layout: V0–V31, FPSR, and FPCR.
#[repr(C, align(16))]
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FpRegSet {
    pub vregs: [u128; 32],
    pub fpsr: u32,
    pub fpcr: u32,
}
