//! AArch64 general-purpose register snapshots.

use crate::Error;
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
    pub fn pc(&self) -> usize {
        self.0.pc as usize
    }
    pub fn set_pc(&mut self, value: usize) {
        self.0.pc = value as u64;
    }
    pub fn sp(&self) -> usize {
        self.0.sp as usize
    }
    pub fn set_sp(&mut self, value: usize) {
        self.0.sp = value as u64;
    }
    pub fn lr(&self) -> usize {
        self.0.regs[30] as usize
    }
    pub fn set_lr(&mut self, value: usize) {
        self.0.regs[30] = value as u64;
    }
    pub fn fp(&self) -> usize {
        self.0.regs[29] as usize
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
