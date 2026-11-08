//! Remote memory access with complete-transfer semantics.

use crate::{Error, RemoteAddress, Tracee};
use nix::errno::Errno;
use nix::sys::ptrace;
use nix::sys::uio::{self, RemoteIoVec};
use std::io::{IoSlice, IoSliceMut};

fn transfer_exact(
    len: usize,
    mut transfer: impl FnMut(usize) -> Result<usize, Error>,
) -> Result<(), Error> {
    let mut completed = 0;

    while completed < len {
        match transfer(completed) {
            Ok(0) => {
                return Err(Error::Io(format!(
                    "remote transfer made no progress after {completed} of {len} bytes"
                )));
            }
            Ok(count) => completed += count,
            Err(Error::System {
                source: Errno::EINTR,
                ..
            }) => continue,
            Err(source) => {
                return Err(Error::Io(format!(
                    "remote transfer failed after {completed} of {len} bytes: {source}"
                )));
            }
        }
    }

    Ok(())
}

fn checked_range(address: RemoteAddress, len: usize) -> Result<(), Error> {
    address.checked_add(len).ok_or_else(|| {
        Error::InvalidArgument(format!(
            "remote range address={address:#x}, len={len} overflows"
        ))
    })?;

    Ok(())
}

impl Tracee {
    pub fn read_u64(&self, address: RemoteAddress) -> Result<u64, Error> {
        ptrace::read(self.active_target()?, address as _)
            .map(|value| value as u64)
            .map_err(|source| Error::System {
                reason: format!("PTRACE_PEEKDATA tid={}, address={address:#x}", self.tid()),
                source,
            })
    }

    pub fn write_u64(&mut self, address: RemoteAddress, value: u64) -> Result<(), Error> {
        ptrace::write(self.active_target()?, address as _, value as _).map_err(|source| {
            Error::System {
                reason: format!("PTRACE_POKEDATA tid={}, address={address:#x}", self.tid()),
                source,
            }
        })?;

        Ok(())
    }

    pub fn read_exact(&self, address: RemoteAddress, output: &mut [u8]) -> Result<(), Error> {
        let tid = self.active_target()?;

        checked_range(address, output.len())?;

        transfer_exact(output.len(), |offset| {
            let remote = RemoteIoVec {
                base: address + offset,
                len: output.len() - offset,
            };

            uio::process_vm_readv(
                tid,
                &mut [IoSliceMut::new(&mut output[offset..])],
                &[remote],
            )
            .map_err(|source| Error::System {
                reason: format!(
                    "process_vm_readv tid={tid}, address={:#x}, len={}",
                    address + offset,
                    output.len() - offset
                ),
                source,
            })
        })
    }

    pub fn write_all(&mut self, address: RemoteAddress, input: &[u8]) -> Result<(), Error> {
        let tid = self.active_target()?;

        checked_range(address, input.len())?;

        transfer_exact(input.len(), |offset| {
            let remote = RemoteIoVec {
                base: address + offset,
                len: input.len() - offset,
            };

            uio::process_vm_writev(tid, &[IoSlice::new(&input[offset..])], &[remote]).map_err(
                |source| Error::System {
                    reason: format!(
                        "process_vm_writev tid={tid}, address={:#x}, len={}",
                        address + offset,
                        input.len() - offset
                    ),
                    source,
                },
            )
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::{Error, RemoteAddress};
    use nix::errno::Errno;

    #[test]
    fn retries_partial_transfers_and_interruptions() {
        let mut calls = 0;
        super::transfer_exact(5, |offset| {
            calls += 1;
            match calls {
                1 => Err(Error::System {
                    reason: "test transfer".into(),
                    source: Errno::EINTR,
                }),
                2 => {
                    assert_eq!(offset, 0);
                    Ok(2)
                }
                _ => {
                    assert_eq!(offset, 2);
                    Ok(3)
                }
            }
        })
        .unwrap();
        assert_eq!(calls, 3);
    }

    #[test]
    fn failure_reports_io_context() {
        let error =
            super::transfer_exact(4, |offset| if offset == 0 { Ok(2) } else { Ok(0) }).unwrap_err();
        let Error::Io(reason) = error else {
            panic!("expected an I/O error");
        };
        assert!(reason.contains("no progress"));
        assert!(reason.contains("2 of 4 bytes"));

        let error = super::transfer_exact(4, |offset| {
            if offset == 0 {
                Ok(2)
            } else {
                Err(Error::System {
                    reason: "test transfer".into(),
                    source: Errno::EFAULT,
                })
            }
        })
        .unwrap_err();
        let Error::Io(reason) = error else {
            panic!("expected an I/O error");
        };
        assert!(reason.contains("2 of 4 bytes"));
        assert!(reason.contains("test transfer"));
        assert!(reason.contains("EFAULT"));
        assert!(super::checked_range(RemoteAddress::MAX, 1).is_err());
        super::transfer_exact(0, |_| panic!("empty transfer must not issue a syscall")).unwrap();
    }
}
