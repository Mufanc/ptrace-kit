//! Snapshots of a process's memory mappings.

use crate::{Error, Pid, RemoteAddress};
use procfs::process::Process;
use std::path::Path;

pub use procfs::process::{
    MMPermissions as MapPermissions, MMapPath as MapPath, MemoryMap as MapEntry,
};

/// Memory mappings captured by reading `/proc/<pid>/maps`.
#[derive(Debug)]
pub struct Maps {
    entries: Vec<MapEntry>,
}

impl Maps {
    /// Reads the process's mappings. The address space may change during or after the read.
    /// Pathnames are parsed as UTF-8 by `procfs`.
    pub fn scan(pid: Pid) -> Result<Self, Error> {
        if pid.as_raw() <= 0 {
            return Err(Error::InvalidArgument(format!(
                "PID {pid} must be positive"
            )));
        }

        let maps = Process::new(pid.as_raw())
            .and_then(|process| process.maps())
            .map_err(|error| Error::Io(format!("read /proc/{pid}/maps: {error}")))?;

        Ok(Self { entries: maps.0 })
    }

    /// Returns the mappings in procfs order.
    pub fn entries(&self) -> &[MapEntry] {
        &self.entries
    }

    /// Returns each file path and its mapping in procfs order.
    pub fn file_entries(&self) -> impl Iterator<Item = (&Path, &MapEntry)> {
        self.entries
            .iter()
            .filter_map(|entry| match &entry.pathname {
                MapPath::Path(path) => Some((path.as_path(), entry)),
                _ => None,
            })
    }

    /// Finds the mapping whose half-open range contains `address`.
    pub fn find(&self, address: RemoteAddress) -> Option<&MapEntry> {
        let address = address as u64;

        self.entries.iter().find(|entry| {
            let (start, end) = entry.address;

            (start..end).contains(&address)
        })
    }
}
