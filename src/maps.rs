//! Snapshots of a process's memory mappings.

#[cfg(feature = "symbols")]
mod symbols;

use crate::{Error, Pid, RemoteAddress};
use procfs::process::Process;
use std::path::Path;

pub use procfs::process::{
    MMPermissions as MapPermissions, MMapPath as MapPath, MemoryMap as MapEntry,
};
#[cfg(feature = "symbols")]
pub use r3solvr::{CachedResolver as SymbolResolver, Query, SymbolResolver as ResolveSymbols};

struct FileId {
    dev: (i32, i32),
    ino: u64,
}

/// Memory mappings captured by reading `/proc/<pid>/maps`.
#[derive(Debug)]
pub struct Maps {
    #[cfg(feature = "symbols")]
    process: Process,
    entries: Vec<MapEntry>,
}

/// The mappings of one backing file in a maps snapshot.
pub struct MappedFile<'maps> {
    path: &'maps Path,
    mappings: Vec<&'maps MapEntry>,
    file_id: FileId,
    #[cfg(feature = "symbols")]
    process: &'maps Process,
    #[cfg(feature = "symbols")]
    resolver: Option<SymbolResolver>,
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

        let process = Process::new(pid.as_raw())
            .map_err(|error| Error::Io(format!("open /proc/{pid}: {error}")))?;
        let maps = process
            .maps()
            .map_err(|error| Error::Io(format!("read /proc/{pid}/maps: {error}")))?;

        Ok(Self {
            #[cfg(feature = "symbols")]
            process,
            entries: maps.0,
        })
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

    /// Selects a backing file by its absolute path or an unambiguous basename.
    pub fn mapped_file(&self, file: impl AsRef<Path>) -> Result<MappedFile<'_>, Error> {
        let file = file.as_ref();
        let is_absolute = file.is_absolute();
        let name = file.as_os_str();

        if !is_absolute && file.file_name() != Some(name) {
            return Err(Error::InvalidArgument(format!(
                "expected an absolute path or basename, got {}",
                file.display()
            )));
        }

        let matching = self.file_entries().filter(|(path, _)| {
            if is_absolute {
                *path == file
            } else {
                path.file_name() == Some(name)
            }
        });
        let mut result = None;

        for (path, entry) in matching {
            let mapped_file = result.get_or_insert_with(|| MappedFile {
                path,
                mappings: Vec::new(),
                file_id: FileId {
                    dev: entry.dev,
                    ino: entry.inode,
                },
                #[cfg(feature = "symbols")]
                process: &self.process,
                #[cfg(feature = "symbols")]
                resolver: None,
            });

            if entry.dev != mapped_file.file_id.dev || entry.inode != mapped_file.file_id.ino {
                return Err(Error::IllegalState(format!(
                    "multiple backing files for {}",
                    file.display()
                )));
            }

            mapped_file.mappings.push(entry);
        }

        result.ok_or_else(|| Error::IllegalState(format!("file {} is not mapped", file.display())))
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

impl MappedFile<'_> {
    /// Translates a byte offset in the backing file to a unique target address.
    /// Only mappings containing every bit in `required_perms` are considered.
    /// Use `MapPermissions::empty()` to consider all mappings.
    /// Returns an error if no mapping matches or multiple addresses remain.
    pub fn address_at_file_offset(
        &self,
        offset: u64,
        required_perms: MapPermissions,
    ) -> Result<RemoteAddress, Error> {
        let mut addresses = self
            .mappings
            .iter()
            .filter(|entry| entry.perms.contains(required_perms))
            .filter_map(|entry| {
                let delta = offset.checked_sub(entry.offset)?;
                let address = entry.address.0.checked_add(delta)?;
                (address < entry.address.1).then_some(address as RemoteAddress)
            });
        let address = addresses.next().ok_or_else(|| {
            Error::IllegalState(format!(
                "{} offset {offset:#x} has no mapping with {required_perms:?}",
                self.path.display()
            ))
        })?;

        if addresses.next().is_some() {
            return Err(Error::IllegalState(format!(
                "{} offset {offset:#x} is mapped at multiple addresses",
                self.path.display()
            )));
        }

        Ok(address)
    }
}
