use super::{MapPermissions, MappedFile, ResolveSymbols, SymbolResolver};
use crate::{Error, RemoteAddress};
use nix::libc;
use rustix::fs::OFlags;
use std::io::Read;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

impl MappedFile<'_> {
    /// Borrows the cached resolver, loading and verifying the ELF on first use.
    /// Import [`ResolveSymbols`] to use its query methods.
    pub fn resolver(&mut self) -> Result<&SymbolResolver, Error> {
        match self.resolver {
            Some(ref resolver) => Ok(resolver),
            None => {
                let resolver = self.load_resolver()?;
                Ok(self.resolver.insert(resolver))
            }
        }
    }

    /// Takes ownership of the resolver, loading the ELF if needed.
    pub fn into_resolver(self) -> Result<SymbolResolver, Error> {
        match self.resolver {
            Some(resolver) => Ok(resolver),
            None => self.load_resolver(),
        }
    }

    /// Resolves an exact ELF symbol name to a unique address in the maps snapshot.
    /// The symbol must have a file offset. Multiple candidate addresses are an error.
    pub fn resolve_symbol(&mut self, name: &str) -> Result<RemoteAddress, Error> {
        let path = self.path.display();
        let resolver = self.resolver()?;
        let lookup_error = |source| Error::IllegalState(format!("resolve {path}:{name}: {source}"));
        let symbol = resolver.lookup_symbol(name).map_err(lookup_error)?;
        let section = resolver
            .lookup_section(symbol.section_index)
            .map_err(lookup_error)?;
        let offset = section
            .file_range
            .and_then(|(start, end)| {
                let offset = start.checked_add(symbol.addr.checked_sub(section.addr)?)?;
                (offset < end).then_some(offset as u64)
            })
            .ok_or_else(|| Error::IllegalState(format!("{path}:{name} has no file offset")))?;

        self.address_at_file_offset(offset, MapPermissions::empty())
    }

    fn load_resolver(&self) -> Result<SymbolResolver, Error> {
        let path = self.path.display();
        let relative_path = self
            .path
            .strip_prefix("/")
            .map_err(|_| Error::IllegalState(format!("mapping path is not absolute: {path}")))?;
        let mut file = self
            .process
            .open_relative_flags(
                Path::new("root").join(relative_path),
                OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NONBLOCK,
            )
            .map_err(|source| Error::Io(format!("open {path}: {source}")))?;
        let metadata = file
            .metadata()
            .map_err(|source| Error::Io(format!("stat {path}: {source}")))?;
        let dev = metadata.dev();

        if !metadata.is_file()
            || (libc::major(dev), libc::minor(dev)) != self.file_id.dev
            || metadata.ino() != self.file_id.ino
        {
            return Err(Error::IllegalState(format!(
                "backing file changed for {path}"
            )));
        }

        let mut data = Vec::new();

        file.read_to_end(&mut data)
            .map_err(|source| Error::Io(format!("read {path}: {source}")))?;

        SymbolResolver::from_data(data)
            .map_err(|source| Error::Io(format!("parse {path}: {source}")))
    }
}
