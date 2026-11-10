use nix::errno::Errno;
use nix::libc::{
    self, _SC_PAGESIZE, MAP_ANONYMOUS, MAP_FAILED, MAP_PRIVATE, PROT_NONE, PROT_READ, PROT_WRITE,
    PTRACE_EVENT_STOP, c_void,
};
use nix::sys::signal;
use nix::sys::wait;
#[cfg(feature = "maps")]
use ptrace_kit::maps::{MapPath, MapPermissions, Maps};
#[cfg(feature = "symbols")]
use ptrace_kit::maps::{Query, ResolveSymbols, SymbolResolver};
use ptrace_kit::{Error, Pid, RemoteAddress, Signal, Tracee, WaitStatus};
use std::error::Error as StdError;
#[cfg(feature = "ipc")]
use std::fs::File;
#[cfg(feature = "ipc")]
use std::io::Read;
#[cfg(feature = "ipc")]
use std::os::fd::AsRawFd;
use std::time::{Duration, Instant};

struct Child(Pid);

impl Drop for Child {
    fn drop(&mut self) {
        let _ = signal::kill(self.0, Signal::SIGKILL);
        while let Err(Errno::EINTR) = wait::waitpid(self.0, None) {}
    }
}

struct Mapping {
    address: *mut c_void,
    len: usize,
}

impl Drop for Mapping {
    fn drop(&mut self) {
        // This object owns the mapping returned by mmap below.
        unsafe {
            libc::munmap(self.address, self.len);
        }
    }
}

#[test]
fn controls_child_and_accesses_its_state() {
    // Allocate two pages and deny access to the second, producing a real partial transfer.
    let page_size = unsafe { libc::sysconf(_SC_PAGESIZE) } as usize;
    let raw = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            page_size * 2,
            PROT_READ | PROT_WRITE,
            MAP_PRIVATE | MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    assert_ne!(raw, MAP_FAILED);
    let mapping = Mapping {
        address: raw,
        len: page_size * 2,
    };
    assert_eq!(
        unsafe { libc::mprotect(raw.add(page_size), page_size, PROT_NONE) },
        0
    );

    let address = raw as RemoteAddress;
    // Initialize child data in an untagged mapping.
    unsafe {
        raw.cast::<u8>().write_bytes(0x11, 16);
    }

    #[cfg(feature = "ipc")]
    let inherited_file = File::open("/dev/zero").unwrap();

    // After fork, the child only issues async-signal-safe syscalls; it never returns to Rust.
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        loop {
            unsafe {
                libc::pause();
            }
        }
    }
    assert!(pid > 0);
    let child = Child(Pid::from_raw(pid));
    #[cfg(feature = "ipc")]
    let remote_fd = {
        let fd = inherited_file.as_raw_fd();
        drop(inherited_file);
        fd
    };
    #[cfg(feature = "maps")]
    let maps = Maps::scan(child.0).unwrap();
    #[cfg(feature = "symbols")]
    let mut file = maps.mapped_file("libc.so").unwrap();
    #[cfg(feature = "maps")]
    {
        let executable = std::env::current_exe().unwrap();
        assert!(maps.file_entries().any(|(path, entry)| {
            path == executable && entry.perms.contains(MapPermissions::EXECUTE)
        }));
        let writable = maps.find(address).unwrap();
        let protected = maps.find(address + page_size).unwrap();
        assert_eq!(writable.address.1, protected.address.0);
        assert!(
            writable
                .perms
                .contains(MapPermissions::READ | MapPermissions::WRITE | MapPermissions::PRIVATE)
        );
        assert_eq!(protected.perms, MapPermissions::PRIVATE);
        assert_eq!(protected.pathname, MapPath::Anonymous);
        assert!(
            maps.entries()
                .iter()
                .any(|entry| entry.pathname == MapPath::Stack)
        );
        assert!(matches!(
            maps.mapped_file("lib/libc.so"),
            Err(Error::InvalidArgument(_))
        ));

        #[cfg(feature = "symbols")]
        {
            // The forked child inherits the libc mappings used by dlsym here.
            for symbol in [c"socketpair", c"close", c"socketpair"] {
                let expected = unsafe { libc::dlsym(libc::RTLD_DEFAULT, symbol.as_ptr()) };
                assert!(!expected.is_null());
                let expected = expected as RemoteAddress;
                let name = symbol.to_str().unwrap();
                let resolver = file.resolver().unwrap();
                let symbol = resolver.lookup_symbol(Query::new(name)).unwrap();
                let section = resolver.lookup_section(symbol.section_index).unwrap();
                let (start, end) = section.file_range.unwrap();
                let offset = start + (symbol.addr - section.addr);
                assert!(offset < end);
                let mapping = maps.find(expected).unwrap();
                let MapPath::Path(path) = &mapping.pathname else {
                    panic!("libc symbol is not file-backed");
                };
                assert_ne!(mapping.offset, 0);
                assert!(mapping.perms.contains(MapPermissions::EXECUTE));
                assert_eq!(
                    file.address_at_file_offset(offset as u64, MapPermissions::EXECUTE)
                        .unwrap(),
                    expected
                );
                assert_eq!(
                    maps.mapped_file(path)
                        .unwrap()
                        .address_at_file_offset(offset as u64, MapPermissions::EXECUTE)
                        .unwrap(),
                    expected
                );
                assert_eq!(file.resolve_symbol(name).unwrap(), expected);
            }
            assert!(matches!(
                file.resolve_symbol("ptrace_kit_missing_symbol"),
                Err(Error::IllegalState(_))
            ));
            assert!(matches!(
                file.address_at_file_offset(u64::MAX, MapPermissions::empty()),
                Err(Error::IllegalState(_))
            ));
        }
    }
    assert!(matches!(
        Tracee::seize(Pid::from_raw(0)),
        Err(Error::InvalidArgument(_))
    ));
    let mut tracee = Tracee::seize(child.0)
        .unwrap()
        .with_timeout(Duration::from_millis(20));
    assert!(matches!(tracee.wait(), Err(Error::Timeout(_))));
    tracee.interrupt().unwrap();
    assert!(matches!(
        Tracee::wait(&mut tracee, Instant::now() + Duration::from_secs(2)).unwrap(),
        WaitStatus::PtraceEvent(_, _, PTRACE_EVENT_STOP)
    ));

    let system_error = tracee.read_u64(0).unwrap_err();
    assert!(matches!(system_error, Error::System { .. }));
    if let Error::System { reason, .. } = &system_error {
        assert!(reason.contains(&format!("tid={}", child.0)));
        assert!(reason.contains("address=0x0"));
    }
    assert!(
        StdError::source(&system_error)
            .unwrap()
            .downcast_ref::<Errno>()
            .is_some()
    );
    let orig = tracee.read_regs().unwrap();
    assert!(matches!(orig.register(31), Err(Error::InvalidArgument(_))));
    let mut modified = orig.clone();
    modified.set_register(0, 0x12345678).unwrap();
    tracee.write_regs(&modified).unwrap();
    assert_eq!(tracee.read_regs().unwrap().return_value(), 0x12345678);
    tracee.write_regs(&orig).unwrap();
    assert_eq!(
        tracee.read_regs().unwrap().return_value(),
        orig.return_value()
    );

    let mut output = [0; 16];
    tracee.read_exact(address, &mut output).unwrap();
    assert_eq!(output, [0x11; 16]);
    tracee.write_all(address, &[0x33; 16]).unwrap();
    tracee.read_exact(address, &mut output).unwrap();
    assert_eq!(output, [0x33; 16]);
    assert_eq!(
        unsafe { std::slice::from_raw_parts(raw.cast::<u8>(), 16) },
        &[0x11; 16]
    );
    for value in [0, 42, 1 << 63, u64::MAX] {
        tracee.write_u64(address, value).unwrap();
        assert_eq!(tracee.read_u64(address).unwrap(), value);
        tracee.read_exact(address, &mut output[..8]).unwrap();
        assert_eq!(&output[..8], &value.to_le_bytes());
    }
    tracee.read_exact(0, &mut []).unwrap();
    let invalid_range = tracee
        .read_exact(RemoteAddress::MAX, &mut output)
        .unwrap_err();
    assert!(matches!(invalid_range, Error::InvalidArgument(_)));
    let boundary = raw as RemoteAddress + page_size - 8;
    assert!(matches!(
        tracee.read_exact(boundary, &mut output),
        Err(Error::Io(_))
    ));
    assert!(matches!(
        tracee.write_all(boundary, &output),
        Err(Error::Io(_))
    ));

    #[cfg(feature = "ipc")]
    {
        for _ in 0..2 {
            let mut local = File::from(tracee.duplicate_fd(remote_fd).unwrap());
            let mut bytes = [0xff; 16];
            local.read_exact(&mut bytes).unwrap();
            assert_eq!(bytes, [0; 16]);
        }
        assert!(matches!(
            tracee.duplicate_fd(-1),
            Err(Error::InvalidArgument(_))
        ));
        assert!(matches!(
            tracee.duplicate_fd(i32::MAX),
            Err(Error::System {
                source: Errno::EBADF,
                ..
            })
        ));
    }

    tracee.resume(None).unwrap();
    tracee.interrupt().unwrap();
    Tracee::wait(&mut tracee, Instant::now() + Duration::from_secs(2)).unwrap();
    tracee.detach(None).unwrap();
    assert!(matches!(tracee.interrupt(), Err(Error::IllegalState(_))));
    let detached = tracee.read_exact(address, &mut output).unwrap_err();
    assert!(matches!(detached, Error::IllegalState(_)));

    #[cfg(feature = "symbols")]
    let close = file.resolve_symbol("close").unwrap();
    #[cfg(feature = "symbols")]
    let mut unloaded = maps.mapped_file("libc.so").unwrap();
    drop((child, mapping));

    #[cfg(feature = "symbols")]
    {
        assert!(matches!(unloaded.resolver(), Err(Error::Io(_))));
        assert_eq!(file.resolve_symbol("close").unwrap(), close);
        let resolver: SymbolResolver = file.into_resolver().unwrap();
        drop(maps);
        assert_eq!(&*resolver.lookup_symbol("close").unwrap().name, "close");
    }
}
