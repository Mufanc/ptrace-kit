# ptrace-kit

A toolkit for interacting with processes through ptrace.

Supports **Android on AArch64**.

- Seize, interrupt, wait for, resume, and detach individual threads.
- Read and write general-purpose and floating-point/SIMD registers.
- Read and write remote memory as `u64` values or byte buffers.
- Read process memory maps and look up mappings by address with the optional `maps` feature.
- Resolve symbols in a mapped ELF with `MappedFile::resolve_symbol` and the optional `symbols` feature.
- Translate file offsets to target addresses with `MappedFile::address_at_file_offset` and the optional `maps` feature.
- Call remote functions with up to eight integer or pointer arguments.
- Transfer file descriptors in either direction with the optional `ipc` feature.
- Call JNI functions and read Java strings with the optional `jni` feature.

Tracing requires access to the target under Android's permission and SELinux policies.

## Usage

Add as a Git dependency:

```toml
[dependencies]
ptrace-kit = { git = "https://github.com/Mufanc/ptrace-kit.git" }
```

Enable `features = ["full"]` to include all optional capabilities.

Enable `features = ["jni"]` to use `Tracee::call_remote_jni` and
`Tracee::read_jstring` with a valid target-thread JNIEnv. String reads need 4 KiB
of additional target stack space and require the thread to have no pending Java
exception.

Use `Tracee::seize`, `interrupt`, and `wait` to establish a ptrace stop. Once stopped,
registers can be inspected directly:

```rust
use ptrace_kit::{Error, RemoteAddress, Tracee};

fn program_counter(tracee: &Tracee) -> Result<RemoteAddress, Error> {
    Ok(tracee.read_regs()?.pc())
}
```

## Semantics

- A `Tracee` controls one TID and stays on the OS thread that seized it.
- `seize` establishes tracing without stopping execution. Inspect the `WaitStatus`
  returned by `wait` before accessing registers or resuming the target.
- `wait` takes an `Instant` deadline. A timeout does not stop or cancel the target.
  Use `Tracee::with_timeout` to configure a fresh timeout budget per wait or remote call.
- Detach explicitly from a ptrace stop. `Drop` does not detach or resume the target;
  callers own signal handling and cleanup, including error paths.
- Memory addresses must be untagged. Buffer operations complete the entire transfer
  or return an error; partial writes are not rolled back.
- Remote calls report register recovery status. The target may remain running after
  a timeout; memory and resource side effects are not rolled back.
