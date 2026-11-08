# ptrace-kit

A toolkit for interacting with processes through ptrace.

Supports **Android on AArch64**.

- Seize, interrupt, wait for, resume, and detach individual threads.
- Read and write general-purpose and floating-point/SIMD registers.
- Read and write remote memory as `u64` values or byte buffers.

Tracing requires access to the target under Android's permission and SELinux policies.

## Usage

Add as a Git dependency:

```toml
[dependencies]
ptrace-kit = { git = "https://github.com/Mufanc/ptrace-kit.git" }
```

Use `Tracee::seize`, `interrupt`, and `wait` to establish a ptrace stop. Once stopped,
registers can be inspected directly:

```rust
use ptrace_kit::{Error, Tracee};

fn program_counter(tracee: &Tracee) -> Result<usize, Error> {
    Ok(tracee.read_regs()?.pc())
}
```

## Semantics

- A `Tracee` controls one TID and stays on the OS thread that seized it.
- `seize` establishes tracing without stopping execution. Inspect the `WaitStatus`
  returned by `wait` before accessing registers or resuming the target.
- `wait` takes an `Instant` deadline. A timeout does not stop or cancel the target.
- Detach explicitly from a ptrace stop. `Drop` does not detach or resume the target;
  callers own signal handling and cleanup, including error paths.
- Memory addresses must be untagged. Buffer operations complete the entire transfer
  or return an error; partial writes are not rolled back.
