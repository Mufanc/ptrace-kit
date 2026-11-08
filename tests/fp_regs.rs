use nix::libc::PTRACE_EVENT_STOP;
use ptrace_kit::{Error, Pid, Signal, Tracee, WaitStatus};
use std::process::{Child, Command};
use std::time::{Duration, Instant};

struct Target(Child);

impl Drop for Target {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn reads_writes_and_restores_fpsimd() {
    let target = Target(Command::new("/system/bin/sleep").arg("30").spawn().unwrap());
    let mut tracee = Tracee::seize(Pid::from_raw(target.0.id() as i32)).unwrap();
    tracee.interrupt().unwrap();
    assert!(matches!(
        tracee
            .wait(Instant::now() + Duration::from_secs(2))
            .unwrap(),
        WaitStatus::PtraceEvent(_, Signal::SIGTRAP, PTRACE_EVENT_STOP)
    ));
    let orig = tracee.read_fp_regs().unwrap();
    let mut modified = orig.clone();
    modified.vregs[0] = u128::MAX;
    modified.vregs[31] = 1 << 127;
    modified.fpsr = 0x10;
    modified.fpcr = 1 << 22;
    tracee.write_fp_regs(&modified).unwrap();
    assert_eq!(tracee.read_fp_regs().unwrap(), modified);
    tracee.write_fp_regs(&orig).unwrap();
    assert_eq!(tracee.read_fp_regs().unwrap(), orig);
    tracee.detach(None).unwrap();
    assert!(matches!(tracee.read_fp_regs(), Err(Error::IllegalState(_))));
}
