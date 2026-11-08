//! Broad error categories with diagnostic context supplied by library operations.

use nix::errno::Errno;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("invalid argument: {0}")]
    InvalidArgument(String),
    #[error("illegal state: {0}")]
    IllegalState(String),
    #[error("execution failed: {0}")]
    Execution(String),
    #[error("operation timed out: {0}")]
    Timeout(String),
    #[error("I/O error: {0}")]
    Io(String),
    #[error("system error: {reason}: {source}")]
    System {
        reason: String,
        #[source]
        source: Errno,
    },
}
