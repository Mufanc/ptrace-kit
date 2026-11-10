use crate::{Error, RemoteAddress};
use nix::libc::{self, MSG_CTRUNC, MSG_TRUNC, SCM_RIGHTS, SOL_SOCKET, cmsghdr, iovec, msghdr};
use nix::sys::socket::{self, ControlMessage, MsgFlags};
use std::io::IoSlice;
use std::mem::{MaybeUninit, offset_of};
use std::os::fd::{AsRawFd, BorrowedFd, RawFd};
use std::ptr;

const CONTROL_SIZE: usize = unsafe { libc::CMSG_SPACE(size_of::<RawFd>() as _) as usize };
const CONTROL_HEADER_SIZE: usize = unsafe { libc::CMSG_LEN(0) as usize };
const DESCRIPTOR_MESSAGE_LEN: usize = unsafe { libc::CMSG_LEN(size_of::<RawFd>() as _) as usize };

#[repr(C)]
struct DescriptorControl {
    header: cmsghdr,
    fd: RawFd,
}

const _: () = {
    assert!(offset_of!(DescriptorControl, fd) == CONTROL_HEADER_SIZE);
    assert!(size_of::<DescriptorControl>() == CONTROL_SIZE);
};

#[repr(C)]
pub(super) struct ReceiveBuffer {
    message: msghdr,
    iov: iovec,
    control: DescriptorControl,
    byte: u8,
}

impl ReceiveBuffer {
    pub(super) fn encode(address: RemoteAddress) -> [u8; size_of::<Self>()] {
        let mut storage = MaybeUninit::<Self>::uninit();
        let buffer = storage.as_mut_ptr();

        // Zero the padding in place and preserve it by writing only scalar fields.
        unsafe {
            buffer.write_bytes(0, 1);
            (*buffer).message.msg_iov =
                ptr::without_provenance_mut(address + offset_of!(Self, iov));
            (*buffer).message.msg_iovlen = 1;
            (*buffer).message.msg_control =
                ptr::without_provenance_mut(address + offset_of!(Self, control));
            (*buffer).message.msg_controllen = CONTROL_SIZE;
            (*buffer).iov.iov_base = ptr::without_provenance_mut(address + offset_of!(Self, byte));
            (*buffer).iov.iov_len = 1;

            buffer.cast::<[u8; size_of::<Self>()]>().read()
        }
    }

    pub(super) fn decode_fd(bytes: &[u8; size_of::<Self>()]) -> Result<RawFd, Error> {
        // The initialized byte array contains only integer and raw pointer fields.
        let buffer = unsafe { bytes.as_ptr().cast::<Self>().read_unaligned() };
        let control = buffer.control;

        if buffer.message.msg_flags & (MSG_CTRUNC | MSG_TRUNC) != 0
            || !(DESCRIPTOR_MESSAGE_LEN..=CONTROL_SIZE).contains(&buffer.message.msg_controllen)
            || control.header.cmsg_len != DESCRIPTOR_MESSAGE_LEN
            || control.header.cmsg_level != SOL_SOCKET
            || control.header.cmsg_type != SCM_RIGHTS
            || control.fd < 0
        {
            return Err(Error::Io(
                "target recvmsg did not return one descriptor".into(),
            ));
        }

        Ok(control.fd)
    }
}

pub(super) fn send_fd(socket: BorrowedFd<'_>, fd: BorrowedFd<'_>) -> Result<usize, Error> {
    socket::sendmsg::<()>(
        socket.as_raw_fd(),
        &[IoSlice::new(&[0])],
        &[ControlMessage::ScmRights(&[fd.as_raw_fd()])],
        MsgFlags::MSG_DONTWAIT | MsgFlags::MSG_NOSIGNAL,
        None,
    )
    .map_err(|source| Error::system("sendmsg descriptor".into(), source))
}
