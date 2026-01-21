// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

use super::{SocketError, SocketErrorKind, SocketResult};
use std::os::unix::io::AsRawFd;
use tokio::net::UnixStream;

pub fn validate_peer_uid(stream: &UnixStream, expected_uid: u32) -> SocketResult<()> {
    let uid = peer_uid(stream)?;
    if uid != expected_uid {
        return Err(SocketError::new(
            SocketErrorKind::Unauthorized,
            format!(
                "Peer UID {} does not match daemon UID {}",
                uid, expected_uid
            ),
        ));
    }
    Ok(())
}

pub fn peer_uid(stream: &UnixStream) -> SocketResult<u32> {
    #[cfg(target_os = "linux")]
    {
        use libc::{SO_PEERCRED, SOL_SOCKET, getsockopt, ucred};
        let fd = stream.as_raw_fd();
        let mut cred = ucred {
            pid: 0,
            uid: 0,
            gid: 0,
        };
        let mut cred_len = std::mem::size_of::<ucred>() as libc::socklen_t;
        let rc = unsafe {
            getsockopt(
                fd,
                SOL_SOCKET,
                SO_PEERCRED,
                &mut cred as *mut ucred as *mut libc::c_void,
                &mut cred_len,
            )
        };
        if rc != 0 {
            return Err(SocketError::new(
                SocketErrorKind::Unauthorized,
                format!(
                    "getsockopt(SO_PEERCRED) failed: {}",
                    std::io::Error::last_os_error()
                ),
            ));
        }
        return Ok(cred.uid);
    }

    #[cfg(any(
        target_os = "macos",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd"
    ))]
    {
        use libc::getpeereid;
        let fd = stream.as_raw_fd();
        let mut uid: libc::uid_t = 0;
        let mut gid: libc::gid_t = 0;
        let rc = unsafe { getpeereid(fd, &mut uid, &mut gid) };
        if rc != 0 {
            return Err(SocketError::new(
                SocketErrorKind::Unauthorized,
                format!("getpeereid failed: {}", std::io::Error::last_os_error()),
            ));
        }
        Ok(uid as u32)
    }

    #[cfg(not(any(
        target_os = "linux",
        target_os = "macos",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd"
    )))]
    {
        let _ = stream;
        Err(SocketError::new(
            SocketErrorKind::Unauthorized,
            "Peer credential checks not supported on this platform",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn peer_uid_matches_current_user() {
        let (client, server) = UnixStream::pair().expect("pair");
        let expected = unsafe { libc::geteuid() as u32 };
        validate_peer_uid(&client, expected).expect("client uid ok");
        validate_peer_uid(&server, expected).expect("server uid ok");
    }

    #[tokio::test]
    async fn peer_uid_rejects_mismatched_user() {
        let (client, _server) = UnixStream::pair().expect("pair");
        let expected = unsafe { libc::geteuid() as u32 };
        let mismatched = expected.wrapping_add(1);
        let err = validate_peer_uid(&client, mismatched).expect_err("should reject");
        assert_eq!(err.kind(), SocketErrorKind::Unauthorized);
    }
}
