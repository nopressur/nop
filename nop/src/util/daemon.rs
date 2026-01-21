// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

use std::ffi::CString;
use std::io;

#[cfg(unix)]
pub fn daemonize_or_warn() -> io::Result<()> {
    daemonize()
}

#[cfg(not(unix))]
pub fn daemonize_or_warn() -> io::Result<()> {
    eprintln!("WARN: Daemon mode is not supported on this platform; running in foreground.");
    Ok(())
}

#[cfg(unix)]
fn daemonize() -> io::Result<()> {
    let root =
        CString::new("/").map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;

    unsafe {
        let pid = libc::fork();
        if pid < 0 {
            return Err(io::Error::last_os_error());
        }
        if pid > 0 {
            std::process::exit(0);
        }

        if libc::setsid() < 0 {
            return Err(io::Error::last_os_error());
        }

        let pid = libc::fork();
        if pid < 0 {
            return Err(io::Error::last_os_error());
        }
        if pid > 0 {
            std::process::exit(0);
        }

        libc::umask(0);

        if libc::chdir(root.as_ptr()) != 0 {
            return Err(io::Error::last_os_error());
        }
    }

    redirect_stdio()?;
    close_open_fds();

    Ok(())
}

#[cfg(unix)]
fn redirect_stdio() -> io::Result<()> {
    let devnull_path = CString::new("/dev/null")
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    let devnull = unsafe { libc::open(devnull_path.as_ptr(), libc::O_RDWR) };
    if devnull < 0 {
        return Err(io::Error::last_os_error());
    }

    if unsafe { libc::dup2(devnull, libc::STDIN_FILENO) } < 0 {
        let error = io::Error::last_os_error();
        unsafe {
            libc::close(devnull);
        }
        return Err(error);
    }

    if unsafe { libc::dup2(devnull, libc::STDOUT_FILENO) } < 0 {
        let error = io::Error::last_os_error();
        unsafe {
            libc::close(devnull);
        }
        return Err(error);
    }

    if unsafe { libc::dup2(devnull, libc::STDERR_FILENO) } < 0 {
        let error = io::Error::last_os_error();
        unsafe {
            libc::close(devnull);
        }
        return Err(error);
    }

    if devnull > libc::STDERR_FILENO {
        unsafe {
            libc::close(devnull);
        }
    }

    Ok(())
}

#[cfg(unix)]
fn close_open_fds() {
    let max = unsafe { libc::sysconf(libc::_SC_OPEN_MAX) };
    if max <= 0 {
        return;
    }

    let max = max as libc::c_int;
    for fd in 3..max {
        unsafe {
            libc::close(fd);
        }
    }
}
