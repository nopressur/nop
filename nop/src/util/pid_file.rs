// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

use std::fs;
use std::io;
use std::io::Write;
use std::path::{Path, PathBuf};

pub const PID_FILE_NAME: &str = "nop.pid";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PidFileStatus {
    Missing,
    Stale { pid: Option<u32> },
    Running { pid: u32 },
}

#[derive(Debug)]
pub struct PidFileGuard {
    path: PathBuf,
}

impl Drop for PidFileGuard {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

pub fn pid_file_path(runtime_root: &Path) -> PathBuf {
    runtime_root.join(PID_FILE_NAME)
}

pub fn check_pid_file(path: &Path) -> io::Result<PidFileStatus> {
    let contents = match fs::read_to_string(path) {
        Ok(contents) => contents,
        Err(err) if err.kind() == io::ErrorKind::NotFound => {
            return Ok(PidFileStatus::Missing);
        }
        Err(err) => return Err(err),
    };

    let parsed_pid = parse_pid(&contents).filter(|pid| *pid > 0);
    let pid = match parsed_pid {
        Some(pid) => pid,
        None => return Ok(PidFileStatus::Stale { pid: None }),
    };

    if is_pid_running(pid)? {
        Ok(PidFileStatus::Running { pid })
    } else {
        Ok(PidFileStatus::Stale { pid: Some(pid) })
    }
}

pub fn cleanup_stale_pid_file(path: &Path) -> io::Result<PidFileStatus> {
    let status = check_pid_file(path)?;
    if matches!(status, PidFileStatus::Stale { .. })
        && let Err(err) = fs::remove_file(path)
        && err.kind() != io::ErrorKind::NotFound
    {
        return Err(err);
    }
    Ok(status)
}

pub fn create_pid_file(path: &Path) -> io::Result<PidFileGuard> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    let pid = std::process::id();
    let contents = format!("{}\n", pid);

    for _ in 0..2 {
        match fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
        {
            Ok(mut file) => {
                file.write_all(contents.as_bytes())?;
                return Ok(PidFileGuard {
                    path: path.to_path_buf(),
                });
            }
            Err(err) if err.kind() == io::ErrorKind::AlreadyExists => match check_pid_file(path)? {
                PidFileStatus::Running { pid } => {
                    return Err(io::Error::new(
                        io::ErrorKind::AlreadyExists,
                        format!("pid file already exists for running process {}", pid),
                    ));
                }
                PidFileStatus::Stale { .. } => {
                    if let Err(err) = fs::remove_file(path)
                        && err.kind() != io::ErrorKind::NotFound
                    {
                        return Err(err);
                    }
                }
                PidFileStatus::Missing => {}
            },
            Err(err) => return Err(err),
        }
    }

    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "pid file already exists",
    ))
}

fn parse_pid(contents: &str) -> Option<u32> {
    let trimmed = contents.trim();
    if trimmed.is_empty() {
        return None;
    }
    trimmed.parse::<u32>().ok()
}

#[cfg(target_os = "macos")]
fn is_pid_running(pid: u32) -> io::Result<bool> {
    let mut info: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
    let info_size = std::mem::size_of::<libc::proc_bsdinfo>() as libc::c_int;
    let result = unsafe {
        libc::proc_pidinfo(
            pid as libc::c_int,
            libc::PROC_PIDTBSDINFO,
            0,
            &mut info as *mut _ as *mut libc::c_void,
            info_size,
        )
    };

    if result == info_size {
        if info.pbi_status == libc::SZOMB {
            return Ok(false);
        }
        return Ok(true);
    }

    let err = io::Error::last_os_error();
    match err.raw_os_error() {
        Some(libc::ESRCH) => Ok(false),
        Some(libc::EPERM) => Ok(true),
        _ => is_pid_running_kill(pid),
    }
}

#[cfg(target_os = "linux")]
fn is_pid_running(pid: u32) -> io::Result<bool> {
    let stat_path = Path::new("/proc").join(pid.to_string()).join("stat");
    match fs::read_to_string(&stat_path) {
        Ok(contents) => {
            if let Some(state) = parse_proc_stat_state(&contents) {
                return Ok(state != 'Z');
            }
        }
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(_) => {}
    }

    is_pid_running_kill(pid)
}

#[cfg(all(unix, not(any(target_os = "linux", target_os = "macos"))))]
fn is_pid_running(pid: u32) -> io::Result<bool> {
    is_pid_running_kill(pid)
}

#[cfg(unix)]
fn is_pid_running_kill(pid: u32) -> io::Result<bool> {
    let result = unsafe { libc::kill(pid as libc::pid_t, 0) };
    if result == 0 {
        return Ok(true);
    }

    let err = io::Error::last_os_error();
    match err.raw_os_error() {
        Some(libc::ESRCH) => Ok(false),
        Some(libc::EPERM) => Ok(true),
        _ => Err(err),
    }
}

#[cfg(not(unix))]
fn is_pid_running(_pid: u32) -> io::Result<bool> {
    Ok(false)
}

#[cfg(target_os = "linux")]
fn parse_proc_stat_state(stat: &str) -> Option<char> {
    let end = stat.rfind(')')?;
    let rest = stat.get(end + 1..)?.trim_start();
    rest.chars().next()
}

#[cfg(test)]
mod tests {
    use super::{PidFileStatus, check_pid_file, cleanup_stale_pid_file, pid_file_path};
    use crate::util::test_fixtures::TestFixtureRoot;
    use std::fs;

    #[test]
    fn pid_file_missing_is_reported() {
        let fixture = TestFixtureRoot::new_unique("pid-missing").unwrap();
        let pid_path = pid_file_path(fixture.path());

        let status = check_pid_file(&pid_path).unwrap();
        assert!(matches!(status, PidFileStatus::Missing));
    }

    #[test]
    fn invalid_pid_file_is_cleaned() {
        let fixture = TestFixtureRoot::new_unique("pid-stale").unwrap();
        let pid_path = pid_file_path(fixture.path());
        fs::write(&pid_path, "not-a-pid").unwrap();

        let status = cleanup_stale_pid_file(&pid_path).unwrap();
        assert!(matches!(status, PidFileStatus::Stale { .. }));
        assert!(!pid_path.exists());
    }

    #[cfg(unix)]
    #[test]
    fn running_pid_is_detected() {
        let fixture = TestFixtureRoot::new_unique("pid-running").unwrap();
        let pid_path = pid_file_path(fixture.path());
        fs::write(&pid_path, format!("{}\n", std::process::id())).unwrap();

        let status = check_pid_file(&pid_path).unwrap();
        assert!(matches!(status, PidFileStatus::Running { pid } if pid == std::process::id()));
    }
}
