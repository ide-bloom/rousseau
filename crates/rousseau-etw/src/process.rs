//! Windows process utilities: snapshots, command lines, working
//! directories, Authenticode signers, privilege checks, device-path
//! mapping and process-tree suspension.
//!
//! All functions are best effort: a process can exit between two calls and
//! protected processes refuse most access, so failures yield `None`.

use std::collections::HashMap;
use std::ffi::c_void;
use std::sync::{Mutex, OnceLock};

use rousseau_core::event::{ProcessInfo, file_name_lower};
use rousseau_core::paths::DeviceMap;
use rousseau_core::time::filetime_to_ms;
use windows::Wdk::System::Threading::{NtQueryInformationProcess, ProcessBasicInformation, ProcessCommandLineInformation};
use windows::Win32::Foundation::{CloseHandle, FILETIME, HANDLE, HWND, UNICODE_STRING};
use windows::Win32::Security::Cryptography::{CERT_NAME_SIMPLE_DISPLAY_TYPE, CertGetNameStringW};
use windows::Win32::Security::WinTrust::{
    WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_DATA, WINTRUST_DATA_0, WINTRUST_FILE_INFO, WTD_CACHE_ONLY_URL_RETRIEVAL, WTD_CHOICE_FILE,
    WTD_REVOKE_NONE, WTD_STATEACTION_CLOSE, WTD_STATEACTION_VERIFY, WTD_UI_NONE, WTHelperGetProvSignerFromChain,
    WTHelperProvDataFromStateData, WinVerifyTrust,
};
use windows::Win32::Security::{GetTokenInformation, TOKEN_ELEVATION, TOKEN_QUERY, TOKEN_USER, TokenElevation, TokenUser};
use windows::Win32::Storage::FileSystem::QueryDosDeviceW;
use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW, TH32CS_SNAPPROCESS, TH32CS_SNAPTHREAD, THREADENTRY32,
    Thread32First, Thread32Next,
};
use windows::Win32::System::Threading::{
    GetCurrentProcess, GetProcessTimes, IsProcessCritical, OpenProcess, OpenProcessToken, OpenThread, PROCESS_BASIC_INFORMATION,
    PROCESS_NAME_WIN32, PROCESS_QUERY_INFORMATION, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_VM_READ, QueryFullProcessImageNameW,
    ResumeThread, SuspendThread, THREAD_SUSPEND_RESUME,
};
use windows::core::{PCWSTR, PWSTR};

/// Closes a handle on drop.
struct Owned(HANDLE);

impl Drop for Owned {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            // SAFETY: the handle was returned by a successful Open*/Create*
            // call, is owned by this wrapper and is closed exactly once.
            unsafe {
                let _ = CloseHandle(self.0);
            }
        }
    }
}

fn open(pid: u32, rights: windows::Win32::System::Threading::PROCESS_ACCESS_RIGHTS) -> Option<Owned> {
    // SAFETY: OpenProcess has no memory-safety preconditions; failure is reported as Err.
    unsafe { OpenProcess(rights, false, pid) }.ok().map(Owned)
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Full Win32 image path of a process.
pub fn image_path(pid: u32) -> Option<String> {
    let h = open(pid, PROCESS_QUERY_LIMITED_INFORMATION)?;
    let mut buf = vec![0u16; 32_768];
    let mut len = buf.len() as u32;
    // SAFETY: `buf` is a writable buffer of `len` UTF-16 units; the API
    // writes at most `len` units and updates `len` with the count written.
    unsafe { QueryFullProcessImageNameW(h.0, PROCESS_NAME_WIN32, PWSTR(buf.as_mut_ptr()), &mut len) }.ok()?;
    Some(String::from_utf16_lossy(&buf[..len as usize]))
}

/// Process creation time (Unix ms).
pub fn start_time(pid: u32) -> Option<i64> {
    let h = open(pid, PROCESS_QUERY_LIMITED_INFORMATION)?;
    let (mut c, mut e, mut k, mut u) = (FILETIME::default(), FILETIME::default(), FILETIME::default(), FILETIME::default());
    // SAFETY: all four out-pointers reference live, writable FILETIME values.
    unsafe { GetProcessTimes(h.0, &mut c, &mut e, &mut k, &mut u) }.ok()?;
    let ft = (i64::from(c.dwHighDateTime) << 32) | i64::from(c.dwLowDateTime);
    Some(filetime_to_ms(ft))
}

/// Command line via `NtQueryInformationProcess(ProcessCommandLineInformation)`.
pub fn command_line(pid: u32) -> Option<String> {
    let h = open(pid, PROCESS_QUERY_LIMITED_INFORMATION)?;
    let mut needed = 0u32;
    // SAFETY: querying with a null buffer and zero length only returns the required size.
    let _ = unsafe { NtQueryInformationProcess(h.0, ProcessCommandLineInformation, std::ptr::null_mut(), 0, &mut needed) };
    if needed == 0 || needed > 1 << 20 {
        return None;
    }
    // u64 storage keeps the UNICODE_STRING header pointer-aligned.
    let mut buf = vec![0u64; (needed as usize).div_ceil(8)];
    // SAFETY: `buf` provides at least `needed` writable bytes, suitably aligned for UNICODE_STRING.
    let status = unsafe {
        NtQueryInformationProcess(
            h.0,
            ProcessCommandLineInformation,
            buf.as_mut_ptr().cast::<c_void>(),
            (buf.len() * 8) as u32,
            &mut needed,
        )
    };
    if status.is_err() {
        return None;
    }
    // SAFETY: on success the buffer starts with a UNICODE_STRING whose Buffer
    // points inside `buf` and holds `Length` bytes of UTF-16.
    unsafe {
        let us = &*(buf.as_ptr().cast::<UNICODE_STRING>());
        if us.Buffer.is_null() || us.Length == 0 {
            return Some(String::new());
        }
        let units = std::slice::from_raw_parts(us.Buffer.0, usize::from(us.Length) / 2);
        Some(String::from_utf16_lossy(units))
    }
}

/// Reads a `T` from another process's memory.
fn read_remote<T: Copy + Default>(h: HANDLE, addr: usize) -> Option<T> {
    let mut v = T::default();
    let mut read = 0usize;
    // SAFETY: `v` is a valid, writable T; ReadProcessMemory copies at most size_of::<T>() bytes into it.
    unsafe { ReadProcessMemory(h, addr as *const c_void, (&mut v as *mut T).cast(), std::mem::size_of::<T>(), Some(&mut read)) }.ok()?;
    (read == std::mem::size_of::<T>()).then_some(v)
}

/// Current working directory, read from the target's PEB
/// (`ProcessParameters->CurrentDirectory.DosPath`). Offsets are for 64-bit
/// PEBs (x64 and arm64); WOW64 processes also have a 64-bit PEB.
pub fn cwd(pid: u32) -> Option<String> {
    const PEB_PROCESS_PARAMETERS: usize = 0x20;
    const PARAMS_CURRENT_DIRECTORY: usize = 0x38;
    let h = open(pid, PROCESS_QUERY_INFORMATION | PROCESS_VM_READ)?;
    let mut pbi = PROCESS_BASIC_INFORMATION::default();
    let mut ret = 0u32;
    // SAFETY: `pbi` is a writable PROCESS_BASIC_INFORMATION of the size passed.
    let status = unsafe {
        NtQueryInformationProcess(
            h.0,
            ProcessBasicInformation,
            (&mut pbi as *mut PROCESS_BASIC_INFORMATION).cast(),
            std::mem::size_of::<PROCESS_BASIC_INFORMATION>() as u32,
            &mut ret,
        )
    };
    if status.is_err() || pbi.PebBaseAddress.is_null() {
        return None;
    }
    let params: usize = read_remote(h.0, pbi.PebBaseAddress as usize + PEB_PROCESS_PARAMETERS)?;
    let len: u16 = read_remote(h.0, params + PARAMS_CURRENT_DIRECTORY)?;
    let buf_ptr: usize = read_remote(h.0, params + PARAMS_CURRENT_DIRECTORY + 8)?;
    if len == 0 || buf_ptr == 0 || len > 4_096 {
        return None;
    }
    let mut units = vec![0u16; usize::from(len) / 2];
    let mut read = 0usize;
    // SAFETY: `units` has room for `len` bytes; the read is bounded by that size.
    unsafe { ReadProcessMemory(h.0, buf_ptr as *const c_void, units.as_mut_ptr().cast(), usize::from(len), Some(&mut read)) }.ok()?;
    let s = String::from_utf16_lossy(&units[..read / 2]);
    Some(s.trim_end_matches('\\').to_string()).filter(|s| !s.is_empty()).map(|s| if s.ends_with(':') { format!("{s}\\") } else { s })
}

fn signer_cache() -> &'static Mutex<HashMap<String, Option<String>>> {
    static C: OnceLock<Mutex<HashMap<String, Option<String>>>> = OnceLock::new();
    C.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Subject of a valid embedded Authenticode signature (cached per path).
/// Catalog-signed or unsigned files return `None`.
pub fn signer(path: &str) -> Option<String> {
    let key = path.to_lowercase();
    if let Ok(c) = signer_cache().lock()
        && let Some(v) = c.get(&key)
    {
        return v.clone();
    }
    let result = verify_signer(path);
    if let Ok(mut c) = signer_cache().lock() {
        if c.len() > 4_096 {
            c.clear();
        }
        c.insert(key, result.clone());
    }
    result
}

fn verify_signer(path: &str) -> Option<String> {
    let wpath = wide(path);
    let mut file = WINTRUST_FILE_INFO {
        cbStruct: std::mem::size_of::<WINTRUST_FILE_INFO>() as u32,
        pcwszFilePath: PCWSTR(wpath.as_ptr()),
        ..WINTRUST_FILE_INFO::default()
    };
    let mut data = WINTRUST_DATA {
        cbStruct: std::mem::size_of::<WINTRUST_DATA>() as u32,
        dwUIChoice: WTD_UI_NONE,
        fdwRevocationChecks: WTD_REVOKE_NONE,
        dwUnionChoice: WTD_CHOICE_FILE,
        Anonymous: WINTRUST_DATA_0 { pFile: &mut file },
        dwStateAction: WTD_STATEACTION_VERIFY,
        dwProvFlags: WTD_CACHE_ONLY_URL_RETRIEVAL,
        ..WINTRUST_DATA::default()
    };
    let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    // SAFETY: `data`, `file`, `wpath` and `action` outlive both WinVerifyTrust
    // calls; the state handle opened by VERIFY is released by CLOSE below.
    unsafe {
        let status = WinVerifyTrust(HWND::default(), &mut action, (&mut data as *mut WINTRUST_DATA).cast());
        let mut name = None;
        if status == 0 {
            let prov = WTHelperProvDataFromStateData(data.hWVTStateData);
            if !prov.is_null() {
                let sgnr = WTHelperGetProvSignerFromChain(prov, 0, false, 0);
                if !sgnr.is_null() && (*sgnr).csCertChain > 0 && !(*sgnr).pasCertChain.is_null() {
                    let cert = (*(*sgnr).pasCertChain).pCert;
                    if !cert.is_null() {
                        let mut buf = [0u16; 512];
                        let n = CertGetNameStringW(cert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, None, Some(&mut buf));
                        if n > 1 {
                            name = Some(String::from_utf16_lossy(&buf[..(n - 1) as usize]));
                        }
                    }
                }
            }
        }
        data.dwStateAction = WTD_STATEACTION_CLOSE;
        let _ = WinVerifyTrust(HWND::default(), &mut action, (&mut data as *mut WINTRUST_DATA).cast());
        name
    }
}

/// Snapshot entry (pid, ppid, exe name).
fn toolhelp_processes() -> Vec<(u32, u32, String)> {
    let mut out = Vec::new();
    // SAFETY: CreateToolhelp32Snapshot has no preconditions; the handle is owned below.
    let Ok(snap) = (unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) }) else {
        return out;
    };
    let snap = Owned(snap);
    let mut e = PROCESSENTRY32W { dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32, ..PROCESSENTRY32W::default() };
    // SAFETY: `e` is initialized with the correct dwSize as the API requires.
    let mut ok = unsafe { Process32FirstW(snap.0, &mut e) }.is_ok();
    while ok {
        let len = e.szExeFile.iter().position(|c| *c == 0).unwrap_or(e.szExeFile.len());
        out.push((e.th32ProcessID, e.th32ParentProcessID, String::from_utf16_lossy(&e.szExeFile[..len]).to_lowercase()));
        // SAFETY: same snapshot handle and correctly sized entry.
        ok = unsafe { Process32NextW(snap.0, &mut e) }.is_ok();
    }
    out
}

/// Detailed info for one process. `deep` also reads the working directory
/// and verifies the signer (slower).
pub fn query(pid: u32, ppid: Option<u32>, name: Option<String>, deep: bool) -> ProcessInfo {
    let image = image_path(pid);
    let name = image.as_deref().map(file_name_lower).or(name);
    let signer = if deep { image.as_deref().and_then(signer) } else { None };
    ProcessInfo {
        pid,
        ppid,
        name,
        command_line: command_line(pid),
        start_time: start_time(pid),
        cwd: if deep { cwd(pid) } else { None },
        signer,
        image,
        exit_code: None,
    }
}

/// All running processes, parents before children where possible (sorted
/// by start time) so the process tree can be rebuilt from the snapshot.
/// `deep_for` decides which processes get the slow fields.
pub fn snapshot(deep_for: &dyn Fn(&str) -> bool) -> Vec<ProcessInfo> {
    let mut list: Vec<ProcessInfo> = toolhelp_processes()
        .into_iter()
        .filter(|(pid, _, _)| *pid > 4)
        .map(|(pid, ppid, name)| {
            let deep = deep_for(&name);
            query(pid, Some(ppid), Some(name), deep)
        })
        .collect();
    list.sort_by_key(|p| p.start_time.unwrap_or(0));
    list
}

/// Info about this process's parent (the MCP client launching `rousseau wrap`).
pub fn parent_of_current() -> Option<ProcessInfo> {
    let me = std::process::id();
    let procs = toolhelp_processes();
    let (_, ppid, _) = procs.iter().find(|(pid, _, _)| *pid == me)?;
    let (_, gp, name) = procs.iter().find(|(pid, _, _)| pid == ppid)?;
    let mut p = query(*ppid, Some(*gp), Some(name.clone()), true);
    // A parent that started after us is a reused PID, not our parent.
    if p.start_time? > start_time(me)? {
        return None;
    }
    p.pid = *ppid;
    Some(p)
}

/// This process as a [`ProcessInfo`].
pub fn current() -> ProcessInfo {
    let me = std::process::id();
    let ppid = toolhelp_processes().into_iter().find(|(p, _, _)| *p == me).map(|(_, pp, _)| pp);
    query(me, ppid, None, false)
}

/// True if the current process token is elevated.
pub fn is_elevated() -> bool {
    let mut token = HANDLE::default();
    // SAFETY: GetCurrentProcess returns a pseudo-handle; `token` receives an owned handle on success.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) }.is_err() {
        return false;
    }
    let token = Owned(token);
    let mut elev = TOKEN_ELEVATION::default();
    let mut len = 0u32;
    // SAFETY: `elev` is a writable TOKEN_ELEVATION of the size passed.
    let ok = unsafe {
        GetTokenInformation(
            token.0,
            TokenElevation,
            Some((&mut elev as *mut TOKEN_ELEVATION).cast()),
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut len,
        )
    };
    ok.is_ok() && elev.TokenIsElevated != 0
}

/// String SID of the current user (for DACLs).
pub fn current_user_sid() -> Option<String> {
    use windows::Win32::Security::Authorization::ConvertSidToStringSidW;
    let mut token = HANDLE::default();
    // SAFETY: see is_elevated.
    unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) }.ok()?;
    let token = Owned(token);
    let mut len = 0u32;
    // SAFETY: size query with no buffer.
    let _ = unsafe { GetTokenInformation(token.0, TokenUser, None, 0, &mut len) };
    if len == 0 {
        return None;
    }
    let mut buf = vec![0u64; (len as usize).div_ceil(8)];
    // SAFETY: `buf` has at least `len` writable, 8-byte aligned bytes.
    unsafe { GetTokenInformation(token.0, TokenUser, Some(buf.as_mut_ptr().cast()), len, &mut len) }.ok()?;
    // SAFETY: on success the buffer begins with a TOKEN_USER whose SID points inside `buf`.
    unsafe {
        let tu = &*(buf.as_ptr().cast::<TOKEN_USER>());
        let mut s = PWSTR::null();
        ConvertSidToStringSidW(tu.User.Sid, &mut s).ok()?;
        let out = s.to_string().ok();
        let _ = windows::Win32::Foundation::LocalFree(Some(windows::Win32::Foundation::HLOCAL(s.0.cast())));
        out
    }
}

/// Builds the NT-device → drive-letter map with `QueryDosDeviceW`.
pub fn device_map() -> DeviceMap {
    let mut pairs = Vec::new();
    for letter in b'A'..=b'Z' {
        let drive = format!("{}:", letter as char);
        let wdrive = wide(&drive);
        let mut buf = vec![0u16; 1_024];
        // SAFETY: `wdrive` is NUL-terminated; `buf` is a writable buffer whose length is passed via the slice.
        let n = unsafe { QueryDosDeviceW(PCWSTR(wdrive.as_ptr()), Some(&mut buf)) };
        if n == 0 {
            continue;
        }
        let first = buf.iter().position(|c| *c == 0).unwrap_or(n as usize);
        let target = String::from_utf16_lossy(&buf[..first]);
        if !target.is_empty() {
            pairs.push((target, drive));
        }
    }
    let system_root = std::env::var("SystemRoot").ok();
    DeviceMap::new(pairs, system_root)
}

/// Image names that are never suspended, whatever the rules say.
const NEVER_SUSPEND: &[&str] = &[
    "system",
    "smss.exe",
    "csrss.exe",
    "wininit.exe",
    "winlogon.exe",
    "services.exe",
    "lsass.exe",
    "lsaiso.exe",
    "svchost.exe",
    "explorer.exe",
    "dwm.exe",
    "fontdrvhost.exe",
    "msmpeng.exe",
    "conhost.exe",
    "rousseau.exe",
    "registry",
    "memcompression",
];

fn is_critical(pid: u32) -> bool {
    if pid <= 4 || pid == std::process::id() {
        return true;
    }
    let Some(h) = open(pid, PROCESS_QUERY_LIMITED_INFORMATION) else {
        // Cannot open it: treat as protected and leave it alone.
        return true;
    };
    let mut crit = windows::core::BOOL::default();
    // SAFETY: `crit` is a writable BOOL.
    let ok = unsafe { IsProcessCritical(h.0, &mut crit) }.is_ok();
    if ok && crit.as_bool() {
        return true;
    }
    image_path(pid).map(|p| NEVER_SUSPEND.contains(&file_name_lower(&p).as_str())).unwrap_or(true)
}

fn for_threads(pids: &[u32], mut f: impl FnMut(HANDLE) -> bool) -> usize {
    // SAFETY: CreateToolhelp32Snapshot has no preconditions; the handle is owned below.
    let Ok(snap) = (unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) }) else {
        return 0;
    };
    let snap = Owned(snap);
    let mut touched = std::collections::HashSet::new();
    let mut e = THREADENTRY32 { dwSize: std::mem::size_of::<THREADENTRY32>() as u32, ..THREADENTRY32::default() };
    // SAFETY: `e` has the correct dwSize.
    let mut ok = unsafe { Thread32First(snap.0, &mut e) }.is_ok();
    while ok {
        if pids.contains(&e.th32OwnerProcessID) {
            // SAFETY: OpenThread has no memory-safety preconditions.
            if let Ok(t) = unsafe { OpenThread(THREAD_SUSPEND_RESUME, false, e.th32ThreadID) } {
                let t = Owned(t);
                if f(t.0) {
                    touched.insert(e.th32OwnerProcessID);
                }
            }
        }
        // SAFETY: same snapshot and entry.
        ok = unsafe { Thread32Next(snap.0, &mut e) }.is_ok();
    }
    touched.len()
}

/// Suspends every thread of the given processes, skipping critical and
/// system processes. Returns how many processes were suspended.
pub fn suspend(pids: &[u32]) -> usize {
    let allowed: Vec<u32> = pids.iter().copied().filter(|p| !is_critical(*p)).collect();
    // SAFETY: `t` is a thread handle opened with THREAD_SUSPEND_RESUME.
    for_threads(&allowed, |t| unsafe { SuspendThread(t) } != u32::MAX)
}

/// Resumes processes suspended by [`suspend`].
pub fn resume(pids: &[u32]) -> usize {
    // SAFETY: `t` is a thread handle opened with THREAD_SUSPEND_RESUME.
    for_threads(pids, |t| unsafe { ResumeThread(t) } != u32::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn current_process_details() {
        let me = std::process::id();
        let img = image_path(me).unwrap();
        assert!(img.to_lowercase().ends_with(".exe"));
        assert!(command_line(me).unwrap().len() > 3);
        assert!(start_time(me).unwrap() > 1_600_000_000_000);
        let dir = cwd(me).unwrap();
        assert_eq!(dir.to_lowercase(), std::env::current_dir().unwrap().display().to_string().trim_end_matches('\\').to_lowercase());
        assert!(current().ppid.is_some());
    }

    #[test]
    fn devices_and_snapshot() {
        let m = device_map();
        let sys = std::env::var("SystemDrive").unwrap_or_else(|_| "C:".into());
        // The system drive maps from some \Device\HarddiskVolumeN.
        let probe = m.normalize(&format!(r"\??\{sys}\Windows"));
        assert!(probe.starts_with(&sys));
        let snap = snapshot(&|_| false);
        assert!(snap.iter().any(|p| p.pid == std::process::id()));
        assert!(current_user_sid().unwrap().starts_with("S-1-"));
    }

    #[test]
    fn signer_of_signed_binary() {
        // PowerShell 5.1 ships embedded-signed by Microsoft.
        let ps = format!(r"{}\System32\WindowsPowerShell\v1.0\powershell.exe", std::env::var("SystemRoot").unwrap());
        if let Some(s) = signer(&ps) {
            assert!(s.contains("Microsoft"), "{s}");
        }
        assert_eq!(signer(r"C:\definitely\not\here.exe"), None);
    }

    #[test]
    fn never_suspends_self_or_system() {
        assert!(is_critical(std::process::id()));
        assert!(is_critical(4));
        assert_eq!(suspend(&[std::process::id(), 4]), 0);
    }
}
