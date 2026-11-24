//! File-system ACLs for the data directory.

use std::path::Path;

use anyhow::{Context, Result};
use windows::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1, SE_FILE_OBJECT, SetNamedSecurityInfoW,
};
use windows::Win32::Security::{
    DACL_SECURITY_INFORMATION, GetSecurityDescriptorDacl, PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR,
};
use windows::core::{HSTRING, PCWSTR};

/// SDDL for the data directory: SYSTEM and Administrators full control,
/// the installing user modify, inheritance to children, no inherited ACEs.
pub fn data_dir_sddl(user_sid: Option<&str>) -> String {
    let mut s = String::from("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)");
    if let Some(sid) = user_sid {
        s.push_str(&format!("(A;OICI;0x1301bf;;;{sid})"));
    }
    s
}

/// Replaces the DACL of `path` with [`data_dir_sddl`].
pub fn restrict_dir(path: &Path, user_sid: Option<&str>) -> Result<()> {
    let sddl = HSTRING::from(data_dir_sddl(user_sid));
    let mut sd = PSECURITY_DESCRIPTOR::default();
    // SAFETY: `sddl` is NUL-terminated; `sd` is freed with LocalFree below.
    unsafe { ConvertStringSecurityDescriptorToSecurityDescriptorW(&sddl, SDDL_REVISION_1, &mut sd, None) }.context("invalid SDDL")?;
    let mut present = windows::core::BOOL::default();
    let mut defaulted = windows::core::BOOL::default();
    let mut dacl = std::ptr::null_mut();
    // SAFETY: `sd` is a valid self-relative descriptor; out-pointers are valid.
    let r = unsafe { GetSecurityDescriptorDacl(sd, &mut present, &mut dacl, &mut defaulted) };
    let wpath = HSTRING::from(path.as_os_str());
    let status = if r.is_ok() {
        // SAFETY: `wpath` is NUL-terminated and `dacl` points into `sd`, which is still alive.
        unsafe {
            SetNamedSecurityInfoW(
                PCWSTR(wpath.as_ptr()),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                None,
                None,
                Some(dacl),
                None,
            )
        }
    } else {
        windows::Win32::Foundation::WIN32_ERROR(1)
    };
    // SAFETY: allocated by ConvertStringSecurityDescriptorToSecurityDescriptorW.
    unsafe {
        let _ = windows::Win32::Foundation::LocalFree(Some(windows::Win32::Foundation::HLOCAL(sd.0)));
    }
    if status.0 != 0 {
        anyhow::bail!("SetNamedSecurityInfoW failed for {} (error {})", path.display(), status.0);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sddl_shapes() {
        assert_eq!(data_dir_sddl(None), "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)");
        assert!(data_dir_sddl(Some("S-1-5-21-1")).ends_with("(A;OICI;0x1301bf;;;S-1-5-21-1)"));
    }

    #[test]
    fn restricts_a_temp_dir() {
        let dir = tempfile::tempdir().unwrap();
        let sid = rousseau_etw::process::current_user_sid();
        restrict_dir(dir.path(), sid.as_deref()).unwrap();
        // We granted ourselves modify rights, so we can still write.
        std::fs::write(dir.path().join("x"), "y").unwrap();
    }
}
