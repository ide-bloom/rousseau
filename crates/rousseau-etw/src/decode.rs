//! Platform-independent decoding helpers for ETW payloads.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Decodes a Kernel-Network address field: 4 bytes (IPv4, network order)
/// or 16 bytes (IPv6).
pub fn ip_from_bytes(b: &[u8]) -> Option<IpAddr> {
    match b.len() {
        4 => Some(IpAddr::V4(Ipv4Addr::new(b[0], b[1], b[2], b[3]))),
        16 => {
            let mut a = [0u8; 16];
            a.copy_from_slice(b);
            Some(IpAddr::V6(Ipv6Addr::from(a)))
        }
        _ => None,
    }
}

/// Decodes a Kernel-Network port field (network byte order in memory).
pub fn port_from_bytes(b: &[u8]) -> Option<u16> {
    (b.len() == 2).then(|| u16::from_be_bytes([b[0], b[1]]))
}

/// Registry value types.
pub const REG_SZ: u32 = 1;
pub const REG_EXPAND_SZ: u32 = 2;
pub const REG_BINARY: u32 = 3;
pub const REG_DWORD: u32 = 4;
pub const REG_MULTI_SZ: u32 = 7;
pub const REG_QWORD: u32 = 11;

/// Renders captured registry data for display and rules.
pub fn registry_data(ty: u32, data: &[u8]) -> String {
    match ty {
        REG_SZ | REG_EXPAND_SZ | REG_MULTI_SZ => {
            let units: Vec<u16> = data.as_chunks::<2>().0.iter().map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
            String::from_utf16_lossy(&units).trim_end_matches('\0').replace('\0', " | ")
        }
        REG_DWORD if data.len() >= 4 => u32::from_le_bytes([data[0], data[1], data[2], data[3]]).to_string(),
        REG_QWORD if data.len() >= 8 => {
            let mut a = [0u8; 8];
            a.copy_from_slice(&data[..8]);
            u64::from_le_bytes(a).to_string()
        }
        _ => {
            let hex: String = data.iter().take(64).map(|b| format!("{b:02x}")).collect();
            if data.len() > 64 { format!("{hex}…") } else { hex }
        }
    }
}

/// Lower-case fragments of registry keys that matter for persistence and
/// defence evasion. Only writes to matching keys are recorded.
const SECURITY_KEYS: &[&str] = &[
    r"\software\microsoft\windows\currentversion\run",
    r"\software\wow6432node\microsoft\windows\currentversion\run",
    r"\software\microsoft\windows\currentversion\policies\explorer\run",
    r"\software\microsoft\windows\currentversion\explorer\startupapproved",
    r"\software\microsoft\windows\currentversion\explorer\shell folders",
    r"\software\microsoft\windows\currentversion\explorer\user shell folders",
    r"\software\microsoft\windows nt\currentversion\winlogon",
    r"\software\microsoft\windows nt\currentversion\windows",
    r"\software\microsoft\windows nt\currentversion\image file execution options",
    r"\software\microsoft\windows nt\currentversion\silentprocessexit",
    r"\software\microsoft\windows defender",
    r"\software\policies\microsoft\windows defender",
    r"\system\currentcontrolset\services\",
    r"\system\currentcontrolset\control\session manager",
    r"\software\microsoft\command processor",
    r"\inprocserver32",
    r"\localserver32",
    r"\shell\open\command",
    r"\environment",
    r"\software\microsoft\powershell",
    r"\software\microsoft\windows\currentversion\app paths",
];

/// True if writes under `key` (normalized, e.g. `HKCU\Software\…`) should be recorded.
pub fn is_security_relevant_key(key: &str) -> bool {
    let k = key.to_lowercase();
    SECURITY_KEYS.iter().any(|frag| k.contains(frag))
}

/// Joins a registry base name and relative name.
pub fn join_registry(base: &str, relative: &str) -> String {
    if relative.starts_with('\\') && relative.to_ascii_uppercase().starts_with(r"\REGISTRY") {
        return relative.to_string();
    }
    match (base.is_empty(), relative.is_empty()) {
        (true, _) => relative.to_string(),
        (false, true) => base.to_string(),
        (false, false) => format!("{}\\{}", base.trim_end_matches('\\'), relative.trim_start_matches('\\')),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn addresses_and_ports() {
        assert_eq!(ip_from_bytes(&[127, 0, 0, 1]).unwrap().to_string(), "127.0.0.1");
        let mut v6 = [0u8; 16];
        v6[15] = 1;
        assert_eq!(ip_from_bytes(&v6).unwrap().to_string(), "::1");
        assert!(ip_from_bytes(&[1, 2, 3]).is_none());
        // 443 = 0x01BB, stored big-endian.
        assert_eq!(port_from_bytes(&[0x01, 0xBB]), Some(443));
        assert_eq!(port_from_bytes(&[1]), None);
    }

    #[test]
    fn registry_values() {
        let s: Vec<u8> = "C:\\x.exe\0".encode_utf16().flat_map(u16::to_le_bytes).collect();
        assert_eq!(registry_data(REG_SZ, &s), "C:\\x.exe");
        assert_eq!(registry_data(REG_DWORD, &1u32.to_le_bytes()), "1");
        assert_eq!(registry_data(REG_BINARY, &[0xde, 0xad]), "dead");
        let m: Vec<u8> = "a\0b\0\0".encode_utf16().flat_map(u16::to_le_bytes).collect();
        assert_eq!(registry_data(REG_MULTI_SZ, &m), "a | b");
    }

    #[test]
    fn key_filter_and_join() {
        assert!(is_security_relevant_key(r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run"));
        assert!(is_security_relevant_key(r"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths"));
        assert!(is_security_relevant_key(r"HKLM\SYSTEM\CurrentControlSet\Services\evil"));
        assert!(!is_security_relevant_key(r"HKCU\Software\Microsoft\Notepad"));
        assert_eq!(join_registry(r"\REGISTRY\MACHINE\SOFTWARE", "Foo"), r"\REGISTRY\MACHINE\SOFTWARE\Foo");
        assert_eq!(join_registry("x", r"\REGISTRY\USER\S-1"), r"\REGISTRY\USER\S-1");
        assert_eq!(join_registry("", "rel"), "rel");
    }
}
