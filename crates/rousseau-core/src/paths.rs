//! Normalization of NT device paths and registry paths into the forms users
//! and rules expect (`C:\…`, `\\server\share\…`, `HKLM\…`, `HKCU\…`).
//!
//! The device-to-drive table is built by the ETW crate with
//! `QueryDosDeviceW`; the logic here is pure so it can be tested anywhere.

/// Maps `\Device\HarddiskVolumeN` style prefixes to drive letters.
#[derive(Debug, Clone, Default)]
pub struct DeviceMap {
    /// `(device prefix lower-case, "C:")`, longest prefixes first.
    entries: Vec<(String, String)>,
    system_root: Option<String>,
}

impl DeviceMap {
    /// Builds a map from `(device, drive)` pairs, e.g.
    /// `("\Device\HarddiskVolume3", "C:")`.
    pub fn new(pairs: impl IntoIterator<Item = (String, String)>, system_root: Option<String>) -> Self {
        let mut entries: Vec<(String, String)> = pairs.into_iter().map(|(d, l)| (d.trim_end_matches('\\').to_lowercase(), l)).collect();
        entries.sort_by_key(|e| std::cmp::Reverse(e.0.len()));
        Self { entries, system_root }
    }

    /// Converts an NT path to a Win32 path. Unknown forms are returned as-is.
    pub fn normalize(&self, path: &str) -> String {
        let p = path.trim();
        for prefix in [r"\??\UNC\", r"\\?\UNC\"] {
            if let Some(rest) = strip_prefix_ci(p, prefix) {
                return format!(r"\\{rest}");
            }
        }
        for prefix in [r"\??\", r"\\?\", r"\\.\"] {
            if let Some(rest) = strip_prefix_ci(p, prefix)
                && rest.len() >= 2
                && rest.as_bytes()[1] == b':'
            {
                return rest.to_string();
            }
        }
        if let Some(rest) = strip_prefix_ci(p, r"\SystemRoot")
            && let Some(root) = &self.system_root
        {
            return format!("{}{rest}", root.trim_end_matches('\\'));
        }
        if let Some(rest) = strip_prefix_ci(p, r"\Device\Mup\") {
            return format!(r"\\{rest}");
        }
        if let Some(rest) = strip_prefix_ci(p, r"\Device\LanmanRedirector\") {
            // `\Device\LanmanRedirector\;Z:0000000000012345\server\share\x`
            let rest = if rest.starts_with(';') { rest.split_once('\\').map(|(_, r)| r).unwrap_or(rest) } else { rest };
            return format!(r"\\{rest}");
        }
        let lower = p.to_lowercase();
        for (dev, letter) in &self.entries {
            if lower.starts_with(dev.as_str()) {
                let rest = &p[dev.len()..];
                if rest.is_empty() || rest.starts_with('\\') {
                    return format!("{letter}{rest}");
                }
            }
        }
        p.to_string()
    }
}

fn strip_prefix_ci<'a>(s: &'a str, prefix: &str) -> Option<&'a str> {
    if s.len() >= prefix.len() && s.is_char_boundary(prefix.len()) && s[..prefix.len()].eq_ignore_ascii_case(prefix) {
        Some(&s[prefix.len()..])
    } else {
        None
    }
}

/// Converts a kernel registry path to the familiar hive form.
///
/// `\REGISTRY\USER\<sid>\…` becomes `HKCU\…` because agent processes run as
/// the interactive user; `<sid>_Classes` becomes `HKCU\Software\Classes\…`.
pub fn normalize_registry(path: &str) -> String {
    let p = path.trim();
    if let Some(rest) = strip_prefix_ci(p, r"\REGISTRY\MACHINE") {
        return format!("HKLM{rest}");
    }
    if let Some(rest) = strip_prefix_ci(p, r"\REGISTRY\USER\") {
        let (sid, tail) = rest.split_once('\\').unwrap_or((rest, ""));
        let tail = if tail.is_empty() { String::new() } else { format!(r"\{tail}") };
        if sid.to_lowercase().ends_with("_classes") {
            return format!(r"HKCU\Software\Classes{tail}");
        }
        if sid.eq_ignore_ascii_case(".default") || sid.starts_with("S-1-5-18") {
            return format!(r"HKU\{sid}{tail}");
        }
        return format!("HKCU{tail}");
    }
    p.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn map() -> DeviceMap {
        DeviceMap::new(
            [(r"\Device\HarddiskVolume3".into(), "C:".into()), (r"\Device\HarddiskVolume12".into(), "D:".into())],
            Some(r"C:\Windows".into()),
        )
    }

    #[test]
    fn devices() {
        let m = map();
        assert_eq!(m.normalize(r"\Device\HarddiskVolume3\Users\a\.ssh\id_rsa"), r"C:\Users\a\.ssh\id_rsa");
        assert_eq!(m.normalize(r"\device\harddiskvolume12\x"), r"D:\x");
        // Volume1 must not match Volume12's prefix and vice versa.
        assert_eq!(m.normalize(r"\Device\HarddiskVolume1\x"), r"\Device\HarddiskVolume1\x");
        assert_eq!(m.normalize(r"\Device\HarddiskVolume3"), "C:");
        assert_eq!(m.normalize(r"\??\C:\Temp\a.exe"), r"C:\Temp\a.exe");
        assert_eq!(m.normalize(r"\\?\C:\Temp\a.exe"), r"C:\Temp\a.exe");
        assert_eq!(m.normalize(r"\??\UNC\srv\share\f"), r"\\srv\share\f");
        assert_eq!(m.normalize(r"\SystemRoot\System32\ntdll.dll"), r"C:\Windows\System32\ntdll.dll");
        assert_eq!(m.normalize(r"\Device\Mup\srv\share\f"), r"\\srv\share\f");
        assert_eq!(m.normalize(r"\Device\LanmanRedirector\;Z:000000000001\srv\share\f"), r"\\srv\share\f");
        assert_eq!(m.normalize(r"C:\already"), r"C:\already");
    }

    #[test]
    fn registry() {
        assert_eq!(normalize_registry(r"\REGISTRY\MACHINE\SOFTWARE\Microsoft"), r"HKLM\SOFTWARE\Microsoft");
        assert_eq!(
            normalize_registry(r"\REGISTRY\USER\S-1-5-21-1-2-3-1001\Software\Microsoft\Windows\CurrentVersion\Run"),
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run"
        );
        assert_eq!(normalize_registry(r"\REGISTRY\USER\S-1-5-21-1-2-3-1001_Classes\ms-settings"), r"HKCU\Software\Classes\ms-settings");
        assert_eq!(normalize_registry(r"\REGISTRY\USER\S-1-5-18\Software"), r"HKU\S-1-5-18\Software");
        assert_eq!(normalize_registry(r"HKLM\X"), r"HKLM\X");
    }
}
