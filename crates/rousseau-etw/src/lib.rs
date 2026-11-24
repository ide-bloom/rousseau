//! ETW sensors and Windows process utilities.
//!
//! * [`providers`]: provider GUIDs, keywords and event ids, verified against
//!   the installed manifests (`docs/etw-providers.md` has the table).
//! * [`decode`]: platform-independent decoding helpers (addresses, ports,
//!   registry data, the security-relevant registry key filter).
//! * `sensor` (Windows): the real-time ETW session that turns kernel events
//!   into Rousseau events for processes inside tracked agent trees.
//! * `process` (Windows): process snapshots, command lines, working
//!   directories, signers, privilege checks and tree suspension.

pub mod decode;
pub mod providers;

#[cfg(windows)]
pub mod process;
#[cfg(windows)]
pub mod sensor;
