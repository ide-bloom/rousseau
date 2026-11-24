//! The MCP layer of Rousseau.
//!
//! * [`framing`] and [`jsonrpc`]: newline-delimited JSON-RPC parsing that
//!   tolerates partial and multi-message reads.
//! * [`canonical`] and [`pinning`]: trust-on-first-use (or strict) pinning of
//!   tool definitions and rug-pull detection.
//! * [`inspect`]: content inspectors for hidden Unicode, injected
//!   instructions, tool shadowing, secrets, exfiltration URLs and dangerous
//!   arguments.
//! * [`observer`]: turns observed MCP traffic into Rousseau events and
//!   decides whether a call must be blocked.
//! * [`stdio`] and [`http`]: the two proxies (`rousseau wrap`,
//!   `rousseau wrap-http`).
//! * [`clients`]: discovery and format-preserving rewriting of MCP client
//!   configuration files (`rousseau protect` / `unprotect`).

pub mod canonical;
pub mod clients;
pub mod framing;
pub mod http;
pub mod inspect;
pub mod jsonrpc;
pub mod jsonspan;
pub mod observer;
pub mod pinning;
pub mod stdio;

/// Installs the `ring` TLS crypto provider process-wide (idempotent).
/// reqwest is built without a bundled provider so the same TLS stack builds
/// for both x64 and arm64 MSVC targets.
pub fn install_crypto_provider() {
    // Err means a provider is already installed, which is fine.
    let _ = rustls::crypto::ring::default_provider().install_default();
}
