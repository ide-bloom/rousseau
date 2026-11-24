# Security policy

Rousseau is a security tool that runs with high privileges, so we take reports seriously.

## Reporting a vulnerability

Please **do not open a public issue**. Report privately through GitHub's [private vulnerability reporting](https://github.com/ide-bloom/rousseau/security/advisories/new) for this repository.

Include the affected version, your Windows build, steps to reproduce, and the impact you observed. We aim to acknowledge reports within 3 working days and to agree on a disclosure timeline with you, normally within 90 days.

## In scope

- Privilege escalation through the service, the named pipe, the data directory or the installer.
- Bypasses of dashboard authentication, CSP or the Host/Origin checks.
- Ways for an MCP server or tool output to execute code in, or crash, the proxy, the sensor or the dashboard.
- Detection bypasses that follow from a bug (rather than from the documented limitations in [docs/threat-model.md](docs/threat-model.md)).
- Tampering with tool pins or rules without the access the threat model assumes.

## Out of scope

- Limitations documented in the threat model, for example administrator-level malware disabling ETW.
- Findings that require an already-compromised administrator account.

## Supported versions

Security fixes go into the latest release.

## Verifying releases

Release zips are listed in `SHA256SUMS` and carry GitHub build-provenance attestations:

```powershell
gh attestation verify rousseau-v0.1.0-windows-x64.zip --repo ide-bloom/rousseau
```
