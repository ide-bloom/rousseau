# Contributing to Rousseau

Thanks for helping make AI agents safer to run. Bug reports, false-positive reports, rules, adapters and code are all welcome.

## Development setup

- Windows 11 x64 or arm64, Rust stable with the MSVC toolchain (Visual Studio Build Tools, "Desktop development with C++"), Python 3.12+, Git.
- An elevated terminal is needed to exercise the ETW sensor (`rousseau run`, integration tests).

```powershell
cargo build
cargo test --workspace
python -m pip install -e "lab[dev]"
cd lab; pytest; mypy; cd ..; ruff check .; ruff format --check .
```

Integration tests (elevated, Python on PATH):

```powershell
cargo test -p rousseau-etw --features integration
cargo test -p rousseau-cli --features integration -- --test-threads 1
```

## Before opening a pull request

- `cargo fmt --all`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace`.
- `ruff check .`, `ruff format --check .`, `mypy` and `pytest` in `lab/`.
- Update the docs when behaviour changes; the README describes only what exists.
- Add a `CHANGELOG.md` entry under *Unreleased*.

## Code standards

- **Rust:** no `unwrap`/`expect` outside tests unless the case is truly infallible, with a comment saying why. Typed errors (`thiserror`) in libraries, `anyhow` in the CLI. Minimal `unsafe`, each block with a `// SAFETY:` comment. Bounded channels with backpressure; nothing on a sensor path may block on the UI or the network.
- **Python:** full type hints (`mypy --strict` clean), no bare `except`.
- **Both:** doc comments on public items; comments explain *why*, not *what*; readable code a security reviewer can audit.
- Never commit literal secret-shaped strings (tokens, keys) in tests; build fixtures from fragments at runtime.

## Rules

1. Add the rule to a file in `rules/` with every field: `owasp` (verified ASI ids), `mitre`, `description`, `falsepositives`.
2. Add a conformance case in `conformance/cases/builtin-rules.yaml` showing what fires and what must not.
3. Check it against synthetic data: `rousseau-lab synth --scenario all -o all.rousseau && rousseau-lab test-rule rules/your-file.yaml --against all.rousseau`.

Changing rule-engine **semantics** requires matching changes in Rust (`crates/rousseau-core/src/rules`) and Python (`lab/src/rousseau_lab/rules.py`), plus new conformance cases.

## Agent signatures and client configs

Agent executables (`crates/rousseau-adapters/src/agents.toml`) and MCP client config locations (`crates/rousseau-mcp/src/clients.toml`) change over time. Please cite the vendor documentation or an observed install path in your pull request. Client config changes need a golden file pair in `crates/rousseau-mcp/tests/golden/` (regenerate with `UPDATE_GOLDEN=1`).

## Pull requests

Keep them focused, explain the motivation, and link related issues. By contributing you agree that your contribution is licensed under the Apache License 2.0.

## Releasing

Push a tag `vX.Y.Z` after updating `CHANGELOG.md`. The release workflow builds and zips both architectures, writes `SHA256SUMS`, attests build provenance and creates the GitHub release with notes from the changelog.

Publishing `rousseau-lab` to PyPI is opt-in: configure a trusted publisher on pypi.org (repository `ide-bloom/rousseau`, workflow `release.yml`, environment `pypi`), then set the repository variable `PYPI_TRUSTED_PUBLISHING` to `true`. Until then the PyPI job is skipped, the release still succeeds, and the run summary explains how to enable it.
