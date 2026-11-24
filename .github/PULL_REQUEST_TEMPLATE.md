## Summary

<!-- What does this change and why? Link issues. -->

## Checklist

- [ ] `cargo fmt --all` and `cargo clippy --workspace --all-targets -- -D warnings` are clean
- [ ] `cargo test --workspace` passes
- [ ] `ruff check .`, `ruff format --check .`, `mypy` and `pytest` (in `lab/`) pass, if Python changed
- [ ] Rule-engine semantics changed? Rust, Python and `conformance/` updated together
- [ ] New or changed rules carry OWASP, MITRE, description and false-positive notes, plus a conformance case
- [ ] Docs and README describe the new behaviour
- [ ] `CHANGELOG.md` updated under *Unreleased*
- [ ] No secret-shaped literals added (build fixtures from fragments)
