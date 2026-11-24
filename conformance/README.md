# Rule-engine conformance suite

Both rule engines (Rust `rousseau-core` and Python `rousseau_lab.rules`) run
every case in `cases/`. A case passes only if the engine produces exactly the
expected matches, in order. This keeps a rule's behaviour the same live
(`rousseau run`) and offline (`rousseau-lab test-rule`).

## Case format

Each `cases/*.yaml` file holds one or more YAML documents separated by `---`.
Each document is one case:

```yaml
name: human-readable description
rule:            # an inline rule (same format as rules/*.yaml) …
  id: C-001
  title: …
  severity: low
  detection: { where: { field: kind, equals: file.read } }
# … or a reference to a built-in rule, relative to the repository root:
# rule_ref: { file: rules/credential-access.yaml, id: ROU-001 }
invalid: false   # true: loading the rule must fail; events/expected are ignored
events:          # processed in order; each needs integer `id` and `ts` (Unix ms)
  - { id: 1, ts: 1000, kind: file.read, file: { path: 'C:\x' } }
expected:        # matches in emission order; `events` lists evidence ids
  - { events: [1] }
```

## Running

```powershell
cargo test -p rousseau-core --test conformance
cd lab; pytest tests/test_conformance.py
```

When you change rule semantics, add a case here first; both engines must pass
it before the change can merge.
