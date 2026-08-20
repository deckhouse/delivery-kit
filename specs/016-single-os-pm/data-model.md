# Data Model: Enforce a Single os-pm Directive

## Package directive

A `packages` list entry in an image’s `werf.yaml` configuration.

| Field | Source form | Meaning | Validation impact |
|---|---|---|---|
| `type` | `packages[].type` | Package ecosystem identifier | `os-pm` is the restricted type; other supported types remain repeatable. |
| `spec` | `packages[].spec` | Inline package list for `os-pm`, or a dependency manifest for file-based ecosystems | Existing per-entry validation remains unchanged. |
| `workdir` | `packages[].workdir` | Working directory for file-based ecosystems | Not applicable to `os-pm`; existing validation remains unchanged. |
| `lock` | `packages[].lock` | Lock file for supported file-based ecosystems | Does not affect multiplicity. |
| `env` | `packages[].env` | Environment values used while installing packages | Does not affect multiplicity. |

## os-pm directive cardinality

- Scope: one image’s `packages` list in one `werf.yaml` document.
- Valid cardinalities: zero or one entry with `type: os-pm`.
- Invalid cardinality: two or more entries with `type: os-pm`.
- Matching is based only on the directive type; package names and other field values do not affect the count.
- List order does not affect the result.
- Other package directive types may occur multiple times and do not contribute to the count.

## Processing state

1. YAML is decoded into raw package entries.
2. The complete raw list is checked for `os-pm` cardinality.
3. Entries are converted and individually validated using existing rules.
4. Package commands are generated only for a valid configuration.
5. Build processing may proceed.

A cardinality violation terminates processing at step 2 with a configuration error that identifies `packages`, `os-pm`, and the one-directive limit.
