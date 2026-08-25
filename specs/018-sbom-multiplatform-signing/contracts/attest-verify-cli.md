# Contract: `werf attest verify` — index verify-all

**Feature**: 018-sbom-multiplatform-signing

Command stays `Hidden: true` (spec 008); no user-facing docs regeneration required.

## Inputs (unchanged flags, new semantics for one case)

- `--repo` (required), `--type` (required), `--key` (repeatable; any match = success — applies **per platform**)
- `--digest` XOR `--tag` (required pair rule unchanged)
- `--image` — artifact lookup filter, applied per platform (unchanged meaning)
- `--platform OS/ARCH[/VARIANT]` — **now optional for index references**

## Reference resolution matrix

| Reference resolves to | `--platform` | Behavior |
|---|---|---|
| single manifest | absent | unchanged: verify one attestation, dump predicate JSON to stdout, exit 0/1 |
| single manifest | present | unchanged: validate platform against manifest config, then as above |
| image index | present | unchanged: `ResolvePlatformDigest` → verify that platform only, dump predicate |
| image index | absent | **NEW (verify-all)**: expand via `ListIndexPlatforms` (skips `unknown/unknown` entries), verify every platform, print result table, aggregate verdict |
| image index, `--platform` not in index | present | unchanged: error listing available `platform → digest` pairs |

## Verify-all output

stdout — tabwriter table (style of `attest ls`):

```
PLATFORM      DIGEST         STATUS
linux/amd64   sha256:aaaa…   verified
linux/arm64   sha256:bbbb…   unsigned (legacy format, rebuild with --sign-key)
```

- Exit 0 iff every platform is `verified`.
- On failure: non-zero exit; error names each failing platform with its classification.
- Raw predicate JSON is NOT dumped in verify-all mode (single-target modes keep dumping it — existing contract preserved).

## Per-platform status classification

| Status | Trigger |
|---|---|
| `verified` | DSSE verifies against any provided key; predicate type matches `--type` |
| `missing` | no attestation artifact for the platform digest (`artifact.ErrNotFound`) |
| `unsigned` | artifact present but legacy bare-DSSE with empty signatures (hint: rebuild with `--sign-key`) |
| `invalid` | signatures present but verification fails (wrong key, tampered payload, predicate-type mismatch) |

Dual-format read order per platform: bundle artifact first, bare-DSSE fallback (unchanged from 016).

## Unchanged commands (regression guard)

`attest get`, `sbom get`: index reference without `--platform` still fails with the `ErrIndexPlatformRequired` listing. `attest ls`, `attest sign`, `sbom merge`, `sbom validate`: untouched.
