# Quickstart: ELF Signing Anchor Digest

## Prerequisites

- Linux development environment with the repository's prepared test tooling.
- Go/toolchain dependencies installed as defined by the repository.
- No BSign executable, private key, registry, or Kubernetes cluster is needed for the focused unit tests; tests construct signing options and signer identities in memory.

## Validation scenarios

1. Run the focused build package tests:

   ```sh
   task test:unit paths="./pkg/build/..."
   ```

   Expected result: the anchor digest suite passes, including deterministic results for identical inputs and different results for changed BSign fingerprints, certificates, and certificate chains.

2. Run the complete required unit suite:

   ```sh
   task test:unit
   ```

3. Apply repository formatting and compile the binary:

   ```sh
   task format
   task build
   ```

4. Install the lint prerequisite once per session and run lint:

   ```sh
   task deps:install:golangci-lint
   task lint
   ```

5. Run the repository's required broader validation gates when implementation is complete:

   ```sh
   task test:e2e paths="./test/e2e/build/..." labelFilter="build"
   task test:integration
   ```

## Expected behavioral checks

- BSign enabled with fingerprint A and fingerprint B produces different anchor digests.
- In-house signing enabled with certificate/chain changes produces different anchor digests.
- Repeating calculation with identical applicable values produces the same digest.
- Changing only a private key passphrase while BSign is disabled does not affect the digest.
- Anchor signing inputs use the same values and labels as the non-anchor checksum path; no signing-state-only marker appears.

See [`data-model.md`](data-model.md) for included and excluded inputs and [`contracts/anchor-digest.md`](contracts/anchor-digest.md) for the internal contract.
