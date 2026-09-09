# Quickstart: Generalized Package Secret References

This guide validates the package-stage behavior described in `spec.md` without exposing secret values in generated commands or persistent image configuration.

## Prerequisites

- Repository dependencies and the prepared test environment are available.
- Run commands from the repository root.
- Use the existing Ginkgo/Gomega test harness and the repository `task` commands.

## Focused unit validation

Run the package configuration tests:

```sh
task test:unit paths="./pkg/config/..."
```

The focused coverage should demonstrate:

1. An exact `packages.env` value such as `/run/secrets/GOPROXY` resolves to the mounted secret content.
2. Environment-, file-, and literal-backed declarations all resolve through the same path.
3. Ordinary values and `${VARIABLE}` text remain unchanged.
4. Repeated references resolve consistently, including empty and shell-special values.
5. Undeclared references and configuration-unresolvable secret sources fail during configuration parsing, before a build stage or package manager starts.
6. Generated command text remains a single-line inline-environment command and returned diagnostics do not contain resolved secret content.
7. A non-`os-pm` directive, such as `go-mod` or `python-pip`, receives the resolved environment.
8. Existing `PACKAGES_VERSION` provenance and `REGISTRY` compatibility behavior remain intact.

## Package-stage validation

Use the focused package-stage tests after the unit coverage is in place:

```sh
task test:unit paths="./pkg/build/stage/..."
```

The package-stage checks should confirm that command/checksum inputs contain the reference syntax but not the resolved secret value, that the final command remains in `ENV_VAR=value command` form, and that mounted build secrets remain read-only and ephemeral.

## End-to-end validation

If the implementation adds a fixture for a package-manager substitute, run its labeled e2e scenario with both required selectors:

```sh
task test:e2e paths="./test/e2e/sbom/..." labelFilter="packages"
```

The substitute should record its received environment in a test artifact, and assertions should verify the secret content while separately checking that the value is absent from generated command output, diagnostics, and the resulting image environment.

## Full repository gates

Before handoff, follow the repository gates in the constitution:

```sh
task format
task build
task deps:install:golangci-lint
task lint
task test:unit
```

Then run the scoped e2e suite and `task test:integration` as appropriate for the final implementation.
