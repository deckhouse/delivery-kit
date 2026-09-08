# Idea Intake: `sbom packages` access to private repositories

- **Slug**: private-repo-sbom
- **Created**: 2026-09-08
- **Source**: user-provided configuration example from an internal GitLab project
- **Type**: improvement

## Idea (as captured)

> The current implementation of `sbom packages` does not allow dependencies to be downloaded from a private repository.
>
> To download dependencies from a private repository, the corresponding GitLab authentication configuration must be applied.
>
> It is necessary to determine how to make this request—downloading dependencies from private repositories—work with `sbom packages`. This may require changes to the UI (`werf.yaml`).

The source includes a configuration example from an internal GitLab project.

## Restated

Consider supporting dependency downloads from private repositories in the `sbom packages` functionality. Determine how to expose the required configuration to users, including whether changes to the user interface and `werf.yaml` configuration are needed.

## Origin & Context

- **Raised by**: user who submitted the request
- **Trigger**: the current implementation of `sbom packages` does not allow dependencies to be downloaded from private repositories; the provided GitLab authentication configuration was supplied as related context.

## Clarifications

- **Supported repository type**: Git repositories hosted on GitLab.
- **Scope**: the solution should be general and must not be limited to Go modules. It should support dependencies from private GitLab Git repositories regardless of the package ecosystem or dependency mechanism involved.
- **Authentication**: use the existing `CI_JOB_TOKEN`, passed into the build as a werf secret named `CI_JOB_TOKEN` (for example, via `secrets: - id: CI_JOB_TOKEN; value: "{{ env \"CI_JOB_TOKEN\" }}"`).
- **Configuration location**: configure private GitLab repository access in `werf.yaml`. The necessary environment variables must still be explicitly passed through `werf.yaml` into the build context; the configuration should not hide or eliminate that requirement.
- **Environment variables**: the exact set is ecosystem-dependent rather than fixed globally. For Go dependencies, the relevant variables may include `CI_JOB_TOKEN`, `GOPRIVATE`, and, in some scenarios, `GOPROXY`.
- **Expected automation**: after the user declares the required ecosystem-specific variables and secrets in `werf.yaml`, `sbom packages` should obtain them, configure access to the private GitLab repository, perform the required ecosystem-specific dependency-download steps, and clean up temporary authentication configuration. Credentials must not remain in image layers, logs, generated SBOMs, or build metadata.
- **Reference implementation context**: the provided configuration example concerns downloading Go modules from a private GitLab host. It sets `GOPRIVATE`, reads `CI_JOB_TOKEN` from a mounted secret where needed, and configures Git URL rewriting with `url.\"https://gitlab-ci-token:${CI_JOB_TOKEN}@<gitlab-host>/\".insteadOf \"https://<gitlab-host>/\"`, instead of relying on a temporary `.netrc` file.

## First-Glance Unknowns

- **Package ecosystem scope**: the first implementation should cover all ecosystems already supported by `sbom packages`, provided their dependencies can be downloaded from GitLab Git repositories.
- **GitLab host**: the host must be configurable by the user in `werf.yaml` and must not be tied to a single predefined GitLab instance.
- [OPEN DESIGN QUESTION: What `werf.yaml` configuration shape should expose the private-repository setup while allowing ecosystem-specific environment variables? This requires separate investigation; no design has been selected yet.]
- **Failure point**: private-repository authentication is unavailable when the package manager itself is running and attempting to download dependencies.
- **Credentials handling**: pass `CI_JOB_TOKEN` through a `werf secret`, mount the secret only while the package manager is running, configure GitLab access in a temporary build context, and remove the Git configuration and other temporary data after dependencies are downloaded. The token must not appear in image layers, logs, generated SBOMs, or build metadata.
- **Success criteria and tests**:
  1. `sbom packages` successfully downloads dependencies from a private GitLab repository for all supported ecosystems.
  2. The GitLab host configured in `werf.yaml` is supported.
  3. Public repositories continue to work without changes.
  4. Missing or invalid `CI_JOB_TOKEN` results in a clear error when access to a private repository is required.
  5. Verification is limited to unit tests that validate the generated Stapel bash command and the relevant private-repository configuration. Other scenarios cannot be verified within the available test scope.
