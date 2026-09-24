# Contributing to werf

werf is an Open Source project, and we are thrilled to develop and improve it in collaboration with the community.

## Before you start

For any significant change, open the issue first (or comment on an existing one) to discuss with the maintainers on what to do and how. When the solution is agreed upon, you can proceed with implementation and open a pull request.

For small changes, such as few lines bugfixes or documentation improvements, feel free to open a pull request directly.

For easy first issues, check the [good first issue](https://github.com/werf/werf/issues?q=is%3Aissue%20state%3Aopen%20label%3A%22good%20first%20issue%22) tag.

You can also check the existing [issues](https://github.com/werf/werf/issues), [discussion threads](https://github.com/werf/werf/discussions), and [documentation](https://werf.io/docs/v2/) — there may already be a discussion or solution on your topic. If not, choose the appropriate way to address the issue on [the new issue form](https://github.com/werf/werf/issues/new/choose).

## Contributing code

1. [Fork the project](https://github.com/werf/werf/fork).
2. Clone the project:

   ```shell
   git clone https://github.com/[GITHUB_USERNAME]/werf
   ```

3. Prepare an environment. To build and run werf locally, you'll need to _at least_ have the following installed:

   - [Git](https://git-scm.com/book/en/v2/Getting-Started-Installing-Git) 2.18.0+
   - [Go](https://golang.org/doc/install) 1.11.4+

      **Important: Go Toolchain Configuration**

      To prevent unwanted modifications to the `go.mod` file (specifically the automatic addition of a `toolchain` directive), you must set the following environment variable:

      ```shell
      export GOTOOLCHAIN=local
      ```

      We recommend adding this setting to your shell profile (e.g., `.bashrc`, `.zshrc`, or equivalent) to make it persistent across sessions:

      ```shell
      echo 'export GOTOOLCHAIN=local' >> ~/.bashrc
      source ~/.bashrc
      ```

      This configuration ensures Go uses only the locally installed version of the tools instead of automatically selecting and potentially adding a toolchain version to `go.mod`, preventing unintended changes to the file.

   - [Docker](https://docs.docker.com/get-docker/)
   - [ginkgo](https://onsi.github.io/ginkgo/#installing-ginkgo) (testing framework required to run tests)
   - [go-task](https://taskfile.dev/installation/) (build tool to run common workflows)
     - Before using Taskfile, set the environment variable:  
         ```shell
         export TASK_X_REMOTE_TASKFILES=1
         ```
         (Add this to your shell configuration file, e.g., `.bashrc` or `.zshrc`, for persistence.)
     - To skip confirmation prompts when running tasks, use the `--yes` flag:  
         ```shell
         task --yes taskname
         ```
         Useful for automation or when you're sure the task should run without manual confirmation.
         
      To install dependencies, use the following task:

   - `task deps:install:all`

   Additionally, to build the `werf` binary, you need to install the `libbtrfs-dev` package.

4. Make your changes.
5. Run `task` with no arguments to run all essential checks (build, lint, format, quick tests, and others).

   You can also check out all available tasks with `task -l`.

6. Testing:
   1. Setup testing environment:
      ```shell
      task test:setup:environment
      ```
   2. Run tests:
      ```shell
      task test:unit
      task test:integration
      task test:e2e
      ```
   3. Cleanup testing environment:
      ```shell
      task test:cleanup:environment
      ```
   4.  Do manual testing (if needed).

7. Commit your changes. See [Conventions](#conventions) for the commit message format. The commit must be signed off (`--signoff`) as an acknowledgment of the [DCO](https://developercertificate.org/).
8. Push and open a pull request.


## Conventions

### CI runner pool

The PR and daily test workflows run each integration/e2e group with its own
registry, kind cluster and kubeconfig. Jobs may run on different VMs or share a VM;
they do not exchange local paths or registry endpoints. Resource names include the
workflow run, attempt and job ID. Do not add a matrix to these jobs without also
adding its identity to the resource names.

Each workflow builds one binary for its heavy test groups and transfers it as a
tar artifact, preserving executable permissions. Daily groups use a binary built
with coverage and the race detector. All runners with the `delivery-github-runner`
label must have a compatible Linux/amd64 userspace and the same required tools.
Use separate workspaces and temporary directories for each runner service.

For a 16-vCPU, 32-GiB RAM, 100-GB disk VM, start with no more than four runner
services in total, across all PRs and workflows. This is a host provisioning limit,
not a per-workflow limit; the workflow does not register runners or enforce it.
Several jobs may run on the same VM. Add VMs to increase the number of slots before
increasing runner density.

The initial per-job resource settings are:

- Ginkgo: three test processes and one suite compiler.
- Go in integration/e2e jobs: `GOMAXPROCS=2` and `GOFLAGS=-p=2`.
- Lint, unit, docs-unit and binary-build jobs: `GOMAXPROCS=4` and `GOFLAGS=-p=4`.
- Binary-build job timeout: 60 minutes for PRs, 90 minutes for daily race/coverage builds.
- After setup, the kind node: two CPUs and 4 GiB RAM, with no additional swap.
- After setup, the registry: half a CPU and 512 MiB RAM, with no additional swap.

These are starting budgets, not a bound on total job memory or disk usage. The kind
bootstrap runs before container limits are applied; test builds can start other
containers. Monitor peak memory, free disk, I/O latency and test timeouts under concurrent PR load before
raising density. Race-enabled daily tests can require more memory. A container OOM
or a longer queue is a reason to adjust the budget using measurements, not to hide
the failure with retries.

The Go limits are inherited by child processes, including werf under test. Daily
integration/e2e tests retain the race detector but run with two Go execution threads
per process; this is a resource compromise, not evidence of equivalent race coverage
to an unrestricted run. Cold-cache build/lint/unit timings with the four-thread
profile have not been established; validate them on a new Linux runner before
treating the timeouts as sufficient. Do not remove host-wide resource budgeting to
address an individual slow job.

Jobs set up ARM64 emulation with `docker/setup-qemu-action@v4`, requesting only
`arm64` with `reset: false`, then require `linux/arm64` in the action's available-platforms output.
The default `tonistiigi/binfmt` installer registers missing handlers without
resetting existing ones. Manual binfmt provisioning is not required on a fresh
runner; an existing broken handler is not automatically replaced, and failed ARM64
availability verification stops the job before environment creation.
Runners must access the local Docker daemon with permission to run privileged
containers, not a daemon on another VM.

Cleanup runs on the same runner after success, failure or partial setup, and removes
the registry's anonymous volume as well as the cluster. Step timeouts leave room
for cleanup before the job timeout. A runner crash or forced termination can still
leave resources behind. Existing scheduled host cleanup remains unchanged; the
workflows neither manage runner availability nor replace that cleanup. Scheduled
deletion of shared caches or container storage can interrupt active jobs, so jobs
must tolerate cold caches but are not guaranteed to survive concurrent deletion.

When rolling out, run two groups concurrently on one host, then on different hosts;
verify registry push/pull, Kubernetes access, failure cleanup and rerunning a failed
job without rerunning setup elsewhere. Keep the existing test groups and selectors;
splitting or reducing test coverage is a separate change.

### Test profiling

The diagnostic PR workflow wraps its five heavy test groups with
`bash scripts/ci/profile-tests.sh task ... -- ...`. Test selectors, concurrency,
retries and timeouts are unchanged. Each job uploads a
`test-profile-<job>-<attempt>` artifact after environment cleanup, retained for
seven days, including when tests fail.

Artifacts contain per-suite Ginkgo JSON reports (including successful-spec output,
events, durations and attempts), verbose console output, the test exit code,
checkout SHA, run/attempt/runner identity, and before/after host snapshots.
`vmstat` samples CPU, memory and disk counters every ten seconds; `iostat` and
`pidstat` add disk latency and per-process CPU/memory/I/O when sysstat is already
installed. Missing tools are explicitly reported; profiling installs nothing.
GNU `time`, when available, records aggregate command resource usage, excluding
Docker-daemon-managed containers. Linux requires `setsid` to isolate the test
process group. Cancellation sends TERM, allows five seconds for graceful exit,
then sends KILL to the group even if the immediate child has already exited.
This adds no time limit to a normally running test command.

These are shared-host measurements, not proof that a test caused host saturation.
Separate compile/setup time from suite/spec time, ignore the initial since-boot
samples when comparing load, and compare several runs with their runner identities.
Only completed suites have JSON reports; verbose logs and already-written reports
may survive cancellation, but a runner crash or forced kill can prevent upload.
Reports contain raw test output and are not GitHub-log-secret-masked: use only
synthetic fixture credentials, never pass real secrets to a diagnostic test.
The collector does not dump environment variables or process command lines.

The Git suite's `should set correct owner and group for /app` scenario compares
Docker ImageList filters before its existing project purge. Each attempt performs
three rotating rounds of `reference+label`, `reference`, and `label` queries, with
a 90-second deadline per query and a ten-minute context for the experiment.
`PURGE_IMAGE_LIST` JSON lines in the Ginkgo output contain the project, round,
position, start timestamp, request/client-processing durations, raw responses,
selected image IDs/tags/digests, StageIDs, and errors. Single-filter responses are
filtered on the client using the missing condition and compared with the unmodified
two-filter response; a mismatch or error fails the scenario but still runs its
ordinary AfterEach purge. The probe does not create or delete images and must be
excluded from ordinary test-duration comparisons. Other scenarios and the
per-test cleanup schedule are unchanged by this comparison.

Local stage discovery now requests Docker images by project reference only and
checks the exact `werf` project label in the client before converting tags to
StageIDs. Missing labels are excluded, including for an empty project name.
Returned tags and digest references are not rewritten. The comparison above
continues to measure the original two-filter query as its baseline, while the
ordinary purge uses the optimized discovery path.

### Commit message

Each commit message consists of a **header** and a [**body**](#body). The header has a special format that includes a [**type**](#type), a [**scope**](#scope) and a [**subject**](#subject):

```
<type>(<scope>): <subject>
<BLANK LINE>
<body>
```

#### Type

Must be one of the following:

- **feat**: new features or capabilities that enhance the user's experience.
- **fix**: bug fixes that enhance the user's experience.
- **refactor**: a code changes that neither fixes a bug nor adds a feature.
- **docs**: updates or improvements to documentation.
- **test**: additions or corrections to tests.
- **chore**: updates that don't fit into other types.

#### Scope

Scope indicates the area of the project affected by the changes. The scope can consist of a top-level scope, which broadly categorizes the changes, and can optionally include nested scopes that provide further detail.

Supported scopes are the following:

```
# The end-user functionalities, aiming to streamline and optimize user experiences.
- giterminism
- build
  - stapel
  - dockerfile
  - docker
  - buildah
  - tagging
  - stages
- deploy
  - values
  - dependencies
  - secrets
  - templates
  - tracking
  - resource-order
  - resource-lifecycle
  - plan
- bundle
- cleanup
- host-cleanup
- run
- kube-run
- compose
- ci-env
- sbom
- vex
- sign
- verify
- elf

# Maintaining, improving code quality and development workflow.
- ci
- release
- dev
- deps
```

In the header, multiple and nested scopes are separated by commas, from the broadest to the most specific: `fix(build, stapel, import): ...`.

#### Subject

The subject contains a succinct description of the change:

- use the imperative, present tense: "change" not "changed" nor "changes"
- don't capitalize the first letter
- no dot (.) at the end
- for **feat** and **fix**, describe the change from the user's side — the symptom that goes away, or what becomes possible. Release notes in `CHANGELOG.md` are generated from these subjects verbatim, and their reader has never seen the code, so internal names and the mechanism belong in the **body**. Prefer "preserve files imported into symlinked directories" over "resolve symlinks in the import target path".
- for **refactor**, **test** and **chore**, the reader is a developer, so the mechanism is the right subject.

#### Body

Just as in the **subject**, use the imperative, present tense: "change" not "changed" nor "changes".
The body should include the motivation for the change and contrast this with previous behavior.

### Branch name

Each branch name consists of a [**type**](#type), [**scope**](#scope), and a [**short-description**](#short-description):

```
<type>/<scope>/<short-description>
```

When naming branches, only the top-level scope should be used. Multiple or nested scopes are not allowed in branch names, ensuring that each branch is clearly associated with a broad area of the project.

#### Short description

A concise, hyphen-separated phrase in kebab-case that clearly describes the main focus of the branch.

### Pull request name

Each pull request title should clearly reflect the changes introduced, adhering to [**the header format** of a commit message](#commit-message), typically mirroring the main commit's text in the PR.

### Code style

See [CODESTYLE.md](CODESTYLE.md).

## Improving the documentation

The documentation is created using [Jekyll](https://jekyllrb.com/) and is located in `./docs`. Please refer to the [docs DEVELOPMENT.md](./docs/DEVELOPMENT.md) for information about the development process.
