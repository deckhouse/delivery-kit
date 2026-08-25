# Quickstart: VEX Lifecycle Validation Guide

**Date**: 2026-07-31

## Prerequisites

- Go 1.24.10+
- `task` (Task runner — see [Taskfile.yml](../../../../Taskfile.yml))
- Access to an OCI-compatible container registry (e.g., Docker Hub, ECR, or local registry)
- Docker or Buildah installed

## Setup

1. **Create a VEX document** following OpenVEX JSON-LD format:

   ```bash
   mkdir -p vex/
   cat > vex/my-app.openvex.json << 'EOF'
   {
     "@context": "https://openvex.dev/ns/v0.2.0",
     "@id": "https://example.com/vex/my-app.vex.json",
     "author": "devops@example.com",
     "timestamp": "2026-07-31T00:00:00Z",
     "version": 1,
     "statements": [
       {
         "vulnerability": "CVE-2023-XXXXX",
         "products": ["pkg:oci/my-app@sha256:abc123..."],
         "status": "not_affected",
         "justification": "component_not_present"
       }
     ]
   }
   EOF
   git add vex/my-app.openvex.json
   git commit -m "chore(vex): add VEX document for my-app"
   ```

2. **Update `werf.yaml`** to reference the VEX document:

   ```yaml
   image: my-app
   dockerfile: Dockerfile
   vex: vex/my-app.openvex.json
   ```

## Validation Scenarios

### Scenario 1: Basic VEX publish (User Story 1)

**Purpose**: Verify that a VEX document is published as an OCI artifact during build.

**Commands**:
```bash
task build
./bin/werf build --repo <your-registry>/my-project
```

**Expected Outcome**:
- Build succeeds.
- Log contains: `"Published VEX artifact for image my-app"`.
- VEX artifact is published in the registry as an OCI subject reference attached to the image manifest.



---

### Scenario 2: No VEX configured (User Story 1, AC2)

**Purpose**: Verify backward compatibility when no `vex` field is specified.

**Commands**:
```bash
# Remove vex field from werf.yaml
# Run build
./bin/werf build --repo <your-registry>/my-project
```

**Expected Outcome**:
- Build succeeds without any VEX-related log messages.
- No VEX-related errors.

---

### Scenario 3: Update VEX document (User Story 2)

**Purpose**: Verify that modifying the VEX file publishes a new version.

**Commands**:
```bash
# Modify VEX document
echo '{"@context":"https://openvex.dev/ns/v0.2.0","@id":"...","author":"...","timestamp":"2026-08-01T00:00:00Z","version":2,"statements":[]}' > vex/my-app.openvex.json
git add vex/my-app.openvex.json
git commit -m "chore(vex): update VEX document"

# Rebuild
./bin/werf build --repo <your-registry>/my-project
```

**Expected Outcome**:
- Build succeeds with new VEX artifact published.
- Log contains: `"Published VEX artifact for image my-app"`.
- Retrieving the VEX shows the updated content with `version: 2`.

---

### Scenario 4: No changes to VEX or image (User Story 2, AC2)

**Purpose**: Verify that rebuiding without changes does not create a new VEX artifact.

**Commands**:
```bash
./bin/werf build --repo <your-registry>/my-project
```

**Expected Outcome**:
- Build succeeds.
- Log message: `"VEX artifact for image my-app is up to date — skipping publish"`.
- No new OCI artifact created for VEX.

---

### Scenario 5: VEX file not found

**Purpose**: Verify validation on missing VEX file.

**Commands**:
```bash
# Set vex: nonexistent.json in werf.yaml
./bin/werf build --repo <your-registry>/my-project
```

**Expected Outcome**:
- Build fails with error: `"image \"my-app\": VEX file not found: \"nonexistent.json\""`.
- Exit code is non-zero.

---

### Scenario 6: VEX file not tracked by Git

**Purpose**: Verify giterminism enforcement.

**Commands**:
```bash
# Create a VEX file but don't git add it
cat > vex/untracked.openvex.json << 'EOF'
{ "@context": "https://openvex.dev/ns/v0.2.0", "statements": [] }
EOF
# Set vex: vex/untracked.openvex.json in werf.yaml
./bin/werf build --repo <your-registry>/my-project
```

**Expected Outcome**:
- Build fails with error: `"VEX file \"vex/untracked.openvex.json\" must be tracked by Git"`.

---

### Scenario 7: Empty VEX file

**Purpose**: Verify validation on empty VEX document.

**Commands**:
```bash
# Create an empty vex file
touch vex/empty.openvex.json
git add vex/empty.openvex.json
# Set vex: vex/empty.openvex.json in werf.yaml
./bin/werf build --repo <your-registry>/my-project
```

**Expected Outcome**:
- Build fails during config validation with error: `"VEX file \"vex/empty.openvex.json\" is empty"`.
- Build does not start (fail-fast before building container).

---

### Scenario 8: Malformed VEX file

**Purpose**: Verify validation on malformed VEX document.

**Commands**:
```bash
# Create a non-JSON vex file
echo "this is not json" > vex/invalid.openvex.json
git add vex/invalid.openvex.json
# Set vex: vex/invalid.openvex.json in werf.yaml
./bin/werf build --repo <your-registry>/my-project
```

**Expected Outcome**:
- Build fails during config validation with error: `"VEX file \"vex/invalid.openvex.json\" is not valid: <parse error>"`.
- Build does not start.

---

### Scenario 9: Multiple images sharing the same VEX file (Edge case)

**Purpose**: Verify that two images can reference the same VEX document.

**Commands**:
```bash
# werf.yaml:
#   image: app1
#   dockerfile: Dockerfile.app1
#   vex: vex/shared.openvex.json
#   image: app2
#   dockerfile: Dockerfile.app2
#   vex: vex/shared.openvex.json

./bin/werf build --repo <your-registry>/my-project
```

**Expected Outcome**:
- Build succeeds.
- Each image gets its own VEX OCI artifact attached via subject reference.
- Log shows two "Published VEX artifact" messages (one per image).

---

### Scenario 10: Registry cleanup (User Story 3)

**Purpose**: Verify that orphaned VEX artifacts are removed during cleanup.

**Prerequisites**: Multiple build runs with VEX configured.

**Commands**:
```bash
# Delete an image tag that has an associated VEX artifact
./bin/werf cleanup --repo <your-registry>/my-project
```

**Expected Outcome**:
- VEX artifacts that are referenced by existing active images are retained.
- VEX artifacts that are orphaned (no active image references them) are removed.
- Log contains: `"Removed <n> orphaned VEX artifact(s)"`.

## Running Unit Tests

```bash
# Run all VEX-related unit tests
task test:unit -- -run "VEX"
```

## Running E2E Tests

```bash
# Run VEX e2e tests (requires Linux with Docker/kind)
task test:e2e paths="./test/e2e/vex/..." labelFilter="VEX"
```

## Related Documents

- [Data model](data-model.md) — Detailed type definitions and constants
- [Config contract](contracts/config.md) — werf.yaml configuration interface
- [OCI artifact contract](contracts/oci-artifact.md) — Storage and retrieval protocol
- [Feature spec](spec.md) — Acceptance scenarios and requirements
- [Research notes](research.md) — Design decisions and tradeoff analysis
- [Implementation tasks](tasks.md) — Task breakdown for implementation (generated by `/speckit-tasks`)