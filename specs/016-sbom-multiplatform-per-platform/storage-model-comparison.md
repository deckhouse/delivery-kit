# Storage Model Comparison: Multi-Platform SBOM

**Spec**: `specs/016-sbom-multiplatform-per-platform/spec.md`

**Date**: 2026-08-11

**Purpose**: Compare three approaches to storing SBOM artifacts for multi-platform container images — delivery-kit/werf, BuildKit (Moby BuildKit), and the OCI Image Specification reference model — highlighting structural similarities and design trade-offs.

All three models address the same fundamental problem: given an OCI Image Index that references N platform-specific manifests, how should per-platform SBOM artifacts be stored, linked, and discovered?

---

## Simplified Visualizations

All diagrams show the same scenario: a two-platform image (`linux/amd64` + `linux/arm64`) with per-platform SBOMs.

### Figure 1: delivery-kit / werf (cosign-compatible fallback-tag layout)

```
Registry: <repo>/<image-name>
│
├── OCI Image Index (tag: <version>)
│   ├── Manifest: linux/amd64 ──── digest A
│   └── Manifest: linux/arm64 ──── digest B
│
├── sha256-<A>    ← fallback tag for platform amd64
│   └── OCI Artifact Index (fallback index)
│       ├── SBOM artifact (digest C)
│       │   ├── Config (mediaType: application/vnd.dsse.envelope.v1+json)¹
│       │   ├── subject: sha256:<A>          ← OCI 1.1 manifest field
│       │   └── Layer: DSSE envelope → in-toto statement → CycloneDX SBOM
│       │       in-toto subject: sha256:<A>
│       │       annotation: io.werf.target-platform=linux/amd64
│       │
│       └── Provenance artifact (digest D) — optional²
│           ├── Config (mediaType: application/vnd.dsse.envelope.v1+json)¹
│           ├── subject: sha256:<A>
│           └── Layer: DSSE envelope → in-toto statement → in-toto Provenance
│
├── sha256-<B>    ← fallback tag for platform arm64
│   └── OCI Artifact Index (fallback index)
│       ├── SBOM artifact (digest E)
│       │   ├── Config (mediaType: ...dsse.envelope...)¹
│       │   ├── subject: sha256:<B>
│       │   └── Layer: DSSE envelope → in-toto statement → CycloneDX SBOM
│       │       in-toto subject: sha256:<B>
│       │       annotation: io.werf.target-platform=linux/arm64
│       │
│       └── Provenance artifact (digest F) — optional² [...same structure...]
│
└── sha256-<index-digest>  ← fallback tag for the index (NO SBOM — FR-009)
    └── (empty / non-existent)
```

¹ The artifact type is declared through `config.mediaType`: go-containerregistry v0.20.1 cannot emit the OCI 1.1 manifest-level `artifactType` field, and per OCI distribution-spec 1.1 a registry MUST derive the descriptor `artifactType` from `config.mediaType` when the manifest-level field is absent. The stricter cosign BUNDLE_SPEC form (empty config + manifest-level `artifactType`) is functionally equivalent at the descriptor level, but registries that validate non-standard config media types (AWS ECR is flagged in cosign's registry testing, [aws/containers-roadmap#2306](https://github.com/aws/containers-roadmap/issues/2306)) may reject this form.

² delivery-kit's build does not produce provenance; the entry illustrates an artifact attached separately via `werf attest sign --type slsaprovenance`.

**Key properties**:
- Artifacts live on **per-platform fallback tags** (`sha256-<platform-manifest-digest>`).
- Platform manifests remain **pure** (no attestation manifests in the top-level index).
- Linking is **artifact → parent** (OCI `subject` + in-toto subject); discovery walks the other way: parent digest → fallback tag → artifact descriptors.
- No index-level artifact (FR-009 — explicit design decision).
- No referrers API dependency — works with any OCI-compliant registry; `subject` is always set, so referrers-capable registries index the artifacts automatically.
- Cosign compatible: unsigned SBOMs are DSSE envelopes; signed SBOMs are Sigstore Bundles v0.3 discovered and verified by cosign through the same per-digest referrers tag schema (`--registry-referrers-mode oci-1-1` / bundle flow).

---

### Figure 2: BuildKit (OCI Image Index with embedded attestation manifests)

```
Registry: <repo>/<image-name>
│
├── OCI Image Index (tag: <version>)
│   ├── Manifest: linux/amd64 ──── digest A
│   ├── Manifest: linux/arm64 ──── digest B
│   │
│   ├── Attestation manifest: SBOM for amd64 ──── digest C
│   │   platform: unknown/unknown
│   │   descriptor annotations:
│   │     vnd.docker.reference.digest: sha256:<A>
│   │     vnd.docker.reference.type: attestation-manifest
│   │   ├── Config ("dummy" image config)³
│   │   └── Layer 0: in-toto statement (application/vnd.in-toto+json)
│   │       └── SPDX SBOM (predicate https://spdx.dev/Document)
│   │
│   ├── Attestation manifest: Provenance for amd64 ──── digest D
│   │   platform: unknown/unknown
│   │   descriptor annotations: vnd.docker.reference.* → sha256:<A>
│   │   ├── Config ("dummy" image config)³
│   │   └── Layer 0: in-toto statement
│   │       └── SLSA Provenance
│   │
│   ├── Attestation manifest: SBOM for arm64 ──── digest E
│   │   descriptor annotations: vnd.docker.reference.* → sha256:<B>
│   │   [...same structure...]
│   │
│   └── Attestation manifest: Provenance for arm64 ──── digest F
│       descriptor annotations: vnd.docker.reference.* → sha256:<B>
│       [...same structure...]
```

³ With the opt-in `oci-artifact=true` exporter option the attestation manifest instead gets a manifest-level `artifactType` (`application/vnd.docker.attestation.manifest.v1+json`), an OCI empty config, and an OCI 1.1 `subject` descriptor pointing at the target manifest.

**Key properties**:
- All artifacts (SBOM, provenance) are **first-class entries in the same OCI Image Index** as the platform manifests.
- Attestation manifests use `platform: "unknown/unknown"` so runtimes do not attempt to execute them.
- Primary linking uses **index descriptor annotations** (`vnd.docker.reference.digest`, `vnd.docker.reference.type=attestation-manifest`); the OCI 1.1 `subject` field is added only in the opt-in `oci-artifact` exporter mode.
- No separate fallback tags needed — discovery is via **index enumeration**.
- `supplementSBOM` function traces layer ancestry to enrich per-layer SPDX data.

Source: [BuildKit attestation storage spec](https://github.com/moby/buildkit/blob/master/docs/attestations/attestation-storage.md).

---

### Figure 3: OCI Spec Reference Model — Per-Platform SBOM via Referrers API

Each SBOM is a standalone OCI Image Manifest that declares itself as an SBOM artifact via `artifactType` and links to its target platform manifest via `subject`. The Referrers API provides discovery: querying the registry for a given digest returns descriptors of all manifests whose `subject` points to it.

```
Registry: <repo>/<image-name>
│
├── OCI Image Index (tag: <version>)
│   ├── Manifest: linux/amd64 ──── digest A
│   └── Manifest: linux/arm64 ──── digest B
│
├── OCI Image Manifest: SBOM for linux/amd64 ──── digest C
│   ├── artifactType: application/spdx+json
│   ├── subject: sha256:<A>
│   ├── Config blob (empty descriptor: application/vnd.oci.empty.v1+json)
│   └── Layer blob: SBOM content (SPDX or CycloneDX document)
│
├── OCI Image Manifest: SBOM for linux/arm64 ──── digest D
│   ├── artifactType: application/spdx+json
│   ├── subject: sha256:<B>
│   ├── Config blob (empty descriptor)
│   └── Layer blob: SBOM content
│
│  ── Discovery via Referrers API ──
│  GET /v2/<name>/referrers/sha256:<A>
│  → [
│       {digest: C, artifactType: "application/spdx+json", annotations: {...}},
│       ...
│     ]
│
│  GET /v2/<name>/referrers/sha256:<B>
│  → [
│       {digest: D, artifactType: "application/spdx+json", annotations: {...}},
│       ...
│     ]
│
│  GET /v2/<name>/referrers/sha256:<index>
│  → []  (no artifacts point at the index — each SBOM points to a platform manifest)
│
└── (No fallback tags; Referrers API is the canonical discovery mechanism)
```

**Key properties**:

- Each SBOM is an **OCI Image Manifest** in its own right — it has its own config blob, layer blobs, and digest.
- `artifactType` (manifest-level) declares what the artifact **is** (e.g. `application/spdx+json`), distinguishing it from runnable images.
- The `subject` field creates a **weak association**: the target manifest is never modified; the artifact simply declares which digest it references.
- Discovery via the **Referrers API** is directionless — you query per target digest and receive descriptors of all referencing artifacts.
- `artifactType` also appears at the **descriptor level** in the API response (as a convenience copy for filtering without fetching the manifest).
- Platform manifests remain **pure** (no artifact entries in the Image Index — matching delivery-kit FR-009 constraint).

---
## Comparison Table

| Aspect | delivery-kit / werf | BuildKit | OCI Spec (referrers model) |
|--------|--------------------|----------|---------------------------|
| **Artifact location** | Per-platform fallback tags (`sha256-<platform-digest>`) | Same Image Index as platform manifests | Independent manifests in same repository |
| **Linking mechanism** | OCI 1.1 `subject` on the artifact manifest + in-toto subject; fallback index maps parent digest → artifact descriptors | Index descriptor annotations (`vnd.docker.reference.*`); OCI 1.1 `subject` only in opt-in `oci-artifact` mode | OCI 1.1 `subject` field on artifact manifests |
| **Discovery path** | Single GET of the `sha256-<parent-digest>` fallback tag, filter descriptors by `artifactType` | Enumerate the top-level Image Index (look for attestation entries) | Referrers API: `GET /referrers/<digest>` |
| **Number of top-level entries in the Image Index** | 2 (platform manifests only) | 2+N×M (platform manifests + N artifacts per platform) | 2 (platform manifests only) |
| **Registry requirement** | Any OCI-compliant registry (no special API) | Any OCI registry (annotations); OCI 1.1 manifest support for `oci-artifact` mode | Referrers API preferred; the spec mandates a client-managed referrers tag schema fallback |
| **Cosign compatibility** | Yes — signed SBOMs are Sigstore Bundles on the same per-digest referrers tag schema cosign uses in OCI 1.1 mode | No — cosign discovery walks per-digest tags, not index entries | Partial — cosign defaults to legacy `.att` tags; referrers flow via `--registry-referrers-mode oci-1-1` and the bundle spec |
| **Index-level artifact** | Explicitly prohibited (FR-009) | Does not apply (artifacts are index entries themselves) | Not prohibited but not idiomatic (subject links to platform manifests) |
| **Artifact format** | DSSE envelope (unsigned) / Sigstore Bundle v0.3 (signed, supersedes the DSSE artifact) | In-toto statement as direct layer inside attestation manifest | Open — any `artifactType`; SPDX/CycloneDX layers inside an OCI manifest |
| **Per-platform scanning** | One scan per platform image; platform annotation is truthful | One scan per platform; SBOM linked by subject | One scan per platform; artifact carries `subject` of its platform manifest |
| **Cache / reuse** | Per-platform content-based tags; checksum includes platform | Layer cache per platform in BuildKit's internal cache | Registry blob deduplication by digest; no built-in SBOM cache contract |
| **Cleanup / orphan detection** | Orphan pass deletes fallback tags of deleted platform manifests | Attestation manifests are index entries — deleted when the index is pruned | Referrers API may return artifacts whose target has been GC'd (weak reference) |
| **Multi-platform base image SBOM handling** | Hard error on legacy index-attached base SBOM (FR-005) | BuildKit generates attestations per-platform; base handling is per-platform | No built-in base SBOM contract — depends on tooling |
| **SBOM format** | CycloneDX 1.6 (in-toto statement inside DSSE envelope) | SPDX (in-toto statement layer) | Open — SPDX, CycloneDX, or any `artifactType` |
| **Provenance separation** | Not produced by the build; can be attached separately via `werf attest sign` into the same fallback index | Separate attestation manifest in the same Image Index | Separate artifact manifest with its own `subject` |
| **Maturity / adoption** | Production in Deckhouse delivery-kit | Production in Docker/BuildKit ecosystem | Specification (OCI image-spec 1.1, distribution-spec 1.1) |

---

## Analysis

### Where the models agree

1. **Per-platform, not per-index**: All three models generate one SBOM per platform manifest. None produces a merged platform-ambiguous SBOM at the index level. This is the fundamental architectural choice driven by correctness: an `amd64` SBOM that lists `arm64` packages would be a false statement.

2. **Subject-linked per-platform artifacts**: All three models attach per-platform SBOM artifacts using some form of `subject` reference (in-toto subject, OCI manifest `subject` field, or DSSE envelope subject) that points to the target platform manifest digest. The linking direction is always **artifact → target**, never modifying the target manifest.

3. **WEAK linking**: No model modifies the target platform manifest. Artifacts are always supplementary objects that reference the target but do not alter it. This is essential for manifest immutability and cosign signature integrity.

4. **One artifact per platform per type**: Each platform gets exactly one SBOM artifact and optionally one provenance artifact. There is no model that, for example, puts both platforms' SBOMs in a single blob.

### Where they differ

| Dimension | delivery-kit | BuildKit | OCI Spec |
|-----------|-------------|----------|----------|
| **Discovery primitive** | Tag-based (fallback tags) | Index enumeration | API-based (referrers) |
| **Top-level index size** | Stable (N entries) | Grows with artifacts (N + M entries) | Stable (N entries) |
| **Registry dependency** | None¹ | None² | Referrers API preferred; tag-schema fallback mandated |
| **Artifact visibility** | Hidden inside fallback tags; visible only via named lookup | Visible in the same index as platform manifests | Visible via API query; may not be visible via tag listing |
| **Artifact format coupling** | DSSE envelope (unsigned) / Sigstore Bundle v0.3 (signed) | Fixed to OCI manifest with in-toto layer | Open — artifact format is unconstrained |

¹ delivery-kit: needs only basic OCI tag write/read.  
² BuildKit: annotation linking works on any registry; OCI Subject mode needs OCI 1.1 manifest support.

### Key trade-offs

**delivery-kit / werf** chose the **tag-based adjacency model** for cosign compatibility and zero-dependency deployment. The fallback tag is a universally supported OCI primitive. Discovery is a single GET of a known tag (`sha256-<parent-digest>`) followed by descriptor filtering — no tag listing is involved (tag listing is used only by the cleanup orphan pass). The real costs are the extra tags accumulating in the repository and the client-managed read-modify-write of the fallback index on attach.

**BuildKit** chose the **single-index model**: all artifacts are entries in the same Image Index. This makes enumeration trivial (walk the index entries) and keeps the number of tag operations minimal. The cost: the index grows with every artifact, and non-image manifests share the index namespace with image manifests, which may confuse naive clients that enumerate the index to find runnable images.

**OCI Spec** chose the **referrers API model** as the canonical discovery path. This separates concerns cleanly: the Image Index describes what is runnable; the referrers API describes what attests to it. The cost: depends on registry support for the referrers API endpoint, which is not universally available (OCI distribution-spec 1.1 adoption is ongoing). The referrers tag schema exists as a fallback for registries without the API.

---

## Relevance to delivery-kit's Design

The delivery-kit model at `016-sbom-multiplatform-per-platform` is a hybrid:

- It uses the **OCI fallback tag schema** (`sha256-<hex>`) as the discovery mechanism (same as the OCI distribution-spec 1.1 referrers tag schema fallback).
- It uses **DSSE envelopes** for unsigned SBOMs and **Sigstore Bundles v0.3** for signed ones (the current bundle version per sigstore/protobuf-specs); the bundle is what cosign verifies, and it supersedes the DSSE artifact when signing is enabled.
- It explicitly **forbids index-level artifacts** (FR-009), which matches the OCI Spec's idiom of per-manifest `subject` links.
- It does **not** embed artifacts in the Image Index (unlike BuildKit), keeping platform manifests as the only index entries.

The resulting model is cosign-compatible, registry-agnostic, and correct per-platform — at the cost of tag enumeration for discovery.
