# Accuracy-first Proto reconstruction

This directory contains the reproducible post-processing step used to build and verify an accuracy-first `StarRail.accuracy.proto` from a same-client compatibility Proto.

## Inputs

Set these environment variables before running:

- `HSR_OWNER_ROOT`: HSR-OWNER checkout. Defaults to the repository root.
- `HSR_PROTO_RUN`: run directory containing `StarRail.proto`, `StarRail.compat.proto`, `packetIds.json`, `derived-compatibility-validation.json`, and the graph/multiversion evidence files.
- `HSR_PROTO_REFERENCE_REPO`: clean checkout containing the same-version external `StarRail.proto` naming reference.
- `HSR_PROTO_REFERENCE_COMMIT`: expected reference commit. Defaults to `40bca1cb24d80e68815fdb310c10906880ca3c3b`.

The reconstruction fails closed if the reference checkout is dirty, its pinned commit/blob/hash does not match, canonical identities change, wire layout changes, a proposed type/field/enum-variant name collides, or the required proof gates are not met. Reference naming bytes are read directly from the pinned Git object rather than from the mutable worktree path. Reconstruction and both portable verifiers hold the same exclusive run-directory publication lock, preventing cooperating processes from reading or publishing interleaved generations. Lock acquisition rejects symbolic and multiply-linked files, uses no-follow opening where supported, and verifies that the pathname still identifies the opened inode after acquisition. Proto, report, marker, and verifier-result files use unique, exclusive, flushed temporary files plus atomic replacement; the publication marker is written last and required by the verifier. Failed publication restores the previous Proto, report, and marker on a best-effort basis. This is process-concurrency and fail-closed validation protection, not a claim of power-loss transaction durability or protection from a privileged actor continuously replacing paths. The artifact verifier additionally pins the accepted Proto and `packetIds.json` hashes, requires every packet target to resolve uniquely to a top-level message, and pins recovery/structure counts, owner-binding counts, reference provenance, and the recorded protox/protobuf descriptor result from `accepted-2026-10-03.json`. These checks use explicit exceptions and remain active under `python -O`.

## Run

```bash
python tools/proto-accuracy-reconstruction/reconstruct_accuracy_proto.py
python tools/proto-accuracy-reconstruction/verify_graph_reconstruction.py
python tools/proto-accuracy-reconstruction/verify_accuracy_artifacts.py
```

The first command writes `StarRail.accuracy.proto` and `accuracy-reconstruction-report.json` into `HSR_PROTO_RUN`. The verification commands check exact recovery counts, field/type/enum substitutions, canonical identities, wire layout, hashes, collisions, and packet ID resolution.

## Accepted October 3, 2026 result

- Fields renamed: 890
  - raw owner: 287
  - readable owner: 457
  - graph edge owner: 124
  - reverse graph owner: 22
- Message types renamed: 27
- Enum types renamed: 11
- Enum variants renamed: 51
- Intentionally excluded field-name collisions: 2
- Messages/fields/enums/oneofs: 4,939 / 14,072 / 478 / 175
- Accuracy Proto SHA-256: `2505a4cc7cd1379b14c826a85afaa21f275a1a8d85bff1ce8eb591627d2dab86`

This is a derived accuracy-first artifact, not a raw runtime export. The raw runtime export remains separately labeled because its strict name/evidence acceptance failed. During this acceptance session, the client executable, `GameAssembly.dll`, and runtime dumper DLL were separately hashed and matched the captured run; those machine-local runtime hashes are recorded as historical evidence in `accepted-2026-10-03.json` but are not rechecked by the portable artifact verifier. Repeating the unchanged runtime export would not validate the post-processing changes in this directory.

## Rust embedded accepted-name database

The reviewed wave10 lineage is packaged for the Rust dumper as:

- generator: `export_rust_name_database.py`
- reviewed provenance: `accepted-rust-name-provenance.v1.json`
- generated database: `crates/dumper/resources/proto/accepted-names.v1.json`
- Rust matcher: `crates/dumper/src/proto/accepted_names.rs`

Regenerate it only from the reviewed raw/accepted Proto and packet files:

```bash
python tools/proto-accuracy-reconstruction/export_rust_name_database.py \
  --raw-proto target/allocator-fh3-runtime-20261003-041926/StarRail.proto \
  --accepted-proto target/allocator-fh3-runtime-20261003-041926/StarRail.accuracy.wave10.proto \
  --raw-packets target/allocator-fh3-runtime-20261003-041926/packetIds.json \
  --accepted-packets target/allocator-fh3-runtime-20261003-041926/packetIds.accuracy.wave10.json
```

The generator binds raw and accepted declarations by canonical identity rather than declaration order, and its tracked provenance file pins every reviewed input hash plus the one explicit canonical override. Custom inputs generated through the Python API are marked `unreviewed`; the default CLI path rejects any input whose hash differs from the approved provenance. It then proves that tags, normalized types, nesting, oneof membership, enum numbers, offsets, and packet ID keys are unchanged and writes deterministic records guarded by a name-independent structural graph fingerprint. Duplicate enum numbers are rejected instead of being paired by declaration ordinal. The current database contains 1,798 active type records, 1,155 field aliases, 400 type aliases, one oneof alias, 39 enum-value aliases, and all 1,108 packet bindings. Its generated SHA-256 is `7ad0b9656d0b78cbf499a3667a5b640c1748edd4df151714a50b2706bd289e4f`.

At runtime the compiled dumper parses this embedded database directly; Python is not invoked. Current-client runtime/native names retain priority. Historical aliases are applied only after a unique structural match. A reviewed exact-client serializer/parser RVA pair may resolve an otherwise structurally symmetric non-packet message, while CmdID anchors packet messages; obfuscated raw names never resolve structural ambiguity. Omitted oneof discriminator enums are excluded from the runtime graph exactly as they are from rendered Proto. Field tag/type/oneof, enum-number/scope, packet ownership, provenance, packet count, and packet-key-set guards all fail closed. Ambiguous, changed, or colliding records remain unchanged and are written to `DUMP/proto-accepted-name-evidence.json` as unresolved/conflict evidence.

Focused verification:

```bash
cargo +nightly -Z bindeps test -p dumper proto::accepted_names::tests -- --nocapture
HSR_PROTO_REPLAY_DIR=target/allocator-fh3-runtime-20261003-041926 \
  cargo +nightly -Z bindeps test -p dumper \
  proto::replay_tests::replay_builtin_accepted_names -- --exact --ignored --nocapture
```

The replay requires the reviewed machine-local wave10 artifacts. It compares every final type, field, oneof, enum variant, and packet display name, verifies the complete structural snapshot, and compiles the generated Proto through the frontend-compatible `protox` path.

## Runtime acceptance and limits

The final October 4, 2026 release DLL completed a fresh Proto WriteTo export in `target/proto-resource-acceptance-20261004-192637`: 1,108 packet IDs, 14,072 fields and all 1,155 embedded field aliases applied, with no unresolved, ambiguous or conflicting overlay records. The dumper library suite passed 289 tests with eight ignored tests; `cargo check` and the release build passed. Runtime log capture remained `partial_empty` and supplied no new identifier evidence.

Resources acceptance is not complete. Earlier exports raised a managed null-reference exception while reading the `RelicMainAffixBaseValue` binary, and the observed client was still at the login screen. IL2CPP/IPC readiness alone does not prove design-data readiness. Probe asset availability with JSON-domain paths such as `ExcelOutput/RelicMainAffixBaseValue.json`; `ExistsDesignData` converts them to baked binary paths internally. Do not pre-add `BakedConfig/`, skip every unavailable table, or count empty output as successful Resources acceptance.

The historical RVA fallback does not independently verify the current binary's identity. Structural and CmdID matching can be reused across versions, but structurally symmetric records resolved by historical RVA pairs are not a verified cross-version guarantee. No new runtime binary-hash gate is included.
