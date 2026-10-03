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
