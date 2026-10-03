import json
import os
import sys
from pathlib import Path

PROJECT = Path(os.environ.get("HSR_OWNER_ROOT", Path(__file__).resolve().parents[2])).resolve()
RUN = Path(os.environ.get(
    "HSR_PROTO_RUN",
    PROJECT / "target/allocator-fh3-runtime-20261003-041926",
)).resolve()
ACCEPTED = Path(os.environ.get(
    "HSR_PROTO_ACCEPTED",
    Path(__file__).resolve().parent / "accepted-2026-10-03.json",
)).resolve()
sys.path.insert(0, str(Path(__file__).resolve().parent))
import publication_lock

publication_lock.acquire_until_exit(RUN / ".accuracy-publication.lock")


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


report = json.loads((RUN / "accuracy-reconstruction-report.json").read_text(encoding="utf-8-sig"))
accepted = json.loads(ACCEPTED.read_text(encoding="utf-8-sig"))
expected_counts = accepted["counts"]
expected_bindings = accepted["field_owner_bindings"]
expected_reference = accepted["reference"]

require(report["field_owner_bindings"] == expected_bindings, "field owner binding counts changed")
require(report["field_recovery_count"] == expected_counts["field_name_recoveries"],
        "field recovery count changed")
require(report["message_type_recovery_count"] == expected_counts["message_type_recoveries"],
        "message type recovery count changed")
require(report["enum_recovery_count"] == expected_counts["enum_type_recoveries"],
        "enum recovery count changed")
require(report["enum_variant_recovery_count"] == expected_counts["enum_variant_recoveries"],
        "enum variant recovery count changed")
require(report["excluded_field_name_collisions"] == expected_counts["excluded_field_name_collisions"],
        "excluded collision count changed")
require(report.get("reference_worktree_clean") is True, "reference worktree is dirty")
require(report.get("reference_repo") == expected_reference["repo"], "reference repository changed")
require(report.get("reference_commit") == expected_reference["commit"], "reference commit changed")
require(report.get("reference_commit_verified") is True, "reference commit was not verified")
require(report.get("reference_commit_blob_oid") == expected_reference["proto_blob_oid"],
        "reference commit Proto blob changed")
require(report.get("reference_worktree_blob_oid") == expected_reference["proto_blob_oid"],
        "reference worktree Proto blob changed")
require(report.get("reference_sha256") == expected_reference["proto_sha256"],
        "reference Proto hash changed")

print(json.dumps({
    "field_owner_bindings": report["field_owner_bindings"],
    "message_types": report["message_type_recovery_count"],
    "enums": report["enum_recovery_count"],
    "enum_variants": report["enum_variant_recovery_count"],
    "excluded_collisions": report["excluded_field_name_collisions"],
    "total_fields": report["field_recovery_count"],
}))