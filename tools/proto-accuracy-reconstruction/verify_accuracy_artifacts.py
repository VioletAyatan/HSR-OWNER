import hashlib
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
import reconstruct_accuracy_proto as reconstruction
import publication_lock

publication_lock.acquire_until_exit(RUN / ".accuracy-publication.lock")


class VerificationError(RuntimeError):
    pass


def require(condition, message):
    if not condition:
        raise VerificationError(message)


def sha(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def load_json(path):
    return json.loads(path.read_text(encoding="utf-8-sig"))


accepted = load_json(ACCEPTED)
report_path = RUN / "accuracy-reconstruction-report.json"
report = load_json(report_path)
compat_report = load_json(RUN / "derived-compatibility-validation.json")
sourceparse = load_json(RUN / "accuracy-sourceparse-validation.json")
publication = load_json(RUN / "accuracy-publication.json")
current = reconstruction.common.parse(RUN / "StarRail.compat.proto")
accuracy = reconstruction.common.parse(RUN / "StarRail.accuracy.proto")

require(not current["errors"] and not accuracy["errors"], {
    "compat_errors": current["errors"], "accuracy_errors": accuracy["errors"]
})
require(set(current["items"]) == set(accuracy["items"]), "canonical type identity set changed")

changed_layouts = [
    canonical for canonical in current["items"]
    if reconstruction.common.layout(current["items"][canonical])
    != reconstruction.common.layout(accuracy["items"][canonical])
]
require(not changed_layouts, {"changed_layouts": changed_layouts[:20]})

expected_fields = {
    (row["canonical"], row["tag"]): (row["before"], row["after"])
    for row in report["field_recoveries"]
}
actual_fields = {}
for canonical, item in current["items"].items():
    if item["kind"] != "message":
        continue
    before = reconstruction.fields(item)
    after = reconstruction.fields(accuracy["items"][canonical])
    for tag, (field, _) in before.items():
        if field["name"] != after[tag][0]["name"]:
            actual_fields[(canonical, tag)] = (field["name"], after[tag][0]["name"])
require(actual_fields == expected_fields, "field substitutions do not exactly match the report")

expected_messages = {
    row["canonical"]: (row["before"], row["after"])
    for row in report["message_type_recoveries"]
}
actual_messages = {
    canonical: (item["name"], accuracy["items"][canonical]["name"])
    for canonical, item in current["items"].items()
    if item["kind"] == "message" and item["name"] != accuracy["items"][canonical]["name"]
}
require(actual_messages == expected_messages, "message substitutions do not exactly match the report")

expected_enums = {
    row["canonical"]: (row["before"], row["after"])
    for row in report["enum_recoveries"]
}
actual_enums = {
    canonical: (item["name"], accuracy["items"][canonical]["name"])
    for canonical, item in current["items"].items()
    if item["kind"] == "enum" and item["name"] != accuracy["items"][canonical]["name"]
}
require(actual_enums == expected_enums, "enum substitutions do not exactly match the report")

expected_variants = {
    (row["canonical"], old): new
    for row in report["enum_recoveries"]
    for old, new in row["variants"].items()
}
actual_variants = {}
for canonical, item in current["items"].items():
    if item["kind"] != "enum":
        continue
    after = accuracy["items"][canonical]
    for (old_name, old_value), (new_name, new_value) in zip(item["variants"], after["variants"]):
        require(old_value == new_value, (canonical, old_value, new_value))
        if old_name != new_name:
            actual_variants[(canonical, old_name)] = new_name
require(actual_variants == expected_variants, "enum variant substitutions do not exactly match the report")

packet_ids = load_json(RUN / "packetIds.json")
unresolved = []
for cmd_id, name in packet_ids.items():
    candidates = {name} if name in accuracy["items"] else accuracy["aliases"].get(name, set())
    if isinstance(candidates, str):
        candidates = {candidates}
    if len(candidates) != 1:
        unresolved.append((cmd_id, name, "unresolved-or-ambiguous"))
        continue
    canonical = next(iter(candidates))
    item = accuracy["items"][canonical]
    if item["kind"] != "message" or item["parent"] is not None:
        unresolved.append((cmd_id, name, "packet-target-is-not-a-top-level-message"))
require(not unresolved, {"unresolved_packet_ids": unresolved[:20]})

owner_bindings_sum = sum(report["field_owner_bindings"].values())
field_change_kinds_sum = sum(report["field_change_kinds"].values())
require(owner_bindings_sum == report["field_recovery_count"], "owner binding total mismatch")
require(field_change_kinds_sum == report["field_recovery_count"], "field change kind total mismatch")
require(report["excluded_external_corrections_conflicting_with_current_evidence"] == 0,
        "accepted reconstruction contains a current-evidence conflict")

accuracy_hash = sha(RUN / "StarRail.accuracy.proto")
compat_hash = sha(RUN / "StarRail.compat.proto")
packet_hash = sha(RUN / "packetIds.json")
require(accuracy_hash == report["output_sha256"], "accuracy hash does not match reconstruction report")
require(compat_hash == compat_report["output_sha256"], "compat hash does not match compatibility report")
require(accuracy_hash == accepted["accuracy_proto_sha256"], "accuracy hash does not match accepted result")
require(compat_hash == accepted["compat_proto_sha256"], "compat hash does not match accepted result")
require(packet_hash == accepted["packet_ids_sha256"], "packet ID mapping hash does not match accepted result")
require(publication["validation"] == "accuracy-publication-complete",
        "accuracy publication is not complete")
require(publication["accuracy_proto_sha256"] == accuracy_hash,
        "publication marker references a different accuracy Proto")
require(publication["reconstruction_report_sha256"] == sha(report_path),
        "publication marker references a different reconstruction report")

accepted_reference = accepted["reference"]
require(report["reference_repo"] == accepted_reference["repo"], "reference repository changed")
require(report["reference_commit"] == accepted_reference["commit"], "reference commit changed")
require(report["reference_commit_verified"] is True, "reference commit was not verified")
require(report["reference_commit_blob_oid"] == accepted_reference["proto_blob_oid"],
        "reference commit Proto blob changed")
require(report["reference_worktree_blob_oid"] == accepted_reference["proto_blob_oid"],
        "reference worktree Proto blob changed")
require(report["reference_worktree_clean"] is True, "reference worktree is dirty")
require(report["reference_sha256"] == accepted_reference["proto_sha256"],
        "reference Proto hash changed")

counts = {
    "messages": sum(item["kind"] == "message" for item in accuracy["items"].values()),
    "fields": sum(
        len(reconstruction.fields(item))
        for item in accuracy["items"].values()
        if item["kind"] == "message"
    ),
    "enums": sum(item["kind"] == "enum" for item in accuracy["items"].values()),
    "oneofs": sum(
        len(item["oneofs"])
        for item in accuracy["items"].values()
        if item["kind"] == "message"
    ),
    "field_name_recoveries": len(actual_fields),
    "message_type_recoveries": len(actual_messages),
    "enum_type_recoveries": len(actual_enums),
    "enum_variant_recoveries": len(actual_variants),
    "excluded_field_name_collisions": report["excluded_field_name_collisions"],
    "packet_ids": len(packet_ids),
}
require(counts == accepted["counts"], {"actual_counts": counts, "accepted_counts": accepted["counts"]})
require(report["field_owner_bindings"] == accepted["field_owner_bindings"],
        "field owner binding counts do not match accepted result")

require(sourceparse["validation"] == "accuracy-sourceparse-passed", "source parser validation did not pass")
require(sourceparse["source_sha256"] == accuracy_hash, "source parser validated a different Proto")
require(sourceparse["descriptor_bytes"] == accepted["validation"]["descriptor_bytes"],
        "descriptor size does not match accepted result")
require(sourceparse["protox_compile"] == "success", "protox compile did not pass")
require(sourceparse["frontend_protobuf3_descriptor_decode"] == "success",
        "protobuf3 descriptor decode did not pass")

result = {
    "accepted_file": str(ACCEPTED),
    "accuracy_sha256": accuracy_hash,
    "compat_sha256": compat_hash,
    "packet_ids_sha256": packet_hash,
    "reference": accepted_reference,
    "counts": counts,
    "field_owner_bindings": report["field_owner_bindings"],
    "descriptor_bytes": sourceparse["descriptor_bytes"],
    "wire_layout_preserved": True,
    "canonical_type_identity_preserved": True,
    "passed": True,
}
reconstruction.atomic_write_bytes(
    RUN / "accuracy-artifact-checks.json",
    json.dumps(result, ensure_ascii=False, separators=(",", ":")).encode("utf-8"),
)
print(json.dumps(result, ensure_ascii=False))