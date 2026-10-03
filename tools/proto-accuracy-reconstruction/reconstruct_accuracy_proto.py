import difflib
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
from collections import defaultdict, deque
from pathlib import Path

PROJECT = Path(os.environ.get("HSR_OWNER_ROOT", Path(__file__).resolve().parents[2])).resolve()
RUN = Path(os.environ.get(
    "HSR_PROTO_RUN",
    PROJECT / "target/allocator-fh3-runtime-20261003-041926",
)).resolve()
SOURCE = RUN / "StarRail.compat.proto"
RAW = RUN / "StarRail.proto"
REFERENCE_REPO = Path(os.environ.get(
    "HSR_PROTO_REFERENCE_REPO",
    Path.home() / "AppData/Local/hermes/cache/scratch/hsr-proto",
)).resolve()
REFERENCE = REFERENCE_REPO / "StarRail.proto"
REFERENCE_COMMIT = os.environ.get(
    "HSR_PROTO_REFERENCE_COMMIT",
    "40bca1cb24d80e68815fdb310c10906880ca3c3b",
)
sys.path.insert(0, str(Path(__file__).resolve().parent))
import proto_document as common
import publication_lock

FIELD_LINE = re.compile(r"^(\s*)(?:(repeated)\s+)?(.+?)\s+([A-Za-z_][A-Za-z_0-9]*)(\s*=\s*)(\d+)(;.*)$")
VARIANT_LINE = re.compile(r"^(\s*)([A-Za-z_][A-Za-z_0-9]*)(\s*=\s*)(-?\d+)(;.*)$")
HASHED_NAME = re.compile(r"H_[0-9a-fA-F]{8}$")
SCALARS = set("double float int32 int64 uint32 uint64 sint32 sint64 fixed32 fixed64 sfixed32 sfixed64 bool string bytes".split())


def sha(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def sha_bytes(data):
    return hashlib.sha256(data).hexdigest()


def stage_bytes(destination, data):
    destination = Path(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)
    descriptor, name = tempfile.mkstemp(
        prefix=f".{destination.name}.", suffix=".tmp", dir=destination.parent
    )
    temporary = Path(name)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        return temporary
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


def atomic_write_bytes(destination, data):
    destination = Path(destination)
    temporary = stage_bytes(destination, data)
    try:
        os.replace(temporary, destination)
    finally:
        temporary.unlink(missing_ok=True)


def publish_generation(destination, output_bytes, report_destination, report_bytes,
                       publication_destination):
    destination = Path(destination)
    report_destination = Path(report_destination)
    publication_destination = Path(publication_destination)
    temporary_output = None
    temporary_report = None
    publication_started = False
    old_output = None
    old_report = None
    old_publication = None
    try:
        temporary_output = stage_bytes(destination, output_bytes)
        temporary_report = stage_bytes(report_destination, report_bytes)
        old_output = destination.read_bytes() if destination.exists() else None
        old_report = report_destination.read_bytes() if report_destination.exists() else None
        old_publication = (
            publication_destination.read_bytes() if publication_destination.exists() else None
        )
        publication_started = True
        publication_destination.unlink(missing_ok=True)
        os.replace(temporary_output, destination)
        temporary_output = None
        os.replace(temporary_report, report_destination)
        temporary_report = None
        publication = {
            "validation": "accuracy-publication-complete",
            "accuracy_proto_sha256": sha_bytes(output_bytes),
            "reconstruction_report_sha256": sha_bytes(report_bytes),
        }
        atomic_write_bytes(
            publication_destination,
            json.dumps(publication, ensure_ascii=False, indent=2).encode("utf-8"),
        )
        return publication
    except BaseException as publication_error:
        rollback_errors = []
        if publication_started:
            for path, previous in (
                (destination, old_output),
                (report_destination, old_report),
                (publication_destination, old_publication),
            ):
                try:
                    if previous is None:
                        path.unlink(missing_ok=True)
                    else:
                        atomic_write_bytes(path, previous)
                except BaseException as rollback_error:
                    rollback_errors.append(rollback_error)
        if rollback_errors:
            raise BaseExceptionGroup(
                "publication failed and rollback was incomplete",
                [publication_error, *rollback_errors],
            )
        raise
    finally:
        if temporary_output is not None:
            temporary_output.unlink(missing_ok=True)
        if temporary_report is not None:
            temporary_report.unlink(missing_ok=True)


def fields(item):
    out = [(f, False) for f in item["fields"]]
    for oneof in item["oneofs"]:
        out.extend((f, True) for f in oneof["fields"])
    return {field["tag"]: (field, is_oneof) for field, is_oneof in out}


def category(document, kind):
    token = kind.strip().removeprefix("Proto.")
    if token.startswith("repeated "):
        return ("repeated", category(document, token[9:]))
    if token.startswith("map<"):
        key, value = token[4:-1].split(",", 1)
        return ("map", category(document, key), category(document, value))
    if token in SCALARS:
        return token
    canonical = token if token in document["items"] else document["aliases"].get(token)
    return document["items"][canonical]["kind"] if canonical in document["items"] else "unknown"


def enum_references(document, kind):
    token = kind.strip().removeprefix("Proto.")
    if token.startswith("repeated "):
        return enum_references(document, token[9:])
    if token.startswith("map<"):
        key, value = token[4:-1].split(",", 1)
        return enum_references(document, key) + enum_references(document, value)
    canonical = token if token in document["items"] else document["aliases"].get(token)
    if canonical in document["items"] and document["items"][canonical]["kind"] == "enum":
        return [canonical]
    return []


def fingerprint(document, item):
    if item["kind"] == "enum":
        return ("enum", tuple(value for _, value in item["variants"]))
    flat = []
    for field in item["fields"]:
        flat.append((field["tag"], category(document, field["normalized_kind"]), False))
    for oneof in item["oneofs"]:
        for field in oneof["fields"]:
            flat.append((field["tag"], category(document, field["normalized_kind"]), True))
    return ("message", tuple(sorted(flat)), len(item["oneofs"]), len(item["children"]))


def align_items(current, reference):
    left, right = list(current["items"].items()), list(reference["items"].items())
    matcher = difflib.SequenceMatcher(a=[key for key, _ in left], b=[key for key, _ in right], autojunk=False)
    pairs = {}
    previous_left = previous_right = 0
    for block in matcher.get_matching_blocks():
        left_gap = list(range(previous_left, block.a))
        right_gap = list(range(previous_right, block.b))
        if len(left_gap) == len(right_gap):
            for a, b in zip(left_gap, right_gap):
                if fingerprint(current, left[a][1]) == fingerprint(reference, right[b][1]):
                    pairs[a] = b
        else:
            gap_matcher = difflib.SequenceMatcher(
                a=[fingerprint(current, left[index][1]) for index in left_gap],
                b=[fingerprint(reference, right[index][1]) for index in right_gap],
                autojunk=False,
            )
            for gap in gap_matcher.get_matching_blocks():
                for offset in range(gap.size):
                    pairs[left_gap[gap.a + offset]] = right_gap[gap.b + offset]
        for offset in range(block.size):
            pairs[block.a + offset] = block.b + offset
        previous_left = block.a + block.size
        previous_right = block.b + block.size
    return left, right, pairs


def type_references(document, kind):
    token = kind.strip().removeprefix("Proto.")
    if token.startswith("repeated "):
        return type_references(document, token[9:])
    if token.startswith("map<"):
        key, value = token[4:-1].split(",", 1)
        return type_references(document, key) + type_references(document, value)
    canonical = token if token in document["items"] else document["aliases"].get(token)
    if isinstance(canonical, set):
        return []
    return [canonical] if canonical in document["items"] else []


def graph_align_items(current, reference):
    mapping, reverse, proofs, rejected = {}, {}, {}, []
    queue = deque()

    def add(left, right, proof):
        if left in mapping:
            if mapping[left] != right:
                rejected.append({"left": left, "right": right, "existing": mapping[left],
                                 "proof": proof, "reason": "left-conflict"})
            return False
        if right in reverse:
            if reverse[right] != left:
                rejected.append({"left": left, "right": right, "existing_left": reverse[right],
                                 "proof": proof, "reason": "right-conflict"})
            return False
        item, other = current["items"].get(left), reference["items"].get(right)
        if (item is None or other is None or item["kind"] != other["kind"]
                or fingerprint(current, item) != fingerprint(reference, other)):
            rejected.append({"left": left, "right": right, "proof": proof,
                             "reason": "kind-or-fingerprint-mismatch"})
            return False
        mapping[left], reverse[right], proofs[left] = right, left, proof
        queue.append(left)
        return True

    for left, item in current["items"].items():
        if left in reference["items"]:
            add(left, left, {"source": "same-canonical-identity"})
            continue
        candidates = []
        for token in (item["display"], item["name"]):
            right = reference["aliases"].get(token)
            if isinstance(right, str):
                candidates.append(right)
            elif right:
                candidates.extend(right)
            if token in reference["items"]:
                candidates.append(token)
        candidates = sorted(set(candidates))
        if len(candidates) == 1:
            add(left, candidates[0], {"source": "same-readable-display-or-name",
                                      "token": item["display"]})

    while queue:
        owner = queue.popleft()
        external_owner = mapping[owner]
        item, other = current["items"][owner], reference["items"][external_owner]
        if item["kind"] != "message":
            continue
        current_fields, reference_fields = fields(item), fields(other)
        for tag, (field, is_oneof) in current_fields.items():
            match = reference_fields.get(tag)
            if not match:
                continue
            external, external_oneof = match
            if (is_oneof != external_oneof
                    or category(current, field["normalized_kind"])
                        != category(reference, external["normalized_kind"])):
                continue
            left_refs = type_references(current, field["normalized_kind"])
            right_refs = type_references(reference, external["normalized_kind"])
            if len(left_refs) != len(right_refs):
                continue
            for left_ref, right_ref in zip(left_refs, right_refs):
                add(left_ref, right_ref, {
                    "source": "mapped-owner-field-type-edge",
                    "owner": owner, "external_owner": external_owner, "tag": tag,
                    "field": field["name"], "external_field": external["name"],
                })
    return mapping, proofs, rejected


def reverse_align_messages(current, reference, mapping):
    """Bind an unmapped owner only when >=3 mapped typed tags uniquely identify it."""
    mapped_right = set(mapping.values())
    reference_buckets = {}
    for canonical, item in reference["items"].items():
        if item["kind"] == "message" and canonical not in mapped_right:
            reference_buckets.setdefault(fingerprint(reference, item), []).append(canonical)

    candidates = []
    for canonical, item in current["items"].items():
        if item["kind"] != "message" or canonical in mapping:
            continue
        for external_owner in reference_buckets.get(fingerprint(current, item), []):
            other = reference["items"][external_owner]
            candidate_name = other["name"]
            if (common.OBF.fullmatch(candidate_name) or HASHED_NAME.fullmatch(candidate_name)
                    or re.search(r"\d+$", candidate_name)):
                continue
            current_fields, reference_fields = fields(item), fields(other)
            anchors = []
            for tag, (field, is_oneof) in current_fields.items():
                match = reference_fields.get(tag)
                if not match:
                    continue
                external, external_oneof = match
                if is_oneof != external_oneof:
                    continue
                left_refs = type_references(current, field["normalized_kind"])
                right_refs = type_references(reference, external["normalized_kind"])
                if (not left_refs or len(left_refs) != len(right_refs)
                        or any(mapping.get(left) != right
                               for left, right in zip(left_refs, right_refs))):
                    continue
                anchors.append({
                    "tag": tag,
                    "current_types": left_refs,
                    "external_types": right_refs,
                    "oneof": is_oneof,
                })
            if len({anchor["tag"] for anchor in anchors}) >= 3:
                candidates.append({
                    "canonical": canonical,
                    "external_owner": external_owner,
                    "anchors": anchors,
                    "source": "reverse-mapped-field-type-anchors",
                })

    left_counts = {}
    right_counts = {}
    for row in candidates:
        left_counts[row["canonical"]] = left_counts.get(row["canonical"], 0) + 1
        right_counts[row["external_owner"]] = right_counts.get(row["external_owner"], 0) + 1
    accepted = [row for row in candidates
                if left_counts[row["canonical"]] == 1
                and right_counts[row["external_owner"]] == 1]
    rejected = [dict(row, reason="reverse-owner-not-bidirectionally-unique")
                for row in candidates if row not in accepted]
    return accepted, rejected


def strict_graph_message_type_names(current, reference, mapping, proofs):
    """Recover message type names supported by >=2 independent root owners."""
    used_names = defaultdict(set)
    for canonical, item in current["items"].items():
        used_names[(item["parent"], item["name"])].add(canonical)

    supports = defaultdict(list)
    for owner, external_owner in mapping.items():
        owner_proof = proofs[owner]
        if owner_proof["source"] not in {
            "same-canonical-identity", "same-readable-display-or-name"
        }:
            continue
        item, other = current["items"][owner], reference["items"][external_owner]
        if item["kind"] != "message" or other["kind"] != "message":
            continue
        current_fields, reference_fields = fields(item), fields(other)
        for tag, (field, is_oneof) in current_fields.items():
            match = reference_fields.get(tag)
            if not match:
                continue
            external, external_oneof = match
            if is_oneof != external_oneof:
                continue
            left_refs = type_references(current, field["normalized_kind"])
            right_refs = type_references(reference, external["normalized_kind"])
            if len(left_refs) != len(right_refs):
                continue
            for left, right in zip(left_refs, right_refs):
                if mapping.get(left) == right:
                    supports[left].append({
                        "owner": owner,
                        "external_owner": external_owner,
                        "tag": tag,
                        "oneof": is_oneof,
                        "current_type": left,
                        "external_type": right,
                        "owner_proof": owner_proof,
                    })

    accepted, rejected = {}, []
    for canonical, rows in sorted(supports.items()):
        external_canonical = mapping[canonical]
        item = current["items"][canonical]
        external = reference["items"][external_canonical]
        root_owners = sorted({row["owner"] for row in rows})
        candidate_name = external["name"]
        reason = None
        if item["kind"] != "message" or external["kind"] != "message":
            reason = "not-message"
        elif not common.OBF.fullmatch(item["name"]):
            reason = "current-name-not-obfuscated"
        elif common.OBF.fullmatch(candidate_name) or HASHED_NAME.fullmatch(candidate_name):
            reason = "candidate-name-not-readable"
        elif len(root_owners) < 2:
            reason = "fewer-than-two-independent-root-owners"
        elif any(other != canonical for other in used_names.get(
                (item["parent"], candidate_name), set())):
            reason = "candidate-name-collision"
        if reason is not None:
            rejected.append({
                "canonical": canonical,
                "external": external_canonical,
                "candidate": candidate_name,
                "root_owners": root_owners,
                "supports": rows,
                "reason": reason,
            })
            continue
        accepted[canonical] = {
            "before": item["name"],
            "after": candidate_name,
            "external_canonical": external_canonical,
            "root_owner_count": len(root_owners),
            "root_owners": root_owners,
            "supports": rows,
            "source": "same-version-reference-type-name-proven-by-two-or-more-independent-root-owners",
        }
        used_names[(item["parent"], candidate_name)].add(canonical)
    return accepted, rejected


def current_name_evidence():
    names = {}
    def add(rows, source):
        for row in rows:
            message, tag = row.get("message"), row.get("tag")
            name = row.get("final_name") or row.get("recovered")
            if message is not None and tag is not None and name:
                names.setdefault((message, int(tag)), []).append({
                    "source": source, "name": name, "status": row.get("status", "")
                })
    field = json.loads((RUN / "proto-field-name-evidence.json").read_text(encoding="utf-8-sig"))
    add(field["summary"]["evidence"], "field-number-constant")
    sync = json.loads((RUN / "proto-sync-field-evidence.json").read_text(encoding="utf-8-sig"))
    add(sync["summary"]["evidence"], "runtime-native-copy")
    gateway = json.loads((RUN / "proto-gateway-name-evidence.json").read_text(encoding="utf-8-sig"))
    add(gateway["evidence"], "gateway-runtime")
    return names


def reconstruct_locked():
    current = common.parse(SOURCE)
    raw = common.parse(RAW)
    if current["errors"] or raw["errors"]:
        raise RuntimeError((current["errors"], raw["errors"]))
    reference_commit = subprocess.check_output(
        ["git", "-C", str(REFERENCE_REPO), "rev-parse", "HEAD"], text=True
    ).strip()
    if reference_commit != REFERENCE_COMMIT:
        raise RuntimeError(f"reference commit changed: {reference_commit}")
    reference_status = subprocess.check_output(
        ["git", "-C", str(REFERENCE_REPO), "status", "--porcelain=v1", "-uall"], text=True
    ).strip()
    if reference_status:
        raise RuntimeError(f"reference worktree is dirty: {reference_status}")
    reference_commit_blob_oid = subprocess.check_output(
        ["git", "-C", str(REFERENCE_REPO), "rev-parse", f"{reference_commit}:StarRail.proto"],
        text=True,
    ).strip()
    reference_worktree_blob_oid = subprocess.check_output(
        ["git", "-C", str(REFERENCE_REPO), "hash-object", "--path=StarRail.proto", "StarRail.proto"],
        text=True,
    ).strip()
    if reference_worktree_blob_oid != reference_commit_blob_oid:
        raise RuntimeError("reference StarRail.proto does not match the verified commit blob")
    reference_remote = subprocess.check_output(
        ["git", "-C", str(REFERENCE_REPO), "remote", "get-url", "origin"], text=True
    ).strip()
    reference_bytes = subprocess.check_output(
        ["git", "-C", str(REFERENCE_REPO), "show", f"{reference_commit}:StarRail.proto"]
    )
    parsed_reference_blob_oid = subprocess.check_output(
        ["git", "-C", str(REFERENCE_REPO), "hash-object", "--stdin"], input=reference_bytes
    ).decode("ascii").strip()
    if parsed_reference_blob_oid != reference_commit_blob_oid:
        raise RuntimeError("reference bytes do not match the verified commit blob")
    reference_temporary = stage_bytes(RUN / "pinned-reference.proto", reference_bytes)
    try:
        reference = common.parse(reference_temporary)
    finally:
        reference_temporary.unlink(missing_ok=True)
    if reference["errors"]:
        raise RuntimeError(reference["errors"])
    reference_sha256 = sha_bytes(reference_bytes)

    field_replacements = {}
    protected_names = current_name_evidence()
    excluded_runtime_conflicts = []
    excluded_readable_corrections = []
    excluded_name_collisions = []
    current_items, reference_items, aligned = align_items(current, reference)
    alignment_counts = {"raw-owner": 0, "readable-owner": 0,
                        "graph-edge-owner": 0, "reverse-graph-owner": 0}
    field_change_kinds = {"new-readable-name": 0, "corrected-readable-name": 0}
    for current_index, reference_index in sorted(aligned.items()):
        canonical, item = current_items[current_index]
        external_owner, other = reference_items[reference_index]
        if (item["kind"] != "message" or other["kind"] != "message"
                or fingerprint(current, item) != fingerprint(reference, other)):
            continue
        if canonical == external_owner:
            owner_binding = "raw-owner"
        elif item["display"] == other["display"] or item["name"] == other["name"]:
            owner_binding = "readable-owner"
        else:
            continue
        current_fields, reference_fields = fields(item), fields(other)
        for tag, (field, is_oneof) in current_fields.items():
            match = reference_fields.get(tag)
            if not match:
                continue
            external, external_oneof = match
            if (field["name"] != external["name"]
                    and not common.OBF.fullmatch(external["name"])
                    and not HASHED_NAME.fullmatch(external["name"])
                    and is_oneof == external_oneof
                    and category(current, field["normalized_kind"])
                        == category(reference, external["normalized_kind"])):
                evidence = protected_names.get((canonical, tag), [])
                raw_match = fields(raw["items"][canonical]).get(tag) if canonical in raw["items"] else None
                raw_name = raw_match[0]["name"] if raw_match else None
                if not common.OBF.fullmatch(field["name"]):
                    excluded_readable_corrections.append({
                        "canonical": canonical, "tag": tag,
                        "current": field["name"], "raw_runtime": raw_name,
                        "external": external["name"], "external_owner": external_owner,
                        "evidence": evidence,
                        "reason": "readable-current-name-requires-separate-stronger-proof",
                    })
                    continue
                colliding_tags = [
                    other_tag for other_tag, (other_field, _) in current_fields.items()
                    if other_tag != tag and other_field["name"] == external["name"]
                ]
                if colliding_tags:
                    excluded_name_collisions.append({
                        "canonical": canonical, "tag": tag,
                        "current": field["name"], "external": external["name"],
                        "external_owner": external_owner,
                        "colliding_tags": colliding_tags,
                        "reason": "candidate-name-already-used-by-another-current-field",
                    })
                    continue
                if any(item["name"] != external["name"] for item in evidence):
                    excluded_runtime_conflicts.append({
                        "canonical": canonical, "tag": tag,
                        "current": field["name"], "external": external["name"],
                        "external_owner": external_owner, "evidence": evidence,
                    })
                    continue
                field_replacements[(canonical, tag)] = {
                    "before": field["name"], "after": external["name"],
                    "kind": field["normalized_kind"], "oneof": is_oneof,
                    "external_owner": external_owner,
                    "owner_binding": owner_binding,
                    "change_kind": "new-readable-name",
                    "source": "same-version-reference-aligned-owner-tag-wire-category",
                }
                alignment_counts[owner_binding] += 1
                field_change_kinds[field_replacements[(canonical, tag)]["change_kind"]] += 1

    graph_mapping, graph_proofs, graph_rejections = graph_align_items(current, reference)
    for canonical, external_owner in sorted(graph_mapping.items()):
        owner_proof = graph_proofs[canonical]
        if owner_proof["source"] != "mapped-owner-field-type-edge":
            continue
        owner_binding = "graph-edge-owner"
        item, other = current["items"][canonical], reference["items"][external_owner]
        if item["kind"] != "message" or other["kind"] != "message":
            continue
        current_fields, reference_fields = fields(item), fields(other)
        for tag, (field, is_oneof) in current_fields.items():
            if (canonical, tag) in field_replacements:
                continue
            match = reference_fields.get(tag)
            if not match:
                continue
            external, external_oneof = match
            if (field["name"] == external["name"]
                    or common.OBF.fullmatch(external["name"])
                    or HASHED_NAME.fullmatch(external["name"])
                    or is_oneof != external_oneof
                    or category(current, field["normalized_kind"])
                        != category(reference, external["normalized_kind"])):
                continue
            evidence = protected_names.get((canonical, tag), [])
            raw_match = fields(raw["items"][canonical]).get(tag) if canonical in raw["items"] else None
            raw_name = raw_match[0]["name"] if raw_match else None
            if not common.OBF.fullmatch(field["name"]):
                excluded_readable_corrections.append({
                    "canonical": canonical, "tag": tag,
                    "current": field["name"], "raw_runtime": raw_name,
                    "external": external["name"], "external_owner": external_owner,
                    "evidence": evidence, "owner_proof": owner_proof,
                    "reason": "readable-current-name-requires-separate-stronger-proof",
                })
                continue
            colliding_tags = [
                other_tag for other_tag, (other_field, _) in current_fields.items()
                if other_tag != tag and other_field["name"] == external["name"]
            ]
            if colliding_tags:
                excluded_name_collisions.append({
                    "canonical": canonical, "tag": tag,
                    "current": field["name"], "external": external["name"],
                    "external_owner": external_owner, "colliding_tags": colliding_tags,
                    "owner_proof": owner_proof,
                    "reason": "candidate-name-already-used-by-another-current-field",
                })
                continue
            if any(item["name"] != external["name"] for item in evidence):
                excluded_runtime_conflicts.append({
                    "canonical": canonical, "tag": tag,
                    "current": field["name"], "external": external["name"],
                    "external_owner": external_owner, "evidence": evidence,
                    "owner_proof": owner_proof,
                })
                continue
            field_replacements[(canonical, tag)] = {
                "before": field["name"], "after": external["name"],
                "kind": field["normalized_kind"], "oneof": is_oneof,
                "external_owner": external_owner,
                "owner_binding": owner_binding,
                "owner_proof": owner_proof,
                "change_kind": "new-readable-name",
                "source": "same-version-reference-owner-proven-by-identity-or-field-type-graph-tag-wire-category",
            }
            alignment_counts[owner_binding] += 1
            field_change_kinds["new-readable-name"] += 1

    reverse_mappings, reverse_mapping_rejections = reverse_align_messages(
        current, reference, graph_mapping
    )
    for owner_proof in reverse_mappings:
        canonical = owner_proof["canonical"]
        external_owner = owner_proof["external_owner"]
        owner_binding = "reverse-graph-owner"
        item, other = current["items"][canonical], reference["items"][external_owner]
        current_fields, reference_fields = fields(item), fields(other)
        for tag, (field, is_oneof) in current_fields.items():
            if (canonical, tag) in field_replacements:
                continue
            match = reference_fields.get(tag)
            if not match:
                continue
            external, external_oneof = match
            if (field["name"] == external["name"]
                    or common.OBF.fullmatch(external["name"])
                    or HASHED_NAME.fullmatch(external["name"])
                    or is_oneof != external_oneof
                    or category(current, field["normalized_kind"])
                        != category(reference, external["normalized_kind"])):
                continue
            evidence = protected_names.get((canonical, tag), [])
            raw_match = fields(raw["items"][canonical]).get(tag) if canonical in raw["items"] else None
            raw_name = raw_match[0]["name"] if raw_match else None
            if not common.OBF.fullmatch(field["name"]):
                excluded_readable_corrections.append({
                    "canonical": canonical, "tag": tag,
                    "current": field["name"], "raw_runtime": raw_name,
                    "external": external["name"], "external_owner": external_owner,
                    "evidence": evidence, "owner_proof": owner_proof,
                    "reason": "readable-current-name-requires-separate-stronger-proof",
                })
                continue
            colliding_tags = [
                other_tag for other_tag, (other_field, _) in current_fields.items()
                if other_tag != tag and other_field["name"] == external["name"]
            ]
            if colliding_tags:
                excluded_name_collisions.append({
                    "canonical": canonical, "tag": tag,
                    "current": field["name"], "external": external["name"],
                    "external_owner": external_owner, "colliding_tags": colliding_tags,
                    "owner_proof": owner_proof,
                    "reason": "candidate-name-already-used-by-another-current-field",
                })
                continue
            if any(row["name"] != external["name"] for row in evidence):
                excluded_runtime_conflicts.append({
                    "canonical": canonical, "tag": tag,
                    "current": field["name"], "external": external["name"],
                    "external_owner": external_owner, "evidence": evidence,
                    "owner_proof": owner_proof,
                })
                continue
            field_replacements[(canonical, tag)] = {
                "before": field["name"], "after": external["name"],
                "kind": field["normalized_kind"], "oneof": is_oneof,
                "external_owner": external_owner,
                "owner_binding": owner_binding,
                "owner_proof": owner_proof,
                "change_kind": "new-readable-name",
                "source": "same-version-reference-owner-proven-by-three-or-more-reverse-type-anchors",
            }
            alignment_counts[owner_binding] += 1
            field_change_kinds["new-readable-name"] += 1

    message_replacements, excluded_message_type_candidates = strict_graph_message_type_names(
        current, reference, graph_mapping, graph_proofs
    )

    current_enums = [(key, value) for key, value in current["items"].items() if value["kind"] == "enum"]
    reference_enums = [(key, value) for key, value in reference["items"].items() if value["kind"] == "enum"]
    if len(current_enums) != len(reference_enums):
        raise RuntimeError("enum declaration counts differ")
    enum_replacements = {}
    type_tokens = {
        row["before"]: row["after"] for row in message_replacements.values()
    }
    reserved_type_names = defaultdict(set)
    for existing_canonical, existing_item in current["items"].items():
        reserved_type_names[(existing_item["parent"], existing_item["name"])].add(existing_canonical)
    for message_canonical, replacement in message_replacements.items():
        parent = current["items"][message_canonical]["parent"]
        reserved_type_names[(parent, replacement["after"])].add(message_canonical)
    enum_candidates = []
    for index, ((canonical, item), (external_canonical, external)) in enumerate(zip(current_enums, reference_enums)):
        current_values = [value for _, value in item["variants"]]
        external_values = [value for _, value in external["variants"]]
        if (current_values == external_values
                and common.OBF.fullmatch(item["name"])
                and not common.OBF.fullmatch(external["name"])):
            enum_candidates.append((index, canonical, item, external_canonical, external, current_values))
    enum_reference_sites = {canonical: [] for _, canonical, _, _, _, _ in enum_candidates}
    external_by_current = {canonical: external for _, canonical, _, external, _, _ in enum_candidates}
    for current_index, reference_index in sorted(aligned.items()):
        owner, item = current_items[current_index]
        external_owner, other = reference_items[reference_index]
        if (item["kind"] != "message" or other["kind"] != "message"
                or fingerprint(current, item) != fingerprint(reference, other)
                or not (owner == external_owner or item["display"] == other["display"]
                        or item["name"] == other["name"])):
            continue
        current_fields, reference_fields = fields(item), fields(other)
        for tag, (field, is_oneof) in current_fields.items():
            match = reference_fields.get(tag)
            if not match:
                continue
            external_field, external_oneof = match
            if is_oneof != external_oneof:
                continue
            for enum in enum_references(current, field["normalized_kind"]):
                if (enum in external_by_current
                        and external_by_current[enum]
                            in enum_references(reference, external_field["normalized_kind"])):
                    enum_reference_sites[enum].append({
                        "owner": owner, "external_owner": external_owner, "tag": tag,
                        "field": field["name"], "external_field": external_field["name"],
                        "owner_binding": "aligned-owner",
                    })
    for owner, external_owner in sorted(graph_mapping.items()):
        item, other = current["items"][owner], reference["items"][external_owner]
        if item["kind"] != "message" or other["kind"] != "message":
            continue
        current_fields, reference_fields = fields(item), fields(other)
        for tag, (field, is_oneof) in current_fields.items():
            match = reference_fields.get(tag)
            if not match:
                continue
            external_field, external_oneof = match
            if is_oneof != external_oneof:
                continue
            for enum in enum_references(current, field["normalized_kind"]):
                external_enum = external_by_current.get(enum)
                if (external_enum is not None
                        and graph_mapping.get(enum) == external_enum
                        and external_enum in enum_references(
                            reference, external_field["normalized_kind"]
                        )):
                    site = {
                        "owner": owner, "external_owner": external_owner, "tag": tag,
                        "field": field["name"], "external_field": external_field["name"],
                        "owner_binding": "graph-owner",
                        "owner_proof": graph_proofs[owner],
                        "enum_proof": graph_proofs[enum],
                    }
                    if site not in enum_reference_sites[enum]:
                        enum_reference_sites[enum].append(site)
    excluded_unreferenced_enums = []
    excluded_enum_name_collisions = []
    for index, canonical, item, external_canonical, external, current_values in enum_candidates:
        reference_sites = enum_reference_sites[canonical]
        if not reference_sites:
            excluded_unreferenced_enums.append({
                "canonical": canonical, "external": external_canonical,
                "candidate": external["name"], "index": index, "values": current_values,
                "reason": "no-aligned-reference-field",
            })
            continue
        candidate_name = external["name"]
        candidate_variants = [name for name, _ in external["variants"]]
        type_key = (item["parent"], candidate_name)
        type_conflicts = sorted(reserved_type_names.get(type_key, set()) - {canonical})
        invalid_variants = sorted({
            name for name in candidate_variants if not common.IDENT.fullmatch(name)
        })
        duplicate_variants = sorted({
            name for name in candidate_variants if candidate_variants.count(name) > 1
        })
        if (not common.IDENT.fullmatch(candidate_name)
                or type_conflicts or invalid_variants or duplicate_variants):
            excluded_enum_name_collisions.append({
                "canonical": canonical,
                "external": external_canonical,
                "candidate": candidate_name,
                "type_conflicts": type_conflicts,
                "invalid_variants": invalid_variants,
                "duplicate_variants": duplicate_variants,
                "reason": "enum-type-or-variant-name-collision",
            })
            continue
        variants = {}
        for (old_name, old_value), (new_name, new_value) in zip(item["variants"], external["variants"]):
            if old_value != new_value:
                raise RuntimeError("enum value sequence changed")
            variants[old_name] = new_name
        enum_replacements[canonical] = {
            "before": item["name"], "after": external["name"],
            "index": index, "values": current_values, "variants": variants,
            "reference_sites": reference_sites,
            "source": "same-version-reference-enum-order-complete-value-sequence-and-reference-field",
        }
        type_tokens[item["name"]] = external["name"]
        reserved_type_names[type_key].add(canonical)

    source = SOURCE.read_text(encoding="utf-8-sig")
    stack = []
    pending = None
    used_fields, used_messages, used_enums, used_variants = set(), set(), set(), set()
    output = []
    for line in source.splitlines(keepends=True):
        trimmed = line.strip()
        if trimmed.startswith("// Obf: "):
            pending = trimmed.removeprefix("// Obf: ").removeprefix("Proto.")
            output.append(line)
            continue
        if trimmed.endswith(" {"):
            kind, display = trimmed[:-2].split(" ", 1)
            if kind in ("message", "enum"):
                parent = next((scope[1] for scope in reversed(stack) if scope[0] == "message"), "")
                raw = pending if pending is not None else display
                canonical = (parent + "." if parent else "") + raw
                replacement = (enum_replacements.get(canonical) if kind == "enum"
                               else message_replacements.get(canonical))
                if replacement is not None:
                    if pending is None:
                        output.append(line[:len(line)-len(line.lstrip())] + f"// Obf: {raw}\n")
                    line = line.replace(f"{kind} {display} {{", f"{kind} {replacement['after']} {{", 1)
                    if kind == "enum":
                        used_enums.add(canonical)
                    else:
                        used_messages.add(canonical)
                    display = replacement["after"]
                stack.append((kind, canonical))
                pending = None
            elif kind == "oneof":
                stack.append((kind, ""))
            output.append(line)
            continue
        if trimmed == "}":
            stack.pop()
            output.append(line)
            continue
        if stack and stack[-1][0] == "enum" and not trimmed.startswith("//"):
            match = VARIANT_LINE.fullmatch(line.rstrip("\r\n"))
            if match:
                canonical = stack[-1][1]
                replacement = enum_replacements.get(canonical)
                if replacement and match[2] in replacement["variants"]:
                    new_name = replacement["variants"][match[2]]
                    ending = line[len(line.rstrip("\r\n")):]
                    line = match[1] + new_name + match[3] + match[4] + match[5] + ending
                    used_variants.add((canonical, match[2]))
            output.append(line)
            continue
        if stack and stack[-1][0] != "enum" and not trimmed.startswith("//"):
            match = FIELD_LINE.fullmatch(line.rstrip("\r\n"))
            if match:
                owner = next(scope[1] for scope in reversed(stack) if scope[0] == "message")
                tag = int(match[6])
                field_type = match[3]
                for old_type, new_type in type_tokens.items():
                    field_type = re.sub(rf"\b{re.escape(old_type)}\b", new_type, field_type)
                field_name = match[4]
                replacement = field_replacements.get((owner, tag))
                if replacement is not None:
                    if field_name != replacement["before"]:
                        raise RuntimeError((owner, tag, field_name, replacement["before"]))
                    field_name = replacement["after"]
                    used_fields.add((owner, tag))
                ending = line[len(line.rstrip("\r\n")):]
                prefix = match[1] + ((match[2] + " ") if match[2] else "")
                line = prefix + field_type + " " + field_name + match[5] + match[6] + match[7] + ending
        output.append(line)

    expected_variants = {(canonical, old) for canonical, row in enum_replacements.items() for old in row["variants"]}
    if (used_fields != set(field_replacements)
            or used_messages != set(message_replacements)
            or used_enums != set(enum_replacements)
            or used_variants != expected_variants):
        raise RuntimeError({"missing_fields": list(set(field_replacements) - used_fields),
                            "missing_messages": list(set(message_replacements) - used_messages),
                            "missing_enums": list(set(enum_replacements) - used_enums),
                            "missing_variants": list(expected_variants - used_variants)})

    destination = RUN / "StarRail.accuracy.proto"
    output_text = "".join(output)
    if os.linesep != "\n":
        output_text = output_text.replace("\n", os.linesep)
    output_bytes = output_text.encode("utf-8")
    output_sha256 = sha_bytes(output_bytes)
    temporary_destination = stage_bytes(destination, output_bytes)
    try:
        reconstructed = common.parse(temporary_destination)
        if reconstructed["errors"]:
            raise RuntimeError(reconstructed["errors"])
        if set(reconstructed["items"]) != set(current["items"]):
            raise RuntimeError("canonical type identities changed")
        changed_layouts = [key for key in current["items"]
                           if common.layout(current["items"][key]) != common.layout(reconstructed["items"][key])]
        if changed_layouts:
            raise RuntimeError(f"wire layout changed: {changed_layouts[:20]}")
    finally:
        temporary_destination.unlink(missing_ok=True)

    report = {
        "validation": "accuracy-reconstruction-structure-passed",
        "output": str(destination), "output_sha256": output_sha256,
        "input": str(SOURCE), "input_sha256": sha(SOURCE),
        "reference": f"{REFERENCE_REPO}@{reference_commit}:StarRail.proto",
        "reference_worktree_path": str(REFERENCE),
        "reference_sha256": reference_sha256,
        "reference_repo": reference_remote,
        "reference_commit": reference_commit,
        "reference_commit_verified": reference_commit == REFERENCE_COMMIT,
        "reference_worktree_clean": not reference_status,
        "reference_commit_blob_oid": reference_commit_blob_oid,
        "reference_worktree_blob_oid": reference_worktree_blob_oid,
        "field_recovery_count": len(field_replacements),
        "field_owner_bindings": alignment_counts,
        "graph_type_mapping_count": len(graph_mapping),
        "graph_type_mappings": [{"canonical": key, "external": graph_mapping[key],
                                 "proof": graph_proofs[key]} for key in sorted(graph_mapping)],
        "graph_alignment_rejections": graph_rejections,
        "reverse_graph_owner_mappings": reverse_mappings,
        "reverse_graph_owner_rejections": reverse_mapping_rejections,
        "message_type_recovery_count": len(message_replacements),
        "message_type_recoveries": [
            {"canonical": key, **row} for key, row in message_replacements.items()
        ],
        "excluded_message_type_candidates": excluded_message_type_candidates,
        "field_change_kinds": field_change_kinds,
        "excluded_external_corrections_conflicting_with_current_evidence": len(excluded_runtime_conflicts),
        "excluded_runtime_conflicts": excluded_runtime_conflicts,
        "excluded_readable_corrections_requiring_stronger_proof": len(excluded_readable_corrections),
        "excluded_readable_corrections": excluded_readable_corrections,
        "excluded_field_name_collisions": len(excluded_name_collisions),
        "field_name_collisions": excluded_name_collisions,
        "enum_recovery_count": len(enum_replacements),
        "excluded_unreferenced_enum_candidates": excluded_unreferenced_enums,
        "excluded_enum_name_collisions": excluded_enum_name_collisions,
        "enum_variant_recovery_count": sum(len(row["variants"]) for row in enum_replacements.values()),
        "field_recoveries": [{"canonical": key[0], "tag": key[1], **row}
                             for key, row in sorted(field_replacements.items())],
        "enum_recoveries": [{"canonical": key, **row} for key, row in enum_replacements.items()],
        "wire_layout_preserved": True,
        "canonical_type_identity_preserved": True,
        "confidence": "high for fields: same-version owner is bound by raw/readable identity, propagated from such an owner through an exact matching field-type edge, or uniquely reverse-bound by at least three mapped non-scalar type anchors; every accepted owner has an exact structural fingerprint, and each field matches tag, wire category and oneof membership; high for message type names: exact fingerprint and at least two independent root owner/tag/type references; high for enums: same enum declaration index + complete numeric value sequence + an aligned or graph-proven exact owner/tag/type reference",
        "boundary": "Accuracy-first reconstruction using a same-version external reverse-engineered protocol as naming evidence. This is not a raw runtime export and external naming provenance is recorded explicitly.",
    }
    report_destination = RUN / "accuracy-reconstruction-report.json"
    report_bytes = json.dumps(report, ensure_ascii=False, indent=2).encode("utf-8")
    publication_destination = RUN / "accuracy-publication.json"
    publish_generation(
        destination,
        output_bytes,
        report_destination,
        report_bytes,
        publication_destination,
    )
    print(json.dumps({"validation": report["validation"], "output": str(destination),
                      "fields": len(field_replacements), "enums": len(enum_replacements),
                      "variants": report["enum_variant_recovery_count"],
                      "sha256": report["output_sha256"]}, ensure_ascii=False))

def main():
    with publication_lock.exclusive_lock(RUN / ".accuracy-publication.lock"):
        reconstruct_locked()


if __name__ == "__main__":
    main()
