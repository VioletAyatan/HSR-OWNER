#!/usr/bin/env python
"""Generate the Rust-embedded, structure-guarded accepted Proto name database.

This is a development/audit tool. The compiled dumper only consumes the generated
JSON and never invokes Python.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import tempfile
from collections import Counter, defaultdict
from pathlib import Path

TOOLS = Path(__file__).resolve().parent
PROJECT = TOOLS.parents[1]
sys.path.insert(0, str(TOOLS))
import proto_document

SCALARS = {
    "double", "float", "int32", "int64", "uint32", "uint64", "sint32",
    "sint64", "fixed32", "fixed64", "sfixed32", "sfixed64", "bool",
    "string", "bytes", "google.protobuf.Any",
}
OBF = re.compile(r"^[A-Z]{11}$")
METHOD_RVAS = re.compile(
    r"^0x([0-9a-fA-F]+)\s*\|\s*MergeFrom:\s*0x([0-9a-fA-F]+)$"
)
FNV_OFFSET = 14_695_981_039_346_656_037
FNV_REVERSE_OFFSET = 7_809_847_782_465_536_322
FNV_PRIME = 1_099_511_628_211
FINGERPRINT_ROUNDS = 16


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def method_rvas(item):
    value = item["metadata"].get("WriteTo", "")
    match = METHOD_RVAS.fullmatch(value)
    if match is None:
        return 0, 0
    return int(match.group(1), 16), int(match.group(2), 16)


def read_provenance(provenance, dataset_id, actual_hashes):
    if provenance is None:
        return {}, {
            "review_status": "unreviewed",
            **actual_hashes,
        }
    data = json.loads(Path(provenance).read_text(encoding="utf-8"))
    require(data.get("schema_version") == 1, "unsupported provenance schema")
    require(data.get("dataset_id") == dataset_id, "provenance dataset ID mismatch")
    require(data.get("review_status") == "approved", "provenance is not approved")
    expected_hashes = data.get("inputs", {})
    require(expected_hashes == actual_hashes, "provenance input hashes do not match")
    overrides = data.get("canonical_overrides", {})
    require(isinstance(overrides, dict), "canonical_overrides must be an object")
    source = {
        key: value
        for key, value in data.items()
        if key not in {"schema_version", "dataset_id", "inputs", "canonical_overrides"}
    }
    source.update(actual_hashes)
    return overrides, source


def fnv1a(data, seed):
    value = seed
    for byte in data:
        value ^= byte
        value = (value * FNV_PRIME) & 0xFFFFFFFFFFFFFFFF
    return value


def hash_pair(value):
    data = value.encode("utf-8")
    return f"{fnv1a(data, FNV_OFFSET):016x}{fnv1a(reversed(data), FNV_REVERSE_OFFSET):016x}"


def split_map(value):
    depth = 0
    for index, char in enumerate(value):
        if char == "<":
            depth += 1
        elif char == ">":
            depth = max(0, depth - 1)
        elif char == "," and depth == 0:
            return value[:index], value[index + 1:]
    return None


def parse_expr(kind, canonical_to_index):
    kind = kind.strip()
    if kind.startswith("repeated "):
        return ("repeated", parse_expr(kind.removeprefix("repeated "), canonical_to_index))
    if kind.startswith("optional "):
        return ("optional", parse_expr(kind.removeprefix("optional "), canonical_to_index))
    if kind.startswith("map<") and kind.endswith(">"):
        parts = split_map(kind[4:-1])
        if parts is None:
            raise RuntimeError(("invalid map type", kind))
        key, value = parts
        return (
            "map",
            parse_expr(key.strip(), canonical_to_index),
            parse_expr(value.strip(), canonical_to_index),
        )
    token = kind.removeprefix(".").removeprefix("Proto.").removeprefix("proto.")
    if token in SCALARS:
        return ("scalar", token)
    if token in canonical_to_index:
        return ("ref", canonical_to_index[token])
    return ("unknown", token)


def expr_refs(expr):
    if expr[0] in {"repeated", "optional"}:
        return expr_refs(expr[1])
    if expr[0] == "map":
        return expr_refs(expr[1]) + expr_refs(expr[2])
    return [expr[1]] if expr[0] == "ref" else []


def render_expr(expr, labels, kinds, self_target=None):
    category = expr[0]
    if category == "scalar":
        return f"S:{expr[1]}"
    if category == "unknown":
        return f"U:{expr[1]}"
    if category == "repeated":
        return f"R({render_expr(expr[1], labels, kinds, self_target)})"
    if category == "optional":
        return f"O({render_expr(expr[1], labels, kinds, self_target)})"
    if category == "map":
        return (
            f"K({render_expr(expr[1], labels, kinds, self_target)},"
            f"{render_expr(expr[2], labels, kinds, self_target)})"
        )
    target = expr[1]
    if target == self_target:
        return "@SELF"
    marker = kinds[target]
    label = labels[target] if labels is not None else marker
    return f"@{marker}:{label}"


def flatten_fields(item):
    rows = [(field, ()) for field in item["fields"]]
    for oneof in item["oneofs"]:
        tags = tuple(sorted({field["tag"] for field in oneof["fields"]}))
        rows.extend((field, tags) for field in oneof["fields"])
    return sorted(rows, key=lambda row: row[0]["tag"])


def build_graph(document, rounds):
    entries = list(document["items"].items())
    canonical_to_index = {canonical: index for index, (canonical, _) in enumerate(entries)}
    kinds = {
        index: ("M" if item["kind"] == "message" else "E")
        for index, (_, item) in enumerate(entries)
    }
    nodes = {}
    incoming = defaultdict(list)
    for index, (canonical, item) in enumerate(entries):
        parent = canonical_to_index[item["parent"]] if item["parent"] is not None else None
        children = [canonical_to_index[child] for child in item["children"]]
        if item["kind"] == "message":
            fields = []
            for field, oneof_tags in flatten_fields(item):
                expr = parse_expr(field["normalized_kind"], canonical_to_index)
                fields.append({"tag": field["tag"], "expr": expr, "oneof_tags": oneof_tags})
                for target in expr_refs(expr):
                    incoming[target].append({
                        "source": index,
                        "tag": field["tag"],
                        "oneof_tags": oneof_tags,
                        "expr": expr,
                        "target": target,
                    })
            groups = sorted(
                tuple(sorted({field["tag"] for field in oneof["fields"]}))
                for oneof in item["oneofs"]
            )
            enum_values = []
        else:
            fields = []
            groups = []
            enum_values = sorted(value for _, value in item["variants"])
        write_to_rva, merge_from_rva = method_rvas(item)
        nodes[index] = {
            "kind": item["kind"],
            "raw_path": canonical,
            "display_path": item["display"],
            "parent": parent,
            "children": children,
            "fields": fields,
            "oneof_groups": groups,
            "enum_values": enum_values,
            "cmd_id": int(item["metadata"].get("CmdID", 0)),
            "write_to_rva": write_to_rva,
            "merge_from_rva": merge_from_rva,
        }

    def tag_text(tags):
        return ",".join(str(tag) for tag in tags)

    def representation(index, labels):
        node = nodes[index]

        def label(target):
            marker = kinds[target]
            return f"{marker}:{labels[target] if labels is not None else marker}"

        parent = label(node["parent"]) if node["parent"] is not None else "-"
        children = sorted(label(child) for child in node["children"])
        incoming_rows = sorted(
            f"{label(edge['source'])}:{edge['tag']}:o={tag_text(edge['oneof_tags'])}:"
            f"t={render_expr(edge['expr'], labels, kinds, edge['target'])}"
            for edge in incoming[index]
        )
        if node["kind"] == "message":
            fields = ";".join(
                f"{field['tag']}:{render_expr(field['expr'], labels, kinds)}:"
                f"o={tag_text(field['oneof_tags'])}"
                for field in node["fields"]
            )
            groups = ";".join(tag_text(group) for group in node["oneof_groups"])
            core = f"M|g={groups}|f={fields}"
        else:
            core = "E|v=" + ",".join(str(value) for value in node["enum_values"])
        return f"{core}|p={parent}|c={';'.join(children)}|in={';'.join(incoming_rows)}"

    labels = {index: hash_pair(representation(index, None)) for index in nodes}
    for _ in range(rounds):
        labels = {index: hash_pair(representation(index, labels)) for index in nodes}

    for index, node in nodes.items():
        node["shape"] = representation(index, labels)
        node["fingerprint"] = hash_pair(node["shape"])
        node["field_shapes"] = {
            field["tag"]: {
                "shape": (
                    f"{render_expr(field['expr'], labels, kinds)}|"
                    f"o={tag_text(field['oneof_tags'])}"
                ),
                "oneof_tags": list(field["oneof_tags"]),
            }
            for field in node["fields"]
        }
    return entries, nodes


def wire_layout(document, entries):
    canonical_to_index = {canonical: index for index, (canonical, _) in enumerate(entries)}
    layouts = []
    for canonical, item in entries:
        parent = canonical_to_index[item["parent"]] if item["parent"] is not None else None
        children = tuple(sorted(canonical_to_index[child] for child in item["children"]))
        if item["kind"] == "enum":
            layouts.append(
                (
                    "enum",
                    parent,
                    children,
                    tuple(sorted(value for _, value in item["variants"])),
                )
            )
            continue
        fields = []
        for field, oneof_tags in flatten_fields(item):
            fields.append((
                field["tag"],
                parse_expr(field["normalized_kind"], canonical_to_index),
                oneof_tags,
                field["offset"],
            ))
        layouts.append(("message", parent, children, tuple(fields)))
    return layouts


def generated_obfuscated(name):
    return bool(OBF.fullmatch(name)) or (
        any(OBF.fullmatch(part) for part in name.split("_"))
        and all(not char.isalpha() or char.isupper() for char in name)
    )


def action_for(name, generated=False):
    return "alias" if (generated_obfuscated(name) if generated else OBF.fullmatch(name)) else "override_exact"


def resolve_packet_type(document, name):
    if name in document["items"]:
        return name
    candidates = document["aliases"].get(name, set())
    require(len(candidates) == 1, ("unresolved-or-ambiguous-packet-type", name, sorted(candidates)))
    return next(iter(candidates))


def generate(
    raw_proto,
    accepted_proto,
    raw_packets,
    accepted_packets,
    dataset_id,
    provenance=None,
):
    actual_hashes = {
        "raw_proto_sha256": sha256(raw_proto),
        "accepted_proto_sha256": sha256(accepted_proto),
        "raw_packet_ids_sha256": sha256(raw_packets),
        "accepted_packet_ids_sha256": sha256(accepted_packets),
    }
    canonical_overrides, source = read_provenance(
        provenance, dataset_id, actual_hashes
    )
    raw = proto_document.parse(raw_proto)
    accepted = proto_document.parse(accepted_proto)
    require(not raw["errors"], ("raw-proto-errors", raw["errors"][:20]))
    require(not accepted["errors"], ("accepted-proto-errors", accepted["errors"][:20]))
    raw_entries, raw_nodes = build_graph(raw, FINGERPRINT_ROUNDS)
    accepted_entries, _ = build_graph(accepted, FINGERPRINT_ROUNDS)
    accepted_by_source = {}
    for accepted_canonical, accepted_item in accepted_entries:
        source_canonical = canonical_overrides.get(
            accepted_canonical, accepted_canonical
        )
        require(
            source_canonical not in accepted_by_source,
            ("duplicate-accepted-source-canonical", source_canonical),
        )
        accepted_by_source[source_canonical] = (accepted_canonical, accepted_item)
    raw_canonicals = {canonical for canonical, _ in raw_entries}
    require(
        set(accepted_by_source) == raw_canonicals,
        (
            "canonical-type-set-changed",
            sorted(raw_canonicals - set(accepted_by_source)),
            sorted(set(accepted_by_source) - raw_canonicals),
        ),
    )
    accepted_entries_aligned = [
        accepted_by_source[canonical] for canonical, _ in raw_entries
    ]
    require(
        all(
            left[1]["kind"] == right[1]["kind"]
            for left, right in zip(raw_entries, accepted_entries_aligned)
        ),
        "type kind changed",
    )
    require(
        wire_layout(raw, raw_entries)
        == wire_layout(accepted, accepted_entries_aligned),
        "wire layout changed between raw and accepted Proto",
    )

    raw_packet_map = json.loads(Path(raw_packets).read_text(encoding="utf-8-sig"))
    accepted_packet_map = json.loads(Path(accepted_packets).read_text(encoding="utf-8-sig"))
    require(raw_packet_map.keys() == accepted_packet_map.keys(), "packet ID key set changed")

    canonical_to_index = {canonical: index for index, (canonical, _) in enumerate(raw_entries)}
    packet_canonical = {}
    for command_text, raw_name in raw_packet_map.items():
        command_id = int(command_text)
        canonical = resolve_packet_type(raw, raw_name)
        index = canonical_to_index[canonical]
        require(raw_nodes[index]["kind"] == "message", ("packet-target-is-not-message", command_id))
        require(raw_nodes[index]["parent"] is None, ("packet-target-is-nested", command_id))
        require(
            raw_nodes[index]["cmd_id"] in {0, command_id},
            ("packet-command-comment-mismatch", command_id, raw_nodes[index]["cmd_id"]),
        )
        packet_canonical[command_id] = canonical

    active = set(packet_canonical.values())
    aliases_by_canonical = {}
    counts = Counter()
    for index, ((canonical, raw_item), (_, accepted_item)) in enumerate(
        zip(raw_entries, accepted_entries_aligned)
    ):
        type_alias = accepted_item["name"] if raw_item["name"] != accepted_item["name"] else None
        if type_alias is not None:
            active.add(canonical)
            counts[f"{raw_item['kind']}_aliases"] += 1

        fields = []
        if raw_item["kind"] == "message":
            raw_fields = {field["tag"]: field for field, _ in flatten_fields(raw_item)}
            accepted_fields = {field["tag"]: field for field, _ in flatten_fields(accepted_item)}
            require(raw_fields.keys() == accepted_fields.keys(), ("field-tags-changed", canonical))
            for tag in sorted(raw_fields):
                before = raw_fields[tag]["name"]
                after = accepted_fields[tag]["name"]
                if before == after:
                    continue
                active.add(canonical)
                counts["field_aliases"] += 1
                shape = raw_nodes[index]["field_shapes"][tag]
                fields.append({
                    "tag": tag,
                    "shape": shape["shape"],
                    "oneof_tags": shape["oneof_tags"],
                    "expected": before,
                    "accepted": after,
                    "action": action_for(before),
                })

            oneofs = []
            raw_oneofs = {
                tuple(sorted({field["tag"] for field in oneof["fields"]})): oneof["name"]
                for oneof in raw_item["oneofs"]
            }
            accepted_oneofs = {
                tuple(sorted({field["tag"] for field in oneof["fields"]})): oneof["name"]
                for oneof in accepted_item["oneofs"]
            }
            require(
                raw_oneofs.keys() == accepted_oneofs.keys(),
                ("oneof-membership-changed", canonical),
            )
            for member_tags in sorted(raw_oneofs):
                before = raw_oneofs[member_tags]
                after = accepted_oneofs[member_tags]
                if before == after:
                    continue
                active.add(canonical)
                counts["oneof_aliases"] += 1
                oneofs.append({
                    "member_tags": list(member_tags),
                    "expected": before,
                    "accepted": after,
                    "action": action_for(before),
                })
            variants = []
        else:
            fields = []
            oneofs = []
            variants = []
            raw_variants = raw_item["variants"]
            accepted_variants = accepted_item["variants"]
            raw_numbers = [value for _, value in raw_variants]
            accepted_numbers = [value for _, value in accepted_variants]
            require(
                len(set(raw_numbers)) == len(raw_numbers)
                and len(set(accepted_numbers)) == len(accepted_numbers),
                ("duplicate-enum-number", canonical),
            )
            require(
                set(raw_numbers) == set(accepted_numbers),
                ("enum-values-changed", canonical),
            )
            accepted_by_number = {
                number: name for name, number in accepted_variants
            }
            for before, number in raw_variants:
                after = accepted_by_number[number]
                if before == after:
                    continue
                active.add(canonical)
                counts["enum_variant_aliases"] += 1
                variants.append({
                    "number": number,
                    "expected": before,
                    "accepted": after,
                    "action": action_for(before, generated=True),
                })

        aliases_by_canonical[canonical] = {
            "accepted_name": type_alias,
            "fields": fields,
            "oneofs": oneofs,
            "variants": variants,
        }

    types = []
    for index, (canonical, raw_item) in enumerate(raw_entries):
        if canonical not in active:
            continue
        aliases = aliases_by_canonical[canonical]
        packet_ids = sorted(command for command, owner in packet_canonical.items() if owner == canonical)
        require(len(packet_ids) <= 1, ("multiple-command-ids-for-type", canonical, packet_ids))
        types.append({
            "canonical": canonical,
            "kind": raw_item["kind"],
            "shape": raw_nodes[index]["shape"],
            "fingerprint": raw_nodes[index]["fingerprint"],
            "cmd_id": packet_ids[0] if packet_ids else None,
            "write_to_rva": raw_nodes[index]["write_to_rva"],
            "merge_from_rva": raw_nodes[index]["merge_from_rva"],
            "accepted_name": aliases["accepted_name"],
            "fields": aliases["fields"],
            "oneofs": aliases["oneofs"],
            "variants": aliases["variants"],
        })

    type_by_canonical = {record["canonical"]: record for record in types}
    packets = []
    for command_id in sorted(packet_canonical):
        canonical = packet_canonical[command_id]
        accepted_item = accepted_by_source[canonical][1]
        accepted_name = accepted_packet_map[str(command_id)]
        require(
            accepted_name == accepted_item["name"],
            ("accepted-packet-name-does-not-match-proto", command_id, accepted_name, accepted_item["name"]),
        )
        packets.append({
            "cmd_id": command_id,
            "type_canonical": canonical,
            "type_fingerprint": type_by_canonical[canonical]["fingerprint"],
            "accepted_name": accepted_name,
        })

    require(len(packets) == len(raw_packet_map), "not all packet IDs were emitted")
    require(len({packet["accepted_name"] for packet in packets}) == len(packets), "duplicate packet display names")
    source = {
        **source,
        "packet_key_set_fingerprint": hash_pair(
            ",".join(str(packet["cmd_id"]) for packet in packets)
        ),
        "counts": {
            **dict(sorted(counts.items())),
            "active_type_records": len(types),
            "packet_bindings": len(packets),
        },
    }
    manifest = {
        "schema_version": 1,
        "dataset_id": dataset_id,
        "fingerprint_rounds": FINGERPRINT_ROUNDS,
        "source": source,
        "types": types,
        "packets": packets,
    }
    return manifest


def atomic_write(path, data):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def main():
    default_run = PROJECT / "target/allocator-fh3-runtime-20261003-041926"
    parser = argparse.ArgumentParser()
    parser.add_argument("--raw-proto", type=Path, default=default_run / "StarRail.proto")
    parser.add_argument(
        "--accepted-proto", type=Path, default=default_run / "StarRail.accuracy.wave10.proto"
    )
    parser.add_argument("--raw-packets", type=Path, default=default_run / "packetIds.json")
    parser.add_argument(
        "--accepted-packets", type=Path,
        default=default_run / "packetIds.accuracy.wave10.json",
    )
    parser.add_argument(
        "--output", type=Path,
        default=PROJECT / "crates/dumper/resources/proto/accepted-names.v1.json",
    )
    parser.add_argument("--dataset-id", default="hsr-4.6.51-wave10-2026-10-04")
    parser.add_argument(
        "--provenance",
        type=Path,
        default=TOOLS / "accepted-rust-name-provenance.v1.json",
    )
    args = parser.parse_args()
    for path in (
        args.raw_proto,
        args.accepted_proto,
        args.raw_packets,
        args.accepted_packets,
        args.provenance,
    ):
        require(path.is_file(), ("missing-input", str(path)))
    manifest = generate(
        args.raw_proto,
        args.accepted_proto,
        args.raw_packets,
        args.accepted_packets,
        args.dataset_id,
        args.provenance,
    )
    output = (json.dumps(manifest, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
    atomic_write(args.output, output)
    require(args.output.read_bytes() == output, "manifest read-back mismatch")
    print(json.dumps({
        "output": str(args.output),
        "sha256": hashlib.sha256(output).hexdigest(),
        "bytes": len(output),
        "types": len(manifest["types"]),
        "packets": len(manifest["packets"]),
        "counts": manifest["source"]["counts"],
    }, ensure_ascii=False, sort_keys=True))


if __name__ == "__main__":
    main()
