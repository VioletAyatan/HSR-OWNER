import collections
import re
from pathlib import Path

OBF = re.compile(r"^[A-Z]{11}$")
IDENT = re.compile(r"^[A-Za-z_][A-Za-z_0-9]*$")
PRIMITIVES = set(
    "double float int32 int64 uint32 uint64 sint32 sint64 fixed32 fixed64 "
    "sfixed32 sfixed64 bool string bytes repeated optional map".split()
)


class ProtoValidationError(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise ProtoValidationError(message)


def parse(path):
    path = Path(path)
    source = path.read_text(encoding="utf-8-sig")
    items, stack, metadata = {}, [], {}
    syntax = None
    for lineno, rawline in enumerate(source.splitlines(), 1):
        line = rawline.strip()
        if not line:
            continue
        if line.startswith("syntax ="):
            require(syntax is None and not stack, (path, lineno, "duplicate or nested syntax"))
            syntax = line
            continue
        if line.startswith("//"):
            key, _, value = line[3:].partition(": ")
            if key in {"Obf", "Type", "CmdID", "WriteTo"}:
                metadata[key] = value
            continue
        if line == "}":
            require(bool(stack), (path, lineno, "unmatched closing brace"))
            stack.pop()
            continue
        if line.endswith(" {"):
            kind, name = line[:-2].split(" ", 1)
            if kind == "oneof":
                require(bool(stack), (path, lineno, "top-level oneof"))
                parent = stack[-1]
                require(parent["kind"] == "message", (path, lineno, "oneof parent is not a message"))
                oneof = {"kind": "oneof", "name": name, "parent": parent, "fields": []}
                parent["oneofs"].append(oneof)
                stack.append(oneof)
                continue
            require(kind in {"message", "enum"}, (path, lineno, line))
            parent = stack[-1] if stack else None
            require(parent is None or parent["kind"] == "message", (path, lineno, "invalid nesting"))
            raw = metadata.get("Obf", name).removeprefix("Proto.")
            canonical = (parent["canonical"] + "." if parent else "") + raw
            display = (parent["display"] + "." if parent else "") + name
            item = {
                "kind": kind,
                "name": name,
                "raw": raw,
                "canonical": canonical,
                "display": display,
                "parent": parent["canonical"] if parent else None,
                "children": [],
                "fields": [],
                "oneofs": [],
                "variants": [],
                "metadata": {key: value for key, value in metadata.items() if key != "Obf"},
            }
            require(canonical not in items, (path, lineno, "duplicate canonical type", canonical))
            items[canonical] = item
            if parent:
                parent["children"].append(canonical)
            metadata = {}
            stack.append(item)
            continue
        require(bool(stack), (path, lineno, "declaration outside type"))
        declaration, _, comment = line.partition("//")
        left, right = declaration.split("=", 1)
        number = int(right.strip().removesuffix(";").strip())
        if stack[-1]["kind"] == "enum":
            stack[-1]["variants"].append((left.strip(), number))
        else:
            kind, name = left.strip().rsplit(" ", 1)
            offset = int(comment.strip().removeprefix("offset: ")) if comment else 0
            stack[-1]["fields"].append(
                {"kind": kind, "name": name, "tag": number, "offset": offset}
            )

    require(not stack and syntax is not None and bool(items), (path, "incomplete or empty proto"))
    aliases = collections.defaultdict(set)
    for canonical, item in items.items():
        aliases[item["display"]].add(canonical)
        aliases[item["name"]].add(canonical)

    def resolve(token, owner):
        if token in PRIMITIVES:
            return token
        display_path = owner["display"]
        while display_path:
            candidates = aliases.get(display_path + "." + token, set())
            if len(candidates) == 1:
                return next(iter(candidates))
            display_path = display_path.rpartition(".")[0]
        candidates = aliases.get(token.removeprefix("."), set())
        if len(candidates) == 1:
            return next(iter(candidates))
        raise ProtoValidationError(
            f'unresolved or ambiguous type {token} in {owner["display"]}: {candidates}'
        )

    errors = []
    displayed_types = collections.Counter(
        (item["parent"], item["name"]) for item in items.values()
    )
    errors.extend(
        ("duplicate displayed type", parent, name)
        for (parent, name), count in displayed_types.items()
        if count > 1
    )
    for item in items.values():
        if item["kind"] == "enum":
            variant_names = collections.Counter(name for name, _ in item["variants"])
            errors.extend(
                ("duplicate enum variant", item["display"], name)
                for name, count in variant_names.items()
                if count > 1
            )
            errors.extend(
                ("invalid enum variant", item["display"], name)
                for name, _ in item["variants"]
                if not IDENT.fullmatch(name)
            )
            continue
        item_fields = item["fields"] + [field for oneof in item["oneofs"] for field in oneof["fields"]]
        for field in item_fields:
            field["normalized_kind"] = re.sub(
                r"[A-Za-z_][A-Za-z_0-9.]*",
                lambda match: resolve(match[0], item),
                field["kind"],
            )
        if not IDENT.fullmatch(item["name"]):
            errors.append(("invalid type", item["display"]))
        names = collections.Counter(field["name"] for field in item_fields)
        tags = collections.Counter(field["tag"] for field in item_fields)
        errors.extend(
            ("duplicate field", item["display"], name)
            for name, count in names.items()
            if count > 1
        )
        errors.extend(
            ("duplicate tag", item["display"], tag)
            for tag, count in tags.items()
            if count > 1
        )
        errors.extend(
            ("invalid field", item["display"], field["name"])
            for field in item_fields
            if not IDENT.fullmatch(field["name"])
        )
    return {"syntax": syntax, "items": items, "aliases": aliases, "errors": errors}


def layout(item):
    def field_layout(fields):
        return [(field["tag"], field["normalized_kind"], field["offset"]) for field in fields]

    return {
        "kind": item["kind"],
        "parent": item["parent"],
        "children": item["children"],
        "fields": field_layout(item["fields"]),
        "oneofs": [field_layout(oneof["fields"]) for oneof in item["oneofs"]],
        "enum_values": [value for _, value in item["variants"]],
        "metadata": item["metadata"],
    }