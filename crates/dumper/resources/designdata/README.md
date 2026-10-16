# Embedded DesignData tables

Generated offline for client DesignData revision 16706787
(`DesignV_46462ce8….bytes`, 143,169 entries). The dumper still validates every
item against the installed index at runtime, so stale entries are ignored rather
than trusted.

| File | Content |
|---|---|
| `names.lz4` | 136,836 logical paths whose xxHash64 (seed 0) matches an index entry. Sorted, front-coded `<shared chars>\t<suffix>` lines, LZ4 block with a 4-byte little-endian size prefix. Recovered from client strings, Excel IDs, the client's path transforms and chunk packing order; only exact hash hits are kept. |
| `rules.tsv` | Root-type rules: `O` JSON-path prefix overrides, `F` path families (directory digits as `#`, filename letter prefix, secondary extensions), `D` directory defaults. Each rule lists `GameCoreConfigLoader` methods in trial order and the evidence (runtime loader log, strict offline decode, client cross-reference, name match). |

Regenerate with the `hsr-designdata-inventory` project skill
(`.hermes/skills/hsr-designdata-inventory/scripts/gen_embed.py`) after a client
update; the runtime still decodes new names it discovers in chunk strings, but new
families need new rules or fall back to raw bytes.
