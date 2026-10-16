---
name: hsr-designdata-inventory
description: "Use when listing or naming every DesignData resource in an HSR client. Parses the hashed index and recovers logical paths."
version: 1.1.0
metadata:
  hermes:
    tags: [hsr, designdata, reverse-engineering, inventory, hsr-owner]
---

# HSR DesignData inventory

Use to answer "which resources does the client have", to audit how much a runtime or offline exporter covers, or to find the real path of an unnamed index entry. Read-only on the client; never launch or patch the game for this.

## Facts to re-verify per build

- The authoritative list is `StarRail_Data/Persistent/DesignData/Windows/M_DesignV.bytes` → `DesignV_<md5>.bytes` (v4: big-endian, magic 255, version 4; per chunk file: u64 hash, md5, u64 size, i32 count, count × (u64 path hash, u32 size, u32 offset), tag marker `0x80` or `00 len bytes 80`). Mini header: `SRMI`, revision LE u32 @24, digest @28 with each 4-byte word reversed, index size LE u64 @44. StreamingAssets holds only a small startup index; Persistent is the full one.
- Entries are named only by `xxHash64(seed 0)` of the logical path. Recover the client's own path rules from `GameAssembly.dll` instead of guessing: `GameCoreConfigLoader.JsonToBinaryPath` (`"BakedConfig/" + path minus extension + ".bytes"`), `BinaryBakeLayoutPath` (`.layout.`), `BinaryMainMissionPartialPath` (`.partial.`), and the obfuscated stage path helper class (`.volume/.region/.VoxelData/.IRIFBXLodSize/.PVSMeta`, `Blocks/ BlockExternals/ Alias/ SharedAlias/ Culling/ Cells/`). Excel roots: `ExcelOutput`, `ExcelOutputGameCore`, `ExcelOutputAdventureGame`, plus `<Table>ExcelTable.binary_header.bytes` and `Textmap(_|Main_)<lang>.binary_header.bytes`.
- Validate the hash rule against the last Resources log: every `ExistsDesignData` true path must hit and every `skip absent path` must miss.
- Inside each chunk, entries are packed contiguously in path order: directory-first traversal, files before subdirectories, case-insensitive, punctuation < digits < letters, shorter stem first (`X.bytes` before `X.binary_header.bytes`). Use the order both to localize unnamed entries and as a correctness check (a wrong name almost always breaks the order).

## Procedure (scripts/ in this skill)

Set `HSR_CLIENT` (default `D:/StarRail_Beta`) and `HSR_INV_WORK` (a scratch dir; never the client `DUMP`). Create a venv with `xxhash`. Run from the work dir:

1. `prep.py` — literals from `DUMP/script-mini.json` ScriptString, identifiers/Excel table stems from `DUMP/dump.cs`, identifier tokens from every chunk.
2. `name_entries.py` — strict index parse plus seeds: runtime log paths, `excel_paths.json`, ConfigManifest entry, path strings inside every payload. Writes `named.json`.
3. `recover.py` → `stage_d.py` (client `.layout.`/`.partial.` transforms) → `stage_c2.py`, `stage_e.py` (tokens inside the unnamed entries themselves), `stage_f.py`, `stage_g.py` (slot tuples harvested from tokens such as `F#_G#`), `stage_h.py` (literal path prefixes), `stage_i.py` (integer IDs from a decoded Excel export of the same revision). All state lives in `names_state.json`; each stage only adds exact hash hits.
4. `report.py <out>` then `write_md.py <out>` — full CSV, unnamed CSV, not-covered-by-runtime CSV, summary.
5. For an unknown family, find the code that builds its path: `xref2.py "<literal>"` lists functions using a string literal (via ScriptString slot RVAs) with their literals and callees; `xref.py --func <rva>` does the same for one function; `xref.py <rva>` lists callers.

## Type rules and the dumper's DesignData step

HSR-OWNER's Resources export ends with an index-driven step (`crates/dumper/src/res/inventory/`, after TextMap/ExcelOutput/Config): every index entry not yet published is decoded with the client's own deserializer and written as JSON, or kept as raw bytes under `DUMP/ResourcesRaw`; `DUMP/ResourcesInventory.{csv,json}` record every entry's outcome. It embeds `crates/dumper/resources/designdata/{names.lz4,rules.tsv}`; regenerate both after a client update:

1. `cargo +nightly build --release` in `scripts/sniff` (copy HSR-Offline `crates/resource-data` next to it and apply `resource-data.patch`; edit the `GAME`/`INVENTORY` constants in `typesniff/src/main.rs`), run `typesniff.exe` → `sniff_all.jsonl`.
2. `sniff/families.py` → `families.json`; `sniff/rules.py` → `rules_auto.json`; `sniff/gen_embed.py <crates/dumper/resources/designdata>` (directory defaults and client-xref overrides live in the script and `extra_defaults.json`).
3. `sniff/predict_runtime.py` checks rule choice against runtime truth (first loader == loader the runtime used: 65,343/65,370 on revision 16706787). `loader_patterns.py` checks that every rule loader is `JsonToBinaryPath` → `IMNECEGBJLE.BAPACPLOLNH` → exactly one static `(FCOEMCEDLNL, out T&)` deserializer; 290/290 did.
4. `cargo +nightly test -p dumper --release --lib -- res::` runs real-data tests against the installed client (index, TextMap row counts, names, rule coverage); they skip when the client is absent.

## Pitfalls

- The offline strict parser (HSR-Offline `DynamicParser` + `DUMP/data.json`) rejects most real config files (58k of 65k runtime-decoded entries). Use its exact hits as positive evidence only; calibrate rule choice on runtime truth, and let the in-game exact-consumption check decide.
- Many loaders call a deserializer declared on a base or obfuscated helper class (`CharacterPreloadConfigBase`, `DKMIIPICEBC`, …), often `internal`. Resolve it from the loader's call targets, not from the return type.
- Index chunks may carry an explicitly encoded empty tag (`00 00 80`); treat it as a core chunk. Locale chunks live in `<root>/<tag>/<md5>.bytes`.
- `Textmap_<lang>.bytes` decode offline (zigzag count; per row varint mask 1=ID{Hash zigzag i32, Hash64 varint}, 2=Text, 4=HasParam); the runtime `TextmapExcelTable` holds only the active language, under the legacy name `TextMapEN.json`.
- `crates/dumper/build.rs` must read `CARGO_MANIFEST_DIR` at run time; a compile-time `env!` keeps the old checkout path after the repo moves and linking fails with LNK1104 on `version.def`.

- Strings inside baked binaries carry a printable length byte; also try offsets 1–2 into each run and cut at `.json`/`.bytes`.
- Excel IDs are binary integers, absent from string corpora; take them from a decoded Excel export.
- Investigating a missing character skin menu requires comparing the server JSON against the client's own `BakedConfig/ExcelOutputGameCore/AvatarSkin.bytes`, not merely checking `skin_list`. Locate the payload through the inventory CSV and corroborate with a decoded export of the same build; skin IDs in icon paths are supporting evidence, not a substitute for decoding. In the local 4.6.1 binary, the factory at RVA `0xCB739C0` enumerates `AvatarSkinExcelTable`, matches row `AvatarID` against the character/path, then groups row IDs by `Type`; `AvatarExtensions.GetFirstSkinType` at RVA `0xCEE4700` checks Normal then Stellar keys. Re-verify addresses after upgrades. These are native data-list helpers, not proof of the exact Lua menu visibility branch or active hotfix behavior.
- Bound every candidate generator per gap; an unbounded cross product (prefix pool × suffixes × extensions) runs for hours. Use bisect on translated sort keys and budgets.
- The execute_code kernel keeps its cwd from earlier calls (it was the client `DUMP` once); always write with absolute paths into the work dir.
- Expect a residual of entries with no reference anywhere (many are 1–2 byte empty configs); report them by neighbouring directory instead of guessing.
- Main `MissionInfo_<id>.bytes` lacks SubMissionList in recent builds; it lives in `MissionInfo_<id>.partial.bytes`. The client (`CLPPAMNDKIM.EMKCDCFEMIP`) loads both and assigns the partial's `SubMissionList` to the main config; the dumper's mission step mirrors this and also publishes the partial.
- The DesignData step serializes families no earlier phase touched. `Config/Activity/Rt{Battle,Defence}/Ability` configs hold `FixVec2`/`FixVec3`, whose computed getters (`x0y` ↔ `xy`/`xz`) form a value-type cycle: the first real run overflowed the 2 MiB command-thread stack and the game vanished after one `Failed to serialize RPG.GameCore.FixPoint. code: StackOverflow` line (a caught overflow eats the guard page; the second one kills the process). `BoxedSerializer` now skips a getter that re-enters an active value type, latches a depth (1024) or stack-headroom (256 KiB) failure so the entry falls back to raw, and re-arms the guard page (`reflection::stack::reset_guard`); IPC command threads reserve 64 MiB. Read `Config: serializer max_depth=` and `serializer_max_depth` in `ResourcesInventory.json` to see real nesting.
- After a hard crash in the DesignData step, the first entry missing from `DUMP/ResourcesInventory.csv` (flushed every row, entries in deterministic path order) is the culprit; the `DesignData: decoder <loader> -> <type>` lines show which deserializers were in use.
- A wrong root type reads garbage lengths: decoding `Hipplen/MiniGame` files with the name-guessed `LoadHipplenGameMainConfig` grew the game from 6.2 to 17.8 GB in seven seconds and tripped the 16 GiB cooperative stop. Rules therefore carry a strength from their evidence column (`name:` Guessed, `dir:` Inferred, `sniff` Sniffed, `runtime truth`/`client ` Proven); a (rule, loader) pair with no success is disabled after 5/50/100 failures (Proven: never by count), any failed decode that grows private bytes by 256 MiB disables its pair at once, and growth of 4 GiB over the step's start switches the rest of the step to raw output instead of failing the dump. Re-calibrate the budgets by replaying a full run's CSV outcome sequence per rule (the latest first success in a mixed family came after 27 failures); a budget that loses any success is too small.
- Every `Config/ConfigEntity/**` entry (3,482) fails under `EntityConfig.OJNNBEJLDIJ` with `OverflowException`, although `LoadEntityConfig` is the standard `JsonToBinaryPath` → `BAPACPLOLNH` → deserializer pattern and the Excel `ConfigEntityPath` columns reference these files; unresolved, kept raw.
- The PUBLISHED registry key must match how Win32 names the file: some runtime catalog paths (Rogue dialogue `Act*.json `) carry a trailing space that `CreateFileW` strips, so `publish_key` trims trailing spaces/dots per component. Without it the DesignData step re-decoded 32 already-written files and `files_written` exceeded the unique file count by 32. Acceptance: `files_written == unique files on disk` (run4: 143,165 = 143,165).
- `hsr-owner.log` is appended across sessions; find the current session by its last `[UI] launched ... hsr-frontend.exe` line. The loaded copy is the root `version.dll.<random>` (compare its SHA-256 with the deployed `HSR-OWNER/version.dll`).
- Launching with HSR-OWNER: StarRail.exe picks up a root-level `D:/StarRail_Beta/version.dll` by DLL search order, and the DLL renames itself to `version.dll.<random>` once loaded, so every launch needs a fresh `cp -p HSR-OWNER/version.dll version.dll` first; a Cyrene launch without that copy runs the plain client. Then click Cyrene's 开始游戏. Cyrene, the game and SparxieSP's peers run elevated while Hermes/cua-driver is Medium integrity, so cua clicks are dropped by UIPI: run a small SetForegroundWindow + SendInput helper through `Start-Process -Verb RunAs` (auto-approved on this machine; `scripts/launch/elev_input.sh <hwnd> click:X:Y`), and find hwnds with `scripts/launch/winlist.py <pid>` (a minimized Cyrene window restores via `PostMessage(WM_SYSCOMMAND, SC_RESTORE)`). Login needs the SparxieSP server on 21000/23301; when IDEA is closed, start it headless with `java @sp_args.txt org.ankol.sparxiesp.SparxieSpApplicationKt` from the SparxieSP root (classpath: programs/gameServer/commons `target/classes` + gameServer's `dependency:build-classpath`). If the game started before the server, its 网络连接错误 dialog's 重新启动 soft-restarts without unloading HSR-OWNER; then click 点击进入.
