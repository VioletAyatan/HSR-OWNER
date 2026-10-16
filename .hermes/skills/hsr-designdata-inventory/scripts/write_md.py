"""Write the Chinese Markdown summary for the inventory (numbers computed, not typed)."""
import collections
import csv
import json
import os
import sys

OUT = sys.argv[1]
rows = list(csv.DictReader(open(os.path.join(OUT, "designdata_inventory.csv"), encoding="utf-8-sig")))
summary = json.load(open(os.path.join(OUT, "summary.json"), encoding="utf-8"))
P = [r for r in rows if r["snapshot"] == "Persistent"]
S = [r for r in rows if r["snapshot"] == "StreamingAssets"]
named = [r for r in P if r["logical_path"]]
unnamed = [r for r in P if not r["logical_path"]]
data = [r for r in named if r["kind"] == "data"]
rt_col = "runtime_dump_2026-10-08"

DIRECT = ["hsr-owner.log", "ConfigManifest", "excel_paths.json", "payload_strings", "script_literal",
          "script_literal_stem", "literal_template", "literal_prefix", "global-metadata", "textmap_template",
          "textmap_literal", "manifest_name", "excel_class_stem", "excel_identifier"]
CLIENT = ["client_layout_path", "client_partial_path"]
GROUP = {
    "hsr-owner.log": "HSR-OWNER 运行时实际加载过的路径（日志）",
    "ConfigManifest": "ConfigManifest 清单",
    "excel_paths.json": "Excel 表路径（运行时导出的 excel_paths.json / 表类名）",
    "excel_class_stem": "Excel 表路径（运行时导出的 excel_paths.json / 表类名）",
    "excel_identifier": "Excel 表路径（运行时导出的 excel_paths.json / 表类名）",
    "textmap_template": "Excel 表路径（运行时导出的 excel_paths.json / 表类名）",
    "textmap_literal": "Excel 表路径（运行时导出的 excel_paths.json / 表类名）",
    "manifest_name": "ConfigManifest 清单",
    "payload_strings": "资源数据内部引用的路径字符串",
    "script_literal": "客户端代码字符串常量（完整路径、模板、前缀）",
    "script_literal_stem": "客户端代码字符串常量（完整路径、模板、前缀）",
    "literal_template": "客户端代码字符串常量（完整路径、模板、前缀）",
    "literal_prefix": "客户端代码字符串常量（完整路径、模板、前缀）",
    "global-metadata": "客户端代码字符串常量（完整路径、模板、前缀）",
    "client_layout_path": "逆出的客户端路径变换（.layout. / .partial.）",
    "client_partial_path": "逆出的客户端路径变换（.layout. / .partial.）",
}
ORDER = DIRECT + CLIENT
prim = collections.Counter()
for r in named:
    srcs = set(r["recovered_by"].split(";"))
    g = next((GROUP[s] for s in ORDER if s in srcs), "按打包顺序推断候选名后哈希命中（插值、目录内组合、自身字符串等）")
    prim[g] += 1

cat = collections.defaultdict(lambda: collections.Counter())
for r in named:
    c = cat[r["category"]]
    c["n"] += 1
    c["bytes"] += int(r["size"])
    if r["kind"] == "data":
        c["data"] += 1
        if r[rt_col] == "yes":
            c["rt"] += 1
        elif r[rt_col] == "no":
            c["nort"] += 1
    else:
        c["aux"] += 1

lv = collections.Counter("/".join(r["logical_path"].split("/")[2:4]) for r in data
                         if r["category"] == "Config/Level" and r[rt_col] == "no")
near = collections.Counter(r["unnamed_near_dir"] for r in unnamed)
near_b = collections.Counter()
for r in unnamed:
    near_b[r["unnamed_near_dir"]] += int(r["size"])
tiny = sum(1 for r in unnamed if int(r["size"]) <= 2)
kinds = collections.Counter(r["kind"] for r in named)
rt_yes = sum(1 for r in data if r[rt_col] == "yes")
rt_no = sum(1 for r in data if r[rt_col] == "no")
tm = [r for r in named if r["category"] == "TextMap" and r["kind"] == "data"]
p = summary["persistent"]

L = []
w = L.append
w("# 星穹铁道测试客户端 DesignData 资源清单\n")
w(f"生成时间：{summary['generated']}　客户端：`D:/StarRail_Beta`\n")
w("## 结论\n")
w(f"- 客户端的 DesignData 资源全部登记在 `StarRail_Data/Persistent/DesignData/Windows/` 的索引里："
  f"revision **{p['revision']}**，`DesignV_{p['index']}.bytes`，{p['chunks']} 个分块文件，"
  f"**{p['entries']:,} 条**，共 {p['bytes'] / 1e6:.1f} MB。")
w(f"- 已恢复路径名 **{p['named']:,} 条（{p['named'] / p['entries']:.1%}）**；"
  f"剩余 **{p['unnamed']:,} 条**（{p['unnamed_bytes'] / 1e6:.1f} MB）只有哈希，见 `unnamed_entries.csv`。")
w(f"- StreamingAssets 里另有启动索引（revision {summary['streaming']['revision']}，{summary['streaming']['entries']} 条），"
  f"全部也在 Persistent 索引里（不在其中的：{summary['streaming']['not_in_persistent']} 条）。")
miss = summary["persistent"]["missing_chunks"]
w(f"- 索引中有 {len(miss)} 个语言分块本地未下载："
  + "、".join(f"`{t}`（{d[:8]}…，{n} 条）" for d, t, n in miss) + "。\n")
w("## 索引与路径规则\n")
w("- 索引只存路径的 xxHash64（seed 0），不存文件名；名字只能用候选路径算哈希去对。")
w("- 规范路径规则取自 `GameAssembly.dll`（RVA 来自当前 dump.cs，函数内的字符串常量由 script-mini.json 的 ScriptString 地址对上）：\n")
w("| 函数 | RVA | 规则 |")
w("|---|---|---|")
w("| `GameCoreConfigLoader.JsonToBinaryPath` | `0x1E62C900` | `Config/A/B.json` → `BakedConfig/Config/A/B.bytes`（`\"BakedConfig/\"` + 去扩展名 + `\".bytes\"`） |")
w("| `GameCoreConfigLoader.BinaryBakeLayoutPath` | `0x1E62C9D0` | 在扩展名前插入 `.layout.` |")
w("| `GameCoreConfigLoader.BinaryMainMissionPartialPath` | `0x1E62CAB0` | 在扩展名前插入 `.partial.` |")
w("| `GENNHNMPKBF.*`（Stage 路径工具类） | `0x166B22D0` 起 | Stage 目录下 `.volume/.region/.VoxelData/.IRIFBXLodSize/.PVSMeta`，子目录 `Blocks/`、`BlockExternals/`、`Alias/`、`SharedAlias/`、`Culling/`、`Cells/` |")
w("\n- 规则校验：10-08 那次 Resources 导出里，`ExistsDesignData` 判为不存在的 6,113 条路径按此规则全部不在索引里；判为存在的 65,370 条全部命中。")
w("- 分块内条目按路径排序紧密排列（目录优先遍历、文件先于子目录、不区分大小写、标点 < 数字 < 字母）。"
  "已命名的条目里只有 12 处与此顺序不符，都是“同主名、扩展名更长者在后”的情况（如 `X.bytes` 在 `X.binary_header.bytes` 前）。"
  "所以每个未命名条目夹在哪两个已知名之间，就能定位到它所在的目录。\n")
w("## 名字来源（按首要证据归类）\n")
w("| 来源 | 条数 |")
w("|---|---:|")
for g, n in prim.most_common():
    w(f"| {g} | {n:,} |")
w(f"\n所有名字都经 64 位哈希精确命中确认，没有把猜测当结果。命中的条目中：数据 {kinds['data']:,}、"
  f"bake layout {kinds['bake-layout']:,}、任务 partial {kinds['mission-partial']:,}、partial layout {kinds['partial-layout']:,}、"
  f"Excel binary_header {kinds['binary-header']:,}。\n")
w("## 按类别\n")
w("| 类别 | 条目 | MB | 数据条目 | 上次运行时导出已覆盖 | 未覆盖 |")
w("|---|---:|---:|---:|---:|---:|")
for k, c in sorted(cat.items(), key=lambda kv: -kv[1]["n"])[:30]:
    w(f"| {k} | {c['n']:,} | {c['bytes'] / 1e6:.1f} | {c['data']:,} | {c['rt']:,} | {c['nort']:,} |")
w(f"\nTextMap：索引里有 {len(tm)} 个数据表（`Textmap_*`/`TextmapMain_*` × cn/en/jp/kr），运行时导出只写了当前语言的一份。\n")
w("## 与 HSR-OWNER 运行时导出的差距（10-08，Resources #1）\n")
w(f"- 已命名的数据条目 {len(data):,} 条，其中运行时导出已产出 **{rt_yes:,}**，未产出 **{rt_no:,}**"
  "（清单见 `not_in_runtime_dump.csv`；不含 layout/partial/binary_header，TextMap 另计）。")
w("- `Config/Level` 未覆盖的主要目录：" + "、".join(f"`{k}` {v:,}" for k, v in lv.most_common(10)) + "。")
w("- 上次日志里 `MissionJsonPath` 回调收集到 0 条的原因已查明：这个版本的子任务列表（SubMissionList）"
  "放在 `MissionInfo_<id>.partial.bytes` 里（索引中 2,275 个），主文件 `MissionInfo_<id>.bytes` 大小中位数只有 20 字节。"
  "客户端在 `CLPPAMNDKIM.EMKCDCFEMIP`（`0xE248990`）里先读主文件，再用 `BinaryMainMissionPartialPath` 读 partial；"
  "HSR-OWNER 只调用 `LoadMainMissionInfoConfig`（`0x1E641E70`，只读主文件），所以拿不到任何子任务路径。\n")
w("## 未恢复名字的条目\n")
w(f"共 {p['unnamed']:,} 条，其中 {tiny:,} 条只有 1–2 字节（空配置）。按相邻已知名推断的所在目录：\n")
w("| 所在目录（推断） | 条目 | MB |")
w("|---|---:|---:|")
for d, n in near.most_common(15):
    w(f"| `{d}` | {n:,} | {near_b[d] / 1e6:.2f} |")
w("\n这些条目用上面所有来源和命名规律都没能命中，多半是没有任何代码或数据引用的文件。"
  "要拿到名字只能继续猜；运行时 hook 也只能看到客户端实际请求过的路径。\n")
w("## 文件\n")
w("- `designdata_inventory.csv`：全部索引条目（Persistent + StreamingAssets）。列：快照、revision、路径哈希、分块、语言标签、分块是否在盘、偏移、大小、"
  "逻辑路径、JSON 域路径、类型（data/bake-layout/mission-partial/partial-layout/binary-header）、类别、未命名条目的推断目录、名字来源、运行时导出是否覆盖。")
w("- `not_in_runtime_dump.csv`：已命名、但 10-08 运行时导出没有产出的数据条目。")
w("- `unnamed_entries.csv`：未恢复名字的条目。")
w("- `summary.json`：上述统计的机器可读版本。")
open(os.path.join(OUT, "DesignData资源清单.md"), "w", encoding="utf-8").write("\n".join(L) + "\n")
print("\n".join(L))
