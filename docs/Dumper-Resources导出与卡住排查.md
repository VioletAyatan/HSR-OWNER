# Dumper Resources 导出内容与卡住排查

> **2026-09-25 第二轮更新：用户运行后确认能导出，但现场 OOM 导致游戏崩溃（约 48.96 GiB 提交内存）；第二轮内存修复及保护已实现，编译和 15 项测试通过，待新版游戏内复测。** 当前状态、日志和限制见[交接文档第 0.1 节](Resources排查工作流与交接.md)。下文保留 2026-09-24 的历史基线分析；stdin 等待、字段定位休眠、错误传播及重复任务保护已修改。当前源码基线此前已有 panic 捕获和 hsr-owner.log 落盘机制，不能继续根据旧文断言它们不存在。

分析日期：2026-09-24。基于本地提交 `11cd291` 的源码静态分析，未运行游戏或复现卡住现象。尚未取得本次卡住时的最后日志，因此下文区分“代码中已确认的问题”和“具体发生在哪一步仍需日志确认”。

用户补充的现象：Dumper 页面一直显示 `Running ...`，工具界面没有卡死。这与“前端正常、后台任务缺少最终事件”一致，但还不能区分后台等待、执行缓慢或线程已经异常退出。`Running ...` 是任务状态文字，不是 Console 页面的最后日志。

## 1. 这个功能实际导出什么

Resources 通过运行中的游戏自身的类型、枚举器和配置加载函数读取数据，再用 `BoxedSerializer` 转为 JSON，保存到**游戏进程当前工作目录**下的 `DUMP/Resources`。

它的入口依次执行三个阶段：

```text
识别 ConfigManifest 的类型字段、路径字段、加载方法
  → 等待标准输入一行
  → TextMap 文本表
  → ExcelOutput 配置表
  → Config 技能、关卡、任务等配置
```

入口：[res/mod.rs:131](/D:/Projects/HSR-OWNER/crates/dumper/src/res/mod.rs:131)。

它不负责导出图片、贴图、模型、音频、视频原文件，也不负责导出协议或程序集。视频相关的输出是字幕配置；任务和技能输出是配置结构，不是完整的原始程序源码。

## 2. TextMap：运行时文本表

输入类型是 `RPG.GameCore.TextmapExcelTable`。代码查找返回类型名称包含 `Enumerator` 的方法，创建枚举器，反复调用 `MoveNext`，取 `Current`，把每一行序列化并加入数组，最后统一写盘。

唯一硬编码的输出文件是：

```text
DUMP/Resources/TextMap/TextMapEN.json
```

有三个边界需要明确：

1. 文件名写死为 `TextMapEN`，源码没有循环切换语言，也没有在此强制加载英文文本。**文件名是 EN，不足以证明运行时取到的一定是英文内容。**
2. 这里输出的是序列化行组成的 JSON 数组，不应默认把它理解为完整的“文本 ID → 字符串”字典格式。
3. 文件在所有行枚举完后才写入，因此此阶段长时间没有新文件不一定说明死锁，也可能还在处理一张大表。

依据：[textmap.rs:18](/D:/Projects/HSR-OWNER/crates/dumper/src/res/textmap.rs:18)、[textmap.rs:55](/D:/Projects/HSR-OWNER/crates/dumper/src/res/textmap.rs:55)。

## 3. ExcelOutput：游戏配置表

这里的 Excel 是游戏配置表分类，输出格式仍是 JSON，而不是 Office 工作簿。

源码遍历 `RPG.GameCore.Config` 程序集中的类型，用以下形状筛选候选表：

- 存在一个 `string[]` 字段，作为路径列表；
- 存在名称包含 `Dictionary`，且含 `Row` 或 `CommonIndexKey` 的字段。

对每个候选表读取路径列表，再调用表的枚举器读取行，输出：

```text
DUMP/Resources/ExcelOutput/<原路径最后一段去掉.bytes>.json
```

具体表的全集由运行时程序集和字段数据决定，源码没有一份固定完整列表。后续 Config 阶段明确消费的表包括：

| 表名 | 后续用途 |
| --- | --- |
| `SummonUnitData.json` | 从 `JsonPath` 找到召唤单位配置 |
| `MazePlane.json` | 从 `PlaneID`、`FloorIDList` 推导关卡楼层配置路径 |
| `VideoConfig.json`、`CutSceneConfig.json`、`LoopCGConfig.json` | 从 `CaptionPath` 找到字幕配置 |
| `RogueNPC.json`、`RogueTournNPC.json`、`RogueMagicNPC.json` | 从 `NPCJsonPath` 找到 NPC 配置 |
| `RogueDLCChessBoard.json` | 从 `ChessBoardConfiguration` 找到棋盘配置 |
| `MainMission.json` | 从 `MainMissionID` 推导任务信息路径 |
| `PerformanceA/C/CG/D/DS/E/Video.json`、`DialogueNPC.json` | 从 `PerformancePath` 或 `ActPath` 找到剧情/表现图配置 |

### 一个影响完整性的实现细节

`should_unload_first` 初始化为 `false`，现有代码没有将其设为 `true`。因此，为单一路径替换路径列表、卸载并重新加载表的分支在当前流程中不会执行。

结果是：虽然函数按路径循环，枚举的是当前表暴露的运行时数据，而不是明确为每个路径重新加载一份数据。多路径表可能存在重复输出、覆盖或遗漏，具体取决于游戏表枚举器的行为，不能宣称当前导出覆盖所有原始分片。

另一个细节是输出仅取路径最后一段；不同目录中相同文件名也可能写到同一个目标。

依据：[excel_output.rs:29](/D:/Projects/HSR-OWNER/crates/dumper/src/res/excel_output.rs:29)、[excel_output.rs:54](/D:/Projects/HSR-OWNER/crates/dumper/src/res/excel_output.rs:54)、[excel_output.rs:104](/D:/Projects/HSR-OWNER/crates/dumper/src/res/excel_output.rs:104)。

## 4. Config：技能、关卡、剧情和任务配置

### 4.1 从 ConfigManifest 导出的七类

代码先调用游戏的 `LoadConfigManifest()`，取得并序列化 Manifest，再按类型名匹配。只有以下七类进入导出分支，其他类型走 `_ => {}`，直接忽略。

| Manifest 类型 | 调用的加载方法 | 内容解释 |
| --- | --- | --- |
| `AdventureAbilityConfig` | `LoadAdventureAbilityConfigList` | 探索状态的能力/技能配置 |
| `TurnBasedAbilityConfig` | `LoadTurnBasedAbilityConfigList` | 回合制能力/技能配置 |
| `BattleLineupSkillTreePresetConfig` | `LoadSkillTreePointPresetConfig` | 技能树预设配置 |
| `GlobalModifierConfig` | `LoadGlobalModifierConfig` | 全局 Modifier 配置 |
| `AdventureModifierConfig` | `LoadAdventureModifierLookupTable` | 探索 Modifier 查询配置 |
| `ComplexSkillAIGlobalGroupConfig` | `LoadComplexSkillAIGlobalGroupLookup` | 复杂技能 AI 分组配置 |
| `GlobalTaskTemplate` | `LoadGlobalTaskListTemplateConfig` | 全局任务列表模板 |

内容解释按类型与加载方法命名归纳，不代表对每个游戏字段语义做了独立验证。

### 4.2 通过表格和字段引用追加导出的内容

Manifest 处理完后，依次执行六组扩展导出：

| 顺序 | 子模块 | 具体输出内容 |
| --- | --- | --- |
| 1 | `summon_unit` | 召唤单位配置 |
| 2 | `level_output_floor` | 运行时楼层、烘焙楼层、跨地图概览、区域、旋转区域、时代切换、导航地图，以及楼层对象引用的 Group |
| 3 | `video_caption` | 视频、过场、循环 CG 引用的字幕配置 |
| 4 | `rogue_npc` | NPC 配置及其 `DialoguePath`、`OptionPath` 引用的对话图/事件配置 |
| 5 | `rogue_chest_map` | 棋盘/宝箱地图配置 |
| 6 | `mission` | 主任务信息、`MissionJsonPath` 指向的子任务图，以及各类剧情表现图 |

这些路径有些直接来自表格字段，有些按 ID 拼出来，有些通过序列化回调收集。例如楼层解析遇到 `GroupPath` 时记录引用，随后再调用 `LoadRtLevelGroupInfo` 导出。

每组在加载前调用 `AssetLoader::ExistsDesignData` 过滤不存在的路径，然后：

```text
GameCoreConfigLoader::<指定方法>(path)
  → 得到托管对象
  → BoxedSerializer 序列化
  → DUMP/Resources/<原始相对路径>
```

典型目录形状为：

```text
DUMP/Resources/
├── TextMap/TextMapEN.json
├── ExcelOutput/<表名>.json
└── Config/
    ├── LevelOutput/RuntimeFloor/P<PlaneID>_F<FloorID>.json
    ├── LevelOutput_Baked/Floor/P<PlaneID>_F<FloorID>_Baked.json
    ├── LevelOutput/Region/FloorRegion_P<PlaneID>_F<FloorID>.json
    ├── LevelOutput/Map/MapInfo_P<PlaneID>_F<FloorID>.json
    ├── Level/Mission/<MainMissionID>/MissionInfo_<MainMissionID>.json
    └── ...由 Manifest 和对象引用决定的其他路径
```

这不是完整枚举所有游戏资源的过程。只会处理代码中列出的配置类型及可发现的引用，且缺失的方法/路径和部分序列化错误会被跳过。

依据：[config/mod.rs:17](/D:/Projects/HSR-OWNER/crates/dumper/src/res/config/mod.rs:17)、[level_output_floor.rs](/D:/Projects/HSR-OWNER/crates/dumper/src/res/config/level_output_floor.rs)、[mission.rs](/D:/Projects/HSR-OWNER/crates/dumper/src/res/config/mission.rs)。

## 5. 为什么点击后会一直卡在那里

### 5.1 导出前确实在等待标准输入

入口中保留了：

```rust
log::debug!("press to dump");
std::io::stdin().read_line(&mut String::default()).unwrap();
```

这不是“等用户再点击一次 Dump”，而是读取后端进程的标准输入。前端 Console 是日志查看页，没有把输入送入后端 stdin 的功能；日志代码只转发 stdout/stderr。

如果 stdin 是一个一直打开但没有提供完整行的终端/管道，这里就会阻塞。若 stdin 已到 EOF 或不可用，也可能立即返回或报错，因此不能仅凭这段代码断言所有卡住都发生在这里。

**如果最后日志是 `press to dump`，且后面没有 `[Textmap Dumper] Dumping Textmaps`，这里是首要检查点。**

依据：[res/mod.rs:136](/D:/Projects/HSR-OWNER/crates/dumper/src/res/mod.rs:136)、[logging.rs:68](/D:/Projects/HSR-OWNER/crates/dumper/src/logging.rs:68)。

### 5.2 识别失败后主动进入超长休眠

在实际写文件之前，入口会强制初始化三个 `LazyLock`。以下失败分支没有返回错误，而是调用近似无限期的 sleep：

| 最后日志 | 出错阶段 | 位置 |
| --- | --- | --- |
| `[Resources] cant find TypeName field name` | 根据运行时类型猜测 Manifest 的类型字段失败 | `res/mod.rs:35` |
| `[Resources] cant find path_list field name` | 结合构造函数指令和字段类型猜测路径数组字段失败 | `res/mod.rs:106` |
| `[Resources] failed to get 'Load' method name` | 从指定类型寻找无参方法失败 | `res/mod.rs:125` |

这里的定位依赖游戏类名、成员类型和机器指令形状。游戏版本变化可能让这些假设失效。

**出现上述日志时，等待几分钟通常不会推进任务，因为源码并没有重新扫描或重试。** 再点按钮也不会完成修复；其他线程还可能一起等待尚未初始化结束的 `LazyLock`。

另外，前两项字段其实主要供最后 Config 阶段使用，第三项加载方法用于当前没有启用的 Excel 重加载分支，但它们仍被放在所有导出之前强制解析。因此即使只想取得文本表，也会先受这些定位结果限制。

依据：[res/mod.rs:11](/D:/Projects/HSR-OWNER/crates/dumper/src/res/mod.rs:11)、[res/mod.rs:40](/D:/Projects/HSR-OWNER/crates/dumper/src/res/mod.rs:40)、[res/mod.rs:111](/D:/Projects/HSR-OWNER/crates/dumper/src/res/mod.rs:111)。

### 5.3 导出线程已经失败，但 UI 仍显示 Running

前端只在接收到 Started、Finished 或 Failed 事件时更新状态。后端执行过程大致是：

```text
发送 Started
  → actions::run(Resources)
  → res::dump()
  → 正常返回才发送 Finished / Result 错误才发送 Failed
```

`res::dump()` 返回 `()`，内部大量 `unwrap()`；任务边界没有 `catch_unwind`。某个 `unwrap()` 触发 Rust panic 时，在通常的线程展开行为下会退出该工作线程，而不是进入 `Err` 分支向前端回报失败。原生错误还可能有更严重影响。

具体易触发点包括：

- 目标类型、方法、Current 属性或枚举器不存在；
- 上一阶段没有产出 `SummonUnitData.json`、`MazePlane.json`、`RogueDLCChessBoard.json`、`MainMission.json` 或某些 Performance 表；
- JSON 字段名、字段类型与代码预期不一致；
- 创建输出目录或写文件失败。

因此“Running 不消失”不一定是线程在运行，也可能是最终事件永远不会到达。

依据：[ipc/mod.rs:243](/D:/Projects/HSR-OWNER/crates/dumper/src/ipc/mod.rs:243)、[actions.rs:8](/D:/Projects/HSR-OWNER/crates/dumper/src/ipc/actions.rs:8)、[Dumper 页面:15](/D:/Projects/HSR-OWNER/crates/frontend/src/pages/dumper.rs:15)。

### 5.4 全量枚举和反射调用很重，却没有有效阶段进度

TextMap、Excel 都先在内存里累积完整 JSON 行数组，再生成格式化字符串、最后写盘。Config 还会逐个调用游戏加载函数并递归序列化对象。

存在以下可确认的限制：

- 没有取消令牌、阶段截止时间或枚举行数上限；
- 单个游戏方法调用是同步等待；
- 配置路径存在性检查在创建该组进度条之前完成；
- 进度条采用 `indicatif` 终端输出，而 stdout/stderr 被转到管道；这条链路没有向 Dumper 页面发送结构化进度，不能依赖终端进度条可靠展示进展；
- `BoxedSerializer` 默认不仅访问字段，还会读取属性，因而执行属性 getter；
- 防循环逻辑只跳过“成员声明类型等于当前类型”的情况，没有完整的对象访问集合和递归深度限制。跨类型引用环可能导致过深递归，但本次未证明游戏数据实际出现了该情况。

如果 CPU 持续占用、输出文件持续更新，可能是处理缓慢；如果停在某一原生调用，则需要任务阶段日志或线程栈才能进一步判断。

资源导出运行在 IPC 新建的工作线程上，只做了 IL2CPP 线程 attach，没有走游戏 Main.Update 任务队列。**attach 并不等于游戏主线程。** 某个加载方法是否必须在主线程执行，需要结合具体卡住调用验证，当前不能直接认定为死锁原因。

依据：[excel_output.rs:183](/D:/Projects/HSR-OWNER/crates/dumper/src/res/excel_output.rs:183)、[config/mod.rs:109](/D:/Projects/HSR-OWNER/crates/dumper/src/res/config/mod.rs:109)、[boxed_serializer.rs:449](/D:/Projects/HSR-OWNER/crates/reflection/src/serializer/boxed_serializer.rs:449)、[ipc/mod.rs:185](/D:/Projects/HSR-OWNER/crates/dumper/src/ipc/mod.rs:185)。

### 5.5 重复点击会启动多个任务

Dumper 页面没有 busy 标志或运行时禁用按钮；后端每条命令另起线程。重复点击可能使多组导出同时读取相同运行时状态、写入同一批文件，并让一个任务的状态覆盖另一个任务。

**当前排查时不要通过连续点击重试。** 应先确认已有任务的日志和输出进度；卡在长休眠/标准输入读取的任务没有页面级取消机制。

依据：[Dumper 页面:58](/D:/Projects/HSR-OWNER/crates/frontend/src/pages/dumper.rs:58)、[ipc/mod.rs:180](/D:/Projects/HSR-OWNER/crates/dumper/src/ipc/mod.rs:180)。

## 6. 根据最后日志快速缩小范围

| 观察结果 | 首先检查什么 |
| --- | --- |
| 三种字段/方法定位失败日志之一 | 版本适配失败后进入超长休眠；不是普通导出耗时 |
| `press to dump` 后没有 Textmap 开始日志 | stdin 阻塞，或读取失败触发 panic |
| `[Textmap Dumper] Dumping Textmaps` 后停止 | 文本表类型、枚举器、MoveNext、Current、序列化与写盘 |
| `[Excel Output Dumper] Dumping Excels` 后停止 | 程序集筛选、表路径、枚举行、序列化；检查是否有 JSON 文件陆续生成 |
| `[Config Dumper] Dumping Configs` 后没有 `Dumping ...` | 加载或序列化 Manifest、读取动态识别出的字段 |
| `Dumping <配置类别>...` 后停止 | 路径存在性检查、配置加载、序列化、写盘；仅凭这条日志还分不清具体子步骤 |
| 控制台出现 `panicked at`，界面仍 Running | 工作线程已失败，任务边界未回传 Failed |
| 工具界面可操作，但 Resources 一直 Running | 优先检查等待、后台线程失败和缺少完成事件 |
| 游戏本身也不响应 | 需要进一步检查游戏加载调用、资源竞争、并发任务或运行时状态；不能只归因于 UI |

输出检查应以**本次点击后的修改时间**为准；目录中已有文件可能是上次残留。TextMap 的单文件写盘方式也意味着“没有文件增长”不能单独证明没有在计算。

## 7. 修复应先处理什么

按诊断价值和改动范围，建议依次处理：

1. 删除 GUI 入口中的 `stdin().read_line()`，让点击本身直接启动任务。
2. 把三个定位失败分支改为返回可读错误，取消超长休眠；能延迟到对应阶段的定位不要提前阻断所有导出。
3. 让资源导出返回 `Result<ExportReport>`，汇报阶段、成功数、跳过数和失败数。
4. 在任务边界捕获可展开的 Rust panic，并发送失败事件；这不能代替原生访问错误处理，也不能中断已经卡住的原生调用。
5. 前后端均增加单任务保护，按任务 ID 管理状态；运行时禁用重复启动。
6. 在每次加载/枚举/序列化前后记录表名或配置路径，并发送节流的进度事件；给长循环加取消检查。
7. 将缺失 Excel 文件、错误 JSON 字段改成带来源文件名的错误或跳过，而不是直接 panic。
8. 在拿到具体卡点后再决定是否需要主线程调度、分页序列化或递归保护，避免把整个重型导出一股脑放进游戏主线程。

单纯去掉标准输入等待不能解决其他卡住来源；单纯给 UI 加超时也只能提示超时，不能安全强杀正在访问游戏对象的工作线程。

## 8. 当前结论

已确认该功能存在数个独立的“卡住”来源，其中**标准输入等待、定位失败后的超长休眠、panic 后不回传失败状态**最值得优先处理。

用户已确认工具界面仍可操作，因此排查首先针对后台任务及完成事件，而不是前端 UI 死锁。仍不能断言具体是哪种后台问题。下一项最有用的证据是：切换左侧 Console 页面，复制本次点击之后的最后约 20 行日志，并观察本次输出文件是否持续更新。应先用这些证据确定停在入口、TextMap、Excel 还是 Config 阶段。

本次仅新增分析说明，没有修改业务源码，也没有对运行中的游戏进行操作。
