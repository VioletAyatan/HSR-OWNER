# Resources 排查工作流与交接

最后更新：2026-09-25

任务状态：**现场确认 Resources 导出期间内存耗尽；第二轮内存修复与保护已编译并通过 15 项测试，完整游戏内导出仍待验证。**
分析基线：Git 提交 `11cd291`，提交说明 `BE OWNER`。  
原工作区：`D:\Projects\HSR-OWNER`。文中源码路径相对仓库根目录，迁移目录后仍可使用。

## 0.1 2026-09-25 第二轮：导出期间游戏崩溃

用户反馈第一轮后已经能导出文件，但游戏中途崩溃，指定现场目录 D:/StarRail_Beta、日志 hsr-owner.log。

### 已取得的证据

- 日志最后停在 Config 的 LoadRtLevelGroupInfo 返回之后，正在序列化 Config/LevelOutput/SharedRuntimeGroup/Groups_P10401_F10401001/LevelGroup_P10401_F10401001_G355_D1002.json；不是卡在入口或标准输入。
- Windows Application 事件 1000：2026-09-25 16:09:32，StarRail.exe，VERSION.dll+0x7eec01，异常 0xc0000409。报告 ID b737daca-38e0-4a6e-9b8e-7268c41c7c8f。
- Windows System 的 Resource-Exhaustion-Detector：16:09:33 记录虚拟内存不足，StarRail.exe 提交内存 52,566,470,656 字节（约 48.96 GiB）；同时 rust-analyzer 约 4.65 GiB、hsr-frontend 约 4.18 GiB。
- 游戏目录保留的 version.dll.3180122265 与第一轮 target/debug/version.dll 的 SHA256 完全一致：5EAF9BBA4054EF1D17FB0308D59590CEB0794BDBD2FA0D591D6E5556911C93AC。用匹配 PDB 解析 0x7eec01，得到 std::alloc::rust_oom → std::process::abort。
- **此次进程终止的直接原因已确认是 OOM，而不是普通可展开 panic。** 哪类托管对象/原生分配占了多少尚未做堆快照，不能把最后一条 Group 配置认定为坏文件。
- 现场输出共 11,816 个 JSON，合计 2,170,375,923 字节；文件数仅为目录快照，不等于已验证的完整导出数。
- 保留的匹配 DLL/PDB、日志尾部、Application/System 事件在 target/resources-validation/crash-20260925。WER 转储目录读取被系统拒绝，本次没有读取完整 minidump，也没有改目录权限。
- StarRail.exe 的文件版本 2019.4.34.8948 是引擎文件版本，用户未提供可确认的游戏内容版本。

### 本轮实施方向

- 修复 Il2CppField/Method/Type::as_raw 每次 Box::into_raw 后不释放的句柄分配；同步 invoke 使用参数借用地址，不创建临时堆对象。
- 缓存原生类型名称，以及序列化器的类型判定、字段/属性元数据，减少重复反射调用和临时托管对象。
- TextMap/Excel 改为逐行写 JSON；Config 直接编码到缓冲文件，不再创建与整个 JSON 文件等大的编码 Vec。写入临时文件，成功后才替换目标，失败清理本次临时文件并保留旧目标。
- 新增进程私有提交内存、工作集、可用提交额度日志。保护阈值为进程私有提交达到 16 GiB 或可用提交额度不高于 2 GiB；每 250ms 最多采样一次，独立监视线程每秒检查，序列化过程中及行/阶段边界协作式退出，错误不能被内部跳过逻辑吞掉。
- 这项保护返回 Failed 并保留已完成文件，**不等于保证全量导出完成，也不能抢占单个原生调用或挽救所有瞬时巨额分配**。
- 保留现有 GC 环境设置，不擅自强制启用 GC 或回收游戏对象；GC_DONT_GC 的实际生效情况和游戏加载器缓存仍待现场内存分析。
- microseh 回调不能让 Rust panic 跨 extern system 边界展开，相关序列化/Config 回调内增加捕获；这修复另一条中止风险，但不是本次已确认的 OOM 根因。

### 本轮验证结果

- cargo test -p dumper -p il2cpp -p reflection --lib --offline：15 项通过（Dumper 11、IL2CPP 1、Reflection 3）。新增覆盖借用句柄地址、真实 Windows 内存读取、两类预算阈值、流式输出失败保留旧文件、嵌套错误吞掉后仍传播停止状态、SEH 回调内 Rust panic 被捕获。
- cargo build -p dumper --offline：通过；新版 Debug DLL 在 target/debug/version.dll。没有替换游戏目录文件，没有启动游戏。
- cargo check -p frontend --offline、修改文件 rustfmt、git diff --check：通过。
- 逐行写盘实际使用 64 KiB BufWriter，缓冲满时批量写入，文件完成才显式 flush，并非每行强制刷新磁盘。JSON 数组数据结构保持不变，空白缩进可变化。
- 新版游戏内耗时、峰值内存、完整导出结果尚未验证；单元测试不替代这些运行验证。

下一步是在新版上观察内存曲线和终态，确认能否完整越过此次中断位置；若触发保护，应调查剩余托管分配/加载器缓存，而不是简单提高上限或关闭保护。

## 0. 2026-09-25 接续：当前实现与验证

本次基线为 `94553b7`，开始时工作区干净。用户明确要求继续 resource 修复并加日志。**没有启动游戏，原始卡住根因仍未证实，不能宣称游戏内问题已解决。** 下文第 1～8 节保留初次分析和工作流；被本节覆盖的旧缺陷不再视为当前未修复项。

核对发现，当前基线已经具备 IPC 任务边界的 Rust panic 捕获，以及追加到游戏进程工作目录下 `hsr-owner.log` 并逐条 flush 的日志机制。本次复用了这些已有能力。

### 已实现

- 删除 Resources 的 stdin 等待，直接执行 TextMap → ExcelOutput → Config。
- Config 字段识别延迟到 Config 阶段，查找失败返回带类型/字段/方法信息的错误，不再使用 LazyLock 超长休眠。增加构造函数 RVA 范围和路径字段候选数检查。
- 删除原本永不启用的 Excel 卸载/重载分支及其 Load 方法预定位；保持枚举当前运行时表的策略，没有启用单路径重载。
- TextMap/Excel 共用枚举函数。枚举器、MoveNext、Current、序列化和写文件错误向上传播，不再默默丢行或把调用错误当作枚举结束。
- Config Manifest、依赖 JSON、必要字段、加载/写盘错误向上传播；相同 Manifest 类型合并路径，避免覆盖。非目标 Manifest 类型及不存在的设计数据路径显式记录跳过。
- **采用遇错停止策略**：返回 Failed，保留此前写出的部分文件。未实现出错后继续其余类别的部分成功调度。此前被忽略的字幕/NPC 可选表缺失现在也会失败；如游戏版本确有可选表差异，需根据现场证据完善策略。
- 共用序列化初始化中另外三处超长 sleep 改为带说明的 Rust panic，由 Resources/IPC 边界转换为 Failed；共用方法现有 API 未变更。
- 前端点击后立即禁用 Dumper 启动按钮；后端所有 Dumper 操作共用 RAII 互斥门，正常结束、错误及可展开 panic 都释放；原生调用仍执行时不会提前释放。
- Dumper 开始/结束/失败事件改用可靠队列发送，避免被满日志队列静默丢弃；其他 IPC 事件语义保持原样。
- 前端启动请求不排队等重连，发送失败立即提示。断连显示后端可能仍运行，重连后的重复任务仍受后端互斥保护；未实现跨连接任务状态查询/恢复。
- 修正 Dumper 构建脚本，只向 cdylib 传递 version.def 导出参数，避免把测试 EXE 错误链接为 DLL。

### 日志用法

查看工具 **Console** 或游戏进程工作目录的 **hsr-owner.log**；不是默认写在本源码目录。开始日志给出绝对输出目录和日志路径。文件日志打开失败会在 Console 警告。

每次 Resources 运行分配进程内递增 ID，使用 `[Resources #N]` 前缀，包含 Unix 毫秒时间、包版本（不是游戏版本）、阶段/表名/路径、操作前后与耗时。Config 区分 exists / load / serialize / encode JSON / write。表枚举每 1000 行打印一次进度，在内存逐行更新 MoveNext / Current / serialize 操作。

独立诊断线程**每 10 秒**打印当前操作、该操作持续毫秒数及本次写文件次数，成功或失败后停止。若相同行号/路径/操作的 `operation_elapsed_ms` 持续增加，就从该调用继续调查。心跳不是取消或超时中断机制。

最终日志记录 finished 或 failed、耗时和 `files_written`（成功写文件次数，不是唯一文件数）；失败注明保留部分输出。输出目录中的旧文件不代表本次产出或完整性。

### 验证结果

- Windows nightly MSVC 可用。
- `cargo build -p dumper --offline`：通过，Debug DLL 已生成，没有替换游戏文件。
- `cargo check -p frontend --offline`：通过。
- `cargo test -p dumper --lib --offline`：8 项通过，覆盖并发拒绝、panic/错误终态与锁释放、全部 Dumper action 的事件语义、队列满时终态发送、Manifest 类型合并和字段错误。
- 修改文件 rustfmt 及 `git diff --check` 通过。
- 初次测试因旧构建脚本导出参数污染 EXE 无法执行（Windows error 193）；修复后重跑通过。
- 仍有仓库现存的依赖、命名和依赖未来兼容性警告，没有在本任务清理。
- **未验证**：游戏版本兼容性、真实导出数据、UI 交互实测、游戏主线程要求、阻塞中的原生调用、所有原生异常、对象引用环、超大表内存与多路径表完整性。catch_unwind 不保证捕获 SEH/栈溢出，心跳不能强行终止游戏调用。

### 下一步

在游戏中使用本次修改的后端和前端，单击 Resources，记录游戏版本及 `[Resources #N] start` 后的日志。应出现 finished 或明确 failed。若仍 Running，取得最后一个 begin / 心跳的完整操作、表名、行号、路径及持续时间，按具体游戏调用继续定位；不要直接把全量导出放进游戏主线程。

## 1. 用户目标与已知现象

用户最初要求分析项目源码并生成详细文档，之后进一步询问：

> 分析一下 Dumper 模块里的 resource 导出功能，具体导出什么东西，我使用的时候经常点击这个功能后卡在这里。

针对卡住表现，用户补充：

> 显示 running xxx 啥的，界面没卡住。

用户目前没有方法现场排查，要求将 Agent 工作流保存在项目，之后有空会开新对话继续。

后续目标是确定 Resources 为什么长期显示 Running，并按后续用户请求修复、验证。不要把“前端还能操作”解释成“游戏一定没卡住”：游戏本体是否响应尚未明确。

## 2. 已完成的工作

- 全项目用途、架构、功能和工程边界分析：[项目源码详细分析](项目源码详细分析.md)。
- Resources 入口、三个导出阶段、序列化、前后端状态与失败路径分析：[Dumper Resources 专项分析](Dumper-Resources导出与卡住排查.md)。
- 用户确认工具 UI 可操作，长期 Running 是 Dumper 页面状态文字，尚未提供 Console 页面的实际日志。
- 已定位数个足以导致等待或状态滞留的实现问题，见下节。

**初次分析时未完成：** 运行复现、根因判定、业务源码修改、编译和回归验证。2026-09-25 的实现及验证见第 0 节；游戏内验证仍未完成。

前次环境通过 PowerShell 查询没有找到可用的 `cargo`、`rustc`、`rustup` 命令。这仅代表当时会话环境；新 Agent 应重新检测，不能永久假设工具链不存在。此前没有安装工具链，没有为该任务创建分支或提交。

## 3. 必须保留的事实与不确定性

### 3.1 Resources 的实际导出范围

顺序为 `TextMap → ExcelOutput → Config`，输出到游戏进程工作目录下的 `DUMP/Resources`：

- TextMap：运行时文本表，文件名固定 `TextMap/TextMapEN.json`。源码没有循环切换语言，不能根据 EN 文件名断言实际语言。
- ExcelOutput：从 `RPG.GameCore.Config` 程序集筛选表并导出 JSON；不是 `.xlsx` 文件。
- Config：指定的技能、Modifier、AI、任务模板，以及召唤物、楼层/区域/地图、字幕、Rogue NPC/对话/棋盘、任务与剧情图配置。
- 此功能不导出图像、模型、音视频原文件；导出覆盖也不是所有游戏配置的完整集合。

### 3.2 已在源码确认的问题

| 编号 | 事实 | 具体影响与限制 |
| --- | --- | --- |
| R1 | `res::dump()` 正式导出前调用 `stdin().read_line()`，此前打印 `press to dump` | stdin 可能阻塞，也可能 EOF 或报错；尚未确认用户此次停在这里 |
| R2 | 三个字段/方法识别失败分支调用 `sleep(u64::MAX)` 级别休眠 | 没有正常失败返回、重试或重新扫描；重复启动还可能等待同一 LazyLock |
| R3 | 内部大量 `unwrap()`，任务边界没有捕获 Rust panic | 线程可能退出而没有 Finished/Failed，UI 继续 Running；原生错误影响另需判断 |
| R4 | 前端无 busy 禁用，后端为每条命令创建线程 | 重复点击可能并行导出并写同一批文件 |
| R5 | 无结构化阶段/条目进度、取消检查或执行期限 | 很难区分慢处理、等待和已经失败 |
| R6 | TextMap/Excel 全量积累后写盘；默认序列化还访问属性 getter | 处理可能较重，长时间不产生新文件不等于已死锁 |
| R7 | Config 阶段直接读取先前应生成的若干 Excel JSON 并 unwrap | 前一阶段缺失文件/字段不符会导致后续失败 |
| R8 | `should_unload_first` 始终为 false | 按路径重载 Excel 的分支未启用，不能保证每个路径得到独立完整数据 |

其他尚需验证的可能性：工作线程调用游戏加载函数是否有主线程要求、跨类型对象引用环、日志/事件队列丢弃、长时间内存增长。没有调用栈或运行数据前，不把这些写成已确认根因。

## 4. 新对话开始时的操作顺序

### 第一步：恢复上下文并核对代码

1. 读本文件和 Resources 专项分析，无需重做整个项目分析。
2. 查看 `git status --short`、当前 HEAD 和相关源码变更。分析基线只是参考，行号可能变化。
3. 保留用户已有修改，包括未提交文档；不要覆盖或清理导出结果作为“准备工作”。
4. 检测当前 Rust 工具链。需要构建时再核对 Windows MSVC、nightly/bindeps、Oodle 及 GUI 依赖条件。
5. 确认用户当前请求是继续诊断还是实施修复，按当次请求执行；无需再次询问项目用途或重复索要已确认的 UI 现象。

### 第二步：取得最少的现场证据

若用户当前可以重现，优先收集：

- 左侧 **Console** 页面中本次点击后的最后约 20 行日志；不要把 Dumper 的 `Running ...` 当成日志。
- 本次点击的大致时间和运行游戏版本。
- 工具之外的游戏本体是否仍响应，是否重复点击过 Dump。
- `DUMP/Resources` 中本次新生成/更新文件的位置及修改时间；旧文件不能证明当前任务已经执行到对应阶段。

先使用现有日志和输出。用户已经表示暂时无法现场排查时，不反复催其启动游戏或提供截图；记录缺口，并根据当次授权继续可独立完成的源码工作。

### 第三步：按最后日志定位阶段

| 证据 | 下一步 |
| --- | --- |
| `cant find TypeName field name` / `cant find path_list field name` / `failed to get 'Load' method name` | 确认定位失败进入超长休眠；检查当前版本的类型/签名/指令假设 |
| `press to dump` 后无 Textmap 开始日志 | 检查 stdin 等待或读取 panic；GUI 不提供后端 stdin 输入 |
| `Dumping Textmaps` 后停止 | 细分查找枚举器、MoveNext、Current、序列化和写盘 |
| `Dumping Excels` 后停止 | 记录当前表类型/路径/行数，检查是否有文件持续写出 |
| `Dumping Configs` 后无具体类别日志 | 检查 LoadConfigManifest、Manifest 序列化和字段解析 |
| `Dumping <类别>...` 后停止 | 细分路径存在性检查、加载、序列化和写盘 |
| `panicked at ...` | 找最早 panic 的文件/行号；同时修复失败通知缺失 |
| 只有 Running，日志不足 | 不猜根因；优先增加诊断信息和失败状态 |

不要通过反复点击尝试“唤醒”任务；现有实现会新增后台任务。不要擅自终止游戏进程来清理线程。必要的运行重启应结合用户当次操作安排。

## 5. 需要修改代码时的分阶段工作流

此节是候选实施路线，**不是已完成的修改，也不是要求必须一次性大改**。以实际证据和后续请求为准。

### A. 先消除无意义等待，让失败可见

- 移除 GUI 资源导出入口中的标准输入等待。
- 将定位失败后的超长 sleep 改成包含阶段/类型/方法信息的错误返回。
- 将只有某一阶段需要的定位推迟到该阶段，避免 Config 定位失败提前阻断文本表导出。
- 让资源导出返回明确 Result 或报告，区分成功、部分成功与失败。
- 在合适任务边界处理可展开的 Rust panic，并回传失败事件；不要把 SEH、Rust panic 和原生调用阻塞混为一谈。
- 前后端加入单任务保护，并确保失败后释放状态。注意其他 Dumper 操作共享任务调度，避免改变它们的现有事件语义。

### B. 增加能定位真实卡点的进度

- 给每次导出分配任务标识，记录开始时间和版本/输入条件。
- 在每个阶段、表或配置加载前后输出结构化日志。
- 枚举行数定期上报，节流，避免大量日志冲掉关键错误。
- 分开记录“路径存在性检查”“调用游戏加载器”“序列化”“写文件”，而不是仅打印一个 Dumping。
- 如增加文件日志，明确实现输出位置和刷新机制。现有源码没有自动生成 `dump.log`，不得假设它已经存在。

### C. 根据具体证据修复数据与执行问题

- 缺失依赖 Excel 文件或 JSON 字段：改为带具体文件/字段信息的错误或明确跳过。
- 部分类型不兼容：针对当前版本确认类型/方法/字段，避免扩大模糊匹配后静默选择错误对象。
- 游戏加载调用停住：在确认线程要求后调整调度；不要把整个全量导出都放入 Main.Update。
- 大表处理慢：考虑分批处理、流式写出和协作式取消。
- 序列化递归风险：使用对象访问记录、深度限制或显式类型规则，并保证输出语义清楚。
- 重建 Excel 单路径加载策略前，确认它对游戏共享表状态的影响和恢复方式。

**限制：** UI 超时只能表示未在期限内完成，不能安全地强制终止正在访问游戏对象的线程；`catch_unwind` 也不能解决永久等待或所有原生异常。

## 6. 验证与完成标准

按实际改动运行针对性检查，不用无关测试替代游戏内验证。

- [x] 实际修改可编译：2026-09-25 Dumper build、frontend check 通过。
- [ ] 点击一次后能看到当前阶段及表名/路径，正常完成有明确报告。
- [ ] 字段/方法查找失败快速返回可读错误，不再长期休眠。
- [ ] 缺失文件、结构不符或可捕获 panic 能使任务显示失败，而非永久 Running。
- [ ] 连续点击不会并行执行同一个不支持并发的导出任务。
- [ ] 输出根目录明确；检查的是本次产生的内容，统计完整与部分成功。
- [ ] 若改动公共 IPC/任务处理，核查其他 Dumper 功能仍能收到正确的开始/结束状态。
- [ ] 记录实际验证的游戏版本、阶段结果和仍未覆盖的数据类型。

可以为纯逻辑补充有价值的测试，例如任务互斥、错误到事件转换、缺失 JSON 的报告；涉及游戏函数的路径需要现场验证。如果只有静态修复，结果应标记为“实现完成，等待运行验证”，不能标记为用户问题已解决。

## 7. 核心源码导航

| 文件 | 阅读重点 |
| --- | --- |
| `crates/frontend/src/pages/dumper.rs` | 按钮发命令；Started/Finished/Failed 更新状态；缺少 busy 保护 |
| `crates/dumper/src/ipc/mod.rs` | 每命令工作线程、handle_dumper、最终事件 |
| `crates/dumper/src/ipc/actions.rs` | 运行时初始化、线程 attach、Resources 分发 |
| `crates/dumper/src/res/mod.rs` | 三项定位、sleep、stdin、三个阶段顺序 |
| `crates/dumper/src/res/textmap.rs` | 文本表枚举、固定输出名、整表写盘 |
| `crates/dumper/src/res/excel_output.rs` | 表筛选、路径列表、加载分支、行枚举 |
| `crates/dumper/src/res/config/mod.rs` | Manifest 分类、路径检查、加载与序列化 |
| `crates/dumper/src/res/config/*.rs` | 对 Excel 文件的依赖及递归发现的引用 |
| `crates/reflection/src/serializer/boxed_serializer.rs` | 递归序列化、getter、特殊类型、循环处理 |
| `crates/dumper/src/logging.rs` | 日志队列和 stdout/stderr 捕获，不包含 stdin 桥接 |
| `crates/il2cpp/src/vm/method.rs` | 同步 il2cpp_runtime_invoke，无超时机制 |

## 8. 接续记录

每次继续任务后更新此表，并把最有用的下一步写在表后；不要只在聊天里保存新发现。

| 日期 | 工作 | 证据 / 结果 | 下一步 |
| --- | --- | --- | --- |
| 2026-09-25 | 用户现场崩溃与第二轮内存修复 | 日志、系统内存不足事件及匹配符号确认 OOM，约 48.96 GiB 私有提交；实现/验证见 0.1 节 | 用新版内存日志验证峰值及完整导出 |
| 2026-09-25 | 第一轮修复和诊断日志 | 基于 94553b7；Dumper build、frontend check、8 项测试通过；没有游戏验证 | 使用新版日志的任务 ID / 心跳定位现场剩余卡点 |
| 2026-09-24 | 全项目与 Resources 静态分析 | 文档已生成，业务源码未修改，未编译/运行 | 获取实际卡住阶段 |
| 2026-09-24 | 用户补充症状并要求跨对话保存 | Resources 长期 Running，工具界面可操作；用户暂时不能排查 | 等用户新对话恢复，先读交接再核对代码与 Console 日志 |

当前最优先的下一步：**使用第二轮版本复测并观察 private_mib / available_commit_mib，确认完整导出或明确内存保护 Failed；已知旧版现场 OOM，不能再当作单纯等待问题。**
