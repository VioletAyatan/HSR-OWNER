# Resources 排查工作流与交接

最后更新：2026-09-25

任务状态：**第六轮游戏内完整流程已验收：用户确认成功，日志 finished，691503ms、64139 次文件发布；内存稳定，无 Error/序列化失败/保护中止。检查未发现阻止提交的问题。导出覆盖范围仍有已记录限制。**
分析基线：Git 提交 `11cd291`，提交说明 `BE OWNER`。  
原工作区：`D:\Projects\HSR-OWNER`。文中源码路径相对仓库根目录，迁移目录后仍可使用。

## 0.6 2026-09-25 完整流程验收与提交检查

用户报告完整完成，并要求审查日志、无重大问题则提交。审查 D:/StarRail_Beta/hsr-owner.log 中本次唯一 Resources #1：

- start unix_ms=1790328585013，finished unix_ms=1790329276517，elapsed_ms=691503（约 11 分 32 秒），files_written=64139。IPC 同时记录 dumper finished: Resources (691s)。
- 游戏目录保留的 version.dll.2257088500 与本地 target/debug/version.dll 的 SHA256 一致：982F37B28EF8C4130094BB1BC517925A591F2193219CD24C9DFB9CBD55F5A760，确认此次验收对应本次构建。
- TextMap、ExcelOutput、Config（SummonUnit、LevelOutput、VideoCaption、RogueNPC、RogueChestMap、Mission）均有 end 记录。全部日志没有 Error，运行区间没有序列化失败、panic 或内存保护中止记录。
- 运行期日志采样 private_mib=4983～5386，working_set_mib=3163～3552；available_physical_mib 最低 6288，终态 6336。样本最大值不是操作系统连续测量的精确峰值。
- 累计 native_calls=206944421；69 条心跳/终态记录中 history_entries 始终 256、history_reserved_bytes 始终 268288（262 KiB）。终态私有提交约 5.26 GiB、工作集约 3.47 GiB，没有原先与调用次数同步的无界增长。
- 字幕三表按预期跳过 26+21+120=167 条空引用，VideoCaption 62ms 完成；另有 1 条公共入口空路径跳过。
- 64139 次发布对应 64138 个唯一输出路径；Config/Level/Mission/8013102/Act/Act403055160.json 在两个流程中发布两次。没有发现未清理的 resources-part 临时文件。均匀选取并补充关键类别共 25 个输出检查：24 个 JSON 解析成功，1 个超过 20 MiB 的 TextMap 仅验证存在，没有全量校验每个文件内容。

非阻塞项与覆盖限制：

- 111 条 empty runtime table 警告。导出的是当前运行时表，不能据此保证原始数据为空；表卸载/按分片加载并未实现。
- 3619 次 ExistsDesignData 返回不存在并跳过；8 种未支持 Manifest 类型的 570 条路径按既有范围跳过。完整 finished 表示既定导出流程完成，不等于所有游戏原始资源无遗漏。
- 其中一张 Excel 表暴露空路径，按既有命名逻辑生成 ExcelOutput/.json，内容为 []；这是非阻塞的输出命名边界，记录为后续完善项，本次没有在已验收代码上扩大改动。
- 启动另有 pool1 size pattern not found 警告，表示现有元数据池补丁未匹配；本次没有因此失败，跨版本兼容风险仍保留。GC_DONT_GC 提醒也仍存在，实际 GC 状态未验证，本次没有变更其行为。
- 详细日志约 133.6 MB，保留当前排查粒度；后续可独立优化日志轮转/级别，不影响本次验收。

提交前检查：复查待提交代码、已有 Dumper 16 项和 IL2CPP 3 项测试通过记录、成功 DLL 构建记录，修改文件 rustfmt 与 git diff --check 通过。本轮仅更新验收文档，没有修改已实测业务代码。审查结果保存在忽略目录 target/resources-validation/completed-run-audit.json，日志与游戏输出不纳入提交。

## 0.5 2026-09-25 第六轮：字幕空引用导致 Invalid path

用户确认新版没有出现内存无限增长，但约 10 分钟后在 Config/VideoCaption 失败。本机日志及输出检查确认：

- Resources #1 elapsed_ms=598810、files_written=37771；错误操作 begin Config: exists 后没有路径，异常 System.Exception，message="Invalid path "。
- 终态 private_mib=5506、working_set_mib=3576、available_physical_mib=6481（总物理内存 32598 MiB）。native_calls=192324193，history_entries=256、history_reserved_bytes=268288；此前多个心跳历史占用也保持不变。现场结果支持第五轮有界缓存修复有效，不能再说尚未游戏复测。
- VideoConfig 90 行：26 条空 CaptionPath、64 条非空；CutSceneConfig 41 行：21 条空、20 条非空；LoopCGConfig 138 行：120 条空、18 条非空。共 167 条空引用，三表均没有缺字段、null 或非字符串。
- 例：VideoConfig 零基 row=3、VideoID=4、CS_Chap01_Act120.usm 的 CaptionPath=""。旧提取逻辑接受空字符串，排序/去重后空值位于第一项，被传给 ExistsDesignData；因此连第一条有效字幕路径都没检查到。

第六轮改动：

- 字幕路径提取跳过空/纯空白字符串，按表名、零基行号、字段、原因打印日志，并输出 rows/caption_paths/skipped_blank 汇总。保留全部非空原始路径，不擅自 trim 改写有效路径。
- 公共 dump_from_config_list 在任何 IL2CPP 查找或路径检查之前过滤空/纯空白引用，记录 loader 名、输入索引及跳过数，然后正常排序去重；全空列表直接返回，不调用游戏 API。
- 缺字段、null、非字符串依然报出来源表和行；非空路径的加载异常仍传播，没有 catch 所有 Invalid path 并继续的行为。
- 维持第五轮有界调用历史、多路径表复用、物理内存保护及第三轮异常详情，没有修改 GC 策略。

验证：cargo test -p dumper --lib --offline：16 项通过，新增字幕混合空值/正常路径、全空、格式错误及公共入口过滤测试；cargo build -p dumper --offline、修改文件 rustfmt、git diff --check 通过。日志在 target/resources-validation/caption-path-{tests,build}.log。新版 target/debug/version.dll 未部署或游戏内运行。

下一步用新版确认日志显示三表合计跳过 167 条空引用并进入字幕加载，再继续 RogueNPC/RogueChestMap/Mission。保留此前 37771 次成功输出，本轮不删除已有文件；完整导出仍待终态 finished 验证。

## 0.4 2026-09-25 第五轮：修复反射调用历史无界增长

用户问“怎么处理”后继续检查，发现比 GC 推测更直接的源码证据：

- crates/il2cpp/src/lib.rs 原 get_native_method 每次执行 LAST_NATIVE_SIGS.lock().unwrap().push(signature.to_string())，全局 Vec<String> 没有容量上限。
- crates/derive/src/il2cpp_api.rs 生成的反射包装每次调用都会走 get_native_method；序列化不断读取字段、属性、类型，因此历史随操作量持续累积，不随 JSON 写完释放。
- clear_native_sigs 仅在反射初始化测试期间调用，正常 Resources 导出没有清理。这是已确认的 Rust 保留内存无界增长；不是“所有 JSON 均释放，所以只剩游戏 GC”的情况。
- 旧历史容器扩容也会导致阶跃式增长。但没有旧版堆快照/历史统计，不能声称现场全部 21 GiB 或某次跳升都由它造成。

已实施：

- 将历史封装到 recent_calls.rs，只保留最近 256 条；每条诊断文本最多 1024 字节，UTF-8 边界截断，循环使用被淘汰条目的 String 缓冲。
- 实际方法查找始终使用完整原始签名，不受诊断截断影响。recent_native_sigs 保留从旧到新的 Vec<String> 查询接口，clear_native_sigs 释放缓存及重置统计；移除可从外部无界写入的旧全局 Vec。
- Resources 心跳/终态增加 native_calls、history_entries、history_reserved_bytes；预热后此项应稳定在 256 条和约 268288 字节（262 KiB），不随累计调用次数继续增大。
- 保留第三/四轮的异常详情、物理内存保护和多路径表复用；未提高限制，未修改 GC 开关或调用卸载方法。

验证：cargo test -p il2cpp -p dumper --lib --offline 共 16 项通过（IL2CPP 3、Dumper 13）。新增百万次记录后容量不增长、最新顺序及长 UTF-8 签名截断测试；cargo build -p dumper --offline、修改文件格式/差异检查通过。日志在 target/resources-validation/native-history-{tests,build}.log。新版 target/debug/version.dll 未部署或游戏内运行。

另查到现场 methods2.json 中存在 GameCoreConfigLoader::UnloadJsonConfig(System.String)、OnConfigUnload() 和 System.GC::GetTotalMemory(System.Boolean)。仅确认接口名称，未分析其共享缓存/引用计数行为，未调用；没有据此实施强制回收或逐文件卸载。GC 引用保护方案暂缓，先验证明确的 Rust 增长点修复收益。

下一步：重启游戏使用新版 DLL 完整导出，确认历史缓存字节数稳定，比较 private_mib/available_physical_mib 曲线与最终 finished/failed。若仍持续上涨，再依据分阶段增量定位托管堆/加载器缓存；GC_DONT_GC 实际效果仍待运行时验证，不能继续当作已确认主因。

## 0.3 2026-09-25 第四轮：Config 内存保护与物理内存压力

用户提供第三轮新版日志，并指出失败前任务管理器内存 100%，HSR 占十多个 GiB。现场 hsr-owner.log 确认：

- 本次越过之前的 ExcelOutput 故障；341838ms、6056 次成功文件发布后，在 LoadLevelFloorCrossMapBriefInfo 的 CrossMapBriefInfo_P20432_F20432001.json 序列化中触发保护。
- 1790326353913 心跳 private_mib=14954、working_set_mib=11517；1790326363917 首次采样超限 private_mib=21280、working_set_mib=9592、available_commit_mib=24853；1790326365581 返回 Failed。
- 这是保护性停止，不是本次已证实的分配失败/OOM 崩溃。旧日志没采集可用物理内存，不能用 available_commit_mib 否定用户观察的 RAM 100%；提交额度含页面文件，与可用物理内存不同（[Microsoft MEMORYSTATUSEX 文档](https://learn.microsoft.com/zh-cn/windows/win32/api/sysinfoapi/ns-sysinfoapi-memorystatusex)）。
- 旧检查是时间采样加协作退出，不能抢占原生调用；第一次采到的值可能已显著越界。16 GiB 不是操作系统强制分配上限，不能宣称新增检查保证零超调。

源码确认与限制：

- Config 每个文件的 serde_json::Value、缓冲 writer 离开作用域即释放；没有把所有 Config JSON 留在 Rust 容器里。但释放后分配器是否马上归还系统不可保证。
- 反射会创建托管临时对象，游戏加载器也可能持有缓存；Il2CppObject 是地址包装，Rust drop 不能回收其指向的托管对象。
- dumper/src/lib.rs 启动时设置 GC_DONT_GC=1，这是禁用回收的明显疑点；当前没有验证游戏实际 GC 状态、堆增长组成或加载器缓存持有关系。现有 Rust 容器中的托管地址没有统一 GC 句柄保护，本轮未改 GC 设置，未强制回收游戏对象。

第四轮实施：

- 内存日志增加 available_physical_mib、total_physical_mib。可用物理内存不高于 max(1 GiB, 总 RAM 的 5%) 时请求停止，保留 16 GiB 私有提交/2 GiB 提交余量原阈值。
- 序列化检查采样间隔降至 100ms，独立监视线程每 250ms 检查、约 10 秒心跳。每个 operation 前后强制采样；成功结束日志加 private_delta_mib，终态刷新实际采样但保留首次停止原因。原生调用无法抢占的限制仍在。
- 同一 Excel 类型的多条路径以前会重复序列化同一运行时表；现在只生成一次，其他不同输出名以 64 KiB 块复制，并检查内存。明确采用同一时刻的表快照，仍未实现每个原始分片独立加载；已知多路径完整性限制不因此消失。
- 复制依然写临时文件后发布，失败保留旧目标；重复输出名不重复发布。开始时记录 GC_DONT_GC 环境变量及“实际 GC 状态未验证”。

验证：cargo test -p dumper --lib --offline：13 项通过，新增物理内存阈值边界检查及复制成功/失败保留文件验证；cargo build -p dumper --offline、rustfmt、git diff --check 通过。日志为 target/resources-validation/physical-memory-{tests,build}.log。新版 target/debug/version.dll 未部署到游戏目录，未游戏内运行。

下一步应比较新日志中加载/序列化的 private_delta_mib、物理内存余量和多路径复用节省；若仍增长，需验证实际 GC 状态与托管引用保护、加载器缓存生命周期。新增保护可能使任务更早 Failed，不能把它当作“释放内存已完成”或保证全量导出。

## 0.2 2026-09-25 第三轮：MoveNext 托管异常

本轮开始基线 fb0c88b，工作区干净。读取用户提供的错误及 D:/StarRail_Beta/hsr-owner.log，确认：

- Resources #1 于 Unix 毫秒 1790325473529 开始，1790325562622 失败；elapsed_ms=89092，files_written=1985。
- 失败表为 OKNONGBAAEM，路径 BakedConfig/ExcelOutputGameCore/SpecialAvatarRelicMainValue.bytes，操作 MoveNext，row=14715 是已成功发出的行数（下一次 MoveNext 的零基索引），不是定位到某个坏数据行的证据。
- 本表约 1.36 秒内已处理 14715 行。错误为 IL2CPP invocation raised exception at 0x700F33442D0；旧日志只有地址，不能确认异常类型、集合版本冲突或数据加载故障。
- 最终 private_mib=9076、working_set_mib=6425、available_commit_mib=36664，未达到保护阈值。本次是托管调用返回错误，日志在 Failed 后仍持续产生，不等同于上一轮 OOM 崩溃。
- 1985 是本次成功发布文件的次数；失败表临时文件被清理，旧同名文件如存在会保留，不能视为本轮成功产物。Config 阶段未执行。

本轮改动：

- Resources 的调用异常不再只打印地址：通过已有原生元数据 API 读取类型和 System.Exception 存储消息字段，不调用异常 getter、ToString 或原有带 unwrap 的 Debug 实现。
- 诊断读取限制元数据长度、消息长度和基类遍历层数；SEH 及内部 Rust panic 捕获失败时退回地址与详情不可用说明，保留原异常。消息字段布局不兼容时仍尽可能保留类型。
- 表枚举器工厂限定为静态零参数方法。从实际枚举器类型查 Current/MoveNext；值类型通过已有 object_unbox API 取调用地址，引用类型保留对象地址，替代无条件 +16。记录工厂名、实际类型、value_type 和 MoveNext RVA，并检查空返回。
- 这些是诊断及调用兼容性修正，**尚不能证明本次 MoveNext 异常已修复**。保留流式输出和遇错停止，没有盲目重试、跳过错误或关闭内存保护。

验证：cargo test -p dumper --lib --offline：12 项通过，新增异常详情成功、读取失败、诊断 panic、空指针退化覆盖；cargo build -p dumper --offline 通过。日志在 target/resources-validation/movenext-{tests,build}.log。新版 target/debug/version.dll 尚未部署或游戏内运行。

下一步：复测新版，读取同一失败位置的 type、message、enumerator 信息，再决定是否是集合变更需快照/受控重试，还是加载/类型适配问题。当前不能给出确证根因或保证完整导出。

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

当前状态：**第 0.6 节已记录完整流程验收，原任务可收尾。后续只有用户继续要求时再处理原始分片完整性、空表来源、输出命名或日志体积；不要把历史故障重新当作当前阻塞。**
