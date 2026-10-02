# Proto 当前问题：剩余命名与语义核实

更新：2026-10-02。当前证据来自 `D:/StarRail_Beta/DUMP` 的 `OSBETAWin4.6.51`。名称输出链、GateServer 字段冲突、XLua 枚举与业务 Sync 整数字段恢复（含 SSE 复制、已证非返回调用及支持的 FH3 异常续接）已通过 WriteTo 运行导出及前端同版解析；以下只保留未完成范围。

## 未完成事项

1. 其他 Proto 模式仍需各自做游戏内验证。
2. 当前 WriteTo 产物仍有 3,581 个混淆消息名、8,659 处混淆字段、219 个混淆枚举名。继续查当前客户端语义证据，不能把离线解析通过等同于原始名称完全还原。
3. 既有按 tag 命名和消息顺序分类模板的业务语义尚未逐项核实。当前运行日志中，`BattleAvatar` 区间消息数预期 20、实际 21，`CmdAvatarType` 区间枚举数预期 4、实际 8，消息数预期 56、实际 100，`BuffInfo` 区间消息数预期 6、实际 5；这些分类源码及模板与原仓库 `11cd291` 一致。需要从当前调用关系重新核实区间和语义，不能只修改数量后按顺序套名。唯一类型匹配也只是模板候选，解析通过不能证明字段含义正确。
4. 同一消息内恢复候选发生名称冲突时保留原名，结合 `[Proto Names]` 日志定位。当前 GateServer tag 3、1595 的两个候选同名，最终保持原名 `AJHCNDDFMJO`、`MOGCHAKOEJH`；不能靠数字后缀冒充语义。SC handler 的 `GridFightAugmentActionInfo`、`SnapShot` 是既有辅助类键，未在 Proto 定义；另 12 个键指向已声明枚举，仍需核实 handler 分类是否应只保留消息。

## 复验入口与边界

源码入口：`proto/mod.rs` 的最终映射接入，`proto/names.rs` 的名称应用与冲突检查，`proto/sync_fields.rs` 的业务属性证据，`proto/sync_scan.rs` 的整数数据流，`proto/native_pe.rs` 与 `proto/native_flow.rs` 的 PE/异常控制流证据，`proto/logic_nt` 的模板。

原仓库参考：[Negligible-price/HSR-OWNER，11cd291](https://github.com/Negligible-price/HSR-OWNER/tree/11cd2913080ab4a573ac74f10f2b8ebcf984a9d6)。当前导出中未找到旧 `Proto*_cast` 路径；参数表的可唯一取值项多数已在产物命名中使用，旧字段模板回放没有新增仍混淆字段候选。对照入口为 `target/upstream-reference-tests/assessment.json`，其中记录直接执行原命名模块、当前原文件与回放输出的同版解析对照，以及适配边界。

字符串解密的已检查原生函数与原仓库公式、常量一致，但不能据此认定全部元数据格式未变。原 Morax 的完整文件加载实际失败在字符串解密之前：原 `metadata_registration + 0x68` 指针槽对应当前磁盘 RVA `0x4B68150`，读出的 u64 为 0。仍需区分表位置变化和运行时初始化，不能把此错误直接归为密钥改变，也不能把独立 Morax/Asm 模式的失败作为当前 WriteTo 名称残留的原因。定位入口为 `target/upstream-morax-stage/stage-result.json`。

当前版本 14,072 个 Int32 字段常量中有 13,822 个常量名混淆；250 个明文 FieldNumber 常量只对应已经可读的字段，不能带来新增恢复。普通 getter/XLua 注册路径的已确认字段也均可读；63 个找到的明文 Proto Descriptor getter 返回 null。这些结果只限定当前已检查形态，不证明其他代码路径没有明文。

业务 Sync collector 跟踪实例 `Sync` 及 `Sync` 后接大写字母的方法，方法必须只有一个实际 Proto 参数，返回类型须通过标量/void ABI 检查；接受 Int32/UInt32 直接复制。明文属性必须属于同一业务声明类，getter 返回类型、setter 参数类型、属性类型和实际访问 offset 全部一致。函数范围取自当前 PE 与声明方法入口，数组长度受真实 managed allocation 约束。候选按原始消息名和 tag 隔离，冲突或已证后续覆盖回退原名。最终命名先验证既有输出，Sync 只补仍混淆的字段，已有明文记为 `preserved-existing-name`。例如 Equipment 同时用于通用装备与 Aether 业务，不能仅凭后者的业务别名覆盖已有 `belong_avatar_id`。证据写入 `DUMP/proto-sync-field-evidence.json`。

SSE 仅接受 legacy MOVQ、MOVDQU/MOVDQA、MOVUPS/MOVAPS 的位复制及 PSHUFD，按独立 4 字节 lane 跟踪，不把相邻字段当成 64 位字段；未知 lane 及索引写入仍参与覆盖拒绝。栈暂存、类型转换、bool/int64、字符串、容器和 oneof 共用 offset 不在当前规则内，需分别建立类型与数据流证据。

异常控制流尚未支持其他版本的 runtime helper profile、非零 unwind action、未知指令与其他 catch 栈帧。当前 `PlayerDiaryItemData::Sync` 在 RVA `0xE4BC220`、`RogueTournHandbookData::SyncUpdate` 在 `0xE8D0E96` 遇到无效指令，`GridFightBattleSttInfo::Sync` 的 EH 栈帧尚不支持；均保留普通调用续接边。后续先核实实际 PE 函数边界和对应反汇编，再补充明确形态。终止链仍须逐函数验证完整 PE 范围、无本地 EH、所有普通出口到达当前 live IAT 绑定的 `RaiseException` 且 flags=1；caller 须通过已审查 MSVC FH3 adapter、TLS helper、metadata consumer 的完整代码 profile，以及实际 EH 表和 catch 的栈/寄存器恢复检查。正缓存每次计划重新检查字节、unwind 与 live IAT。标准 Windows AMD64/MSVC 运行时和一次扫描期间稳定的映射是语义边界，未证明自定义 handler/context 修改；不能因某条异常路径可恢复而放行其他形态。

异常控制流离线复验（当前 DLL 和捕获输入必须逐字节一致；只运行显式指定的忽略测试）：

```powershell
$env:HSR_PROTO_FLOW_DLL = 'D:/StarRail_Beta/GameAssembly.dll'
$env:HSR_PROTO_FLOW_INPUT = 'D:/Projects/HSR-OWNER/target/proto-name-pilot/runtime-prefix-native-input.json'
$env:HSR_PROTO_FLOW_BASELINE = 'D:/Projects/HSR-OWNER/target/proto-name-pilot/runtime-prefix-native-output.json'
$env:HSR_PROTO_FLOW_OUT = 'D:/Projects/HSR-OWNER/target/native-flow-replay'
cargo test -p dumper --lib --offline proto::native_flow:: -- --include-ignored --nocapture
```

返回类型不在已确认 ABI 范围的候选暂不扫描，避免隐藏返回缓冲区改变 owner/Proto 参数位置。当前 `GridFightForgeInfo::SyncAdd`、`SyncUpdate` 返回 `GridFightForgeItemData`，`ChenLingBattleGameSession::SyncHandCard` 返回 `List<HandCard>`；后续须从实际元数据与原生调用约定补证，不能只凭类型名放行。没有 GameAssembly 原生地址的接口或其他候选仍保持有界拒绝。后续优先沿仍混淆字段的客户端使用点补证据。

反射参数数组需要按真实元素类型验证：当前客户端的空参数数组是 `MonoParameterInfo[]`，非空公开返回为 `ParameterInfo[]`。接受合法派生数组时仍检查 SZArray 类身份、rank/bounds、真实 allocation 和逐项元素类型，不能把空数组当作任意数组放行。实际形态统计包含在 Sync 证据文件中。

热修复分支可能改写实际业务行为，collector 只证明当前原生实现的复制关系，业务属性名也不能保证历史 Proto 的准确拼写；旧版明文 Proto 仅作结构参照。

运行已有产物的离线验收：

```powershell
$env:HSR_PROTO_REPLAY_DIR = 'D:/StarRail_Beta/DUMP'
cargo test -p dumper --lib --offline proto::replay_tests::replay_dump -- --ignored --nocapture
```

此测试保留原始文件，输出 `StarRail.deobfuscated.proto`、`packetIds.deobfuscated.json`、`proto-deobfuscation-validation.json`，用前端同款 `protox 0.9.1` 解析，核对 tag、类型引用、offset、嵌套/oneof 布局、枚举数值、元数据和包 ID 引用。存在同目录 Script/Methods 与父目录 DLL 时，另外逐函数读取当前 PE 并恢复 XLua 枚举，证据写入 `proto-xlua-enum-validation.json`；其中 accepted 仅指候选，最终接受数量以主验证摘要的枚举前后计数为准。

回放重用既有类型候选，按旧 `nt.txt` 的写入顺序识别初始字段种子，并重新执行保守字段规则；它不能复验游戏内反射、反汇编、网络取值和重试。原始产物已恢复字段的原名只有唯一反向映射时可重建，无法重建的边界记入摘要。`nt.txt` 保存候选映射，最终输出可以因局部冲突拒绝候选；判断可用性应以最终 Proto 和包 ID 为准。

全部运行验收与语义核实完成后，清理本文件对应事项及 AGENTS.md 引用。
