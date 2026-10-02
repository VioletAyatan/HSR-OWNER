# Proto 当前问题：剩余命名与语义核实

更新：2026-10-02。当前证据来自 `D:/StarRail_Beta/DUMP` 的 `OSBETAWin4.6.51`，已通过 WriteTo 运行导出及前端同版解析；以下只保留未完成范围和必要复验边界。

## 未完成事项

1. 其他 Proto 模式仍需各自做游戏内验证。
2. 当前 WriteTo 产物仍有 3,581 个混淆消息名、8,359 处混淆字段、219 个混淆枚举名。继续查当前客户端语义证据，不能把离线解析通过等同于原始名称完全还原。
3. 既有按 tag 命名和消息顺序分类模板的业务语义尚未逐项核实。当前运行日志中，`BattleAvatar` 区间消息数预期 20、实际 21，`CmdAvatarType` 区间枚举数预期 4、实际 8，消息数预期 56、实际 100，`BuffInfo` 区间消息数预期 6、实际 5；这些分类源码及模板与原仓库 `11cd291` 一致。需要从当前调用关系重新核实区间和语义，不能只修改数量后按顺序套名。唯一类型匹配也只是模板候选，解析通过不能证明字段含义正确。
4. 同一消息内恢复候选发生名称冲突时保留原名，结合 `[Proto Names]` 日志定位。当前 GateServer tag 3、1595 的两个候选同名，最终保持原名 `AJHCNDDFMJO`、`MOGCHAKOEJH`；不能靠数字后缀冒充语义。SC handler 的 `GridFightAugmentActionInfo`、`SnapShot` 是既有辅助类键，未在 Proto 定义；另 12 个键指向已声明枚举，仍需核实 handler 分类是否应只保留消息。

当前已证直接复制候选只剩 `NBKKABHMMPP` tag 1082：`OACBLHIIIEH` 经 `PixAirModule::_HandleBeforeEnterGameSettle` 复制到明文属性 `Score`，但同一消息 tag 6 已命名为 `score`，最终保持原名。tag 6 的名字来自全局访问器映射，当前来源证明为其他业务类 `AAINKPKFDFF`、`DAIBOFDLEBF` 各自的 own `get_Score/set_Score`，并非此 Proto 自身的明文名称。tag 6 自身 getter/setter 仍混淆；完整 caller 的普通分支将该字段传给 `PixAirGameSettlementData::Create(Boolean,UInt32×7)` 的第二参数（`0xE420D80`），工厂普通分支将第二参数写入返回对象 `+32`，与 `TotalScore` own getter/setter（`0xE420F80/0xE420F90`）一致，但 IFix 分支尚未证明相同关系。

该 caller `0xE4299D0` 的尾跳 `0xE429BD9 -> 0x16C2F000` 尚未通过完整 frame proof：`lea r8,[rbp-0x10]` 传出局部地址，不能仅凭已支持的受限 RBP 栈别名、epilogue 或局部 load/CALL 放行。当前 4/8 字节扫描分别观察到 5/1 个调用参数，但 `rejected_paths=1`，最终 `proven_call_arguments=0`；没有捕获 tag 6 的工厂 ParameterInfo 名称，其他参数的诊断不能证明本参数也为空。下一步须补地址逃逸与工厂所有返回路径证据，再决定是否允许消息内语义覆盖；不能用数字后缀或直接覆盖既有名字消除冲突。定位入口为 `target/settlement-name-recovery/factory-proof-review.json`、`ghidra-mcp-review.json` 和当前 `proto-global-field-name-evidence.json`。已恢复消息显示名可能变化，后续候选须按原始 Obf 标识和 tag 核对，不能仅按 `message <原名>` 搜索而认定类型丢失。

## 复验入口与边界

当前已验收构建、客户端哈希、运行标记及产物验收位于 `target/enum-parameter-validation/runtime-manifest.json`、`runtime-acceptance.json` 与 `sourceparse-validation.json`。`run-runtime.py` 和 `verify-setter-runtime.py` 是复验入口；每次导出前另存原始产物，使用新的运行标记与事件文件，不能用上一轮 `dumper_finished` 或旧产物充当新验收。验收要求保留所有已有明文及 wire 布局，必须实际覆盖移位 Proto 参数和附加枚举参数，核对完整实际签名、参数类型证明与同轮 method decision，并复查网关内容命名。setter 离线证据为本目录 `setter-offline-replay/setter-call-replay.json`，解析使用同版 sourceparse-validator。其他 Proto 模式尚未游戏内验收。

源码入口均在 `crates/dumper/src/proto`：`mod.rs` 的最终映射接入，`names.rs` 的名称应用与冲突检查，`sync_fields.rs` 的业务成员证据，`sync_property_name.rs` 的属性/访问器名称来源，`sync_declared_fields.rs` 与 `sync_constructor.rs` 的实例字段和构造函数绑定，`sync_scan.rs` 的复制数据流，`native_pe.rs`、`native_flow.rs` 与 `native_switch.rs` 的函数/控制流证据，`logic_nt` 的模板。

原仓库参考：[Negligible-price/HSR-OWNER，11cd291](https://github.com/Negligible-price/HSR-OWNER/tree/11cd2913080ab4a573ac74f10f2b8ebcf984a9d6)。当前导出中未找到旧 `Proto*_cast` 路径；参数表的可唯一取值项多数已在产物命名中使用，旧字段模板回放没有新增仍混淆字段候选。对照入口为 `target/upstream-reference-tests/assessment.json`，其中记录直接执行原命名模块、当前原文件与回放输出的同版解析对照，以及适配边界。

字符串解密的已检查原生函数与原仓库公式、常量一致，但不能据此认定全部元数据格式未变。原 Morax 的完整文件加载实际失败在字符串解密之前：原 `metadata_registration + 0x68` 指针槽对应当前磁盘 RVA `0x4B68150`，读出的 u64 为 0。仍需区分表位置变化和运行时初始化，不能把此错误直接归为密钥改变，也不能把独立 Morax/Asm 模式的失败作为当前 WriteTo 名称残留的原因。定位入口为 `target/upstream-morax-stage/stage-result.json`。

当前版本 14,072 个 Int32 字段常量中有 13,822 个常量名混淆；250 个明文 FieldNumber 常量只对应已经可读的字段，不能带来新增恢复。普通 getter/XLua 注册路径的已确认字段也均可读；63 个找到的明文 Proto Descriptor getter 返回 null。这些结果只限定当前已检查形态，不证明其他代码路径没有明文。

当前已验收业务复制 collector 覆盖实例方法和单 Proto 参数构造函数；普通实例方法须恰有一个实际当前 Proto Message 参数，位于 managed ordinal 0/1/2，其余仅接受实际类型缓存确认的 primitive scalar 或交叉证明底层整数类型与 own `value__` 的封闭枚举。引用、结构体、byref、指针等附加参数仍拒绝，Proto 栈参数仍未证明。普通方法返回类型须通过标量/void 或闭合托管引用 ABI 检查；构造函数经 native API 绑定，不能把 `MonoCMethod` 当作 `MonoMethod`。支持 bool、32/64 位整数，以及运行时类型完全一致的枚举和引用。属性必须属于同一声明类，getter 返回类型、setter 参数类型、属性类型和实际访问 offset 一致；仅当属性元数据名混淆时，才从同一 PropertyInfo 的非泛型 getter/setter 取严格一致的明文 `get_X`/`set_X`，索引器和缺失访问器不放行。声明字段还须核实 native handle、类型、实例范围与所有字段的重叠关系，不能填补冲突属性占用的槽。函数范围取自当前 PE 与声明方法入口，数组长度受真实 managed allocation 约束。候选按原始消息名和 tag 隔离，冲突或已证后续覆盖回退原名，只补仍混淆的字段；已有明文记为 `preserved-existing-name`。例如 Equipment 同时用于通用装备与 Aether 业务，不能仅凭后者的业务别名覆盖已有 `belong_avatar_id`。证据写入 `DUMP/proto-sync-field-evidence.json`，包含名称来源证明以及按当次候选/属性枚举规模记录、统一写出的 `methods_decisions`、`property_decisions`，用于定位早退门槛。

SSE 仅接受 legacy MOVQ、MOVDQU/MOVDQA、MOVUPS/MOVAPS 的位复制及 PSHUFD，按独立 4 字节 lane 跟踪，不把相邻字段当成 64 位字段；未知 lane 及索引写入仍参与覆盖拒绝。函数尾部 switch 表须有实际 32 位索引准备与 JA/JAE 范围守卫，表范围属于完整函数且连续，各目标均为实际指令边界，其他分支或 EH 续接不能进入守卫内部。栈暂存、类型转换、浮点复制、容器构造和 oneof 共用 offset 仍需分别建立证据；引用直接复制不等于支持容器转换。

异常控制流尚未支持其他版本的 runtime helper profile、非零 unwind action、未知指令与其他 catch 栈帧。当前运行仍拒绝四个 caller：`NDGFICEEICD::PAGKOAEOLKA`（`0xC268A70`，索引使用尚未支持的 ROR；表实际落在邻接 PE 函数内）、`JIGBEFNLENA::ALJIOCDBMKO`（`0xB8DAE30`，表在邻接 PE 函数内）、`HJCHNOIBJCA::PDIJKIJOCBP`（`0x169EAD50`，解析另一函数的尾部数据时在 `0x169EB26E` 报无效指令；不在 caller 本体内）、`SwordTrainingGameInstance::Update`（`0xEA4B090`，范围守卫内夹有尚未支持的指令）。复核未找到这四者与明文 own 成员匹配的直接复制候选；前三个 Proto 分别剩 3、4、1 个混淆字段，Sword 的 `detail`、`source` 字段名已明文，混淆的是类型名。定位证据在 `target/recovery-expansion/live-flow-remaining-review.json`；后续须新增字段语义或函数/表所有权证据，不能仅为消除日志而扩大 CFG 规则。

终止链仍须逐函数验证完整 PE 范围、无本地 EH、所有普通出口到达当前 live IAT 绑定的 `RaiseException` 且 flags=1；caller 须通过已审查 MSVC FH3 adapter、TLS helper、metadata consumer 的完整代码 profile，以及实际 EH 表和 catch 的栈/寄存器恢复检查。正缓存每次计划重新检查字节、unwind 与 live IAT。标准 Windows AMD64/MSVC 运行时和一次扫描期间稳定的映射是语义边界，未证明自定义 handler/context 修改；不能因某条异常路径可恢复而放行其他形态。

异常控制流离线复验（当前 DLL 和捕获输入必须逐字节一致；只运行显式指定的忽略测试）：

```powershell
$env:HSR_PROTO_FLOW_DLL = 'D:/StarRail_Beta/GameAssembly.dll'
$env:HSR_PROTO_FLOW_INPUT = 'D:/Projects/HSR-OWNER/target/proto-name-pilot/runtime-prefix-native-input.json'
$env:HSR_PROTO_FLOW_BASELINE = 'D:/Projects/HSR-OWNER/target/proto-name-pilot/runtime-prefix-native-output.json'
$env:HSR_PROTO_FLOW_OUT = 'D:/Projects/HSR-OWNER/target/native-flow-replay'
cargo test -p dumper --lib --offline proto::native_flow::native_flow_replay::replay_existing_native_methods -- --ignored --nocapture
```

返回类型不在已确认 ABI 范围的候选暂不扫描，避免隐藏返回缓冲区改变 owner/Proto 参数位置。当前仍拒绝 18 个返回类型候选，包括枚举和其他值类型；须从实际元数据与原生调用约定补证，不能只凭类型名放行。`BIDDFDEAEGB::PHADIIJCOOE(Proto.EntitySnapshot)` 的具体本体通过 EAX 返回计算结果，但没有复制到明文 own 成员，放行该样本也无新增命名证据；不能把它推广成全部值类型返回规则。没有 GameAssembly 原生地址的接口或其他候选仍保持有界拒绝。后续优先沿仍混淆字段的客户端使用点补证据。

反射参数数组需要按真实元素类型验证：当前客户端的空参数数组是 `MonoParameterInfo[]`，非空公开返回为 `ParameterInfo[]`。接受合法派生数组时仍检查 SZArray 类身份、rank/bounds、真实 allocation 和逐项元素类型，不能把空数组当作任意数组放行。实际形态统计包含在 Sync 证据文件中。

setter 调用仅接受真实业务 receiver 的直接 CALL、参数槽 1 的已证 Proto 来源、唯一 own 属性 setter RVA 与精确 runtime type；直接 store 和 setter 调用的后续覆盖均参与拒绝。非完整 CFG 的调用参数不用于命名。已验证尾跳只证明当前完整 PE 函数内已保存寄存器与栈帧恢复、无未知栈写入及目标为当前声明方法和 PE 的精确入口，不证明 IFix callee 行为。工厂参数名称只作诊断，不应用于字段名；共享原生 body 须按当次全部方法定义中不同 native handle 判为歧义，不能使用 RVA 字典最后覆盖的单个 handle 冒充唯一 callee。

热修复分支可能改写实际业务行为，collector 只证明当前原生实现的复制关系，业务属性名也不能保证历史 Proto 的准确拼写；旧版明文 Proto 仅作结构参照。

运行已有产物的离线验收：

```powershell
$env:HSR_PROTO_REPLAY_DIR = 'D:/StarRail_Beta/DUMP'
cargo test -p dumper --lib --offline proto::replay_tests::replay_dump -- --ignored --nocapture
```

此测试保留原始文件，输出 `StarRail.deobfuscated.proto`、`packetIds.deobfuscated.json`、`proto-deobfuscation-validation.json`，用前端同款 `protox 0.9.1` 解析，核对 tag、类型引用、offset、嵌套/oneof 布局、枚举数值、元数据和包 ID 引用。存在同目录 Script/Methods 与父目录 DLL 时，另外逐函数读取当前 PE 并恢复 XLua 枚举，证据写入 `proto-xlua-enum-validation.json`；其中 accepted 仅指候选，最终接受数量以主验证摘要的枚举前后计数为准。

回放重用既有类型候选，按旧 `nt.txt` 的写入顺序识别初始字段种子，并重新执行保守字段规则；它不能复验游戏内反射、反汇编、网络取值和重试。原始产物已恢复字段的原名只有唯一反向映射时可重建，无法重建的边界记入摘要。`nt.txt` 保存候选映射，最终输出可以因局部冲突拒绝候选；判断可用性应以最终 Proto 和包 ID 为准。

全部运行验收与语义核实完成后，清理本文件对应事项及 AGENTS.md 引用。
