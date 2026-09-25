# Proto 当前问题：GateServer 字段重名

更新：2026-09-25。Proto/WriteTo 已在游戏内完成，用户确认前端显示 Finished；当前只需继续处理产物可用性问题。

## 已确认的证据

游戏版本 `OSBETAWin4.5.54`，输出 `D:/StarRail_Beta/DUMP/StarRail.proto`。前端同款 `protox::compile`（0.9.1）拒绝解析：`camel-case name of field 'grid_fight_game_ref_color_header_key' conflicts with field 'grid_fight_game_ref_color_header_key'`。

GateServer 内发现两组完全重复的字段名称：

| 字段名 | tag / 当前文件行号 |
| --- | --- |
| grid_fight_game_ref_color_header_key | 14 / 32017；340 / 32032 |
| asb_relogin_desc | 8 / 32011；1239 / 32063 |

`packetIds.json` 可解析，1083 项均引用存在的顶层消息；`cs-type-infos.json`、`sc-packet-handlers.json` 也可解析。尚未修改业务代码或导出文件来处理重名，名称错误的具体来源未确认。

## 下一步

1. 追踪 `crates/dumper/src/proto/handler_nt/handler/gate_server/parse_gate_server.rs` 的名称恢复，以及映射合并、`proto/output.rs` 的应用和输出逻辑。
2. 修复时保留真实字段 tag、类型和布局，检查名称映射对其他消息、普通字段、oneof、嵌套消息和各 Proto 模式的影响。不能删除冲突字段，也不能仅靠添加后缀就宣称语义正确。
3. 用前端相同解析器验证实际产物，复核包 ID 引用，完成相关回归和必要的游戏内复测。

已有本地校验工具：`target/proto-validation/disasm/src/bin/validate_output.rs`；摘要：`target/proto-validation/success-output-audit.json`。两者位于忽略目录，可能不随仓库迁移。

## 验证边界

- 本轮只验证 WriteTo 游戏内流程；其他三种模式、新版 GUI 的游戏崩溃断线行为未做游戏内验收。
- 命名/命令号覆盖仍有限：日志缺少 nt field、FightGame::Send、XLua ObjectTranslator 及枚举名称恢复所需的元数据；响应扫描有 80 个未匹配候选，请求映射有 1 个命令号冲突。流程成功不代表所有协议字段和映射语义正确。
- 接续时重新核对工作区与暂存状态，以实际源码为准。
