# HSR-OWNER

An all-in-one reverse-engineering and modding toolkit for **Honkai: Star Rail** on Windows. To keep things legit, all illicit cheat features have been completely stripped out. Once compiled, you'll get `StarRail.exe` (it already has the anti-anti-cheat built in).

> **Disclaimer** — This project is provided for research and educational purposes only. It is not affiliated with or endorsed by miHoYo / HoYoverse / Cognosphere. Using third-party tools against an online game may violate its Terms of Service and applicable local laws. Use at your own risk.

---

## OWNER

This runtime layer pretty much adapts itself to any new game version — the only crates you'll ever need to touch are `il2cpp`, `reflection`, `morax`, and `dumper`.

How do you update? Barely any manual work. `morax` is fully commented, so just hook up IDA Pro through its MCP server and let an AI agent take it from start to finish. Same with `dumper` — hand it to an AI too. All it needs is admin rights; just make sure it saves `dump.log`.

Once it's running, you get the whole client figured out: how gacha fetching works, how images and text get unpacked, all of it.

You can even mess with the game's data and build your own characters. NeonTeam's former reverse master made a real "OWN" once — go see it for yourself: [BiliBili](https://www.bilibili.com/video/BV1KpP8z9EtQ).

But he’s totally done with reverse engineering — he finds it way too easy, so it just got boring for him. That’s also why we can’t provide any of the anti-cheat stuff: we simply don’t have the chops to reverse those parts ourselves, and he never leaked enough info anyway, just leaving behind a single architecture diagram. Everything here is his old code (Just HSR is over 100k lines)—we basically just cleaned it up a bit and pushed it out. Honestly, it’s only because he got sick of RE that any of this got open-sourced in the first place (“I don’t care anything about Hoyo shit, if you want then do it”)... which is also why NeonTeam only open-sourced shit Private Servers before.

## Building

### 构建环境

- **Windows x86_64**。
- Visual Studio 的 **MSVC C++ 工具链和 Windows SDK**。
- **Rust nightly**（本项目启用了 Cargo artifact dependencies / `bindeps`）。
- **OpenCL.lib**（x64 导入库），其目录需要加入 `LIB`；运行前端还需要系统提供 `OpenCL.dll`。

本机已安装 Rust nightly，并配置了以下**当前用户级持久环境变量**，不覆盖原有条目：

| 变量 | 添加的目录 |
| --- | --- |
| `Path` | `%USERPROFILE%\.cargo\bin` |
| `LIB` | `%LOCALAPPDATA%\hermes\tools\opencl\lib` |

上述 OpenCL 路径是本机配置，其他机器应替换为自己的 x64 OpenCL SDK 库目录。本机的 `OpenCL.lib` 由 Khronos 官方 OpenCL 导出定义通过 MSVC `lib.exe` 生成，仅用于链接，并不是 OpenCL 运行库。

环境变量配置后，请重新打开终端；如果终端来自 IDE 或 Hermes，也需要重启对应应用。已有 PowerShell 会话可以执行以下命令加载新增配置：

```powershell
$cargoBin = Join-Path $env:USERPROFILE '.cargo\bin'
$env:Path = "$cargoBin;$env:Path"
$userLib = [Environment]::GetEnvironmentVariable('LIB', 'User')
$env:LIB = (@($env:LIB, $userLib) | Where-Object { $_ }) -join ';'
```

### Release 构建

在项目根目录执行（PowerShell / Git Bash 都适用）：

```text
cargo +nightly build --release --locked
```

`--locked` 使用现有 `Cargo.lock`，不会自动更新依赖版本。首次构建会下载依赖并进行优化，后续构建复用缓存。

主要产物：

- `target/release/StarRail.exe`：主程序，已内嵌前端。
- `target/release/version.dll`：后端 DLL。

### 独立前端

完整构建成功后，前端可执行文件位于 Cargo 的 artifact dependency 目录。用以下 **PowerShell** 命令将最新产物复制到 `target/release/hsr-frontend.exe`：

```powershell
$frontend = Get-ChildItem 'target/release/build/frontend/*/artifact/bin/hsr_frontend.exe' |
    Sort-Object LastWriteTime -Descending |
    Select-Object -First 1
if (-not $frontend) { throw '前端产物不存在，请先完成 Release 构建。' }
Copy-Item -LiteralPath $frontend.FullName -Destination 'target/release/hsr-frontend.exe' -Force
```

### 常见构建问题

- 找不到 `cargo`：确认 `%USERPROFILE%\.cargo\bin` 已加入 `Path`，并重开终端。
- `LNK1181: 无法打开输入文件 OpenCL.lib`：确认 `LIB` 包含实际存放 x64 `OpenCL.lib` 的目录。若从 Visual Studio 开发者终端构建，需确认其初始化脚本未覆盖此配置；必要时使用上面的 PowerShell 命令重新加载用户 `LIB`。
- 构建成功只表示编译和链接通过，不表示游戏内功能已完成运行验证。

## NeonTeam

- [Discord](https://discord.gg/RQfpnaPtRV) — official discord
- [YouTube](https://www.youtube.com/@neon7team) — YouTube

## Credits

- [gpui](https://github.com/zed-industries/zed) and [gpui-component](https://github.com/longbridge/gpui-component) — frontend UI framework
- [texture2ddecoder](https://github.com/UniversalGameExtraction/texture2ddecoder) (vendored, MIT/Apache-2.0) — block-compressed texture decoding
- [HoYo.Gacha](https://github.com/lgou2w/HoYo.Gacha) — gacha record fetching via Chromium disk-cache reading (reference for `crates/gacha`)
- Oodle (`oo2core_win64.lib`) — asset decompression (statically linked, © Epic Games/RAD Game Tools)

## License

This project is licensed under the [MIT License](LICENSE).
