# DirNetBlock —— 目录级内核封网工具

一个 Windows 下的目录级联网封锁工具：选择任意目录，将目录下所有 `.exe` 加入 Windows 防火墙（内核 WFP/BFE 执行）的 Block 规则（出站 + 入站各一条），实现“内核级禁止联网”。支持多目录、系统网络工具封禁、子进程自动封禁、后台托盘运行与开机自启。

> 纯本地工具，不联网、不上传任何数据。封禁规则由 Windows 防火墙引擎（BFE/WFP）在内核态执行，不依赖本程序常驻（规则持久生效，程序退出后依然有效）。

---

## 功能特性

- **目录级批量封禁**：选择一个目录，扫描其中全部 `*.exe`（含子目录），每个程序生成出站+入站两条 Block 规则
- **多目录支持**：可同时添加多个目录统一管理，每个目录独立展示
- **系统网络工具封禁**：一键封禁 `curl / certutil / bitsadmin / mshta / wscript / cscript / ftp / telnet / nslookup / regsvr32 / rundll32 / wmic / net / net1 / msiexec / hh / odbcconf` 等 17 个可被“借刀”联网的系统工具（System32 + SysWOW64）
- **子进程自动封禁**：实时监控目标目录程序拉起的子进程（含跨层父子链），拉起即封，防止绕过
- **整目录一键解除**：选中目录即可一次性解除该目录下全部规则，无需逐个操作
- **开机自启**：注册开机自启，启动后自动恢复全部封禁规则并重启子进程监视
- **托盘后台运行**：关闭窗口后最小化到系统托盘继续运行，右键可退出
- **双模式**：图形界面（GUI）+ 命令行（CLI）
- **封禁前自动开启 Windows 防火墙**：无条件 `set on` + 复查 + 重试

## 工作原理

Windows 防火墙基于 BFE（Base Filtering Engine），在内核态（WFP，Windows Filtering Platform）执行过滤规则。本工具通过 `netsh advfirewall` 或 COM 接口（`HNetCfg.FwPolicy2`）为每个程序创建：

- 出站规则 `dir=out action=block`
- 入站规则 `dir=in  action=block`

规则创建后由系统内核强制执行，即使本程序退出、系统重启，规则依然生效。

规则命名：`DirNetBlock_<标签>_<文件名>_<SHA1哈希>`，标签区分 `OC`（出站）/ `IA`（入站）/ `ST`（系统工具）。

## 环境要求

- Windows 7 / 8 / 10 / 11（x64 优先，x86 亦可）
- .NET Framework 4.0+
- 需要**管理员权限**（程序含 UAC 清单，运行时会自动请求提权）

## 快速开始

### 方式一：使用预编译版本（Release）

从 [Releases](https://github.com/sunrise010605/DirNetBlock/releases) 下载最新版压缩包，解压后右键 `DirNetBlock.exe` → **以管理员身份运行**。

### 方式二：自行编译

需要 Windows + .NET Framework 4.0+（自带 `csc.exe`）。双击运行 `build.ps1`（或右键→使用 PowerShell 运行），产物输出到 `bin/` 目录：

```
bin\DirNetBlock.exe       图形界面版
bin\DirNetBlock_cli.exe   命令行版
```

### GUI 使用

1. 点击「添加目录…」选择要封禁的目录（可添加多个）
2. 勾选「同时封禁系统网络工具」和「子进程自动封禁」（默认开启）
3. 点击「封禁联网」→ 程序自动确保防火墙开启后开始封禁
4. 封禁完成后，列表按 **目录 / 系统工具 / 子进程** 分组展示每个程序的状态
5. 关闭窗口即最小化到托盘，后台继续运行；右键托盘图标可退出

## 命令行用法

```
DirNetBlock_cli.exe --block <目录> [目录2 ...]     封禁目录下所有 exe
DirNetBlock_cli.exe --block-hard <目录> [...]      封目录 + 系统工具 + 子进程监视（常驻）
DirNetBlock_cli.exe --unblock <目录>               解除该目录的全部规则
DirNetBlock_cli.exe --unblock-all                  解除全部规则
DirNetBlock_cli.exe --unblock-sys                  解除系统网络工具规则
DirNetBlock_cli.exe --autostart-on                 开启开机自启
DirNetBlock_cli.exe --autostart-off                关闭开机自启
DirNetBlock_cli.exe --list                         列出全部规则
```

## 目录结构

```
DirNetBlock/
├── src/
│   ├── DirNetBlock.cs        # 全部源码（单文件，GUI+CLI 共用）
│   ├── DirNetBlock.ico       # 程序图标
│   └── app.manifest          # UAC 管理员清单
├── docs/
│   ├── 使用说明.md           # 详细图文使用说明
│   └── 常见问题.md           # FAQ
├── build.ps1                 # 一键编译脚本（输出到 bin/）
├── LICENSE                   # MIT 开源协议
└── README.md
```

## 常见问题

**Q：封禁后程序还是能联网？**
先检查 Windows 防火墙是否被第三方安全软件（360、腾讯管家等）关闭。本工具封禁前会自动尝试开启防火墙；若被安全软件接管，需在安全软件中恢复防火墙。另外确认该程序没有被系统服务或驱动（如内核驱动联网）绕过——应用层封禁对驱动级联网无效。

**Q：杀毒软件报毒/误报？**
本工具需要管理员权限、操作防火墙规则、监控进程，行为特征与部分远程控制软件相似，可能被误报。请核对源码后添加信任。本项目完全开源，无任何恶意行为，不联网、不上传数据。

**Q：规则删除不干净？**
GUI 中选中规则所在行 → 「解除选中」，或使用命令行 `--unblock-all` 一次性清理。

**Q：如何完全卸载？**
点击「全部解除」删除所有规则 → 托盘菜单关闭「开机自启」→ 删除程序目录即可（无需安装，绿色软件）。

## 免责声明

本工具仅供**合法的网络管理与安全管理**用途（如家长控制、防止未授权外联、测试环境隔离等）。请勿用于侵害他人权益或违反法律法规的场景。使用者须自行承担使用后果，作者不对任何直接或间接损失负责。

## License

[MIT](LICENSE) © 2026 DirNetBlock contributors
