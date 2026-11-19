# 项目状态与开发台账

更新日期：2026-11-19。信息来源为仓库当前代码、配置、测试和 GitHub Actions 工作流。应用版本：`0.3.1`。

## 1. 项目目标

提供能够以 RustDesk 协议进行连接的无图形界面终端与文件传输工具，包含 Linux 被控端和跨平台命令行客户端；尽量兼容原版 RustDesk 客户端及 hbbs/hbbr。保留严格的账户权限界限，并为只有 root 账户的嵌入式 Linux 提供私用模式。

项目不包含桌面图像、音视频、图形界面或输入设备远程控制。

## 2. 已有功能

| 范围 | 当前实现 | 代码入口 |
| --- | --- | --- |
| Linux 被控端 | TCP 监听、设备身份、加密握手、连接类型分派、并发控制 | [server.py](../rdheadless/server.py) |
| CLI 客户端 | 终端、目录列表、上传、下载、直连和 TCP 中继 | [cli.py](../rdheadless/cli.py)、[client.py](../rdheadless/client.py) |
| 私用模式 | 使用服务账户及其文件权限；允许 root；必须验证连接密码 | [server.py](../rdheadless/server.py) |
| 公用模式 | root 服务验证 PAM，独立工作进程切换到用户 UID、GID 和附属用户组 | [auth.py](../rdheadless/auth.py)、[worker.py](../rdheadless/worker.py) |
| 官方 GUI 文件传输认证方案 | 在虚拟目录重命名两个条目后进入 `LOGIN` 触发 PAM；尚待真实 GUI 验证 | [file_login.py](../rdheadless/file_login.py) |
| 文件系统访问 | 目录读取、上传、下载、重命名、删除及目录操作；目录描述符和符号链接限制 | [files.py](../rdheadless/files.py) |
| 受限端口转发 | 关闭为默认值；仅允许配置列表中的本机 TCP 端口 | [server.py](../rdheadless/server.py)、[worker.py](../rdheadless/worker.py) |
| hbbs/hbbr | UDP 注册、TCP 协调及 TCP 中继，已有本地模拟联调 | [rendezvous.py](../rdheadless/rendezvous.py) |
| OpenWrt | `ash`、`procd`、musl 动态库及 root 私用模式源码安装 | [openwrt](../openwrt/)、[verify_openwrt.sh](../scripts/verify_openwrt.sh) |
| 自动构建 | Linux x86-64/ARM64、macOS x86-64/ARM64、Windows x86-64 和 OpenWrt 源码包 | [工作流](../.github/workflows/) |

## 3. 已执行的验证

| 环境 | 方式 | 已验证内容 | 参考文件 |
| --- | --- | --- | --- |
| Linux（普通用户） | pytest，真实 socket 及模拟 RustDesk 协议 | 终端、文件操作、连接密码、身份固定、hbbs/hbbr 模拟 | [测试目录](../tests/) |
| Linux（root） | pytest，模拟 PAM，真实 Linux UID 切换 | 公用模式登录、文件传输认证前的限制、失败重试、权限隔离、私用模式 root | [test_public_e2e.py](../tests/test_public_e2e.py)、[test_openwrt_private.py](../tests/test_openwrt_private.py) |
| Windows、macOS | CI 中安装依赖、导入 CLI、协议消息往返检查 | 命令行模块与协议模块可以在对应系统运行 | [verify.yml](../.github/workflows/verify.yml) |
| Linux 单文件程序 | PyInstaller 构建后运行测试 | 可执行文件启动、实际 socket 连接、认证、文件操作 | [smoke_bundle.py](../scripts/smoke_bundle.py) |
| OpenWrt 25.12-SNAPSHOT x86-64 官方容器 | musl 系统内安装源码并启动服务 | 系统依赖、root 文件传输、BusyBox `ash` 终端 | [openwrt_smoke.py](../scripts/openwrt_smoke.py) |

以上验证没有覆盖真实官方 GUI、真实公网 hbbs/hbbr 或 OpenWrt 其他 CPU 架构的实体设备。与这些环境有关的功能需要单独记录测试结果。

## 4. 版本记录

| 日期 | 版本 | 主要内容 |
| --- | --- | --- |
| 2026-11-14 | `v0.3.0` | Linux 被控端、跨平台 CLI、测试及 GitHub Actions 构建发布 |
| 2026-11-14 | `v0.3.1` | 私用模式 root 支持、OpenWrt 源码安装、musl 和 BusyBox 测试 |
| 2026-11-19 | 文档维护 | 建立架构、开发、安全、协议、运维、发布与交接文档；应用版本保持 `0.3.1` |

发行记录以 [GitHub Releases](https://github.com/HSOS6Miyabi/rustdesk-headless-cli/releases) 和对应标签为准。

## 5. 已确定的设计

1. 保持对官方 RustDesk 客户端的协议兼容目标，不要求修改官方客户端。
2. 私用模式保留 RustDesk 共享连接密码，终端和文件操作继承服务账户权限；只有 root 的嵌入式系统可以使用 root。
3. 公用模式由 root 运行服务，Linux 账户认证通过 PAM；认证后的终端与文件操作在相应用户进程内执行。
4. 普通连接密码使用稳定的设备级 `salt` 和每次连接更新的 `challenge`，兼顾挑战响应与客户端“记住密码”功能。PAM 身份不随连接密码保存。
5. 公用模式的文件传输连接分别认证；不依据客户端声称的 ID、来源地址或另一个连接的认证结果直接授予访问权限。
6. 端口转发只允许管理员明确配置的本地 TCP 目标，默认关闭；公用模式不额外要求 PAM。

具体安全理由及风险见 [认证与安全设计](SECURITY_MODEL.md)。

## 6. 后续工作与完成标准

| 优先级 | 工作 | 完成标准 |
| --- | --- | --- |
| 高 | 使用未经修改的官方 RustDesk GUI 联调 | 在固定版本的桌面客户端上分别完成管理员终端、文件传输认证、上传下载、重连和记住密码测试，保留版本号及实际结果 |
| 高 | 真实 hbbs/hbbr 联调 | 使用官方 hbbs/hbbr 的独立测试实例，验证注册、加密身份、TCP 中继及服务端重连，不记录真实服务器密钥 |
| 高 | 安全审查与故障注入 | 检查 PAM 会话、工作进程权限、认证目录、文件路径操作、异常断开和请求超时；增加相应自动化测试 |
| 高 | 端口转发真实数据收发测试 | 使用本机测试服务验证双向传输、连接断开、权限限制及错误处理 |
| 中 | UDP/KCP、WebRTC 和 WebSocket/WSS 支持 | 分别实现协议处理及回退行为，并完成官方客户端/服务器互操作测试 |
| 中 | 适配更多 OpenWrt CPU 架构 | 在至少一个 ARM/MIPS 等实际目标设备或对应架构运行环境中执行安装、加密连接与文件传输测试 |
| 中 | 评估嵌入式资源占用 | 记录启动内存、并发会话、网络断连恢复、长期运行、磁盘占用及 Python 依赖大小 |
| 中 | 完善公开发布与升级 | 检查发布文件、散列值、升级保留配置和服务重启步骤，形成可重复执行的维护记录 |

工作完成后应更新本表及测试说明，记录具体版本和环境；不要将推测写成已验证结果。

## 7. 交接维护记录

接手人员应按 [交接检查表](HANDOFF.md) 核实仓库权限、部署环境、身份文件备份、PAM 配置、CI 与 Release 权限，以及安全事项。服务器地址、账号和密码只通过组织认可的安全方式交接，不写入此台账。
