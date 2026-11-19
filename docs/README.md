# 项目文档与交接入口

本文档目录面向接手开发、部署维护、安全审查和发布工作的人员。请先阅读项目根目录的 [README](../README.md)，了解实际提供的功能和安装条件。

## 阅读顺序

| 文档 | 用途 |
| --- | --- |
| [项目台账](PROJECT_LEDGER.md) | 当前版本、已经验证的功能、未完成事项、维护优先级和开发记录 |
| [系统架构](ARCHITECTURE.md) | 主要模块、连接处理、进程权限和文件操作的执行过程 |
| [协议与兼容性](PROTOCOL_COMPATIBILITY.md) | RustDesk 消息、支持的传输方式、官方客户端兼容范围和联调步骤 |
| [认证与安全设计](SECURITY_MODEL.md) | 信任边界、私用模式、公用模式 PAM、文件传输登录及安全注意事项 |
| [开发与测试](DEVELOPMENT.md) | 环境配置、测试命令、代码修改位置和测试覆盖情况 |
| [部署与运维](OPERATIONS.md) | Linux、OpenWrt 的配置、启动、升级、备份和故障排查 |
| [发布与持续集成](RELEASING.md) | GitHub Actions、版本管理、发布文件和校验流程 |
| [交接检查表](HANDOFF.md) | 接手前必须核实的事项、权限资料和维护操作 |

项目的面向用户的安全说明见 [SECURITY.md](../SECURITY.md)；当前发布说明见 [RELEASE_NOTES.md](../RELEASE_NOTES.md)。

## 当前版本与边界

文档按 2026-11-19 的仓库 `main` 分支编写，应用版本为 `0.3.1`。服务端只运行于 Linux；Windows 和 macOS 提供命令行客户端。OpenWrt 使用其系统 Python 和动态库安装源码，支持私用模式以 root 运行。

本项目实现直接 TCP 和 hbbs/hbbr TCP 中继相关流程。尚未实现 WebRTC、UDP/KCP 打洞、WebSocket/WSS，也尚未在真实未经修改的官方 GUI 与公网 hbbs/hbbr 环境中完成连接验证。详见 [协议与兼容性](PROTOCOL_COMPATIBILITY.md)。在部署和推广前必须按实际目标环境补做相应联调。

## 维护约定

* 修改认证、权限、网络协议、部署脚本或测试时，同步更新有关文档和[项目台账](PROJECT_LEDGER.md)。
* 仅记录实际执行过的测试。区分模拟连接、官方 OpenWrt 容器、真实 RustDesk 客户端与公网部署。
* 不在仓库、Issues、日志或测试记录中写入真实 PAM 密码、设备身份私钥、RustDesk 连接密码和服务器密钥。
* 版本发布及运维交接应按相应检查表执行，避免让后续人员依赖聊天记录了解项目情况。
