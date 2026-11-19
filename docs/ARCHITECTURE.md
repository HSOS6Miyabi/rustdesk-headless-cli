# 系统架构与代码导航

应用版本：`0.3.1`。阅读本文件前，可先查看 [项目台账](PROJECT_LEDGER.md) 了解实际验证范围。

## 1. 组件与运行位置

`rdheadless` 是 Python 包。Linux 进程通过 `python3 -m rdheadless host --config ...` 运行被控服务；CLI 在 Linux、macOS、Windows 上运行。OpenWrt 使用固件提供的 Python 与 musl 兼容动态库。普通 Linux 可使用 PyInstaller 单文件程序。

~~~text
RustDesk GUI 或 rdheadless CLI
     │  直接 TCP
     ├─────────────────────────┐
     │                         │
     └── hbbs 注册/协调 ── hbbr TCP 中继
                               │
                     Linux HostServer
                       │  身份签名、会话加密
                       │  共享密码/PAM 认证
                       ├── 私用模式：当前服务账户
                       └── 公用模式：对应 Linux 用户
                               │
                        独立 Worker 进程
                         ├── PTY / Shell
                         ├── FileManager
                         └── 本机受限 TCP 端口
~~~

hbbs/hbbr 负责设备登记、连接协调及中继。PAM 凭据通过被控端身份验证后的加密连接传递。当前的实现范围是直接 TCP 和 TCP 中继；其他传输机制见 [协议与兼容性](PROTOCOL_COMPATIBILITY.md)。

## 2. 源码模块

| 模块 | 主要责任 |
| --- | --- |
| [cli.py](../rdheadless/cli.py) | 参数解析、`host`、`identity`、`client` 命令、交互式密码输入 |
| [client.py](../rdheadless/client.py) | 验证对端公钥、建立加密连接、终端与文件传输操作 |
| [server.py](../rdheadless/server.py) | TOML 配置、密钥身份、连接类型分派、挑战响应、PAM 授权、工作进程 |
| [auth.py](../rdheadless/auth.py) | Linux 用户查询、PAM 身份验证与会话管理、失败尝试限制 |
| [file_login.py](../rdheadless/file_login.py) | 官方 GUI 文件传输连接的虚拟认证目录，认证前的文件操作限制 |
| [worker.py](../rdheadless/worker.py) | 单连接的用户进程、终端 PTY、文件会话、受限端口转发 |
| [exec_shell.py](../rdheadless/exec_shell.py) | 为登录 Shell 设置控制终端 |
| [files.py](../rdheadless/files.py) | 文件系统访问范围、目录操作、传输消息和分块上传下载 |
| [rendezvous.py](../rdheadless/rendezvous.py) | hbbs UDP 注册、TCP 请求中继、hbbr 连接配对 |
| [stream.py](../rdheadless/stream.py) | RustDesk 消息分帧、加密收发、消息计数 |
| [protocol.py](../rdheadless/protocol.py) | Protobuf 字段编码与解析、消息类型和连接类型常量 |
| [crypto.py](../rdheadless/crypto.py) | Ed25519、X25519、加密盒及标准密码挑战响应 |
| [native.py](../rdheadless/native.py)、[zstd.py](../rdheadless/zstd.py) | musl/glibc 动态库加载与有大小限制的解压缩 |
| [测试目录](../tests/) | 私用与公用模式、模拟中继、权限隔离、OpenWrt 安装测试 |

## 3. 一次连接的处理过程

1. `HostServer.start()` 创建 TCP 监听器。启用注册后，`Registration.run()` 在独立线程通过 UDP 向指定 hbbs 注册。
2. `HostServer.serve_forever()` 接收连接；每个连接由独立线程处理，同时使用信号量限制最多 64 个连接。
3. `_handshake()` 向客户端发送由设备 Ed25519 私钥签名的身份与临时公钥，并协商加密密钥。`Stream` 对之后的消息加密。
4. 服务端发出 `Hash`，包含设备身份对应的稳定 `salt` 和当前连接随机 `challenge`。客户端在 `LoginRequest` 中选择终端、文件传输或端口转发。
5. `_authorize()` 检查共享连接密码和具体功能权限。公用模式的终端读取 `os_login` 进行 PAM 认证；文件传输若未携带 `os_login`，转到 `FileLoginGateway`。
6. 认证完成后，`_worker()` 启动子进程，把加密会话计数及所需会话配置传递给该进程，并关闭父进程持有的连接副本。
7. `Worker.run()` 只执行当前连接获准使用的功能。连接结束后，进程结束并由服务端关闭关联的 PAM 会话。

公用模式的 UID、GID 和附属用户组由父进程在启动子进程时设置。程序不会在多线程服务进程中临时切换整体进程的用户身份。私用模式沿用服务账户的权限，允许 root。

## 4. 终端与文件操作

* 终端通过 `pty.openpty()` 创建伪终端，`exec_shell.py` 设置控制终端，然后启动配置的 Shell。`login_shell = true` 时使用带 `-` 前缀的 `argv[0]`。
* 一个工作进程最多同时管理 8 个终端标识；`_run_messages()` 根据连接功能分发消息，拒绝跨功能使用。
* 文件操作通过 `FileWorkspace` 的目录描述符和 `O_NOFOLLOW` 访问设定的 `file_root`，以 Linux 文件权限进一步限制操作。上传、下载由 `FileManager` 维护。
* 公用模式的 GUI 文件连接先位于内存中的 `/__rd_login__`。认证成功后才启动目标用户的文件工作进程；认证前不接触实际文件目录。
* 端口转发默认禁止；启用时只能访问允许列表中的本机 TCP 端口。其运行状态不能转化成文件或终端权限。

## 5. 持久化数据与配置来源

| 数据 | 存放位置 | 要求 |
| --- | --- | --- |
| 服务配置 | `--config` 指定的 TOML 文件 | 管理员维护；OpenWrt 默认 `/etc/rdheadless/config.toml` |
| 设备身份 | `identity_file` | 首次启动生成；必须由服务账户持有且只允许所属用户读写 |
| RustDesk 连接密码 | `password_file` | 私用模式必填；文件只允许所属用户读取，至少 12 字节 |
| CLI 自身标识 | `~/.config/rdheadless/client-id` | 本机生成；不作为跨连接 PAM 授权凭据 |
| PAM 用户与策略 | 系统账号数据库和 PAM 配置 | 由 Linux 系统管理员管理；仓库不保存系统密码 |
| 公用模式文件认证状态 | 每个连接的内存 | 断开时失效，不向其他连接转移 |

OpenWrt 安装目录及升级方法见 [部署与运维](OPERATIONS.md)。文件身份、密钥材料和备份属于敏感数据，不应上传到公开仓库。

## 6. 并发和输入限制

* 同时最多接受 64 个服务连接；一次最多处理 16 个登记/中继连接任务。
* 未认证的文件传输连接默认最多等待 180 秒、最多尝试 4 次；登录失败还有基于来源地址的短时间限制。
* Protobuf 消息大小在 `protocol.py` 限制；未认证阶段另设较小的读取限制。
* 终端大小、终端标识数量、文件操作和解压大小分别在对应模块中限制。
* 网络中断、工作进程异常退出、文件操作失败均需要维持认证与权限隔离；有关回归测试见 [开发与测试](DEVELOPMENT.md)。

## 7. 修改前的检查

涉及协议字段时，对照 [RustDesk 官方 message.proto](https://github.com/rustdesk/rustdesk/blob/master/libs/base/protos/message.proto) 和 [hbb_common](https://github.com/rustdesk/hbb_common)；涉及认证及文件时，首先检查 [安全设计](SECURITY_MODEL.md)。调整连接方式后应先完成本地模拟，再进行官方客户端与服务器的实际联调。
