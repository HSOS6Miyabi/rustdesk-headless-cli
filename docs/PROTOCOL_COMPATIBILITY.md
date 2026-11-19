# RustDesk 协议与兼容性范围

应用版本：`0.3.1`。本项目直接实现了部分 RustDesk Protobuf 消息与网络处理。新增功能必须与官方协议定义核对；兼容性结论以实际互操作测试为准。

## 1. 当前功能状态

| 功能或通道 | 当前状态 | 验证范围 |
| --- | --- | --- |
| 被控端 TCP 监听 | 已实现 | 本地真实 socket |
| Ed25519 身份签名、X25519 密钥交换、会话加密 | 已实现 | 自带 CLI 与测试 |
| RustDesk 密码挑战响应和保存密码后的重连 | 已实现 | 本地模拟 GUI 消息与 CLI |
| 终端 PTY、Shell 登录与调整终端大小 | 已实现 | 本地运行 Shell 的测试 |
| 目录列举、文件上传下载、重命名和删除 | 已实现 | 本地实际文件操作测试 |
| 公用模式 PAM 及按用户执行文件操作 | 已实现 | 模拟 PAM 与实际 UID 切换 |
| 官方 GUI 文件传输虚拟认证目录 | 已实现协议消息处理 | 尚待未经修改的官方 GUI 实测 |
| hbbs UDP 设备注册、TCP 请求和 hbbr 中继 | 已实现部分所需消息 | 本地 hbbs/hbbr 模拟服务器 |
| 原版 GUI 与真实官方 hbbs/hbbr 的完整互操作 | 待验证 | 无正式联调记录 |
| 直接 TCP 打洞、UDP/KCP、WebRTC、WebSocket/WSS | 未实现 | 无 |
| 远程桌面、音视频、图形界面 | 项目范围之外 | 无 |
| 端口转发允许列表 | 已实现 | 本地权限检查；双向流量联调待完成 |

“已实现”仅描述当前源码和表格所列的测试范围。新版本 RustDesk 可能调整消息字段、密钥协商或传输行为，应在更新依赖或修改协议时重新验证。

## 2. 相关实现与官方参考

* [协议编码器](../rdheadless/protocol.py)：RustDesk 消息类型、连接类型及受限制的 Protobuf 解析器。
* [Stream](../rdheadless/stream.py)：RustDesk 长度前缀与加密数据处理。
* [加密与身份](../rdheadless/crypto.py)：设备身份、密钥交换、挑战响应。
* [连接处理](../rdheadless/server.py)、[CLI 客户端](../rdheadless/client.py)。
* [注册与中继](../rdheadless/rendezvous.py)。
* [官方 message.proto](https://github.com/rustdesk/rustdesk/blob/master/libs/base/protos/message.proto)。
* [官方 hbb_common](https://github.com/rustdesk/hbb_common) 与 [RustDesk 服务端](https://github.com/rustdesk/rustdesk-server)。

`protocol.py` 中包含 `SIGNED_ID`、`PUBLIC_KEY`、`HASH`、`LOGIN_REQUEST`、`LOGIN_RESPONSE`、`FILE_ACTION`、`FILE_RESPONSE`、`TERMINAL_ACTION`、`TERMINAL_RESPONSE` 等消息类型。Rendezvous 协调使用 `REGISTER_PK`、`REGISTER_PEER`、`REQUEST_RELAY`、`RELAY_RESPONSE` 等消息。

当前 `server.py` 只接受其实现支持的密钥交换版本。与新增版官方客户端联调时，应首先检查密钥交换版本和身份签名验证是否匹配。

## 3. 两种连接方式

**直接 TCP：** CLI 通过 `host:port` 与被控端建立连接，使用预先固定的设备 Ed25519 公钥验证 `SignedId`；连接加密后才发送登录信息。服务器本机监听地址默认是 `127.0.0.1:21118`，跨机器直连前需配置实际可达地址，并限制暴露范围。

**hbbs/hbbr TCP 中继：** 被控端在开启注册后，向配置的 hbbs 发送 UDP 注册消息；发起端在 TCP 通道请求中继；hbbr 根据本次请求 ID 配对转发。网络协调本身不会赋予用户权限。CLI 仍须使用指定的设备公钥验证被控端身份。`--peer-key` 指设备身份公钥，不能填入 hbbs 的服务器公钥。

当前中继仅使用 TCP。不能假设具备官方客户端的全部 NAT 穿透、自动回退或加密协商行为。

## 4. 用户认证与连接密码

* 标准 RustDesk 密码先计算 `SHA256(password || salt)`，再计算 `SHA256(first_hash || challenge)`。`salt` 与设备身份关联，`challenge` 每次连接变化。
* 私用模式要求连接密码，用户操作继承服务账户权限。
* 公用模式可选共享连接密码；终端使用 `LoginRequest.os_login` 进行 PAM 验证。官方 GUI 的文件传输连接通常不携带该字段，本项目先提供虚拟认证目录。详情见 [安全设计](SECURITY_MODEL.md)。
* 已登录终端不自动授权新文件连接；同一 IP 或 CLI 客户端 ID 不作为 PAM 授权方式。

## 5. 真实互操作测试计划

使用**独立测试设备和测试账号**，记录 RustDesk GUI、hbbs/hbbr、本项目的准确版本，以及操作系统、网络和连接类型。

1. 使用未修改的 RustDesk 桌面客户端连接本项目的设备 ID；检查设备是否能正确注册及展示在线状态。
2. 测试私用模式的终端、文件目录读取、上传、下载，检查错误密码、保存密码后的断开与重连。
3. 测试公用模式管理员终端的 PAM 成功与失败登录、退出后的权限撤销。
4. 在文件传输界面依次重命名 `USERNAME`、`PASSWORD`，进入 `LOGIN`；检查失败重试、错误文件操作拒绝、认证后用户权限、再次建立连接要求重新认证。
5. 测试不同网络与中继配置；核查真实 hbbs/hbbr 的身份、公钥、协议版本和连接失败时的行为。
6. 对允许端口进行 TCP 双向流量测试；对未允许端口和非本机地址确认拒绝。
7. 审查 GUI 是否显示或记录输入的文件传输 PAM 密码；使用专用测试密码并清理录制及历史信息。

发现不兼容时，记录具体服务端和 GUI 版本、消息类别、预期行为与实际行为，不写入账号密码、设备私钥或完整敏感数据包。优先在 [测试目录](../tests/) 增加可重复执行的回归测试，并更新 [项目台账](PROJECT_LEDGER.md)。

## 6. 兼容性发布条件

在正式声明支持某个 RustDesk 官方客户端或 hbbs/hbbr 版本前，必须完成上述相关操作的实际互操作测试。模拟消息通过只能作为开发验证。未经检验的平台或传输方式应在使用说明中标注测试范围。
