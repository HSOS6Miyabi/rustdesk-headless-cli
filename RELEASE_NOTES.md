# RustDesk Headless CLI v0.3.0

本版本提供 Linux 无图形界面的 RustDesk 被控端，以及 Linux、macOS 和 Windows 命令行客户端。

- Linux 私用模式：使用运行服务的用户身份，提供终端、文件传输和受限制的端口转发。
- Linux 公用模式：通过 PAM 验证 Linux 用户名和密码。官方文件传输界面可通过虚拟认证目录提交 PAM 登录信息，所有未认证操作均受到限制。
- RustDesk 协议：兼容的加密连接和挑战响应、设备级稳定 salt、hbbs UDP 注册、hbbr TCP 中继协调。
- CLI：通过设备 IP 地址直接连接，或经由 hbbs/hbbr 按设备 ID 建立 TCP 中继连接。
- GitHub Actions：跨平台构建单文件可执行程序，运行测试和 Linux 打包程序联调，自动发布并附带 SHA-256 校验文件。

**功能范围：** 当前版本尚不包含远程桌面、图形界面、WebRTC、UDP/KCP 打洞、WebSocket/WSS。公用模式的 PAM 服务端仅适用于 Linux。模拟联调已经通过，但尚未完成官方 GUI 和真实公网 hbbs/hbbr 联调。

使用说明和安全注意事项请查阅仓库中的 README.md 与 SECURITY.md。
