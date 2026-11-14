# RustDesk Headless CLI v0.3.1

该版本提供 Linux 私用模式 root 运行支持，以及适用于 OpenWrt 的源码安装包。

- 私用模式可直接以 root 运行，终端和文件管理继承服务账户权限，仍要求连接密码。
- 新增 OpenWrt `ash`、`procd` 服务安装脚本，自动安装所需系统依赖并保留现有配置。
- 使用系统的 musl 兼容 `libsodium` 和 `libzstd`，不依赖 glibc 单文件程序。
- 增加 root 用户终端、文件传输、认证失败及动态库加载测试。
- 原有 Linux、macOS 和 Windows 命令行版本保持支持。

使用前请阅读 README 的 OpenWrt 安装说明。root 私用模式获得设备的最高文件与终端权限，务必设置强连接密码，并限制可访问目录。
