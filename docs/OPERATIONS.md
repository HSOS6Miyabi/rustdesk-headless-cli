# 部署、升级和运维说明

应用版本：`0.3.1`。部署前阅读 [安全设计](SECURITY_MODEL.md)，确认采用私用模式还是公用模式。未经过真实官方 GUI 与公网 hbbs/hbbr 联调的环境，应先使用独立测试设备验证。

## 1. 部署方式与适用平台

| 环境 | 安装方式 | 服务端账户 | 说明 |
| --- | --- | --- | --- |
| 普通 Linux | Python 包或对应架构的单文件程序 | 私用模式为普通账户或 root；公用模式必须 root | 使用 glibc 的通用单文件程序由 CI 构建 |
| OpenWrt | Release 中的源码包和设备自身软件仓库 | root 私用模式 | 需要 Python 3.11+、ctypes、libsodium、libzstd、`/dev/ptmx` |
| Windows / macOS | 对应平台的单文件程序 | 无 Linux 服务端 | 目前只提供 CLI 客户端 |

OpenWrt 已在 25.12-SNAPSHOT x86-64 官方容器验证。其他架构及真实路由器应检查软件包是否可用、内存及存储空间是否足够。

## 2. Linux 初始化

按发行版准备 Python 3.11+、必要的加密和压缩依赖，在源码目录运行：

~~~sh
python3 -m pip install -e '.[bundle]'
python3 -m rdheadless --help
~~~

**私用模式：** 从 [private.toml](../examples/private.toml) 复制配置并修改所有示例路径；以运行服务的用户创建独立密码文件，设置文件权限 `0600`。必须在配置中填写 `password_file` 与 `identity_file`。身份文件首次运行时自动创建。

**公用模式：** 从 [public.toml](../examples/public.toml) 复制配置；以 root 启动，确认系统 PAM 策略和真实用户账户存在。可选 `password_file` 为 PAM 外增加共享 RustDesk 连接密码。文件传输和终端仍须分别登录 PAM。

检查身份与启动：

~~~sh
rdheadless identity --config /etc/rdheadless/config.toml
rdheadless host --config /etc/rdheadless/config.toml
~~~

以上路径为运维人员选择的示例。`identity` 命令会使用配置初始化身份文件，应在受信任的主机上执行。跨设备直接连接需要调整 `listen_host`；默认监听 `127.0.0.1:21118`。

如由 systemd 管理 Linux 服务，请根据实际安装路径设置 `ExecStart`，私用模式指定相应 `User`，公用模式使用 root，并限制服务配置、身份文件和密码文件的访问权限。修改服务管理配置后，在测试环境确认启动、停止和重新启动的行为。

## 3. OpenWrt 安装与服务管理

从 [Releases](https://github.com/HSOS6Miyabi/rustdesk-headless-cli/releases) 下载当前版本的 `rdheadless-openwrt-source.tar.gz`，上传至路由器的私有目录，执行：

~~~sh
tar -xzf rdheadless-openwrt-source.tar.gz
cd rdheadless-openwrt
sh openwrt/install.sh
vi /etc/rdheadless/config.toml
/etc/init.d/rdheadless enable
/etc/init.d/rdheadless start
~~~

安装器按系统选择 `apk` 或 `opkg`，安装 Python、`python3-ctypes`、`libsodium` 与 `libzstd`，复制 Python 包到 `/usr/lib/rdheadless`，安装 `/usr/bin/rdheadless` 与 `/etc/init.d/rdheadless`，生成私用模式配置、设备 ID 和随机连接密码。

OpenWrt 常用命令：

~~~sh
/etc/init.d/rdheadless status
/etc/init.d/rdheadless restart
/etc/init.d/rdheadless stop
logread -e rdheadless
rdheadless identity --config /etc/rdheadless/config.toml
~~~

配置文件：`/etc/rdheadless/config.toml`。连接密码：`/etc/rdheadless/password`。身份文件：`/etc/rdheadless/identity.json`。服务由 `procd` 管理并在意外退出后尝试重新启动。

## 4. 配置项说明

以下配置项位于 TOML 的 `[server]` 内，完整示例见 [examples](../examples/) 和 [OpenWrt 示例](../openwrt/private.toml)。

| 配置项 | 作用及注意事项 |
| --- | --- |
| `mode` | `private` 或 `public`；公用模式要求 root 与 PAM |
| `device_id` | RustDesk 设备 ID；必须与身份文件中的 ID 一致 |
| `identity_file` | 设备身份文件，首次使用自动生成，权限需满足程序检查 |
| `password_file` | 私用模式必填；公用模式可选。普通文件、服务账户所属，其他用户不能读取 |
| `listen_host`、`listen_port` | TCP 监听地址与端口，默认 `127.0.0.1:21118` |
| `pam_service` | 公用模式使用的 PAM 服务名称，默认 `login` |
| `shell`、`login_shell` | 指定可执行的 Shell 绝对路径；空值采用该用户的默认 Shell；是否以登录 Shell 启动 |
| `file_root` | 文件操作目录范围；空值采用用户家目录；必须是绝对路径 |
| `file_auth_timeout` | 公用模式虚拟文件认证等待时间，范围 10～600 秒，默认 180 秒 |
| `allow_tunnel`、`tunnel_ports` | 是否允许 TCP 转发以及允许连接的本地端口列表；默认禁止 |
| `enable_public_rendezvous` | 是否向 hbbs 注册并接收中继协调消息 |
| `rendezvous_server` | hbbs 的地址与端口，常用端口 `21116` |
| `relay_server` | hbbr 的地址与端口，常用端口 `21117` |
| `rendezvous_key` | hbbr 需要的许可证密钥；存储配置时注意文件权限 |

示例：

~~~toml
[server]
mode = "private"
device_id = "RDExample"
identity_file = "/etc/rdheadless/identity.json"
password_file = "/etc/rdheadless/password"
listen_host = "127.0.0.1"
listen_port = 21118
shell = "/bin/ash"
login_shell = true
file_root = "/root"
allow_tunnel = false
tunnel_ports = []
enable_public_rendezvous = true
rendezvous_server = "hbbs.example.org:21116"
relay_server = "hbbr.example.org:21117"
~~~

服务器地址和设备 ID 需按真实测试环境替换。不能将实际密码或设备私钥写进公开配置示例。

## 5. 备份、升级与恢复

**备份：** 在限制访问的备份位置保存 `config.toml`、`identity.json` 和 `password`；公用模式还应由系统管理员备份独立维护的 PAM 配置及用户管理资料。身份文件或连接密码泄露会影响访问安全，备份文件必须限制权限并妥善保管。

**OpenWrt 升级：** 先检查新版本的发布说明和目标系统的可用空间，停止服务，备份上述文件，解压新源码包并重新执行 `sh openwrt/install.sh`，最后重新启动服务。安装脚本会保留已有 `config.toml` 和 `password`；`identity_file` 由应用在首次运行时创建，重装前必须确认备份及原文件仍在。

**恢复：** 恢复对应的设备身份、配置与密码，检查文件所有者和 `0600` 权限，再启动服务并验证能否按设备 ID 连接。恢复其他设备的身份文件会改变其设备身份及信任关系，必须在有权限的维护窗口进行。

**更新密码：** 修改共享连接密码后重新启动服务；保存了旧密码的客户端应更新密码。更新 PAM 用户密码按照主机的账户管理制度执行。

## 6. 故障排查

| 现象 | 检查顺序 |
| --- | --- |
| 无法启动 | 查看 `logread -e rdheadless` 或 Linux 服务日志；检查配置 TOML、Python 版本、端口占用、文件所有者和权限 |
| 找不到加密或压缩库 | 检查 `libsodium`、`libzstd`、`python3-ctypes` 与 musl/glibc 平台；OpenWrt 使用源码安装包 |
| 连接提示密码错误 | 检查 `password_file` 是否属于当前服务用户、长度是否合规；确认客户端使用的共享密码已更新 |
| 设备不在线或无法中继 | 检查 `enable_public_rendezvous`、hbbs/hbbr 地址、DNS、UDP/TCP 出站访问、防火墙与服务端日志 |
| CLI 报告设备身份不符 | 检查实际设备 ID 和 `--peer-key`；不要关闭身份验证来绕过错误 |
| 公用模式 PAM 失败 | 检查 PAM 服务名、账号状态、PAM 配置及登录限制；不要将密码写到日志中 |
| 远程 Shell 无法启动 | 检查 `shell` 是否为可执行绝对路径、用户家目录、`/dev/ptmx` 和进程权限 |
| 文件列表为空或操作失败 | 检查 `file_root`、用户权限、符号链接及文件访问范围；公用模式先检查是否完成 PAM 登录 |
| 端口转发失败 | 检查 `allow_tunnel`、`tunnel_ports`、本地服务监听地址及连接功能限制 |

生产环境故障应记录时间、版本、操作系统、网络方式、脱敏错误和复现步骤，供接手人员继续调查；机密信息不得进入问题报告。

## 7. 运行检查

服务启动后，至少确认进程稳定、设备 ID 正确、普通连接密码生效、终端以预期用户运行、文件操作遵循 `file_root`。采用 hbbs/hbbr 时应在目标网络完成真实中继测试。若启用公用模式或端口转发，还须分别验证 PAM 身份隔离或允许列表及真实数据传输。对未经验证的官方 GUI 版本，不应承诺完全兼容。
