# RustDesk Headless

RustDesk Headless 提供 Linux 无图形界面的远程终端与文件传输服务端，以及 Linux、macOS 和 Windows 命令行客户端。服务端使用 RustDesk 的标准消息格式，支持直接 TCP 连接和通过 hbbs/hbbr 建立中继连接。设计目标是兼容未经修改的 RustDesk 桌面客户端。实际 GUI 兼容性仍需进一步验证。

项目提供私用模式和公用模式。私用模式直接使用服务进程所属账户的权限。公用模式通过 PAM 验证 Linux 账户，为验证成功的会话启动对应用户的独立进程。

## 已实现的功能

| 功能 | 私用模式 | 公用模式 |
| --- | --- | --- |
| RustDesk 加密连接 | 支持 | 支持 |
| 普通连接密码 | 必须设置 | 可以选择设置 |
| RustDesk 记住密码 | 支持 | 设置普通连接密码时支持 |
| 终端 | 当前服务用户 | PAM 验证的 Linux 用户 |
| Shell | 用户默认 Shell 或指定程序 | 登录用户默认 Shell 或指定程序 |
| 文件传输 | 当前服务用户 | 每个连接单独验证 PAM |
| 文件操作 | 上传、下载、浏览目录、建立目录、重命名和删除 | 同左，按登录用户权限执行 |
| 端口转发 | 仅访问管理员允许的本地端口 | 同左，不要求额外的 PAM 验证 |
| 远程桌面和 GUI | 不包含 | 不包含 |

当前版本实现了直接 TCP 连接、hbbs UDP 设备注册和通过 hbbs/hbbr 协调的 TCP 中继连接。已通过本地 hbbs/hbbr 模拟服务器，完成注册、建立中继、加密认证、浏览目录和下载文件的联调。尚未实现 WebRTC、UDP/KCP 打洞和 WebSocket/WSS，也尚未使用未经修改的官方 GUI 或真实公网 hbbs/hbbr 完成连接测试。

## 安装条件

- Linux 服务端需要 Linux 与 PAM（公用模式），私用模式使用普通系统账户运行。
- 源码安装需要 Python 3.11 或更新版本，可以使用系统 `libsodium`、`libzstd` 动态库，或者安装 PyNaCl 和 zstandard。
- GitHub Release 发布的 Linux 单文件可执行程序包含 Python 运行时及加密、压缩相关依赖。系统仍需安装并配置 PAM，才能使用公用模式。
- Windows 和 macOS 发布单文件命令行客户端；这两个平台不运行 Linux PAM 服务端。

在源码目录执行：

```bash
python3 -m rdheadless --help
```

也可以安装本项目的 Python 包：

```bash
python3 -m pip install .
rdheadless --help
```

## 私用模式

根据 `examples/private.toml` 填写设备 ID、身份文件、连接密码文件、Shell 及文件访问目录。

```bash
mkdir -p ~/.config/rdheadless
printf '%s\n' 'replace-with-a-long-random-password' > ~/.config/rdheadless/password
chmod 600 ~/.config/rdheadless/password
python3 -m rdheadless host --config examples/private.toml
```

连接时使用标准 RustDesk 密码。终端和文件操作都使用运行本程序的 Linux 账户，不会额外询问 PAM 密码。

## 公用模式

公用模式配置示例见 `examples/public.toml`。以 root 运行服务端。用户通过 PAM 验证后，终端及文件操作使用其 UID、GID 和附属用户组执行。

### 使用官方 RustDesk 终端

在官方客户端选择 **终端（以管理员身份运行）**，使用现有的操作系统登录对话框填写 Linux 用户名和密码。服务端在加密连接中接收 `LoginRequest.os_login`，验证 PAM 后启动该用户的 Shell。

注意：在公用模式下，即使使用官方客户端的管理员终端入口，也按照 PAM 登录账户的身份运行 Shell。是否具有 root 权限取决于实际登录账户。

### 使用官方 RustDesk 文件传输

普通 RustDesk 文件传输界面不能直接提交 PAM 凭据。本项目采用虚拟认证目录实现登录，无需修改客户端。

1. 打开该设备的**文件传输**界面，服务端首先显示 `/__rd_login__` 目录。
2. 目录中有 `USERNAME` 和 `PASSWORD` 两个虚拟文件，以及 `LOGIN` 文件夹。
3. 将 `USERNAME` 重命名为你的 **Linux 用户名**，例如 `alice`。
4. 将 `PASSWORD` 重命名为对应的 **Linux 登录密码**。
5. 进入 `LOGIN` 文件夹提交凭据。认证成功后，服务端以该用户身份打开实际文件目录；认证失败时，可以返回认证目录重新填写。

这些名称只保存在本次连接的内存中，服务端不会创建对应的实体文件，也不会将密码作为文件名返回给客户端。认证前的所有其他文件操作均被拒绝。成功登录后，客户端访问文件时遵循该 Linux 用户的权限和 `file_root` 目录限制。

**密码显示风险：** 官方 GUI 的重命名输入框和本地文件列表可能暂时显示新文件名，即所输入的密码。如果客户端保存操作历史、录制屏幕或有人可以看到客户端界面，密码可能泄露。此外，文件名受客户端文件命名规则限制，包含 `/`、`\\`、`:` 等字符的密码无法通过这种方式提交。处理敏感账户时，建议使用独立 CLI 客户端直接输入 PAM 凭据；CLI 使用隐藏的密码输入方式。

每个文件传输连接需要单独完成 PAM 登录。进入认证目录的操作不会授予其他连接权限。认证目录最多允许四次提交，默认等待时间为 180 秒；对同一地址的失败登录也有限制。

### 记住密码会怎样？

普通 RustDesk 密码使用标准 SHA-256 挑战响应机制。服务端为每个设备保留稳定的 `salt`，每次连接重新生成 `challenge`。因此，用户保存连接密码后，下次连接可以继续完成标准挑战响应。

- 公用模式如果**未设置** `password_file`：接受普通连接并进入 PAM 登录流程。保存的 RustDesk 密码不会赋予终端或文件访问权限。
- 公用模式如果**设置了** `password_file`：先验证共享的 RustDesk 连接密码，再要求使用 PAM 登录 Linux 账户。保存的连接密码可以重复使用。

PAM 登录状态只对当前连接有效。保存的连接密码不会代替 PAM，也不会自动授予后续文件传输连接权限。

### 使用独立命令行客户端

CLI 的公用模式在终端和文件传输中均直接提示输入 Linux 用户名及 PAM 密码，发送 `LoginRequest.os_login`，无需通过虚拟目录重命名文件。

```bash
python3 -m rdheadless identity --config examples/public.toml

python3 -m rdheadless client 127.0.0.1:21118 \
  --peer-id YOUR_DEVICE_ID --peer-key SERVER_PUBLIC_KEY \
  --mode public ls /home/alice
```

如果公用模式配置了额外的 RustDesk 连接密码，可以附加 `--ask-connection-password`，CLI 将额外提示输入该密码，密码不会出现在命令行参数中。

## 通过 RustDesk 服务器连接

本项目支持通过现有 hbbs/hbbr 中继服务器，按 RustDesk 设备 ID 建立连接，适用于无法直接访问被控设备 TCP 端口的情况。服务端在配置中开启 `enable_public_rendezvous = true`，并填写 `rendezvous_server`、`relay_server`。客户端示例：

```bash
rdheadless client hbbs.example.org:21116 \
  --via-hbbs --relay hbbr.example.org:21117 \
  --peer-id RDHeadless123 --peer-key BASE64_DEVICE_PUBLIC_KEY \
  --mode private ls /home/rduser
```

`--peer-key` 为被控端的 Ed25519 身份公钥，通过 `rdheadless identity --config ...` 查看。客户端在发送登录凭据前验证该公钥；hbbs/hbbr 仅负责连接协调和转发。当 hbbr 启用了许可证密钥验证时，可增加 `--rendezvous-key` 参数。不能将 hbbs 服务器公钥误填为设备身份公钥。

此实现采用 TCP 中继，尚不包含 WebSocket/WSS、WebRTC 和 UDP/KCP 连接方式。

## GitHub Actions 与版本发布

推送代码到 `main` 分支后，GitHub Actions 自动执行私用模式与公用模式测试，随后分别构建 Linux x86-64、Linux ARM64、macOS x86-64、macOS ARM64、Windows x86-64 的单文件可执行程序。全部构建、可执行程序启动检查和 Linux 实际文件传输检查通过后，发布与 `pyproject.toml` 版本一致的 GitHub Release，并附上各平台归档文件及 SHA-256 校验文件。

修改程序版本时，需要同步更新 `pyproject.toml` 与 `rdheadless/__init__.py`。已经发布的版本号不得重复使用。

## 端口转发

端口转发默认关闭。开启时必须列出允许连接的端口：

```toml
allow_tunnel = true
tunnel_ports = [8080, 2222]
```

仅允许连接 `localhost`、`127.0.0.1` 和 `::1` 上的指定 TCP 端口。公用模式的端口转发不要求 PAM，只有明确列入 `tunnel_ports` 的服务可以通过该功能访问。如果本地服务有敏感操作，应保持端口转发关闭，或同时配置 RustDesk 共享连接密码。

## 安全设置

- 设备身份文件和密码文件的权限应设置为 `0600`，并由运行服务端的账户持有。
- 公用模式使用 root 启动，被认证用户的 Shell 和文件管理程序在用户权限下运行。
- 建议为公用模式创建独立的 PAM 服务配置，结合服务器实际用户管理策略使用。
- 使用 `file_root` 限制可访问目录。用户仍须具备相应的 Linux 文件权限。
- 服务器不会依据来源 IP、客户端显示的设备 ID 或记住的连接密码来继承其他连接的 PAM 身份。

更详细的说明见 [SECURITY.md](SECURITY.md)。

## 本地测试

私用模式由普通账户执行：

```bash
PYTHONPATH=.:tests python3 -m pytest -q -p no:cacheprovider \
  tests/test_host_e2e.py tests/test_file_ops.py tests/test_cli.py tests/test_rendezvous.py tests/test_relay_e2e.py tests/test_cross_platform_api.py
```

公用模式由 root 执行，使用模拟 PAM 凭据验证操作和真实操作系统 UID 切换：

```bash
PYTHONPATH=.:tests python3 -m pytest -q -p no:cacheprovider \
  tests/test_auth.py tests/test_public_e2e.py
```

实际 PAM 错误密码拒绝测试应在已配置 PAM 的 Linux 环境下运行。真实账户的成功登录需要在部署环境中使用专用测试账户验证。

## 上游协议

- [RustDesk 官方项目](https://github.com/rustdesk/rustdesk)
- [hbb_common](https://github.com/rustdesk/hbb_common)
- [RustDesk 消息定义](https://github.com/rustdesk/rustdesk/blob/master/libs/base/protos/message.proto)
- [官方 hbbs/hbbr](https://github.com/rustdesk/rustdesk-server)

许可证：AGPL-3.0，见 [NOTICE](NOTICE)。
