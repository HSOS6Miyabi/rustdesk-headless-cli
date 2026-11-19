# 开发环境、测试与修改指南

应用版本：`0.3.1`。与开发任务相关的功能状态请查阅 [项目台账](PROJECT_LEDGER.md)，协议细节见 [兼容性文档](PROTOCOL_COMPATIBILITY.md)。

## 1. 环境准备

源码开发推荐 Linux 与 Python 3.11 或更高版本。项目采用 `setuptools`，测试使用 `pytest`。在仓库根目录执行：

~~~sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e '.[bundle,test]'
python -m rdheadless --help
~~~

`bundle` 包含 PyNaCl 和 zstandard；OpenWrt 源码安装可以使用系统提供的 `libsodium`、`libzstd`，无需自行编译 Python 扩展。Linux 公用模式测试与部分 root 私用模式测试需要 root 权限。

## 2. 测试项目与执行命令

所有命令在仓库根目录执行。

| 测试文件 | 主要内容 |
| --- | --- |
| [test_host_e2e.py](../tests/test_host_e2e.py) | 私用模式终端、文件浏览、连接密码、保存密码后的重新连接 |
| [test_file_ops.py](../tests/test_file_ops.py) | 文件目录限制、上传、错误路径拒绝 |
| [test_cli.py](../tests/test_cli.py) | CLI 上传下载及固定设备公钥验证 |
| [test_rendezvous.py](../tests/test_rendezvous.py) | 地址解析、注册和中继协调消息 |
| [test_relay_e2e.py](../tests/test_relay_e2e.py) | 模拟 hbbs/hbbr，通过中继连接真实 HostServer/Worker |
| [test_cross_platform_api.py](../tests/test_cross_platform_api.py) | Windows/macOS 可导入的 CLI 和协议模块 |
| [test_auth.py](../tests/test_auth.py) | 登录尝试限制与虚拟目录名称规则 |
| [test_public_e2e.py](../tests/test_public_e2e.py) | PAM 模拟登录、文件虚拟目录、权限隔离、连接独立认证和转发允许列表 |
| [test_openwrt_private.py](../tests/test_openwrt_private.py) | 私用模式 root 终端/文件、密码验证、musl 库加载 |
| [test_openwrt_install.py](../tests/test_openwrt_install.py) | 安装脚本的配置保留与 `procd` 配置 |

普通用户测试：

~~~sh
python -m pytest -q -p no:cacheprovider \
  tests/test_host_e2e.py tests/test_file_ops.py tests/test_cli.py \
  tests/test_rendezvous.py tests/test_relay_e2e.py \
  tests/test_cross_platform_api.py
~~~

公用模式与 root 私用模式测试必须在**专门的 Linux 测试环境**运行。`test_public_e2e.py` 中的测试账户名称目前固定为 `oai`，由测试用例模拟 PAM 验证，其 UID/GID 查询与工作进程身份切换使用真实 Linux 账户：

~~~sh
sudo useradd --create-home --shell /bin/sh oai
sudo env "PATH=$PATH" python -m pytest -q -p no:cacheprovider \
  tests/test_auth.py tests/test_public_e2e.py \
  tests/test_openwrt_private.py tests/test_openwrt_install.py
~~~

只在隔离测试机上创建该账号；如果已有 `oai` 用户，先检查并保留现有用户。运行测试的工作目录需允许测试用户访问。CI 的 [verify.yml](../.github/workflows/verify.yml) 包含账户创建和权限准备步骤。上述测试的 PAM 成功登录使用测试替身；它不能替代生产系统的真实 PAM 策略测试。

## 3. 构建后的可执行文件测试

在 Linux 上安装 PyInstaller 后执行：

~~~sh
python -m pip install 'pyinstaller>=6.11,<7'
python -m PyInstaller --noconfirm --clean --onefile --console \
  --name rdheadless --collect-all nacl --collect-all cffi \
  --hidden-import _cffi_backend --collect-all zstandard \
  --hidden-import rdheadless.worker \
  --hidden-import rdheadless.exec_shell rdheadless/__main__.py
./dist/rdheadless --help
python scripts/smoke_bundle.py ./dist/rdheadless
~~~

官方 CI 对 Linux x86-64/ARM64 执行单文件连接测试；Windows、macOS 的产物在各自运行器上检查启动。具体构建命令以 [release.yml](../.github/workflows/release.yml) 为准。

## 4. OpenWrt 测试

需要 Docker、联网的软件包仓库和能够运行容器的 Linux 测试机：

~~~sh
bash scripts/verify_openwrt.sh
~~~

脚本拉取官方 `openwrt/rootfs:x86-64-openwrt-25.12` 容器，安装依赖并在 musl 环境中运行 [openwrt_smoke.py](../scripts/openwrt_smoke.py)。它验证 root 文件访问和 BusyBox `ash` 终端。容器通过不等于真实路由器的 CPU、网络与持久化存储条件均已检验。

## 5. 修改模块时的对应测试

| 修改范围 | 至少运行 |
| --- | --- |
| `server.py`、`crypto.py`、`stream.py` | 私用模式、协议与 CLI、安全登录测试 |
| `auth.py`、`file_login.py`、`worker.py` | 公用模式测试和 root 用户切换测试 |
| `files.py` | 文件目录限制、上传下载、公用模式文件认证测试 |
| `rendezvous.py` | 注册及中继模拟测试，另做真实 hbbs/hbbr 联调 |
| `cli.py`、`client.py` | CLI 测试和跨平台导入测试 |
| `native.py`、`zstd.py`、`openwrt/` | OpenWrt 官方容器测试及打包测试 |
| GitHub Actions 或版本配置 | 文档检查、Verify 工作流及对应构建任务 |

协议安全相关改动需要同时检查错误输入、网络中断、消息边界、身份转换和认证撤销。新加的协议字段应与官方 [message.proto](https://github.com/rustdesk/rustdesk/blob/master/libs/base/protos/message.proto) 及 [hbb_common](https://github.com/rustdesk/hbb_common) 核对。没有完成官方 GUI 的联调时，文档中仍须标注兼容范围。

## 6. 文档与代码同步

本仓库使用 [check_docs.py](../scripts/check_docs.py) 检查交接文档是否存在、相对链接是否有效，以及版本号是否与发布说明一致。修改文档后运行：

~~~sh
python scripts/check_docs.py
~~~

修改源代码及安全策略后，应检查 [项目台账](PROJECT_LEDGER.md)、[安全设计](SECURITY_MODEL.md)、[运维说明](OPERATIONS.md) 是否需要同步。所有测试必须在提交说明中准确描述执行环境，避免把模拟服务端测试写成真实 RustDesk 服务器验证。
