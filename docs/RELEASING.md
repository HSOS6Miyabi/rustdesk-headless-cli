# 持续集成与版本发布

本项目 GitHub 仓库：[HSOS6Miyabi/rustdesk-headless-cli](https://github.com/HSOS6Miyabi/rustdesk-headless-cli)。开发版本以仓库 `main` 当前提交为准，发布版本以 Git 标签和 Release 附件为准。

## 1. GitHub Actions 工作流

| 工作流 | 触发条件 | 作用 |
| --- | --- | --- |
| [Verify](../.github/workflows/verify.yml) | `main` 推送、Pull Request、手动执行 | Linux 测试、root/PAM 模拟测试、Windows/macOS 客户端测试、OpenWrt 官方容器测试和文档检查 |
| [Build binaries and publish release](../.github/workflows/release.yml) | 涉及程序或构建内容的 `main` 推送、手动执行 | 先运行协议与权限测试，再构建五个平台程序和 OpenWrt 源码包，检查后创建 Release |

仅更新文档、文档检查脚本或维护工作流时，发布工作流不会自动重新发布原版本；Verify 仍执行。需要发布新版本时，必须修改应用版本号。

## 2. 正式发版步骤

1. 检查 [项目台账](PROJECT_LEDGER.md)、[安全说明](../SECURITY.md) 和 [协议兼容性](PROTOCOL_COMPATIBILITY.md)，确认发布说明只包含经过测试的功能。
2. 修改 [pyproject.toml](../pyproject.toml) 的 `project.version` 和 [__init__.py](../rdheadless/__init__.py) 的 `__version__`，两处版本必须一致。更新 [RELEASE_NOTES.md](../RELEASE_NOTES.md)。
3. 运行 `python scripts/check_docs.py` 和与本次更改有关的测试，并检查安全敏感文件未被提交。
4. 提交到 `main` 后检查 Verify 和 Release 工作流。Release 中的测试、五个平台构建、OpenWrt 容器与源码包任务必须全部成功。
5. Release 工作流依据 `pyproject.toml` 创建 `vX.Y.Z` 标签，上传文件并生成 `SHA256SUMS`。标签必须指向本次构建的同一提交。
6. 在 [Releases 页面](https://github.com/HSOS6Miyabi/rustdesk-headless-cli/releases) 核对每个下载附件、发布说明、标签提交和 SHA-256 校验信息。
7. 更新台账中已经发布的版本与验证范围；如有真实设备部署，按照 [运维文档](OPERATIONS.md) 检查升级。

**版本不可复用。** 如果已有标签指向旧提交，Release 工作流会拒绝重新使用该版本号。重新发版须增加版本号并创建新的 Release。

## 3. Release 文件清单

| 附件 | 适用环境 |
| --- | --- |
| `rdheadless-linux-amd64.tar.gz` | Linux x86-64，glibc 单文件程序 |
| `rdheadless-linux-arm64.tar.gz` | Linux ARM64，glibc 单文件程序 |
| `rdheadless-macos-amd64.tar.gz` | macOS x86-64 CLI |
| `rdheadless-macos-arm64.tar.gz` | macOS ARM64 CLI |
| `rdheadless-windows-amd64.zip` | Windows x86-64 CLI |
| `rdheadless-openwrt-source.tar.gz` | OpenWrt 源码包，使用设备软件仓库安装 Python 和 musl 动态库 |
| `SHA256SUMS` | 上述归档文件的 SHA-256 摘要 |

Linux 构建包含运行测试；OpenWrt 在官方 x86-64 容器运行 root/BusyBox 测试。Windows 和 macOS 包检查可执行文件能否启动。其他 OpenWrt 架构与官方 GUI 的真实互操作需要另行测试。

## 4. 出现异常时的处理

* Verify 未通过：先阅读失败任务日志，重现相应测试并修复；不要绕过测试发布。
* 构建任务未通过：检查运行器架构、Python 版本、打包依赖和运行时动态库。
* OpenWrt 任务未通过：区分软件仓库、容器环境、安装器与实际 socket 测试问题。
* 版本已存在：核对标签和 `pyproject.toml`，创建新的递增版本。
* Release 缺少文件：检查 `actions/download-artifact` 的下载结果和 `SHA256SUMS`；完整构建通过前不应手工发布残缺附件。

完整 CI 配置以仓库中的 YAML 文件为准。维护人员修改工作流后必须检查触发规则、权限范围及实际运行情况。
