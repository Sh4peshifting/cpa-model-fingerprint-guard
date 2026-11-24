# CLIProxyAPI 官方插件源收录准备

核对版本为官方仓库 `main` 提交 `0e9856e58275f909c5686114abcf682b7f5dd747`。该仓库只维护插件条目，构建产物、校验和与说明随本仓库自己的 GitHub Release 发布。

| 审核项 | 本项目 |
| --- | --- |
| `schema_version: 1`，插件 ID 合规且唯一 | `model-fingerprint-guard` 符合命名规则。核对时官方注册表中无同名 ID |
| `id`、`name`、`description`、`author`、`repository` | `docs/plugin-store-entry.json` 提供完整条目和简体中文描述 |
| GitHub 仓库格式 | `https://github.com/bul1horn/cpa-model-fingerprint-guard` |
| 最新公开 Release 标签为 `v<数字版本>` | 仓库默认分支的新版本通过 CI 后自动发布 |
| `<id>_<version>_<goos>_<goarch>.zip` 与 `checksums.txt` | 发布工作流构建并校验完整套件，再用 CLIProxyAPI v8.1.2 安装器检查各平台归档 |
| ZIP 根目录恰有一个匹配平台扩展名的动态库 | 统一打包脚本校验路径、重复条目及动态库名。许可证和说明可随包分发 |

首次 Release 公开后，可向官方仓库提交仅修改 `registry.json` 的 PR。把 `docs/plugin-store-entry.json` 的对象追加到现有 `plugins` 数组，保留 `schema_version: 1`。PR 正文提供本项目仓库 URL、最新 Release 标签、ZIP 和 `checksums.txt` 的链接，以及简短的插件功能说明。后续插件升级通过本仓库发布新的 Release，官方注册表条目可继续使用。

[官方收录规则](https://github.com/router-for-me/CLIProxyAPI-Plugins-Store/blob/0e9856e58275f909c5686114abcf682b7f5dd747/README.md)
