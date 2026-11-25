# 模型指纹守卫

`model-fingerprint-guard` 是 CLIProxyAPI v8.1.2 的独立动态库插件。它用 lm-detector 生成三次随机数挑战并在本机评分，结合空闲检测和上游异常，识别疑似模型替换和降级。插件在原生宿主和官方管理面板 v1.29.1 上提供隔离、检测队列、审计和简体中文管理页。发布动态库内嵌页面和参考库，共用宿主端口。

## 当前能力

- 按 Auth ID 记录业务活动和流式请求的生命周期。全局、提供商和单认证可分别配置检测策略。
- 业务失败按宿主提供的具体 Auth ID 匹配状态码、结构化代码和文本。收到匹配后在内存中隔离认证并同步保存状态，诊断任务优先调度。
- 原生 OAuth 诊断按同一 Auth ID 和模型调用宿主。仅三份样本均通过 lm-detector 严格校验并取得达到阈值的参考库内校准概率，才判定匹配或不一致。
- 多轮确认指纹不一致后会持久化隔离，默认两天后自动复检。通过后解除插件隔离，未通过则继续隔离并等待下一次复检。隔离只影响插件的调度判定。
- 超时、限流、无效样本、未知参考模型或低可信度结果有独立状态。业务异常引起隔离后，连续探测得到 502 或 503 且耗尽短重试时，插件继续隔离并定期复检。常规空闲检测失败只记入检测记录。

有关适用路径、原生冷却、流式错误和热升级的边界，见 [宿主兼容性](docs/compatibility.md)。

## 构建

需要 Go 1.26.10 以上、目标平台的 C 编译器、Git、Bash、gzip 和 Python 3.11 以上。使用相同 OS/架构构建最简单。

```sh
./scripts/build.sh
```

构建脚本按固定提交提取 lm-detector 参考库并核对 SHA-256。第一次构建会联网下载 Go 模块和参考库。离线构建可用已缓存模块和 `MFG_REFERENCE_REPO=/absolute/path/to/lm-detector`。可用 `MFG_VERSION=0.1.0` 指定版本。Linux 示例产物在 `dist/linux-amd64/model-fingerprint-guard-v0.1.0-dev.so`。

发布工作流兼容 Linux glibc 2.17，并构建 macOS、Windows 的 amd64/arm64 和 FreeBSD amd64。平台测试范围见 [测试与发布](docs/compatibility.md#测试与发布)。

## 安装与使用

1. 使用支持原生插件的 CLIProxyAPI v8.1.2 发行版。从本仓库 Releases 下载并解压对应平台的 ZIP，或使用本地构建产物。复制动态库到宿主的 `plugins.dir`。保留文件名中的 `model-fingerprint-guard` ID。
2. 将 [示例配置](config.example.yaml) 的 `plugins` 段合并到宿主 YAML。为该宿主实例设置唯一的 `state-dir`，并通过宿主配置管理密钥和远程访问策略。
3. 启动或重启宿主。在官方管理面板的插件资源菜单打开“模型指纹守卫”。也可直接访问 `/v0/resource/plugins/model-fingerprint-guard/index.html`。同源访问时，如果已在面板中勾选“记住密码”并登录当前宿主，插件会自动验证该密钥。会话不可用或验证失败时，可在登录卡片手动输入宿主管理密钥。插件使用的密钥只保留在当前页面内存中。
4. 为要检测的提供商或认证配置请求模型、预期模型，然后开启全局检测。原版宿主的 `native-diagnostics: true` 仅适用于经过核对的原生 OAuth 路由。要求稳定别名映射、禁用会改变诊断路由或模型的其他插件或规则。以 [兼容性说明](docs/compatibility.md) 为准。
5. 在“认证管理”中可切换卡片和列表，按认证或状态筛选，并通过选中栏批量操作。每项认证可设置继承项、手动检测、隔离或解除隔离。卡片和列表都标记待检测认证、显示预计检测时间，并按各认证的全部保留记录统计一致、不一致、失败次数和一致率。小方块显示最新 16 次检测结果。嵌入时，CPA 面板的刷新按钮会重新加载插件页。

待检测任务可通过“取消检测”跳过本次。周期性空闲检测和已安排的定期复检从取消时重新计算下一轮间隔。认证原有的隔离状态仍然有效。

插件内嵌官方管理面板 v1.29.1 使用的 Lucide 图标。发布包附带相应许可证。[官方面板图标源文件](https://github.com/router-for-me/Cli-Proxy-API-Management-Center/blob/v1.29.1/src/components/ui/icons.tsx)

宿主级 `plugins.configs.model-fingerprint-guard.enabled` 控制整个插件实例。插件自己“全局检测”开关控制新任务，已经隔离的凭证继续隔离。对同一实例，`settings` 仅在首次创建状态文件时导入。后续从管理页保存，配置即时生效，避免宿主重载时覆盖持久化设置。

| 设置 | 用途 |
| --- | --- |
| `default`、`providers`、`auths` | 默认值、提供商覆盖、Auth ID 覆盖 |
| `expected_models`、`prefer_failed_model` | 显式映射请求别名，优先检测有匹配映射的故障模型 |
| `scan_seconds`、`idle_seconds`、`interval_seconds` | 扫描周期、空闲时长、同认证最短检测间隔 |
| `mismatch_recheck_seconds` | 确认指纹不一致后的复检间隔，默认 `172800` 秒（两天），可设为 1 到 2592000 秒 |
| `gateway_recheck_seconds` | 短重试耗尽后的业务恢复复检间隔，默认 `3600` 秒（一小时），可设为 1 到 2592000 秒 |
| `http_statuses`、`error_codes`、`error_texts` | 可独立设置的异常触发规则，任一匹配即可计入 |
| `dedupe_seconds`、`trigger_count` | 事件去重窗口和触发门槛 |
| `min_probability`、`confirm_rounds` | 参考库内的最小校准概率、连续不一致确认轮数 |
| `timeout_seconds`、`max_concurrent`、`per_provider` | 单次挑战的结果时限、全局及单提供商的检测轮数并发 |
| `parallel_challenges` | 同一轮三道挑战可同时交给 CPA，默认 `false`，依次执行 |
| `retry_seconds`、`max_retry_seconds`、`max_retries`、`jitter_seconds` | 指数退避、重试上限和随机抖动 |
| `overload_limit`、`overload_pause_seconds`、`history_limit` | 过载保护门槛、暂停时长和历史条数 |

预期模型应选择参考库的规范 ID。业务恢复复检固定使用触发隔离的 Auth ID 和业务请求模型，匹配该模型的预期指纹后才自动解除隔离。模型别名通过 `expected_models` 指定预期指纹。SDK 的排名分数不是概率，参考库内校准概率也无法证明库外模型的身份。

业务恢复检测等待 CPA 提供的冷却截止时间，等待和宿主拒绝执行的冷却响应不消耗短重试次数。实际探测返回 502 或 503 会计入短重试。无冷却时间时使用插件退避。进入长间隔复检后，每轮复检按设定间隔继续排队，可在认证管理手动提前检测。

确认不一致后的自动复检沿用原记录的请求模型和预期指纹，从确认时间或最近检测完成时间起算。间隔届满后由下一轮扫描按并发限制安排。全局和该认证的检测需保持开启，宿主已停用的认证由宿主控制。可在“检测设置”的“扫描与复检”分组调整“不一致复检间隔（秒）”。

## 参考库运行时更新

发布版启动时先加载经过校验的本地缓存或随包参考库，再在后台通过 HTTPS 检查 lm-detector 的公开数据源。仅下载新版公开模型清单和检测器分片。启用前核对数据格式、文件大小、SHA-256 和 Go SDK 加载结果。网络异常、格式不兼容或缓存在写入时失败都会保留当前版本。每轮检测只读取启动时选用的参考库，切换版本后重新计数连续不一致轮数。

在 CPA 的「插件管理」打开模型指纹守卫的配置弹窗，可保存 `native-diagnostics`、`reference-auto-update` 和 `reference-refresh-interval`。保存后由宿主热应用，插件专页的「宿主生效配置」会显示实际值。格式或时长无效时，运行中的插件保留上一次生效值，并在专页提示。`state-dir` 和 `reference-dir` 的变更需要重启宿主。

参考库默认启动后检查一次，随后每 24 小时检查。`reference-refresh-interval` 支持 `1m` 到 `720h`。启用自动更新或修改更新间隔后会立即检查一次。暂停更新会保留当前已加载的参考库。关闭自动更新后启动插件时使用发布版内嵌数据。指定 `reference-dir` 时使用该本地目录，并暂停自动下载。当前构建时间和最近更新状态可在插件专页查看。缓存位于 `state-dir/reference-cache.json`。

## 发布与官方插件源

发布版本记录在 `VERSION`。提交到默认分支 `master` 后，如果该版本尚未发布，GitHub Actions 会先运行 CI，再构建所有平台。验证 ZIP、SHA-256 和 CLIProxyAPI 的实际安装逻辑后，自动创建形如 `v0.1.0` 的标签和 GitHub Release。已发布的版本会跳过重复发布。标签推送也可触发发布，标签版本须与 `VERSION` 一致。

各平台的资产名为 `model-fingerprint-guard_<version>_<goos>_<goarch>.zip`。每个 ZIP 含一个位于根目录的 `model-fingerprint-guard.so`、`.dylib` 或 `.dll`，并附带许可证和文档。统一的 `checksums.txt` 包含所有 ZIP 的 SHA-256。收录准备材料见 [官方插件源提交说明](docs/plugin-store.md)。

GitHub Actions 每周查询 lm-detector Go SDK 的更新，Dependabot 负责发起只更新该 SDK 的依赖 PR。合并后，下一个发布版本使用更新后的 `go.mod` 和 `go.sum`。CI 会检查 Go SDK 与随包参考库的兼容性。运行时数据更新与 SDK 发版独立。

## 升级、卸载与排查

升级前备份状态目录。停止宿主、替换同 ID 的动态库，再启动宿主并核对认证隔离清单。CLIProxyAPI 支持逻辑热替换，原生库实际映射和跨版本状态交接存在限制，维护窗口升级可以保留隔离边界。

卸载前先用宿主原有认证管理功能停用仍不能接收业务的认证。禁用该插件或在停止宿主后移除动态库。备份或保留 `state-dir` 可供以后恢复。隔离是插件施加的调度条件，卸载插件后该条件随之解除。

- **找不到入口**：核对平台、架构、glibc 版本、动态库文件名及宿主插件开关，再查询 `GET /v0/management/plugins` 是否列出该资源。
- **页面显示手动登录**：自动登录使用同源官方面板保存的会话。跨源访问、未勾选“记住密码”或会话失效时，可填写宿主管理密钥。手动验证失败时，核对密钥和宿主的远程访问权限。
- **不支持检测**：核对是否选用了已核对的原生 OAuth 提供商、是否打开 `native-diagnostics`，以及预期模型是否在参考库中。
- **一直隔离**：查看宿主原有冷却、限额、再次检测时间和历史。默认未确认正常的认证会继续隔离。
- **配置更新冲突**：刷新页面或重新载入设置，再提交最新版本。状态错误时检查专用目录及磁盘空间，保留原有状态文件供排查。
- **原始样本与敏感信息**：记录只包含脱敏状态和判定数据，样本、完整认证内容、Token、管理密钥均不进入插件的持久化记录。

## 开发测试

```sh
go test ./...
go vet ./...
go test -race ./...
node --check cmd/model-fingerprint-guard/web/app.js
MFG_TEST_REFERENCE=/absolute/path/to/lm-detector/data go test ./internal/fingerprint
python3 tests/host_integration.py --host /absolute/path/to/cli-proxy-api \
  --plugin dist/linux-amd64/model-fingerprint-guard-v0.1.0-dev.so --browser-test
```

集成测试使用固定提交的真实 CLIProxyAPI、临时认证目录和两个本地模拟认证。浏览器测试需要 Chromium 与 Node.js 22 以上。项目使用 MIT 许可证，随发布包提供 [第三方许可证](licenses/)。
