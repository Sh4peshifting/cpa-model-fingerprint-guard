# 模型指纹守卫

`model-fingerprint-guard` 是 CLIProxyAPI v8.1.2 的独立动态库插件。它用 lm-detector 生成三次随机数挑战并在本机评分，结合空闲检测和上游异常，识别疑似模型替换和降级。插件在原生宿主和官方管理面板 v1.29.1 上提供隔离、检测队列、审计和简体中文管理页。发布动态库内嵌页面和参考库，共用宿主端口。

## 当前能力

- 按 Auth ID 记录业务活动和流式请求的生命周期。全局、提供商和单认证可分别配置检测策略。
- 业务失败按宿主提供的具体 Auth ID 匹配状态码、结构化代码和文本。收到匹配后在内存中隔离认证并同步保存状态，诊断任务优先调度。
- 原生 OAuth 诊断按同一 Auth ID 和模型调用宿主。仅三份样本均通过 lm-detector 严格校验并取得达到阈值的参考库内校准概率，才判定匹配或不一致。
- 匹配解除插件隔离。原版宿主上的多轮确认不一致会进入持久化隔离和人工处理状态。原版插件 ABI 缺少原子更新认证和恢复所有权检查，具体方案见 [宿主接口提案](docs/host-extension.md)。
- 超时、限流、无效样本、未知参考模型或低可信度结果有独立状态。并发、指数退避、抖动、过载暂停和隔离到期策略可配置。默认隔离到期后等待人工处理。

有关适用路径、原生冷却、流式错误和热升级的边界，见 [宿主兼容性](docs/compatibility.md)。

## 构建

需要 Go 1.26.10 以上、目标平台的 C 编译器、Git、Bash、gzip 和 Python 3.11 以上。使用相同 OS/架构构建最简单。

```sh
./scripts/build.sh
```

构建脚本按固定提交提取 lm-detector 参考库并核对 SHA-256。第一次构建会联网下载 Go 模块和参考库。离线构建可用已缓存模块和 `MFG_REFERENCE_REPO=/absolute/path/to/lm-detector`。可用 `MFG_VERSION=0.1.0` 指定版本。Linux 示例产物在 `dist/linux-amd64/model-fingerprint-guard-v0.1.0-dev.so`。

发布工作流兼容 Linux glibc 2.17，并构建 macOS、Windows 的 amd64/arm64 和 FreeBSD amd64。平台测试范围见 [测试与发布](docs/compatibility.md#测试与发布)。

## 安装与使用

1. 使用支持原生插件的 CLIProxyAPI v8.1.2 发行版。复制匹配当前操作系统和架构的动态库到宿主的 `plugins.dir`。保留文件名中的 `model-fingerprint-guard` ID。
2. 将 [示例配置](config.example.yaml) 的 `plugins` 段合并到宿主 YAML。为该宿主实例设置唯一的 `state-dir`，并通过宿主配置管理密钥和远程访问策略。
3. 启动或重启宿主。在官方管理面板的插件资源菜单打开“模型指纹守卫”。也可直接访问 `/v0/resource/plugins/model-fingerprint-guard/index.html`。填写宿主管理密钥后进入页面，密钥只保留在当前页面内存中。
4. 为要检测的提供商或认证配置请求模型、预期模型，然后开启全局检测。原版宿主的 `native-diagnostics: true` 仅适用于经过核对的原生 OAuth 路由。要求稳定别名映射、禁用会改变诊断路由或模型的其他插件或规则。以 [兼容性说明](docs/compatibility.md) 为准。
5. 在“认证管理”中可以搜索、筛选、设置继承项、手动检测、隔离、解除隔离或批量操作。确认异常时先查看“检测记录”，再用宿主原有认证管理功能停用认证。解除插件隔离后仍由宿主决定该认证是否可调度。

宿主级 `plugins.configs.model-fingerprint-guard.enabled` 控制整个插件实例。插件自己“全局检测”开关控制新任务，已经隔离的凭证继续隔离。对同一实例，`settings` 仅在首次创建状态文件时导入。后续从管理页保存，配置即时生效，避免宿主重载时覆盖持久化设置。

| 设置 | 用途 |
| --- | --- |
| `default`、`providers`、`auths` | 默认值、提供商覆盖、Auth ID 覆盖 |
| `expected_models`、`prefer_failed_model` | 显式映射请求别名，优先检测有匹配映射的故障模型 |
| `scan_seconds`、`idle_seconds`、`interval_seconds` | 扫描周期、空闲时长、同认证最短检测间隔 |
| `http_statuses`、`error_codes`、`error_texts` | 可独立设置的异常触发规则，任一匹配即可计入 |
| `dedupe_seconds`、`trigger_count` | 事件去重窗口和触发门槛 |
| `min_probability`、`confirm_rounds`、`auto_disable` | 参考库内的最小校准概率、连续不一致确认轮数、宿主原子停用能力可用时的策略 |
| `timeout_seconds`、`max_concurrent`、`per_provider` | 单次挑战的结果时限、全局及单提供商并发 |
| `retry_seconds`、`max_retry_seconds`、`max_retries`、`jitter_seconds` | 指数退避、重试上限和随机抖动 |
| `max_isolation_seconds`、`expiry` | 自动隔离到期行为，`hold` 等待人工，`release` 仅可解除未确认异常的临时隔离 |
| `overload_limit`、`overload_pause_seconds`、`history_limit` | 过载保护门槛、暂停时长和历史条数 |

预期模型应选择参考库的规范 ID。若上游故障模型和配置测试模型不同，结果只描述被测模型，原隔离需要另行处理。SDK 的排名分数不是概率，参考库内校准概率也无法证明库外模型的身份。

## 升级、卸载与排查

升级前备份状态目录。停止宿主、替换同 ID 的动态库，再启动宿主并核对认证隔离清单。CLIProxyAPI 支持逻辑热替换，原生库实际映射和跨版本状态交接存在限制，维护窗口升级可以保留隔离边界。

卸载前先用宿主原有认证管理功能停用仍不能接收业务的认证。禁用该插件或在停止宿主后移除动态库。备份或保留 `state-dir` 可供以后恢复。隔离是插件施加的调度条件，卸载插件后该条件随之解除。

- **找不到入口**：核对平台、架构、glibc 版本、动态库文件名及宿主插件开关，再查询 `GET /v0/management/plugins` 是否列出该资源。
- **页面无法登录**：核对宿主管理密钥和远程访问权限。推荐经 HTTPS 打开远程管理页面。管理面板把资源放在 iframe 中，需要在该页面单独登录。
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
