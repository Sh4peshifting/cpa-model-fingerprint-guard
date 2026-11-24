# 宿主兼容性

| 组件 | 锁定版本 | 源码提交 |
| --- | --- | --- |
| CLIProxyAPI | v8.1.2，C ABI 1，RPC schema 10 | `85225381d89915595598ed13766cd79890c03a84` |
| CLIProxyAPI 管理面板 | v1.29.1 | `3128b0ba10ae425d243f52e865b96e7e7c518291` |
| lm-detector Go SDK、参考库 | `v0.2.1-0.20261123065740-e0472890bea8` | `e0472890bea827d15ca883636a77d4c10bbe843b` |

宿主通过 C ABI 加载共享库。以 `internal/pluginhost/testdata/loader_unix_reload_plugin` 的 Go 示例和 `sdk/pluginabi`、`sdk/pluginapi` 为准。宿主和插件分别构建。

- `scheduler.pick` 支持 `ExcludeCandidates`。选择完成后还可用 `request.intercept_after` 按 `selected_auth_id` 拒绝当前凭证，让宿主尝试下一认证。Home 模式禁用本机管理接口。
- `host.model.execute` 的 `auth_id` 能锁定认证，但常规执行路径仍检查原生冷却。OpenAI 兼容配置认证的模型别名可展开到多个上游模型。原生回调无法要求拒绝模型池。
- `usage.handle` 提供实际 Auth ID 和失败详情，异步交付。`request.complete` 是整次执行的异步终态。`response.intercept_stream_chunk` 只会看到宿主实际转发到该钩子的流。`response.intercept_after` 只覆盖成功响应。
- `host.auth.save` 按文件名接收完整 JSON。它没有版本前置条件和原子字段变更操作。`host.auth.get` 加 `host.auth.save` 不能避免覆盖 OAuth 刷新；原生管理端的 `Manager.Modify` 没有对应插件回调。
- 资源菜单通过 `management.register` 注册。面板的 `PluginResourcePage` 仅用 iframe 打开资源。资源入口公开，插件管理数据走带宿主管理身份验证的 `/v0/management` 路由。面板没有把登录令牌转交给 iframe 的协议。

[CLIProxyAPI](https://github.com/router-for-me/CLIProxyAPI/tree/v8.1.2) · [官方管理面板](https://github.com/router-for-me/Cli-Proxy-API-Management-Center/tree/v1.29.1) · [lm-detector](https://github.com/Ikaleio/lm-detector/tree/e0472890bea827d15ca883636a77d4c10bbe843b)

## 原版运行边界

- 原生诊断是显式开启的部署选项。当前识别文件型 OAuth 的 Codex、Claude、Gemini CLI 和 Kimi 系列路由。它依赖使用无歧义、稳定的原生模型映射，以及没有其他插件或规则替换模型、请求内容或执行器。对模型池、其他提供商、运行时虚拟认证和 Home 模式，不提供严格诊断保证。原生回调锁定 Auth ID，但无法在调用之间绑定宿主路由配置版本。
- 原生回调自身可能重复尝试同一认证。插件每轮最多发起三次独立调用。结果超时后作废，原生同步 C ABI 对后台 `host.model.execute` 没有向宿主传递截止时间的机制，因此无法硬取消阻塞的宿主调用。
- `usage.handle` 的请求 ID 由实际 executor 生成，与生命周期请求 ID 不同。插件用实际 Auth ID 结合宿主 Selection ID 或 Trace ID 关联业务尝试，且只处理曾经进入 after-auth 钩子的请求。观察范围受宿主是否发出记录或流事件制约。异步使用量回调之前开始的业务可继续运行，收到回调后的候选过滤和 after-auth 拒绝会生效。
- 流拦截器观察宿主转译后交付的 SSE 事件；宿主提前吞掉或在内部重写的错误帧需要同步宿主钩子。活动范围由 after-auth 到整次请求终止，包含失败尝试和仍在输出的流。插件启用之前已入场的请求不在其活动跟踪内，启动时至少观察一个空闲阈值才安排空闲检测。
- 事件路径立即尝试诊断，原生冷却仍可能拒绝该调用。遇到冷却、过载或限流时保持隔离并重试，插件不调用冷却重置或配额清空接口。诊断经过常规宿主执行路径，宿主仍可按普通结果更新自己的用量和冷却状态。
- 认证更新使用宿主公开的文件快照信息复核，部分宿主维护性写入也会保守地使当前检测失效。确认不一致的结果在原版宿主上持久化到插件状态，认证文件与宿主永久停用状态由管理员处理。在插件未成功加载、被卸载、被宿主熔断或同进程热替换的过渡期间，不能承诺插件隔离持续生效。
- lm-detector Go SDK 无可注入的 HTTP 发送器。插件复用 `GenerateChallenges`、`BuildRequest` 和 `Analyze(..., true)`，由宿主执行非流式请求，适配层只核对响应完成标志和提取回答文本。原始参考库经固定 SHA-256 校验，运行时 SDK 走本地目录模式。

## 测试与发布

本地验证环境为 Linux amd64、Go 1.26.11，真实宿主从固定提交构建。GitHub Actions 配置覆盖 Linux amd64/arm64、macOS amd64/arm64、Windows amd64/arm64 与 FreeBSD amd64。Linux 发行构建使用与宿主一致的 manylinux2014 glibc 2.17 环境。直接在较新的发行版上运行构建脚本会使用本机 glibc，产物要求可能更高。其他平台的动态库加载未经本地验证。

本地验收运行了 Go 单元测试、vet 和 race，以及 Chromium 浏览器流程。真实宿主和本地 Kimi 模拟上游验证了三次精确认证调用、拒绝越权管理、HTTP 503 后原生冷却与插件隔离并存、HTTP 200 SSE 异常归属和跨进程重启恢复。浏览器用例直接打开插件资源，同时以宿主插件列表验证菜单注册。

lm-detector 该提交中的既有 conformance fixture 对应 2026 年 11 月 17 日的旧参考数据，本次固定参考库构建于 2026 年 11 月 23 日。用上游 TypeScript 生成器在临时副本中按固定参考库重建 fixture 后，原版 Go SDK 通过 13 个分析、11 个解析、49 个请求和 13 个流式用例。
