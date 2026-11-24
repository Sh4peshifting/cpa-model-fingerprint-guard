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
