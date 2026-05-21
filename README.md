# simple-config-service
SimpleConfigService – 基于 Go 的配置中心。  - 公网管理接口：登录 + JWT 认证，支持创建/更新配置 - 内网查询接口：仅监听内网，需通过前置鉴权网关访问 - 提供网关示例，验证调用方身份（API Key / Token）  适用于配置写入需要公网访问，但查询只能由内网服务经二次认证后调用的安全场景。
