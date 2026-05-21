# simple-config-service

一个轻量级 Go 配置中心，使用 PostgreSQL 作为后端存储，适合中小型服务把运行配置集中管理起来。

本项目实现了：

- 公网管理接口：注册、登录、配置创建、更新、删除、查询、版本历史、回滚。
- 内网查询接口：供前置鉴权网关调用，只返回密文配置。
- 用户隔离：不同注册用户只能管理自己的配置。
- 邀请码注册：邀请码从 `.env` 读取，缺失或错误时拒绝注册。
- 配置加密落库：配置值写入数据库前使用信封加密。
- 客户端解密模型：配置中心查询链路不返回明文，由业务方或 SDK 解密。

更完整的手把手使用流程见 [用户使用指南](docs/USER_GUIDE.md)。

## 架构说明

服务启动后会监听两个 HTTP 地址：

- `public_listen_addr`：公网管理接口，默认 `0.0.0.0:8080`。
- `internal_listen_addr`：内网查询接口，默认 `127.0.0.1:8081`。

公网接口负责账号体系和配置管理。内网接口默认由前置鉴权网关访问，配置中心本身不重复处理网关鉴权，只通过 `X-Config-User-ID` 识别用户并做数据隔离。

## 快速启动

1. 准备 PostgreSQL 数据库。
2. 复制 `.env.example` 为 `.env`。
3. 修改 `.env` 中的数据库连接、邀请码、JWT 密钥和配置主密钥。
4. 启动服务：

```powershell
go run ./cmd/config-service
```

服务启动时会自动执行幂等数据库迁移，创建所需表结构。

## 环境变量

`.env` 示例：

```env
pg_host=127.0.0.1
pg_port=5432
pg_user=config_service
pg_password=change-me
pg_database=config_service
pg_sslmode=disable

invite_code=change-this-invite-code
jwt_secret=change-this-jwt-secret-at-least-16-bytes

config_master_key=0123456789abcdef0123456789abcdef
config_key_id=default

public_listen_addr=0.0.0.0:8080
internal_listen_addr=127.0.0.1:8081
jwt_ttl=24h
```

`config_master_key` 必须满足以下任一格式：

- 32 字节原始字符串。
- 64 位十六进制字符串。
- 32 字节内容的 base64 编码。

生产环境请使用高强度随机密钥，并妥善保存。该密钥不能和数据库密码、JWT 密钥复用。

## 加密设计

配置值写入数据库前会先加密。每次写入配置时：

1. 服务生成一个随机 Data Encryption Key。
2. 使用该 Data Encryption Key 通过 `AES-256-GCM` 加密配置值。
3. 使用 `.env` 中的 `config_master_key` 加密 Data Encryption Key。
4. 数据库只保存密文、加密后的 Data Encryption Key、nonce、算法和 key id。

查询接口返回密文字段，不返回明文配置。业务方拿到密文后，需要在客户端或业务 SDK 中解密。

## 公网管理接口

注册：

```http
POST /api/register
Content-Type: application/json

{
  "username": "alice",
  "password": "password123",
  "invite_code": "change-this-invite-code"
}
```

登录：

```http
POST /api/login
Content-Type: application/json

{
  "username": "alice",
  "password": "password123"
}
```

登录成功后，后续公网管理接口需要带上：

```http
Authorization: Bearer <access_token>
```

创建配置：

```http
POST /api/configs
Authorization: Bearer <access_token>
Content-Type: application/json

{
  "key": "db.password",
  "value": "secret",
  "application": "order-service",
  "environment": "prod",
  "description": "数据库密码",
  "status": "enabled"
}
```

其他接口：

- `POST /api/refresh`：刷新访问令牌。
- `POST /api/logout`：退出登录。
- `GET /api/configs?application=order-service&environment=prod&limit=50&offset=0`：查询配置列表。
- `PUT /api/configs/{id}`：更新配置。
- `DELETE /api/configs/{id}`：软删除配置。
- `GET /api/configs/{id}/versions`：查询版本历史。
- `POST /api/configs/{id}/rollback`：回滚到指定版本。
- `GET /healthz`：健康检查。

## 内网查询接口

内网接口只返回启用且未删除的配置：

```http
GET /internal/configs?application=order-service&environment=prod
X-Config-User-ID: <user_id>
```

示例响应：

```json
{
  "application": "order-service",
  "environment": "prod",
  "configs": [
    {
      "key": "db.password",
      "value_ciphertext": "...",
      "encrypted_data_key": "...",
      "nonce": "...",
      "data_key_nonce": "...",
      "algorithm": "AES-256-GCM",
      "key_id": "default",
      "version": 3,
      "updated_at": "2026-05-21T10:00:00Z"
    }
  ]
}
```

## 数据表

服务启动时会自动创建：

- `users`：用户账号、密码哈希和状态。
- `configs`：当前配置记录。
- `config_versions`：配置历史版本。
- `audit_logs`：审计日志。

## 开发与验证

运行测试：

```powershell
go test ./...
```

构建服务：

```powershell
go build ./cmd/config-service
```
