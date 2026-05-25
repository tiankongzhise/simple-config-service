# simple-config-service

一个轻量级 Go 配置中心，使用 PostgreSQL 存储配置和版本历史。配置值在网络传输和数据库存储阶段都以密文流转，元数据如项目名、环境名、配置 key、描述和状态保持明文，便于管理和查询。

## 功能概览

- 公网管理接口：注册、登录、用户公钥、用户私钥轮换、项目管理、配置创建/更新/删除/查询、版本历史、回滚。
- 内网查询接口：供前置鉴权网关调用，只返回按项目公钥加密后的密文配置值。
- 用户隔离：不同注册用户只能管理自己的项目和配置。
- 双向 RSA 信封加密：客户端用用户公钥加密提交，服务端解密后用服务本地公钥加密入库，读取时再用项目公钥加密返回。
- 服务本地 RSA 密钥：启动时自动生成 `keys/service_private.pem` 和 `keys/service_public.pem`，后续复用。

## 快速启动

1. 准备 PostgreSQL 数据库。
2. 复制 `.env.example` 为 `.env`。
3. 修改数据库连接、邀请码和 JWT 密钥。
4. 启动服务：

```powershell
go run ./cmd/config-service
```

服务启动时会自动执行幂等数据库迁移，并在 `keys/` 目录下生成或复用服务 RSA 密钥。`keys/*.pem` 已被 `.gitignore` 忽略。

## 环境变量

```env
pg_host=127.0.0.1
pg_port=5432
pg_user=config_service
pg_password=change-me
pg_database=config_service
pg_sslmode=disable

invite_code=change-this-invite-code
jwt_secret=change-this-jwt-secret-at-least-16-bytes

service_private_key_path=keys/service_private.pem
service_public_key_path=keys/service_public.pem

# Optional legacy AES master key, only needed to read old AES-256-GCM records.
config_master_key=
config_key_id=default

public_listen_addr=0.0.0.0:8080
internal_listen_addr=127.0.0.1:8081
jwt_ttl=24h
```

`config_master_key` 现在是兼容旧数据的可选项。新写入数据使用 `RSA-OAEP-SHA256+A256GCM` 信封格式。

## 加密流程

配置值使用 RSA 信封加密，而不是直接 RSA 加密整段明文：

1. 客户端调用 `GET /api/users/me/public-key` 获取用户公钥。
2. 客户端用用户公钥加密配置值，提交 `encrypted_value`。
3. 服务端用用户私钥解密客户端密文。
4. 服务端用本地服务公钥重新加密后存入数据库。
5. 查询配置时，服务端用服务私钥解开库内密文，再用项目公钥加密返回。

信封 payload 字段：

```json
{
  "algorithm": "RSA-OAEP-SHA256+A256GCM",
  "key_id": "project:<id>:<fingerprint>",
  "encrypted_data_key": "...",
  "nonce": "...",
  "value_ciphertext": "..."
}
```

## 主要接口

注册用户，`rsa_private_key` 可选；不传则系统生成：

```http
POST /api/register
Content-Type: application/json
```

```json
{
  "username": "alice",
  "password": "password123",
  "invite_code": "change-this-invite-code",
  "rsa_private_key": ""
}
```

获取用户公钥：

```http
GET /api/users/me/public-key
Authorization: Bearer <access_token>
```

创建项目：

```http
POST /api/projects
Authorization: Bearer <access_token>
Content-Type: application/json
```

```json
{
  "name": "order-service",
  "description": "订单服务",
  "rsa_public_key": "-----BEGIN PUBLIC KEY-----..."
}
```

创建配置：

```json
{
  "project_id": "<project_id>",
  "key": "db.password",
  "environment": "prod",
  "description": "数据库密码",
  "status": "enabled",
  "encrypted_value": {
    "algorithm": "RSA-OAEP-SHA256+A256GCM",
    "key_id": "user:<id>:<fingerprint>",
    "encrypted_data_key": "...",
    "nonce": "...",
    "value_ciphertext": "..."
  }
}
```

其他接口：

- `PUT /api/users/me/rsa-private-key`：更换当前用户 RSA 私钥；请求体可传 `rsa_private_key`，为空则系统生成。
- `GET /api/projects`：查询项目列表。
- `PUT /api/projects/{id}/rsa-public-key`：更换项目 RSA 公钥。
- `GET /api/configs?project_id=<project_id>&environment=prod`：查询配置列表。
- `PUT /api/configs/{id}`：更新配置。
- `DELETE /api/configs/{id}`：软删除配置。
- `GET /api/configs/{id}/versions`：查询版本历史。
- `POST /api/configs/{id}/rollback`：回滚到指定版本。

## 内网查询

```http
GET /internal/configs?project_id=<project_id>&environment=prod
X-Config-User-ID: <user_id>
```

响应中的 `encrypted_value` 已按项目公钥加密，业务方使用对应项目私钥解密。

## 开发验证

```powershell
go test ./...
go build ./cmd/config-service
```
