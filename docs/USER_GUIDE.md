# simple-config-service 用户使用指南

这份指南演示如何启动服务、注册账号、管理项目和配置，以及如何通过内网接口获取按项目公钥加密后的密文配置。

## 1. 准备环境

需要准备：

- Go 1.24 或更高版本。
- PostgreSQL 13 或更高版本。
- 一个可以连接 PostgreSQL 的数据库用户。

示例数据库初始化 SQL：

```sql
CREATE DATABASE config_service;
CREATE USER config_service WITH PASSWORD 'change-me';
GRANT ALL PRIVILEGES ON DATABASE config_service TO config_service;
```

如果 PostgreSQL 对 public schema 权限较严格，还需要连接到 `config_service` 数据库后执行：

```sql
GRANT ALL ON SCHEMA public TO config_service;
```

## 2. 配置 .env

```powershell
Copy-Item .env.example .env
```

编辑 `.env`：

```env
pg_host=127.0.0.1
pg_port=5432
pg_user=config_service
pg_password=change-me
pg_database=config_service
pg_sslmode=disable

invite_code=my-invite-code
jwt_secret=replace-with-a-long-random-jwt-secret

service_private_key_path=keys/service_private.pem
service_public_key_path=keys/service_public.pem

config_master_key=
config_key_id=default

public_listen_addr=0.0.0.0:8080
internal_listen_addr=127.0.0.1:8081
jwt_ttl=24h
```

说明：

- `invite_code` 是注册邀请码。
- `jwt_secret` 至少 16 字节，生产环境应使用随机强密钥。
- `service_private_key_path` 和 `service_public_key_path` 是服务本地 RSA 密钥路径；首次启动会自动生成。
- `config_master_key` 仅用于读取历史 `AES-256-GCM` 数据，新数据可以留空。

## 3. 启动服务

```powershell
go run ./cmd/config-service
```

服务启动时会执行数据库迁移，并生成或复用：

- `keys/service_private.pem`
- `keys/service_public.pem`

## 4. 注册和登录

注册时可以传入已有 RSA 私钥；如果不传，系统会生成一把用户私钥并保存其服务密文。

```powershell
curl -X POST http://127.0.0.1:8080/api/register `
  -H "Content-Type: application/json" `
  -d "{\"username\":\"alice\",\"password\":\"password123\",\"invite_code\":\"my-invite-code\"}"
```

保存响应中的 token 和用户 ID：

```powershell
$token = "<access_token>"
$userId = "<user.id>"
```

已有账号登录：

```powershell
curl -X POST http://127.0.0.1:8080/api/login `
  -H "Content-Type: application/json" `
  -d "{\"username\":\"alice\",\"password\":\"password123\"}"
```

## 5. 获取用户公钥

客户端提交配置值前，先获取当前用户公钥：

```powershell
curl http://127.0.0.1:8080/api/users/me/public-key `
  -H "Authorization: Bearer $token"
```

响应：

```json
{
  "algorithm": "RSA-OAEP-SHA256+A256GCM",
  "key_id": "user:<id>:<fingerprint>",
  "rsa_public_key": "-----BEGIN PUBLIC KEY-----..."
}
```

客户端使用这个公钥把配置值加密成 `encrypted_value` 后再提交给后端。

## 6. 创建项目

项目需要提供 RSA 公钥。后续这个项目的配置返回值都会使用该项目公钥加密。

```powershell
curl -X POST http://127.0.0.1:8080/api/projects `
  -H "Content-Type: application/json" `
  -H "Authorization: Bearer $token" `
  -d "{\"name\":\"order-service\",\"description\":\"订单服务\",\"rsa_public_key\":\"-----BEGIN PUBLIC KEY-----...\"}"
```

保存返回的 `id`：

```powershell
$projectId = "<project.id>"
```

## 7. 创建配置

请求体中的 `encrypted_value` 必须是使用当前用户公钥加密后的 RSA 信封密文：

```powershell
curl -X POST http://127.0.0.1:8080/api/configs `
  -H "Content-Type: application/json" `
  -H "Authorization: Bearer $token" `
  -d "{\"project_id\":\"$projectId\",\"key\":\"db.password\",\"environment\":\"prod\",\"description\":\"数据库密码\",\"status\":\"enabled\",\"encrypted_value\":{\"algorithm\":\"RSA-OAEP-SHA256+A256GCM\",\"key_id\":\"user:<id>:<fingerprint>\",\"encrypted_data_key\":\"...\",\"nonce\":\"...\",\"value_ciphertext\":\"...\"}}"
```

后端会：

1. 用用户私钥解开请求中的 `encrypted_value`。
2. 用服务本地 RSA 公钥重新加密后写入数据库。
3. 返回时再用项目 RSA 公钥加密为新的 `encrypted_value`。

## 8. 查询和更新配置

按项目查询：

```powershell
curl "http://127.0.0.1:8080/api/configs?project_id=$projectId&environment=prod" `
  -H "Authorization: Bearer $token"
```

更新配置：

```powershell
$configId = "<config.id>"

curl -X PUT "http://127.0.0.1:8080/api/configs/$configId" `
  -H "Content-Type: application/json" `
  -H "Authorization: Bearer $token" `
  -d "{\"project_id\":\"$projectId\",\"key\":\"db.password\",\"environment\":\"prod\",\"description\":\"更新后的数据库密码\",\"status\":\"enabled\",\"encrypted_value\":{\"algorithm\":\"RSA-OAEP-SHA256+A256GCM\",\"key_id\":\"user:<id>:<fingerprint>\",\"encrypted_data_key\":\"...\",\"nonce\":\"...\",\"value_ciphertext\":\"...\"}}"
```

版本历史和回滚：

```powershell
curl "http://127.0.0.1:8080/api/configs/$configId/versions" `
  -H "Authorization: Bearer $token"

curl -X POST "http://127.0.0.1:8080/api/configs/$configId/rollback" `
  -H "Content-Type: application/json" `
  -H "Authorization: Bearer $token" `
  -d "{\"version\":1}"
```

## 9. 更换密钥

更换用户 RSA 私钥：

```powershell
curl -X PUT http://127.0.0.1:8080/api/users/me/rsa-private-key `
  -H "Content-Type: application/json" `
  -H "Authorization: Bearer $token" `
  -d "{\"rsa_private_key\":\"-----BEGIN PRIVATE KEY-----...\"}"
```

如果 `rsa_private_key` 为空字符串，系统会重新生成一把用户私钥。

更换项目 RSA 公钥：

```powershell
curl -X PUT "http://127.0.0.1:8080/api/projects/$projectId/rsa-public-key" `
  -H "Content-Type: application/json" `
  -H "Authorization: Bearer $token" `
  -d "{\"rsa_public_key\":\"-----BEGIN PUBLIC KEY-----...\"}"
```

密钥更换只影响后续请求和后续返回，不会扫描重写历史数据。

## 10. 内网查询

前置鉴权网关完成鉴权后，把用户 ID 传给配置中心：

```powershell
curl "http://127.0.0.1:8081/internal/configs?project_id=$projectId&environment=prod" `
  -H "X-Config-User-ID: $userId"
```

响应中的 `encrypted_value` 已按项目公钥加密：

```json
{
  "project_id": "<project_id>",
  "environment": "prod",
  "configs": [
    {
      "project_id": "<project_id>",
      "project_name": "order-service",
      "key": "db.password",
      "encrypted_value": {
        "algorithm": "RSA-OAEP-SHA256+A256GCM",
        "key_id": "project:<id>:<fingerprint>",
        "encrypted_data_key": "...",
        "nonce": "...",
        "value_ciphertext": "..."
      },
      "version": 2,
      "updated_at": "2026-05-21T10:00:00Z"
    }
  ]
}
```

业务方使用项目私钥解密 `encrypted_value` 得到真实配置值。

## 11. 常见问题

注册返回 `403 forbidden`：

- 检查 `invite_code` 是否与 `.env` 完全一致。

接口返回 `401 unauthorized`：

- 检查是否传入 `Authorization: Bearer <access_token>`。
- 检查 token 是否过期。

配置写入返回 `encrypted_value: could not be decrypted`：

- 检查请求中的 `encrypted_value` 是否由当前用户公钥加密。
- 检查 `algorithm` 是否为 `RSA-OAEP-SHA256+A256GCM`。

内网查询返回空列表：

- 检查 `X-Config-User-ID`、`project_id` 和 `environment` 是否匹配。
- 检查配置状态是否为 `enabled`，且未被删除。
