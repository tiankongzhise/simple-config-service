# simple-config-service 用户使用指南

这份指南从零开始演示如何启动服务、注册账号、登录、管理配置，以及如何通过内网查询接口获取密文配置。

## 1. 准备环境

你需要先准备：

- Go 1.24 或更高版本。
- PostgreSQL 13 或更高版本。
- 一个可以连接 PostgreSQL 的数据库用户。

示例数据库初始化 SQL：

```sql
CREATE DATABASE config_service;
CREATE USER config_service WITH PASSWORD 'change-me';
GRANT ALL PRIVILEGES ON DATABASE config_service TO config_service;
```

如果你的 PostgreSQL 对 public schema 权限收得比较紧，还需要连接到 `config_service` 数据库后执行：

```sql
GRANT ALL ON SCHEMA public TO config_service;
```

## 2. 配置 .env

复制示例配置：

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
config_master_key=0123456789abcdef0123456789abcdef
config_key_id=default

public_listen_addr=0.0.0.0:8080
internal_listen_addr=127.0.0.1:8081
jwt_ttl=24h
```

重要说明：

- `invite_code` 是注册邀请码，没有邀请码不能注册。
- `jwt_secret` 至少 16 字节，生产环境要使用随机强密钥。
- `config_master_key` 必须是 32 字节密钥、64 位十六进制字符串，或 32 字节内容的 base64 编码。
- `internal_listen_addr` 建议只绑定内网地址，例如 `127.0.0.1:8081` 或内网网卡地址。

## 3. 启动服务

执行：

```powershell
go run ./cmd/config-service
```

看到类似日志说明启动成功：

```text
server listening name=public addr=0.0.0.0:8080
server listening name=internal addr=127.0.0.1:8081
```

服务第一次启动时会自动创建数据库表，不需要手工执行迁移文件。

## 4. 检查健康状态

公网管理服务：

```powershell
curl http://127.0.0.1:8080/healthz
```

内网查询服务：

```powershell
curl http://127.0.0.1:8081/healthz
```

正常响应：

```json
{"status":"ok"}
```

## 5. 注册账号

注册时必须使用 `.env` 中配置的邀请码：

```powershell
curl -X POST http://127.0.0.1:8080/api/register `
  -H "Content-Type: application/json" `
  -d "{\"username\":\"alice\",\"password\":\"password123\",\"invite_code\":\"my-invite-code\"}"
```

成功后会返回 `access_token` 和用户信息。记录返回中的：

- `access_token`：后续管理接口要使用。
- `user.id`：内网查询接口需要通过 `X-Config-User-ID` 传递。

PowerShell 中可以先保存 token：

```powershell
$token = "<access_token>"
$userId = "<user.id>"
```

## 6. 登录账号

已有账号可以直接登录：

```powershell
curl -X POST http://127.0.0.1:8080/api/login `
  -H "Content-Type: application/json" `
  -d "{\"username\":\"alice\",\"password\":\"password123\"}"
```

如果密码错误，会返回 `401 unauthorized`。

## 7. 创建配置

创建一条生产环境配置：

```powershell
curl -X POST http://127.0.0.1:8080/api/configs `
  -H "Content-Type: application/json" `
  -H "Authorization: Bearer $token" `
  -d "{\"key\":\"db.password\",\"value\":\"secret-password\",\"application\":\"order-service\",\"environment\":\"prod\",\"description\":\"订单服务数据库密码\",\"status\":\"enabled\"}"
```

响应里不会出现明文 `secret-password`，只会出现：

- `value_ciphertext`
- `encrypted_data_key`
- `nonce`
- `data_key_nonce`
- `algorithm`
- `key_id`

这说明配置已经加密落库。

## 8. 查询配置列表

```powershell
curl "http://127.0.0.1:8080/api/configs?application=order-service&environment=prod" `
  -H "Authorization: Bearer $token"
```

这个接口是给管理后台使用的，仍然只返回密文，不返回明文。

## 9. 更新配置

先从列表响应中找到配置 `id`，然后更新：

```powershell
$configId = "<config.id>"

curl -X PUT "http://127.0.0.1:8080/api/configs/$configId" `
  -H "Content-Type: application/json" `
  -H "Authorization: Bearer $token" `
  -d "{\"key\":\"db.password\",\"value\":\"new-secret-password\",\"application\":\"order-service\",\"environment\":\"prod\",\"description\":\"更新后的数据库密码\",\"status\":\"enabled\"}"
```

每次更新都会让 `version` 增加，并写入版本历史。

## 10. 查看版本历史

```powershell
curl "http://127.0.0.1:8080/api/configs/$configId/versions" `
  -H "Authorization: Bearer $token"
```

版本历史可以用于审计和回滚。

## 11. 回滚配置

回滚到版本 1：

```powershell
curl -X POST "http://127.0.0.1:8080/api/configs/$configId/rollback" `
  -H "Content-Type: application/json" `
  -H "Authorization: Bearer $token" `
  -d "{\"version\":1}"
```

回滚不会覆盖历史记录，而是生成一个新的当前版本。

## 12. 禁用或删除配置

禁用配置可以通过更新 `status` 实现：

```powershell
curl -X PUT "http://127.0.0.1:8080/api/configs/$configId" `
  -H "Content-Type: application/json" `
  -H "Authorization: Bearer $token" `
  -d "{\"key\":\"db.password\",\"value\":\"new-secret-password\",\"application\":\"order-service\",\"environment\":\"prod\",\"description\":\"临时禁用\",\"status\":\"disabled\"}"
```

软删除配置：

```powershell
curl -X DELETE "http://127.0.0.1:8080/api/configs/$configId" `
  -H "Authorization: Bearer $token"
```

被禁用或删除的配置不会出现在内网查询接口中。

## 13. 通过内网接口查询配置

前置鉴权网关完成鉴权后，应把用户 ID 传给配置中心：

```powershell
curl "http://127.0.0.1:8081/internal/configs?application=order-service&environment=prod" `
  -H "X-Config-User-ID: $userId"
```

响应示例：

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
      "version": 2,
      "updated_at": "2026-05-21T10:00:00Z"
    }
  ]
}
```

注意：这个接口不会返回明文配置。

## 14. 客户端解密思路

业务方拿到内网查询接口返回的密文后，需要在客户端或业务 SDK 中解密。

解密需要：

- `.env` 中对应的 `config_master_key`。
- 接口返回的 `value_ciphertext`。
- 接口返回的 `encrypted_data_key`。
- 接口返回的 `nonce`。
- 接口返回的 `data_key_nonce`。
- 接口返回的 `algorithm`。
- 接口返回的 `key_id`。

仓库中已经提供了解密逻辑，位置是 `pkg/configcrypto`。同一个 Go 项目中可按下面方式使用：

```go
payload := configcrypto.Payload{
    ValueCiphertext:  "...",
    EncryptedDataKey: "...",
    Nonce:            "...",
    DataKeyNonce:     "...",
    Algorithm:        "AES-256-GCM",
    KeyID:            "default",
}

masterKey, err := configcrypto.ParseMasterKey("0123456789abcdef0123456789abcdef")
if err != nil {
    panic(err)
}

plaintext, err := configcrypto.Decrypt(masterKey, payload)
if err != nil {
    panic(err)
}
fmt.Println(string(plaintext))
```

生产环境建议封装一个业务 SDK，由 SDK 负责：

- 调用内网查询接口。
- 缓存配置。
- 解密配置。
- 处理查询失败、解密失败和配置不存在等错误。

## 15. 常见问题

注册返回 `403 forbidden`：

- 检查请求里的 `invite_code` 是否和 `.env` 完全一致。

接口返回 `401 unauthorized`：

- 检查是否传了 `Authorization: Bearer <access_token>`。
- 检查 token 是否过期。

内网查询返回空列表：

- 检查 `X-Config-User-ID` 是否是正确用户 ID。
- 检查 `application` 和 `environment` 是否匹配。
- 检查配置状态是否为 `enabled`。
- 检查配置是否已被删除。

服务启动失败：

- 检查 PostgreSQL 是否可连接。
- 检查 `.env` 是否包含所有必填项。
- 检查 `config_master_key` 是否是合法 32 字节密钥。

数据库里看不到明文配置：

- 这是预期行为。配置值只会以密文形式保存。
