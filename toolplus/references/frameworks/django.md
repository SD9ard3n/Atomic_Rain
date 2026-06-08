---
name: django
description: Django 目标栈专项 playbook — ORM SQLi 边界 / Template SSTI / Admin / DEBUG=True 泄露 / Middleware 顺序 / 序列化 pickle。Python Web 经典框架。
category: frameworks
tags: [framework, python, django, orm, admin]
---

# Django Playbook

---

## 1. 指纹识别

| 信号 | 含义 |
| :--- | :--- |
| Cookie `csrftoken` / `sessionid` | Django session 默认 |
| `/admin/login/` 200 | Django Admin 默认路径 |
| `Server` 含 `WSGIServer` | runserver dev 模式 |
| `X-Frame-Options: DENY` | Django 默认 XFO |
| 错误页含 DEBUG / `Django Error Page` | DEBUG=True |
| `_csrftoken` field | CSRF 中间件 |
| `/static/admin/` 200 | 静态资源路径 |

---

## 2. 攻击面地图

### 2.1 DEBUG=True (严重 P0)

错误页直接显示:
- SECRET_KEY (用于 cookie/csrf 签名)
- DB credentials
- 文件路径 (BASE_DIR)
- 中间件列表
- 完整 traceback

**触发**: 访问不存在的 URL → 错误页。

### 2.2 Django Admin (`/admin/`)

- 默认路径 `/admin/`,可能改名
- 默认 superuser 弱口令 (`admin/admin` / `admin/django`)
- 一旦登录后台 → 改任何 model

### 2.3 ORM SQLi 边界

```python
User.objects.raw(f"SELECT * FROM users WHERE id={user_id}")   # raw SQLi
User.objects.extra(where=[f"id={user_id}"])                    # extra SQLi
cursor.execute(f"... {user_input} ...")                        # cursor SQLi
User.objects.order_by(user_input)                              # order_by 注入
```

### 2.4 Template SSTI

自定义 filter / tag 可能 RCE;`Engine.from_string(user_input)` → SSTI。

### 2.5 Pickle 反序列化

旧版 / 自定义 session 用 pickle (`SESSION_SERIALIZER = 'PickleSerializer'`) → 任意 RCE。也常在 cache / Celery 中。

### 2.6 Middleware 顺序

`AuthenticationMiddleware` 应在 `CsrfViewMiddleware` 之前;自定义错位可能绕鉴权。

### 2.7 Open Redirect

```python
next_url = request.GET.get('next', '/')
return HttpResponseRedirect(next_url)   # 任意跳转
```

`is_safe_url` 校验常忘用。

### 2.8 FileField 路径遍历

`upload_to` 回调用 `filename` → 路径遍历。

### 2.9 静态文件错配

`STATICFILES_DIRS` + DEBUG=False + WhiteNoise 错配 → 任意文件读。

---

## 3. 高价值入口

1. **DEBUG=True 错误页** (P0 Critical 信息泄露)
2. **`/admin/` + 默认凭证** (P0)
3. **raw() / extra() / cursor SQLi** (P0)
4. **Pickle session deserialize** (P0)
5. **Open Redirect via next=** (P1-P2)
6. **DRF endpoint 无鉴权** (P0)
7. **静态文件错配 → 任意读** (P0)

---

## 4. CVE / 历史漏洞

| CVE | 影响 | 版本 |
| :--- | :--- | :--- |
| CVE-2022-28346 | SQLi via `QuerySet.annotate` | <4.0.3 / <3.2.13 |
| CVE-2021-35042 | SQLi via order_by | < 3.2.4 |
| CVE-2021-44420 | Path traversal | < 3.2.10 |
| CVE-2020-7471 | StringAgg SQLi | < 3.0.3 |
| CVE-2019-19844 | Account takeover (password reset) | < 2.2.9 |
| CVE-2024-24680 | DoS via intcomma | < 5.0.2 |

---

## 5. 系统化 Recon

```bash
# DEBUG=True 探测
curl https://target/non-existent-xyz | grep -i "DEBUG\|SECRET_KEY"

# Admin 路径
for p in admin admin/ administrator manager django-admin myadmin; do
  curl -s -o /dev/null -w "[$p] %{http_code}\n" https://target/$p
done

# DRF
curl https://target/api/
curl https://target/api/v1/
curl https://target/api/schema/

# 备份 / 配置
for p in .env .git/HEAD settings.py manage.py db.sqlite3; do
  curl -s -o /dev/null -w "[$p] %{http_code}\n" https://target/$p
done
```

---

## 6. 利用链优先级

### 6.1 DEBUG=True
1. 404 触发错误页拉 SECRET_KEY
2. SECRET 拿到 → 伪造 session cookie → 任意账号
3. Critical 报告

### 6.2 Admin
1. 默认凭证 `admin/admin` / `admin/django` / `admin/password`
2. SECRET 伪造 superuser session
3. 后台直接改 DB

### 6.3 raw SQL
走 [vuln/sqli.md](../vuln/sqli.md),sqlmap `-r req.txt`。

### 6.4 DRF API
1. `/api/` browsable API 看 endpoint
2. 测无 token 访问 (BFLA)
3. JWT 测试 → [vuln/jwt-advanced.md](../vuln/jwt-advanced.md)
4. 改 `pk=` (BOLA)

---

## 7. False Positives

| 现象 | 真实判断 |
| :--- | :--- |
| DEBUG 页面但是 staging | 看域名 / 资产归属 |
| `/admin/` 重定向 | 正常,测登录 |
| csrftoken 存在但 endpoint 用 `@csrf_exempt` | 找哪些标注 exempt |
| SECRET_KEY 是 placeholder | 看是否真随机 50 字符 |

---

## 8. Impact 证据

| 漏洞 | Impact | 证据 |
| :--- | :--- | :--- |
| DEBUG=True + SECRET | 账号接管 | 错误页脱敏截图 |
| Admin 默认凭证 | 后台接管 | 登录截图 |
| raw SQLi | 全库读 | sqlmap 脱敏 |
| Pickle deserialize | RCE | OOB callback |
| 静态文件任意读 | 文件读 | /etc/passwd 前 3 行 |

---

## 9. Pro Tips

- **`/admin/` 改名**: `path('admin-x9/', admin.site.urls)` — ffuf 找
- **DEBUG 触发**: 畸形 URL / 不存在 path / 强制 500
- **SECRET 伪造 session**: `python manage.py shell` 用 SECRET 签 session cookie
- **DRF 默认 browsable API**: 浏览器直接看 + 测试
- **`@csrf_exempt`**: 找标注的 endpoint (高 ROI)
- **Django Channels (WebSocket)**: 鉴权常忽略
- **数据库 Field Lookup**: `__startswith` / `__contains` 配合 raw SQL 可注入
- **国内场景少**: 主要创业 / 教育 / 政府站
- **大学站点常 Django**: 学校 SRC

---

## 10. 工具升级线

**classic 版**:
- DEBUG 探测: curl + grep
- Admin 路径: `ffuf -w admin-paths.txt`
- SQLi: sqlmap
- Pickle: Python `pickle.dumps` 手构造

**toolPlus 版**:
- `mcp__yaklang__http_fuzzer` sweep admin 变体
- `mcp__yaklang__ssa_compile language="python"` + SyntaxFlow 找 raw SQL / pickle.loads sink

---

## 11. 相关参考

- 通用 vuln: [../vuln/](../vuln/)
- SQLi: [../vuln/sqli.md](../vuln/sqli.md)
- 反序列化 (Pickle): [../vuln/deserialize.md](../vuln/deserialize.md)
- SSTI: [../vuln/ssti.md](../vuln/ssti.md)
- Open Redirect (走 csrf-clickjacking): [../vuln/csrf-clickjacking.md](../vuln/csrf-clickjacking.md)
- BOLA / BFLA: [../api-security.md](../api-security.md)
- 路径遍历: [../vuln/path-traversal.md](../vuln/path-traversal.md)
- 信息收集: [../recon.md](../recon.md)
