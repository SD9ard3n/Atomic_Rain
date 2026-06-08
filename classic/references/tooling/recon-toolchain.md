---
name: recon-toolchain
description: 侦察工具链 playbook (classic) — subfinder + amass + httpx + katana + naabu + nmap 组合 SOP。Phase 1 一步到位拿资产树。
category: tooling
tags: [tool, recon, subdomain, port-scan, classic]
---

# 侦察工具链 Playbook (classic only)

> **何时用本文件**: Phase 1 资产测绘。subfinder → httpx → katana → nuclei 一条流水线。
> **toolPlus 替代**: `mcp__yaklang__subdomain_collection` / `mcp__yaklang__port_scan` / `mcp__yaklang__web_crawler` 等 MCP 工具。

---

## 1. 配置

```yaml
# tool-config.md
subfinder: "/path/to/subfinder/"
amass: "/path/to/amass/"
httpx: "/path/to/httpx/"
katana: "/path/to/katana/"
naabu: "/path/to/naabu/"
nmap: "/path/to/nmap/"
masscan: "/path/to/masscan/"
gospider: "/path/to/gospider/"
```

---

## 2. 子域名收集 (subfinder + amass)

### 2.1 快速 (subfinder)

```bash
subfinder -d target.com -all -recursive -o subs.txt
# -all 用所有 source (含 API key)
# -recursive 二级子域
```

### 2.2 深度 (amass)

```bash
amass enum -d target.com -active -brute \
  -w SecLists/Discovery/DNS/n0kovo_subdomains_huge.txt \
  -src -o amass.txt
# -active 主动扫(DNS 解析验证)
# -brute 暴力枚举
```

### 2.3 整合

```bash
cat subs.txt amass.txt | sort -u > all-subs.txt
# 通常 1000-50000 条
```

**P3.5 OPSEC**: 大目标 (>10k 子域) 主动扫前 HITL 确认范围与速率。

---

## 3. 存活探测 (httpx)

```bash
httpx -l all-subs.txt \
  -title -tech-detect -status-code \
  -threads 50 -rate-limit 100 -timeout 5 \
  -o alive.txt -json -o alive.jsonl
# 同时拿 title / 技术栈 / 状态码
```

输出示例:
```
https://prod.target.com [200] [Login Page] [nginx,Vue.js]
https://admin.target.com [403] [Forbidden] [Apache,Tomcat]
```

### 高 ROI 过滤

```bash
# 只看 admin / login / api
httpx -l alive.txt -mc 200,401,403 \
  -match-string "admin,login,api,console,manage,dashboard,monitor"

# 只看 Spring / Java
httpx -l alive.txt -tech-detect | grep -iE "spring|tomcat|jboss|weblogic"
```

---

## 4. 端口扫描 (naabu + nmap)

### 4.1 快扫 (naabu)

```bash
naabu -l alive.txt -top-ports 1000 -rate 1000 -o ports.txt
# top-1000 端口快扫
```

### 4.2 精扫 (nmap)

```bash
# 单目标精扫
nmap -sV -sC -T4 -p- target.com -oN nmap.txt
# 拿到服务版本 + 默认脚本

# 高危端口针对性
nmap -sV --script=banner -p 21,22,80,443,3306,3389,6379,8080,8443,9200,11211,27017,15672 target.com
```

### 4.3 大网段 (masscan)

```bash
# 警告: 大量包,易触发风控,**必须 HITL 范围确认**
masscan 10.0.0.0/16 -p 80,443,8080,8443 --rate=1000 -oG out.txt
```

---

## 5. 爬虫 (katana / gospider)

### 5.1 katana (推荐)

```bash
katana -u https://target.com \
  -d 3 -jc -kf all -fx \
  -o crawl.txt
# -d 深度,-jc JS 内 URL,-kf 关注 keywords
# -fx 拉所有外链
```

### 5.2 gospider

```bash
gospider -s https://target.com -d 3 -c 10 -t 20 \
  --js --sitemap --robots -o output/
```

### 5.3 JS 提取 URL

```bash
katana -u https://target.com -jc -o all-urls.txt
# 自动从 JS 文件抓 URL,弥补单纯爬虫漏掉的 SPA endpoint
```

---

## 6. 整合流水线

```bash
# 一行打通
TARGET=target.com
subfinder -d $TARGET -all -silent | \
  httpx -silent -title | tee alive.txt | \
  awk '{print $1}' | \
  katana -silent -d 2 | tee urls.txt | \
  nuclei -severity high,critical -silent -o vuln.txt
```

或者分阶段:
```bash
# Phase 1a: 子域
subfinder -d $TARGET -all -o subs.txt

# Phase 1b: 存活
httpx -l subs.txt -title -tech-detect -o alive.txt

# Phase 1c: 端口
naabu -l alive.txt -top-ports 100 -o ports.txt

# Phase 1d: 爬虫
katana -list alive.txt -d 2 -o crawl.txt

# Phase 1e: 漏洞扫
nuclei -l alive.txt -severity high,critical -o nuclei.txt
```

---

## 7. atomic-rain 协议集成

| 阶段 | 工具 | 输出 |
| :--- | :--- | :--- |
| Phase 1 Recon (M0.4) | subfinder + amass | assets.md `## 子域` |
| Phase 1 存活 (M0.5) | httpx | assets.md `## 存活` |
| Phase 1 指纹 (M0.6) | httpx -tech | assets.md `## 技术栈` |
| Phase 1 端口 (M0.7) | naabu / nmap | assets.md `## 端口` |
| Phase 1 爬虫 (M0.8) | katana / gospider | assets.md `## 端点` |
| Phase 1 漏扫 (M0.9) | nuclei | nuclei.txt → vulns.md |

**禁止**: 一次性跑 nuclei + masscan 大网段扫,极易触发风控。

---

## 8. OPSEC 速率配置

| 目标规模 | subfinder | httpx | nuclei |
| :--- | :--- | :--- | :--- |
| 单站 (< 50 子域) | 默认 | `-threads 30` | `-rate 50` |
| 中型 (50-1000) | `-all` | `-threads 50` | `-rate 100 -bulk-size 25` |
| 大型 (1000+) | `-all -recursive` | `-threads 100 -rate-limit 200` | `-rate 200 -bulk-size 50` |
| 国内云目标 | 默认 | `-threads 20` | `-rate 30 -timeout 10` |

WAF 触发 → 暂停 30 分钟 + 改 UA + 减速。

---

## 9. Pro Tips

- **subfinder + amass 双跑**: 单工具漏报多,合并去重
- **httpx -tech-detect**: 比 wappalyzer 命中更全,优先用
- **katana -jc 必开**: 不爬 JS 内 URL 等于漏掉 50% SPA endpoint
- **naabu 比 masscan 安全**: 速率默认低,适合内网外网都用
- **nmap `-sC` 默认脚本**: 拿到 banner + 服务版本一次性
- **CDN 后端真实 IP**: 配合 `securitytrails` / 历史 DNS / Censys 找
- **`api.shodan.io` / `fofa.so` / `quake.360.cn`** API 集成: 比子域工具更深度
- **GitHub dorks**: `"target.com" "password"` `"target.com" "AKIA"` — 常补漏
- **路径分组**: 把 alive.txt 按子域分组 (`prod.*` / `staging.*` / `dev.*`) 不同优先级

---

## 10. 相关参考

- 信息收集主入口: [../recon.md](../recon.md)
- 漏扫工具: [nuclei.md](nuclei.md)
- 后端站专项: [../recon.md §9](../recon.md)
- 工具配置: [../tool-config.md](../tool-config.md)
- 项目工作流: [../project-workflow.md](../project-workflow.md)
