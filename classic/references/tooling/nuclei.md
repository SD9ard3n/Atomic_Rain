---
name: nuclei
description: nuclei 实战 playbook — 模板驱动 CVE 扫描 / 自定义模板 / 速率限制 / 误报过滤 / 实战 recipe 8 个。Phase 1-2 主要侦察工具。
category: tooling
tags: [tool, scanner, cve, nuclei, classic]
---

# nuclei Playbook (classic only)

> **何时用本文件**: Phase 1 资产侦察 / Phase 2 CVE 命中扫描。模板驱动,速度快,误报率比 xray 低。
> **toolPlus 替代**: `mcp__yaklang__http_fuzzer` + 自定义 fuzztag (适合更精准的 PoC)。
> **强制约束**: 大规模目标先 HITL 确认范围与速率。

---

## 1. 配置

```yaml
# tool-config.md
nuclei: "/path/to/nuclei/"
nuclei_templates: "/path/to/nuclei-templates/"
```

定期更新模板: `nuclei -ut` (每次启动前可跑一次)。

---

## 2. 八大典型 Recipe

### 2.1 单目标全量扫 (慎用)

```bash
nuclei -u https://target.com -severity critical,high -rate-limit 50
# -rate-limit 限速,避免 WAF / 触发风控
```

### 2.2 批量子域 (Phase 1 推荐)

```bash
nuclei -l subdomains.txt -severity critical,high,medium \
  -rate-limit 100 -bulk-size 25 -concurrency 10 -timeout 5
```

### 2.3 指定模板分类

```bash
nuclei -u https://target.com -t exposures/             # 文件暴露
nuclei -u https://target.com -t cves/2023/             # 2023 年 CVE
nuclei -u https://target.com -t default-logins/        # 默认凭证
nuclei -u https://target.com -t misconfiguration/      # 错配
nuclei -u https://target.com -t exposed-panels/        # 后台面板
nuclei -u https://target.com -t technologies/spring*   # 技术栈针对
```

### 2.4 国内常见高 ROI 模板

```bash
# 国内框架/中间件
nuclei -u https://target -t technologies/thinkphp* -t technologies/spring* \
       -t technologies/shiro* -t technologies/jboss* \
       -t exposed-panels/druid* -t exposed-panels/nacos*

# Actuator + Druid + Nacos (Spring Cloud Alibaba 经典三件套)
nuclei -u https://target -t exposed-panels/spring-boot-actuator* \
       -t exposed-panels/druid-* -t default-logins/nacos*
```

### 2.5 自定义模板 (写一次,反复跑)

```yaml
# my-template.yaml
id: my-actuator-env-check
info:
  name: Actuator /env Exposure
  severity: high

requests:
  - method: GET
    path:
      - "{{BaseURL}}/actuator/env"
      - "{{BaseURL}}/manage/env"
      - "{{BaseURL}}/management/env"
    matchers:
      - type: word
        words:
          - "activeProfiles"
          - "propertySources"
        condition: and
      - type: status
        status:
          - 200
```

```bash
nuclei -u https://target -t my-template.yaml
```

### 2.6 输出 JSON (供脚本消费)

```bash
nuclei -u https://target -severity critical,high -o results.txt -json
# 或写 JSON line
nuclei -u https://target -jsonl -o results.jsonl
```

### 2.7 走代理 + 排除噪音模板

```bash
nuclei -u https://target \
  -proxy http://127.0.0.1:8080 \
  -etags ssl,info,osint \
  -severity critical,high
# 排除 ssl / info / osint 类 (大量无用噪音)
```

### 2.8 配合 fuzzing 模板

```bash
nuclei -u https://target -t fuzzing-templates/        # 通用 fuzz
nuclei -u https://target -t fuzzing/sqli-detection.yaml -dast
```

---

## 3. atomic-rain 协议集成

| 阶段 | 动作 |
| :--- | :--- |
| Phase 1 | 子域批量扫,只看 critical/high 命中 |
| Phase 2 First-pass | 针对性模板 (技术栈 + 中间件) |
| Phase 2 中 | 自定义模板验证业务漏洞 (写到 `my-templates/`) |
| Phase 4 报告 | 截图 + 模板 ID + 触发证据 |

**OPSEC**: nuclei 默认 UA 含 "Nuclei" 字符串 → 大目标必改 `-H 'User-Agent: Mozilla/5.0...'`。

---

## 4. 速率与 OPSEC

| 场景 | 速率配置 |
| :--- | :--- |
| 单目标精扫 | `-rate-limit 10 -concurrency 5` |
| 批量子域 | `-rate-limit 100 -bulk-size 25 -concurrency 10` |
| 国内云目标 (WAF 严) | `-rate-limit 5 -timeout 10` |
| 红队隐蔽 | `-rate-limit 1 -delay 3s` |

WAF 触发后:
- 暂停 30 分钟
- 改 UA / 走不同源 IP
- 减小 `-rate-limit` / 加 `-delay`

---

## 5. False Positives

| 现象 | 真实判断 |
| :--- | :--- |
| nuclei 报 actuator 暴露但访问 404 | 模板匹配过宽 (只看 200) — 手访问确认 |
| 报 default-login 但实际登录失败 | 业务侧已改密但 banner 没改 — 手测 |
| Critical 命中但 PoC 无法复现 | 模板更新后语义变化 — 看 GitHub issue |
| 同一 CVE 报告多次 | 多模板覆盖同 CVE — 去重 |
| 信息泄露但内容已脱敏 | 误判,影响有限 — 记录但降级 |

---

## 6. Pro Tips

- **每天 `-ut`**: 模板更新很快,新 CVE 模板及时拉
- **`-validate` 写完模板先验证语法**: 避免运行时报错
- **`-include-tags` 配合实战**: `-include-tags java` 只跑 Java 相关
- **`-passive`**: 只读响应不主动发 — 与 ZAP 类似
- **结合 httpx**: `httpx -l urls.txt -title -tech-detect | nuclei` 先过滤再扫
- **`-self-contained`**: 包含完整 HTTP 请求 (含 Host header) — 适合反代/CDN 后端测试
- **国内云目标**: 加 `-H 'CDN-Real-IP: <真实 IP>'` 跳 CDN
- **`-interactsh-url`**: 自建 OOB,不要默认走 oast.fun
- **不要扫域名通配符**: 一不小心扫上千域名,触发风控

---

## 7. 模板贡献

发现新漏洞 → 写模板提交 nuclei-templates 仓库 → 社区 + 简历加分。

---

## 8. 相关参考

- 决策卡 / 漏洞类: [../vuln/](../vuln/)
- 资产侦察: [../recon.md](../recon.md)
- OOB 自建: [../oob-infrastructure.md](../oob-infrastructure.md)
- WAF 绕过: [../waf-bypass.md](../waf-bypass.md)
- 框架专项: [../frameworks/spring-boot.md](../frameworks/spring-boot.md)
