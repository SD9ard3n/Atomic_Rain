# Grep 命令速查中心

> 只保留最高频入口；细节直接读对应 reference。路径以 skill 根目录为基准。

## 1. 总入口
```bash
# Phase / 工具 / 报告
grep -A 40 "Phase 1" references/phase-guide.md
grep -A 30 "工具强制加载" references/phase-guide.md
grep -A 30 "标准漏洞条目模板" references/report-template.md

# 判断协议
grep -A 20 "快速判断法" references/sensitivity-matrix.md
grep -A 20 "验证动作" references/sensitive-info-exploitation.md
grep -A 20 "判断流程" references/resource-classification.md
grep -A 20 "触发规则映射表" references/intuition-triggers.md
grep -A 15 "级联优先级" references/chained-logic-extended.md
```

## 2. 漏洞 Decision Card
```bash
grep -A 30 "Decision Card" references/vuln/sqli.md
grep -A 30 "Decision Card" references/vuln/xss.md
grep -A 30 "Decision Card" references/vuln/ssrf.md
grep -A 30 "Decision Card" references/vuln/shiro.md
grep -A 30 "Decision Card" references/vuln/spring-vuln.md
grep -A 30 "Decision Card" references/vuln/jwt-advanced.md
grep -A 30 "Decision Card" references/vuln/fastjson-jackson.md
```

## 3. 构造思路 / 场景库
```bash
grep -A 25 "思路 1" references/payload-construction/sqli-construction.md
grep -A 25 "思路 1" references/payload-construction/jwt-construction.md
grep -A 25 "思路 1" references/payload-construction/bola-construction.md
grep -A 20 "NoSQL" references/vuln/sqli-scenarios.md
grep -A 20 "Blind XSS" references/vuln/xss-scenarios.md
grep -A 20 "Gopher" references/vuln/ssrf-scenarios.md
```

## 4. 专项协议
```bash
grep -A 20 "国际 / 英文 SaaS" references/weak-password-generation.md
grep -A 20 "有限制站" references/weak-password-generation.md
grep -A 20 "interactsh" references/oob-infrastructure.md
grep -A 20 "硬性触发" references/human-in-the-loop.md
grep -A 20 "后端站专用协议" references/recon.md
```
