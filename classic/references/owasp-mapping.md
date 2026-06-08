---
name: owasp-mapping
description: 写报告时请使用标准编号, 提升专业度与可追溯性。 赏金/SRC 平台越来越接受 OWASP 编号分级, 企业甲方对 CWE 有硬性要求。
category: methodology
---

# OWASP / CWE 编号映射参考

> 写报告时请使用标准编号, 提升专业度与可追溯性。
> 赏金/SRC 平台越来越接受 OWASP 编号分级, 企业甲方对 CWE 有硬性要求。

---

## 一、OWASP Web Security Testing Guide (WSTG) v4.2

### 1.1 WSTG 分类前缀

| 前缀 | 全称 | 中文 |
|------|------|------|
| WSTG-INFO | Information Gathering | 信息收集 |
| WSTG-CONFIG | Configuration and Deployment Management Testing | 配置与部署 |
| WSTG-IDNT | Identity Management Testing | 身份管理 |
| WSTG-ATHN | Authentication Testing | 认证 |
| WSTG-ATHZ | Authorization Testing | 授权 |
| WSTG-SESS | Session Management Testing | 会话管理 |
| WSTG-INPV | Input Validation Testing | 输入验证 |
| WSTG-ERRH | Error Handling | 错误处理 |
| WSTG-CRYP | Cryptography | 密码学 |
| WSTG-BUSLOGIC | Business Logic Testing | 业务逻辑 |
| WSTG-CLNT | Client-side Testing | 客户端 |
| WSTG-APIT | API Testing | API |

### 1.2 常用漏洞 → WSTG 编号

| 漏洞 | WSTG | 说明 |
|------|------|------|
| SQL 注入 | WSTG-INPV-05 | SQL Injection |
| XSS(反射) | WSTG-INPV-01 | Reflected XSS |
| XSS(存储) | WSTG-INPV-02 | Stored XSS |
| DOM XSS | WSTG-CLNT-01 | DOM-based XSS |
| 命令注入 | WSTG-INPV-12 | OS Command Injection |
| SSRF | WSTG-INPV-19 | Server-Side Request Forgery |
| XXE | WSTG-INPV-07 | XML Injection |
| SSTI | WSTG-INPV-18 | Server-side Template Injection |
| Code Injection | WSTG-INPV-11 | Code Injection / 反序列化 |
| LDAP 注入 | WSTG-INPV-06 | LDAP Injection |
| NoSQL 注入 | WSTG-INPV-05(扩展) | NoSQL Injection |
| 文件上传 | WSTG-BUSLOGIC-09 | Upload Dangerous Files |
| 路径遍历 | WSTG-INPV-13 | HTTP Splitting Smuggling / Path Traversal |
| HTTP 走私 | WSTG-INPV-15 | HTTP Splitting/Smuggling |
| Host 头攻击 | WSTG-CONFIG-07 | Host Header Attack |
| CORS 错误配置 | WSTG-CLNT-07 | CORS Misconfiguration |
| CSRF | WSTG-SESS-05 | Testing for CSRF |
| Clickjacking | WSTG-CLNT-09 | Testing for Clickjacking |
| 会话固定 | WSTG-SESS-03 | Session Fixation |
| 会话劫持 | WSTG-SESS-09 | Session Hijacking |
| 登出功能 | WSTG-SESS-06 | Logout Functionality |
| JWT 攻击 | WSTG-SESS-10 | JSON Web Token |
| 账号枚举 | WSTG-IDNT-04 | Account Enumeration |
| 默认凭证 | WSTG-ATHN-02 | Default Credentials |
| 弱锁定 | WSTG-ATHN-03 | Lockout Mechanism |
| 认证绕过 | WSTG-ATHN-04 | Bypass Authentication |
| 弱密码策略 | WSTG-ATHN-07 | Weak Password Policy |
| 密码重置漏洞 | WSTG-ATHN-09 | Weaker Authentication in Alternative Channel |
| 目录遍历 (Authz) | WSTG-ATHZ-01 | Directory Traversal / Authz Schema |
| 鉴权绕过 | WSTG-ATHZ-02 | Bypass Authorization |
| 权限提升 | WSTG-ATHZ-03 | Privilege Escalation / BFLA |
| IDOR / BOLA | WSTG-ATHZ-04 | Insecure Direct Object References |
| 业务流程 | WSTG-BUSLOGIC-02 | Ability to Forge Requests |
| 条件竞争 | WSTG-BUSLOGIC-07 | Testing for Process Timing |
| 支付/逻辑 | WSTG-BUSLOGIC-06 | Circumvention of Work Flows |
| 功能滥用 | WSTG-BUSLOGIC-08 | Defenses Against App Misuse |
| 弱 TLS | WSTG-CRYP-01 | Weak Transport Layer Security |
| Padding Oracle | WSTG-CRYP-02 | Padding Oracle |
| 信息泄露(错误) | WSTG-ERRH-01 | Error Code |
| 堆栈跟踪泄露 | WSTG-ERRH-02 | Stack Traces |
| 子域名接管 | WSTG-CONFIG-10 | DNS Subdomain Takeover |
| 备份文件 | WSTG-CONFIG-04 | Backup and Unreferenced Files |
| HTTP方法滥用 | WSTG-CONFIG-06 | HTTP Methods |

---

## 二、CWE (Common Weakness Enumeration)

### 2.1 高频 CWE 速查

| CWE | 漏洞类型 |
|-----|----------|
| CWE-20 | Improper Input Validation |
| CWE-22 | Path Traversal |
| CWE-23 | Relative Path Traversal |
| CWE-74 | Injection |
| CWE-77 | Command Injection |
| CWE-78 | OS Command Injection |
| CWE-79 | Cross-Site Scripting (XSS) |
| CWE-80 | Basic XSS |
| CWE-87 | Alternate XSS Syntax |
| CWE-89 | SQL Injection |
| CWE-90 | LDAP Injection |
| CWE-91 | XML Injection |
| CWE-94 | Code Injection |
| CWE-95 | Eval Injection |
| CWE-98 | PHP File Inclusion (RFI/LFI) |
| CWE-116 | Improper Encoding or Escaping of Output |
| CWE-200 | Information Exposure |
| CWE-201 | Information Exposure Through Sent Data |
| CWE-209 | Error Message with Sensitive Info |
| CWE-269 | Improper Privilege Management |
| CWE-284 | Improper Access Control / 未授权 |
| CWE-285 | Improper Authorization / BFLA |
| CWE-287 | Improper Authentication |
| CWE-290 | Authentication Bypass by Spoofing |
| CWE-294 | Authentication Bypass by Capture-replay |
| CWE-306 | Missing Authentication for Critical Function |
| CWE-326 | Inadequate Encryption Strength |
| CWE-327 | Broken Crypto Algorithm |
| CWE-330 | Use of Insufficiently Random Values |
| CWE-345 | Insufficient Verification of Data Authenticity |
| CWE-347 | Improper Verification of Cryptographic Signature / JWT |
| CWE-350 | Reliance on Reverse DNS / 子域名接管相关 |
| CWE-352 | CSRF |
| CWE-362 | Race Condition |
| CWE-384 | Session Fixation |
| CWE-400 | Resource Exhaustion / DoS |
| CWE-434 | Unrestricted File Upload |
| CWE-444 | HTTP Request Smuggling |
| CWE-502 | Deserialization of Untrusted Data |
| CWE-601 | Open Redirect |
| CWE-611 | XXE (XML External Entity) |
| CWE-639 | IDOR / BOLA |
| CWE-640 | Weak Password Recovery |
| CWE-643 | XPath Injection |
| CWE-693 | Protection Mechanism Failure / CORS |
| CWE-798 | Hard-coded Credentials |
| CWE-840 | Business Logic Errors |
| CWE-863 | Incorrect Authorization |
| CWE-915 | Mass Assignment |
| CWE-918 | SSRF |
| CWE-940 | Improper Verification of Source |
| CWE-1004 | Sensitive Cookie Without HttpOnly |
| CWE-1021 | Clickjacking |
| CWE-1236 | CSV Formula Injection |
| CWE-1321 | Prototype Pollution |
| CWE-1333 | ReDoS |
| CWE-1336 | SSTI |
| CWE-1390 | Weak Authentication |

---

## 三、OWASP Top 10 for LLM Applications 2025

| 编号 | 风险 | CWE 对照 | 典型场景 |
|------|------|----------|----------|
| LLM01 | Prompt Injection | CWE-1427 | 直接注入指令覆盖 / 间接注入(RAG/外部API) |
| LLM02 | Sensitive Information Disclosure | CWE-200 | System Prompt 泄露 / 训练数据外泄 |
| LLM03 | Supply Chain | CWE-1357 | 恶意模型 / 框架供应链 / Pickle RCE |
| LLM04 | Data and Model Poisoning | CWE-1426 | 训练数据投毒 / RAG 投毒 |
| LLM05 | Improper Output Handling | CWE-116 | LLM 输出→XSS/SQL/命令, 未过滤 |
| LLM06 | Excessive Agency | CWE-250 | Agent 工具权限过大 |
| LLM07 | System Prompt Leakage | CWE-540 | System Prompt 暴露 |
| LLM08 | Vector and Embedding Weaknesses | — | 向量数据库污染 / 嵌入泄露 |
| LLM09 | Misinformation | — | 幻觉 / 虚假信息输出 |
| LLM10 | Unbounded Consumption | CWE-400 | LLM 资源耗尽 / DoS |

---

## 四、OWASP Agentic AI Security Top 10 (ASI) 2026

| 编号 | 风险 | 典型攻击 |
|------|------|----------|
| ASI01 | Goal Hijacking | 目标劫持: 直接/间接注入让 Agent 执行非预期操作 |
| ASI02 | Tool Misuse | 工具滥用: 参数注入 / description 投毒 / 权限越界 |
| ASI03 | Identity and Permissions | 身份权限: Agent Token 管理 / 权限边界 / 凭据保护 |
| ASI04 | Supply Chain | 供应链: MCP Server 来源 / Skill 审计 / 依赖安全 |
| ASI05 | Code Execution | 代码执行: 沙箱逃逸 / 命令注入 / 文件写入 |
| ASI06 | Memory Poisoning | 记忆投毒: 上下文持久化攻击 / 状态腐败 / 历史注入 |
| ASI07 | Communication Security | 通信安全: 多 Agent 消息伪造 / 信任传递 / 中间人 |
| ASI08 | Cascading Failures | 级联故障: 单点失败传播 / 故障隔离测试 |
| ASI09 | Trust Exploitation | 信任利用: 输出验证机制 / 人工审批流程缺失 |
| ASI10 | Runaway Agent | 失控 Agent: 行为监控 / 异常检测 / Kill Switch |

---

## 五、OWASP API Security Top 10 2023

| 编号 | 风险 | CWE |
|------|------|-----|
| API1 | Broken Object Level Authorization (BOLA) | CWE-639 |
| API2 | Broken Authentication | CWE-287 / 306 |
| API3 | Broken Object Property Level Authorization | CWE-915 |
| API4 | Unrestricted Resource Consumption | CWE-400 |
| API5 | Broken Function Level Authorization (BFLA) | CWE-285 |
| API6 | Unrestricted Access to Sensitive Business Flows | CWE-840 |
| API7 | Server Side Request Forgery (SSRF) | CWE-918 |
| API8 | Security Misconfiguration | CWE-16 |
| API9 | Improper Inventory Management | CWE-1059 |
| API10 | Unsafe Consumption of APIs | CWE-20 |

---

## 六、OWASP Top 10 2021 (Web Application)

| 编号 | 风险 | 典型漏洞 |
|------|------|----------|
| A01 | Broken Access Control | IDOR / BOLA / 目录遍历 / 未授权 |
| A02 | Cryptographic Failures | 弱 TLS / 硬编码密钥 / 弱哈希 |
| A03 | Injection | SQL / XSS / CMDi / SSTI / XXE |
| A04 | Insecure Design | 文件上传无限制 / 业务逻辑缺失 / 条件竞争 |
| A05 | Security Misconfiguration | 默认密码 / 目录列出 / 详细错误 / 子域名接管 |
| A06 | Vulnerable and Outdated Components | 依赖 CVE / 框架旧版 |
| A07 | Identification and Authentication Failures | 弱密码 / JWT / 会话管理 |
| A08 | Software and Data Integrity Failures | 反序列化 / 原型污染 / CI/CD 供应链 |
| A09 | Security Logging and Monitoring Failures | 日志缺失 |
| A10 | Server-Side Request Forgery (SSRF) | SSRF(独立类别) |

---

## 七、一键映射表 (最常用)

> 写报告时直接复制这段到漏洞条目的 "OWASP 编号" 字段。

```
SQLi:           WSTG-INPV-05 / CWE-89  / A03:2021
XSS-Reflected:  WSTG-INPV-01 / CWE-79  / A03:2021
XSS-Stored:     WSTG-INPV-02 / CWE-79  / A03:2021
DOM-XSS:        WSTG-CLNT-01 / CWE-79  / A03:2021
CMDi:           WSTG-INPV-12 / CWE-78  / A03:2021
SSRF:           WSTG-INPV-19 / CWE-918 / A10:2021 / API7:2023
XXE:            WSTG-INPV-07 / CWE-611 / A05:2021
SSTI:           WSTG-INPV-18 / CWE-1336/ A03:2021
Deserialize:    WSTG-INPV-11 / CWE-502 / A08:2021
File-Upload:    WSTG-BUSLOGIC-09 / CWE-434 / A04:2021
Path-Traversal: WSTG-INPV-13 / CWE-22  / A01:2021
LFI:            WSTG-INPV-13 / CWE-98  / A01:2021
IDOR/BOLA:      WSTG-ATHZ-04 / CWE-639 / A01:2021 / API1:2023
BFLA:           WSTG-ATHZ-03 / CWE-285 / A01:2021 / API5:2023
Mass-Assign:    WSTG-APIT-01 / CWE-915 / A08:2021 / API3:2023
JWT-Attack:     WSTG-SESS-10 / CWE-347 / A02:2021
CSRF:           WSTG-SESS-05 / CWE-352 / A01:2021
Clickjacking:   WSTG-CLNT-09 / CWE-1021/ A05:2021
CORS:           WSTG-CLNT-07 / CWE-693 / A05:2021
Open-Redirect:  WSTG-CLNT-04 / CWE-601 / A01:2021
Race-Condition: WSTG-BUSLOGIC-07 / CWE-362 / A04:2021
HTTP-Smuggling: WSTG-INPV-15 / CWE-444 / A05:2021
Prototype-Poll: — / CWE-1321 / A08:2021
Type-Juggling:  — / CWE-697 / A02:2021
Subdomain-TKO:  WSTG-CONFIG-10 / CWE-350 / A05:2021
CSV-Injection:  — / CWE-1236 / A03:2021
GraphQL-Issue:  WSTG-APIT-01 / CWE-20  / A03:2021
Insecure-Auth:  WSTG-ATHN-04 / CWE-287 / A07:2021
Default-Creds:  WSTG-ATHN-02 / CWE-798 / A07:2021
Unauth-Access:  WSTG-ATHZ-01 / CWE-306 / A01:2021
Prompt-Inject:  — / CWE-1427 / — / LLM01
Output-Handling:— / CWE-116  / — / LLM05
Excessive-Agency:— / CWE-250 / — / LLM06 / ASI02
Sys-Prompt-Leak:— / CWE-540  / — / LLM07
Goal-Hijack:    — / CWE-20   / — / ASI01
Memory-Poison:  — / CWE-20   / — / ASI06
```

---

## 八、引用方式(报告示例)

```markdown
## VULN-001: 用户搜索接口 SQL 注入

| 属性 | 详情 |
|------|------|
| 等级 | 严重 (CVSS 9.1) |
| CVSS 向量 | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N |
| **OWASP 映射** | **WSTG-INPV-05 / CWE-89 / A03:2021 Injection** |
| 目标 | https://target.com/api/v1/search |
| 参数 | `keyword` (POST JSON) |
```

专业性立刻上一个台阶。

---

*版本: v1.0 | 基于 WSTG v4.2 / CWE Top 25 2024 / OWASP Top 10 2021 / LLM Top 10 2025 / ASI Top 10 2026 / API Top 10 2023*
