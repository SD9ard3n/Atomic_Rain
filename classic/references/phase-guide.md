---
name: phase-guide
description: 把 SKILL.md 的 Phase 摘要落成可执行的 信息收集 → 漏洞挖掘 → 影响证明 → 报告 四阶段。 每个 Phase 末列出可直接跳转的 Deep 层文件(vuln/ + 各专题)。
category: methodology
---

# Phase 1-4 执行指南 (Category)

← 主入口 [../SKILL.md](../SKILL.md)

> 把 SKILL.md 的 Phase 摘要落成可执行的 **信息收集 → 漏洞挖掘 → 影响证明 → 报告** 四阶段。
> 每个 Phase 末列出可直接跳转的 Deep 层文件(vuln/ + 各专题)。

---

## Phase 1: 信息收集与攻击面测绘

> 详细命令和工具参考 → [recon.md](recon.md)
> 实战命令模板 → [tool-usage.md](tool-usage.md)

### 1.0 工具强制加载 (Phase 1 前必须执行)

> **强制规则**: 进入 Phase 1 之前, Agent **必须** 先读取工具配置, 否则后续无法构造正确的工具命令。

```
Step 1: Read references/tool-config.md
        ├─ 文件存在 → 解析路径, 进入 Step 2
        └─ 文件不存在 → 触发 HITL:
            "未发现 tool-config.md。请创建该文件,
             并将各工具目录路径替换为你本地工具的真实绝对路径。"
            用户完成后回到 Step 1, 否则全程降级为 curl + HITL。
Step 2: 解析所有非空路径, 记录到会话变量:
  - $NUCLEI_PATH    (nuclei 可执行路径)
  - $SQLMAP_PATH    (sqlmap 路径)
  - $DIRSEARCH_PATH (dirsearch 路径)
  - $SUBFINDER_PATH (subfinder 路径)
  - $HTTPX_PATH     (httpx 路径)
  - 其他已配置工具...
Step 3: 后续所有工具调用使用这些变量而非硬编码路径
Step 4: 未配置的工具 → 降级为 curl 手工测试 + HITL 提醒用户配置路径
```

**工具可用性检查** (Phase 1 开始时执行):

| 工具 | 已配置 → | 未配置 → 降级 |
|------|---------|--------------|
| nuclei | `${NUCLEI_PATH}/nuclei -t ...` | curl + 手工构造 payload |
| sqlmap | `${SQLMAP_PATH}/sqlmap.py -u ...` | curl + 手工 UNION/BLIND 测试 |
| dirsearch | `${DIRSEARCH_PATH}/dirsearch.py -u ...` | curl + 常见路径字典 |
| subfinder | `${SUBFINDER_PATH}/subfinder -d ...` | crt.sh / SecurityTrails API |
| httpx | `${HTTPX_PATH}/httpx -l ...` | curl 逐个探测 |
| katana | `${KATANA_PATH}/katana -u ...` | curl + 手工提取 JS |

**降级时 HITL 提示模板**:
```markdown
## HITL 提示: 工具未配置

发现需要使用 {工具名} 但 tool-config.md 中未配置路径。

**两个选项**:
1. 在 tool-config.md 中填入路径, 我重新读取后继续自动执行
2. 我用 curl 手工替代, 效率较低但能完成

**你的选择**: ?
```

### 1.1 核心流程

```
1. 被动收集: 子域名 / IP / 历史DNS / 证书透明度 / GitHub泄露 / 空间测绘
2. 存活探测: httpx 批量检测 → 过滤 CDN / 无效域名 → 活跃资产清单
3. 端口扫描: TOP1000 → 全端口(仅高价值目标) → 服务版本识别
4. Web 指纹: httpx/whatweb 技术栈 + WAF 识别 + JS 文件分析
5. 目录枚举: gobuster/ffuf → 敏感文件(.env/.git/config)
6. 自动化扫描: nuclei (CVE + exposure + misconfig) → 快速发现已知漏洞
7. 攻击面汇总: 按功能点分类(认证/上传/API/支付/管理) → 标记测试优先级
```

### 1.2 关键产出

```markdown
# 写入 assets.md
## 高价值攻击面
- [ ] 管理后台 /admin         (未保护?)
- [ ] API 接口 /api/v1/       (BOLA?)
- [ ] 文件上传 /upload        (WebShell?)
- [ ] 用户中心 /user/         (越权?)
- [ ] 支付流程 /pay           (逻辑漏洞?)
- [ ] 移动端 APP              (证书绑定绕过?)
- [ ] AI 对话接口 /chat       (Prompt 注入?)
```

### 1.3 Phase 1 Deep 文件

| 内容 | 文件 |
|------|------|
| 子域名 / 端口 / 指纹 / JS / 目录扫描 | [recon.md](recon.md) |
| 工具路径与场景映射 | [tool-config.md](tool-config.md) / [tool-usage.md](tool-usage.md) |

---

## Phase 2: 漏洞挖掘

### 2.1 Web 漏洞(按赏金价值排序测试)

> 单漏洞深度 → [vuln/](vuln/) 目录, 每漏洞核心文件(SKILL) + 边角场景(SCENARIOS) 双文件机制
> 高频 payload 速查 → [payloads.md](payloads.md)
> 构造思路 (从现象到 payload 的推导过程) → [payload-construction/](payload-construction/) (sqli/xss/ssrf/jwt/bola)

```
1.  未授权访问 / 默认口令 / 弱口令    ← 最快出结果      auth-logic.md
2.  SQL 注入 (所有参数)                ← 高影响          vuln/sqli.md + sqli-scenarios.md
3.  SSRF (URL 参数 / 文件导入)         ← 内网 RCE        vuln/ssrf.md + ssrf-scenarios.md
4.  文件上传 → RCE                     ← 直接接管        vuln/upload.md
5.  命令注入 (ping / 转换 / 处理功能)  ← 直接接管        vuln/cmdi.md
6.  越权 (IDOR / BOLA)                 ← 批量数据泄露    api-security.md
7.  认证绕过 (验证码/密码重置/Session)  ← 账号接管        auth-logic.md
8.  XSS (反射 / 存储 / DOM)            ← 账号接管链      vuln/xss.md + xss-scenarios.md
9.  逻辑漏洞 (支付 / 竞争 / 状态)      ← 业务影响        vuln/race-condition.md + auth-logic.md
10. 反序列化 / SSTI / XXE              ← 高影响          vuln/deserialize.md / ssti.md + ssti-scenarios.md / xxe.md
11. 原型污染 / 类型混淆                ← 现代 Web 高价值 vuln/prototype-pollution.md / type-juggling.md
12. HTTP 走私 / 缓存投毒               ← 基础设施层      vuln/request-smuggling.md / cors-cache.md
13. 子域名接管                         ← 资产层          vuln/subdomain-takeover.md
14. CSRF / Clickjacking / CORS         ← 补充            vuln/csrf-clickjacking.md / cors-cache.md
15. GraphQL / WebSocket                ← 现代协议        vuln/graphql-websocket.md
```

### 2.2 API 安全

> 详细方法 → [api-security.md](api-security.md)

```
- [ ] 未授权: 删除 Token / 修改 ID → 仍返回数据?
- [ ] BOLA / IDOR: 替换 userId / orderId → 访问他人数据
- [ ] BFLA: 普通用户调用管理员 API
- [ ] 批量赋值: 注入 {"role":"admin"} / {"isVip":true}
- [ ] 参数篡改: price=-1 / quantity=99999 / isPaid=true
- [ ] 速率限制: 无限发送短信 / 验证码 / 登录请求
- [ ] 信息泄露: 错误响应暴露堆栈 / SQL / 内网 IP / 密钥
- [ ] JWT: none 算法 / 算法混淆 / 弱密钥 / 未验证签名
- [ ] GraphQL: 内省查询 / 嵌套 DoS / mutation 越权
```

### 2.3 认证与业务逻辑

> 详细方法 → [auth-logic.md](auth-logic.md)

```
- [ ] 验证码: 回显 / 删除参数 / 万能码 / 爆破 / 复用
- [ ] 密码重置: 步骤跳过 / 手机号篡改 / Token 可预测 / Host 注入
- [ ] 登录: SQL 注入 / 万能密码 / 验证码绕过 / 账号枚举
- [ ] Session: 固定 / 预测 / 并发 / 登出后失效
- [ ] 支付: 金额篡改 / 数量篡改 / 负数 / 并发 / 优惠券叠加
- [ ] 越权: 水平(ID 替换)/ 垂直(低权限→管理)/ 未授权(删 Cookie)
```

### 2.4 云安全

> 详细方法 → [cloud-security.md](cloud-security.md)

```
- [ ] AK/SK 泄露: GitHub / JS 文件 / 配置文件 / 环境变量
- [ ] 对象存储: S3/OSS/COS 公开读写 / 列目录
- [ ] 元数据服务: SSRF → 169.254.169.254 → AK/Token
- [ ] 云函数: 未授权调用 / 环境变量泄露 / IAM 权限过大
- [ ] 堡垒机 / 云管: 默认口令 / 未授权 / SSRF
```

### 2.5 移动端 APP

> 详细方法 → [mobile-app.md](mobile-app.md)

```
1. 流量拦截: 证书绑定绕过 → 抓包(Burp / mitmproxy)
2. 接口测试: 抓到的 API 按 §2.2 测试
3. 逆向分析: APK 反编译 → 硬编码密钥 / 后门接口 / 调试开关
4. 组件安全: Activity / Service / Receiver 导出 / Content Provider 泄露
5. 本地存储: SharedPreferences / 数据库 / 文件 中的敏感信息
6. Frida Hook: 绕过签名校验 / Root 检测 / 加密函数
```

### 2.6 WAF 绕过

> 详细技巧 → [waf-bypass.md](waf-bypass.md)

被 WAF 拦截时按以下顺序尝试:
```
1. 编码绕过: URL 编码 / 双重 URL 编码 / HTML 实体 / Unicode / Base64
2. 分块传输: Transfer-Encoding: chunked
3. HTTP 走私: CL.TE / TE.CL 请求拆分
4. 参数污染: id=1&id=2&id=3 (不同层解析差异)
5. 大小写 / 双写 / 注释: SeLeCt / selselectect / /*!select*/
6. 协议层: HTTP/2 / HTTP 请求走私 / H2C 走私
```

### 2.7 AI 应用漏洞 (LLM / Agent / MCP)

> Prompt 注入 / 越狱 / MCP 投毒 / Agent 利用 → [ai-app-security.md](ai-app-security.md)
> System Prompt 泄露 / RAG 投毒 / 推断攻击 → [ai-data-security.md](ai-data-security.md)

```
测试清单 (按 OWASP LLM Top 10 / ASI Top 10 对齐):
- [ ] 直接 Prompt 注入 (指令覆盖 / 角色扮演 / 编码绕过)
- [ ] 间接 Prompt 注入 (RAG 文档 / 外部 API 返回 / 用户上传文件)
- [ ] System Prompt 泄露 (角色扮演 / 翻译绕过 / 重复指令)
- [ ] 越狱 (DAN / 假定场景 / Many-shot / 对抗性后缀)
- [ ] MCP 工具投毒 (description 嵌入 <IMPORTANT>恶意指令</IMPORTANT>)
- [ ] Agent 目标劫持 (ASI01) / 工具滥用 (ASI02) / 记忆投毒 (ASI06)
- [ ] 输出 → Web sink (LLM 返回 XSS payload 被前端 innerHTML)
- [ ] 跨层: Web XSS 窃取对话 / SSRF 直接调用内部模型 API
```

---

## Phase 3: 漏洞利用与影响证明

### 3.1 影响证明原则

漏洞赏金的核心是 **证明影响**, 而不只是证明漏洞存在:

| 漏洞 | 低影响证明 | 高影响证明 |
|------|-----------|-----------|
| XSS | `alert(1)` | 窃取 Cookie → 账号接管 → 展示用户数据 |
| SSRF | 探测到内网 IP | 读取云元数据 → 获取 AK → 列出 Bucket 内容 |
| SQL 注入 | `1=1` 回显 | 读取管理员密码 / 提取 100 万用户数据 |
| 越权 | 修改他人 1 条数据 | 批量导出全部用户信息 |
| 文件上传 | 上传成功 | 获取 WebShell → 执行 whoami |

### 3.2 组合攻击链思路

```
XSS  → 窃取 Admin Cookie → 登录后台 → 文件上传 → RCE
SSRF → 云元数据 → AK/SK → 对象存储写入 → 存储桶投毒
SQL 注入 → 读取凭证 → SSH 登录 → 内网横向 → 数据库拖库
越权 → 获取 Admin Token → 调用管理 API → 创建后门账号
Prompt 注入 → 工具滥用 → 读取内部 API → 数据库查询越权
```

> 注: 定位限定在 **不做内网横向 / 不做后渗透**。"SSH 登录"" 内网横向" 等步骤仅作为影响证明的可能性说明, 实际测试中应停在 "证明可达性" 层面, 不真实执行进一步渗透。

---

## Phase 4: 漏洞报告

> 报告模板 → [report-template.md](report-template.md)

### 4.1 SRC / 赏金报告要点

1. **标题**: 一句话说明漏洞 + 影响 (例: "某系统 SQL 注入可导致全量用户数据泄露")
2. **漏洞等级**: 自评严重 / 高危 / 中危 / 低危 + CVSS 评分
3. **接口发掘路径**: 每个漏洞必须写明接口是怎么发现的 (从 vulns.md 的 Discovery-Origin 搬入)
4. **复现步骤**: 每步都要可复现, 必须包含完整 BP 格式请求包 (请求行 + 全部 Header + Cookie + Body, 从 vulns.md 的 Repro-Request 搬入, 不是单行 curl)
5. **利用链打法**: 如果是级联漏洞, 每步如何衔接, 每步的完整请求包+响应摘要 (从 vulns.md 的 Chain-Steps 搬入)
6. **影响证明**: 展示实际危害, 不只是 PoC
7. **修复建议**: 短期缓解 + 长期修复 + 验证方法 三段式

### 4.2 报告质量检查清单

- [ ] 标题能让审核员 30 秒内判断严重度
- [ ] 每个漏洞有接口发掘路径 (怎么发现这个接口的)
- [ ] 复现步骤含完整 BP 格式请求包 (不是单行 curl 命令)
- [ ] 级联漏洞有利用链打法 (每步请求包 + 如何衔接)
- [ ] 复现步骤自包含 (含环境 / 凭证 / 原始请求)
- [ ] 影响证明有截图 + 脱敏后的响应片段
- [ ] CVSS 向量写全
- [ ] 含 False Positive 排除说明
- [ ] 修复建议可落地, 不是泛泛 "加过滤"
