# Shiro 自动化执行协议 (Light Deep Card)

> **CWE**: 502 / 287 | **ROI**: 极高 (P0)
> **轻便原则**: 本文件只保留 Shiro 550 / 721 / 路径绕过的决策路径。大字典、gadget 全表不要放这里,按需调用工具/外部字典。

---

## 0. First-pass Signal

| 信号 | 判断 | 下一步 |
|------|------|--------|
| Cookie 含 `rememberMe` | Shiro 可能性高 | 进入 §1 |
| 删除 Cookie 后自动写回 `rememberMe=deleteMe` | Shiro 几乎确认 | 进入 §1 |
| 伪造 rememberMe 后 500 | 反序列化/解密异常 | 进入 §1.2 |
| `/admin` 出现 Shiro 过滤链特征 | 可能存在路径绕过 | 进入 §3 |

**禁止**: 一上来盲跑全 gadget / 全 key / 全路径字典。必须先记录 `HTTP_CODE`, `RESP_LENGTH_DELTA`, `TIMING_DELAY`。

---

## 1. Shiro-550 (rememberMe AES-CBC 反序列化)

### 1.1 Key 验证顺序

1. 用少量高频 key 生成 **URLDNS** payload。
2. 只观察 OOB DNS 回调,不直接 RCE。
3. DNS 回调成功 → 记录 key 命中 → 再选择 gadget。
4. DNS 不回调 → 不扩大 gadget,先换 OOB 通道 / 检查出站限制。

**高频 key 来源**:
- 默认 key: `kPH+bIxk5D2deZiIxcaaaA==`
- 项目泄露: `shiro.ini`, `application.yml`, `.properties`, JS/备份文件
- 级联: `[Linkable]` 中的硬编码 key / 密钥片段

### 1.2 关键证据

```markdown
- 指纹: Cookie rememberMe 存在 / deleteMe 回写
- Payload: URLDNS only
- OOB: <dnslog/interactsh 子域>
- 结果: DNS 回调 / 未回调
- HTTP: code=<code>, len_delta=<delta>, timing=<ms>
```

### 1.3 Gadget 选择

| 环境信号 | 优先 gadget |
|----------|-------------|
| Java 8 + commons-collections | CC5/CC6 |
| Spring 环境 | Spring1/Spring2 |
| 无依赖信息 | 仅 URLDNS 证明存在,停手问用户是否升级 |
| 出站 DNS 被封 | 尝试 HTTP OOB;仍失败则不报 RCE,只报可疑 Shiro 反序列化 |

---

## 2. Shiro-721 (Padding Oracle)

**适用前提**: Shiro 版本存在 rememberMe 加密 padding oracle;不依赖默认 key,但请求量更高。

### 决策路径

1. 确认 rememberMe 行为稳定。
2. 发送畸形 padding Cookie,观察 `500/302/200` 差异。
3. 若差异稳定 ≥3 次 → 标记 `[Padding_Oracle_Suspected]`。
4. 需要大量请求时先 HITL 确认测试窗口和速率限制。

**报告口径**: 未完成可控明文构造前,不要直接报 RCE;报 "Shiro rememberMe Padding Oracle 可疑/已确认" 并附差异证据。

---

## 3. Shiro 路径规范化绕过

适用于 Shiro filter chain 与前端网关/容器解析路径不一致。

### First-pass Payload

```http
/admin/%2e
/admin/.
/admin;/
/admin..;/
/;/admin
/admin/%2f..%2fadmin
```

### 判断

| 现象 | 判断 |
|------|------|
| 原始 `/admin` = 302/401/403, 变体 = 200 | 可能绕过 |
| 变体进入登录后页面但功能 403 | 仅路由层绕过,影响较低 |
| 变体可调用管理 API | 高危/BFLA |

---

## 4. Triage

| 现象 | 可能原因 | 动作 |
|------|----------|------|
| 100% 500 | key 错 / gadget 不兼容 / 反序列化 crash | 回到 URLDNS-only |
| 200 但无 OOB | 出站被封 / key 错 / GCM 模式 | 换 OOB / 查版本 |
| `deleteMe` 写回但无漏洞 | Shiro 指纹成立但版本已修 | 转路径绕过 / 认证逻辑 |
| 路径变体 200 但内容为空 | 网关返回默认页 | 对比响应长度与关键 DOM |

---

## 5. 级联

- 命中 Shiro key → 检索 `[Linkable]` 中的登录入口,测试 Cookie 伪造或 rememberMe 利用。
- 命中路径绕过 → 立刻测 BFLA:普通用户/无 Token 调管理员 API。
- 发现 `shiro.ini` / `application.yml` → 进入敏感信息三阶段验证。

---

## 6. 相关参考

- OOB 基础设施 → [../oob-infrastructure.md](../oob-infrastructure.md)
- 反序列化通用 → [deserialize.md](deserialize.md)
- Fastjson/Jackson → [fastjson-jackson.md](fastjson-jackson.md)
- 级联策略 → [../chained-logic-extended.md](../chained-logic-extended.md)
