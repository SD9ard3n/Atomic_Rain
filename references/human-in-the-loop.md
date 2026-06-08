# 人工介入协议 (Human-in-the-Loop, HITL)

← 回主入口 [../SKILL.md](../SKILL.md)

> **核心原则**: 当 AI 遇到自动化无法覆盖 / 需要凭证 / 需要人眼判断的节点时,
> **必须停下来, 明确告诉用户"需要做什么、需要提供什么"**, 用户复现后回传给 AI 继续。
> 避免 AI 瞎猜 / 编造结果 / 跳过关键步骤。

---

## 1. 什么时候触发 HITL

### 1.1 硬性触发条件 (必须请求用户介入)

| 场景 | 原因 |
|------|------|
| 需要登录凭证 (目标登录态) | AI 不能代为注册 / 填验证码 |
| 需要手机短信 / 邮箱验证码 | AI 拿不到, 必须真人操作 |
| 需要图形验证码 / 滑块 / 点选 | OCR 不稳定, 直接让人做 |
| 需要 Cookie / JWT / Session Token | 用户登录后从浏览器复制 |
| 需要抓包某个具体交互 (比如支付最后一步) | AI 跑不起浏览器, 用 Burp/浏览器抓 |
| 需要安装 APK / 逆向 APK | 非自动化 (jadx 图形化查看) |
| 需要真机 / 模拟器运行 App | Frida hook / 证书绑定 |
| 需要确认法律/授权边界 (某新发现资产是否 scope 内) | 只有用户知道合同细则 |
| 需要在受限环境 (防火墙后) 复现 | 用户的网络才能到达 |
| 遇到"需要 Burp 手工改包"的复杂场景 | AI 给 payload, 用户在 Burp Repeater 改 |
| 遇到"需要看浏览器 DevTools Console / Network" | AI 看不到, 必须截图 |
| 云厂商 AK/SK 使用决策 (例: 要不要 sts GetCallerIdentity) | 法律/监控风险, 必须明确授权 |
| 漏洞影响证明需要升级 (例: 要不要 dump 全库) | 高风险操作, 合规决策 |

### 1.2 软性触发条件 (建议请求确认)

- 发现可能超出 scope 的关联资产 → 问用户是否纳入
- 某个自动化结果成本高 (如 sqlmap --dump-all) → 问是否跑
- 发现高危漏洞要立即停手报告, 还是继续横向测其他漏洞 → 问策略

---

## 2. HITL 请求格式 (AI 发给用户的)

当 AI 需要用户介入时, **必须** 用以下结构化格式, 避免用户猜:

```markdown
## 🙋 HITL 请求 #<编号>

**我需要做的事**: <一句话>

**我需要你做的事**:
1. <具体步骤 1>
2. <具体步骤 2>
3. ...

**我需要你回传的信息**:
- <信息 1> (格式: 例如 `Cookie: session=xxx; csrf=xxx`)
- <信息 2>

**为什么需要**:  <1-2 句话, 不赘述>

**阻塞**: 是 (我会等你回传后继续)  /  否 (你可以稍后提供, 我先做别的)
```

### 2.1 真实例子

#### 例 1: 需要登录凭证

```markdown
## 🙋 HITL 请求 #1

**我需要做的事**: 以普通用户身份测 /api/user/profile 的 BOLA

**我需要你做的事**:
1. 用浏览器注册两个账号 A 和 B, 分别登录
2. A 登录状态下打开 /profile, F12 → Network → 找到请求 /api/user/profile
3. 复制完整 Cookie + Authorization header
4. 同样在 B 账号下拿一份
5. 记录 A 和 B 的 userId (URL 里或响应 JSON 里)

**我需要你回传的信息**:
- A 账号: Cookie / Authorization / userId
- B 账号: Cookie / Authorization / userId
- 示例请求 (一条完整的 curl / HTTP 请求粘贴过来)

**为什么需要**: BOLA 必须两个账号交叉重放才能证明, 单账号无意义

**阻塞**: 是
```

#### 例 2: 需要浏览器 DevTools 信息

```markdown
## 🙋 HITL 请求 #2

**我需要做的事**: 验证 /search?q= 的反射型 XSS 是否真在 body 渲染

**我需要你做的事**:
1. 浏览器打开: https://target.com/search?q=<svg/onload=alert(1)>
2. 查看是否弹框
3. F12 → Elements 面板, 搜索 "svg" 看标签在 DOM 里是什么形态
4. F12 → Network 面板, 看响应 Content-Type / CSP header

**我需要你回传的信息**:
- 是否弹框 (是/否)
- DOM 里 svg 的完整外层 HTML (或截图)
- 响应 Headers (完整复制粘贴)

**为什么需要**: curl 看到的是原始 HTML, 但浏览器实际渲染可能被 CSP 拦 / 被 HTML 实体化

**阻塞**: 是
```

#### 例 3: 需要抓包特定交互

```markdown
## 🙋 HITL 请求 #3

**我需要做的事**: 拿到"找回密码"完整请求链

**我需要你做的事**:
1. 开 Burp, 代理浏览器
2. 浏览器走一遍"忘记密码"流程(填手机 → 收验证码 → 改密码)
3. 在 Burp HTTP History 里导出涉及的所有请求 (File → Save items)
4. 或者手动复制每一步的 请求+响应 粘贴给我

**我需要你回传的信息**:
- 每步的 请求(含 method/URL/headers/body) + 响应(含 status/headers/body)
- 收到的验证码是否在响应 JSON 里直接返回了 (关键!)

**为什么需要**: 密码重置的逻辑漏洞 90% 出在中间步骤, 必须看完整流程

**阻塞**: 是
```

#### 例 4: 需要看 APK

```markdown
## 🙋 HITL 请求 #4

**我需要做的事**: 从 APK 提取硬编码 AK 和 API endpoint

**我需要你做的事**:
1. 下载 APK 到本地 (<apk 下载链接或路径>)
2. 用 jadx-gui 打开 APK (或 jadx <apk> -d out/)
3. 搜索以下字符串(Ctrl+Shift+F): AKIA, AKID, LTAI, accesskey, secret, api/v1, api/v2
4. 看 AndroidManifest.xml 的 exported=true 的 Activity/Service/Receiver

**我需要你回传的信息**:
- 搜索到的硬编码字符串(脱敏后前缀 4 位 + 后缀 4 位即可)
- exported 组件清单
- 若发现 API base URL, 完整 URL

**为什么需要**: APK 静态分析必须在本地跑, 我没法远程反编译

**阻塞**: 是
```

---

## 3. 用户回传格式 (用户发给 AI 的)

用户回传时 **推荐** 以下结构 (不强制, 但这样 AI 解析最快):

```markdown
## HITL 回传 #<编号>

<按 AI 请求的 "我需要你回传的信息" 逐条贴数据>

<额外补充的观察 / 异常情况>
```

**注意事项**:
- Cookie / Token **必须完整** 不要省略, AI 无法凭空推测
- 截图用图片 (Claude Code 能识图) 或 Ctrl+A 复制文本
- 如果某步做不出来, 明确说 "这步卡住了, 错误如下: ..." — 不要装作没遇到

---

## 4. AI 侧的承诺

启用 HITL 协议后, AI **必须**:

1. ✅ **不编造浏览器行为** — 没亲眼看过的 DOM / Console 输出, 绝不写"页面弹窗了""控制台打印了 xx"
2. ✅ **不编造凭证** — 没有用户给的 Cookie, 就明说"需要凭证"
3. ✅ **不跳过验证步骤** — 遇到需要真实浏览器 / 真实登录的场景, 停下来要, 而不是假装 curl 能验证
4. ✅ **请求前先尝试自动化** — 例如 curl / Playwright MCP / sqlmap 能自动跑的先跑, 跑不动再请求人
5. ✅ **批量请求** — 如果预见到多步都要人做, 一次性列清单, 别挤牙膏
6. ✅ **等人回来才继续** — 阻塞型请求发出后, 不假装完成了, 就等

---

## 5. 触发频度控制

**不是所有事都找人**. 典型分层:

| AI 自动化能做 | 需要人介入 |
|---------------|-----------|
| 子域名收集 / 端口扫描 / 目录爆破 | 登录 / 验证码 / 短信 |
| nuclei / xray / sqlmap 自动跑 | 手动 Burp 改包复杂场景 |
| curl / httpx 简单验证 | 浏览器 DOM / CSP 实际渲染验证 |
| JS 文件下载 / grep 密钥 | APK 逆向 / Frida hook |
| 读 OpenAPI / Swagger 生成测试用例 | 真机 App 行为观察 |
| 用 interactsh 验证 OOB 触发 | 凭证 / 授权边界 / 合规决策 |

---

## 6. 与 Phase 的结合

- **Phase 1 信息收集**: 基本自动化, 偶尔请用户提供"主动提供的资产清单"
- **Phase 2 漏洞挖掘**: HITL 高频, 按 §2 模板发请求
- **Phase 3 影响证明**: HITL 最关键 — 是否继续深挖必须经用户授权
- **Phase 4 报告**: HITL 收尾 — 让用户核对是否脱敏 / 是否提交

---

## 7. 相关参考

- 主入口 → [../SKILL.md](../SKILL.md)
- 项目工作流 → [project-workflow.md](project-workflow.md)
- 浏览器自动化 (可减少 HITL 请求) → [tool-usage.md](tool-usage.md) §浏览器 MCP
- OOB 基础设施 (异步回调替代 HITL) → [oob-infrastructure.md](oob-infrastructure.md)
