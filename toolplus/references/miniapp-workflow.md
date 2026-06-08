---
name: miniapp-workflow
description: 本文件只写"小程序独家"的漏洞链路(鉴权 / 加密 / 微信原生 API / 跨端字段),通用漏洞(BOLA / SQL / XSS 等)走主 skill 不重复。 不绑任何反编译工具 — 任何工具产出 [代码 + 配置 + 接口清单] 三件套都能消费(tscanplus /…
category: methodology
---

# 微信小程序漏洞挖掘核心链路

← 主入口 [../SKILL.md](../SKILL.md) | 区别于通用 APP 测试 [mobile-app.md](mobile-app.md)

> **本文件只写"小程序独家"的漏洞链路**(鉴权 / 加密 / 微信原生 API / 跨端字段),通用漏洞(BOLA / SQL / XSS 等)走主 skill 不重复。
> **不绑任何反编译工具** — 任何工具产出 [代码 + 配置 + 接口清单] 三件套都能消费(tscanplus / wxapp-unpacker / unveilr / 无影 任选)。

---

## §0 边界声明

### 范围
- ✅ 微信小程序逆向后的漏洞挖掘核心链路
- ✅ 小程序独有攻击面(openid / wx.* API / 跨端字段)
- ❌ 不重复通用漏洞测试方法(走 [api-security.md](api-security.md) / [auth-logic.md](auth-logic.md) / vuln/* )
- ❌ 不绑反编译工具产出格式

### 反编译工具(用户本地操作,HITL)
| 工具 | 产出 | 备注 |
|---|---|---|
| wxapp-unpacker | `app.js + pages/*/index.js` | 标准格式,可读 |
| unveilr | 类似 wxapp-unpacker | 现代项目 |
| tscanplus | `__APP__/app-service.js (wcc 合并)` + `extraction_cache.json` | tscanplus 自带预提取索引 (金矿) |
| 无影 | 接口清单为主 | 不解源码 |
| 手抓 .wxapkg | (HITL:用户先解包) | 用上述工具解 |

**关键**:任何工具产出**只要包含三件套**(代码 + 配置 + 接口清单)都能消费。

---

## §1 信息来源(3 段)

### §1.1 反编译产物路径
- **任选工具**,关键是拿到三件套:
  - **代码**:业务 JS / 加密函数 / API 调用点
  - **配置**:`app.json` / `app-config.json` (pages 清单 / 权限声明 / appid)
  - **接口清单**:无影 / tscanplus 已提取 / 或 grep 自建

### §1.2 抓包凭证路径
- **任选工具**(Burp / Yakit / Charles)
- 关键是拿到登录态 cookie / session_key / openid 等鉴权字段
- HITL:用户从 Burp 复制 Authorization / Cookie / 自定义 token 头给 Claude

### §1.3 Claude 入口
```bash
cd <反编译目录> && claude
```
- **按需 grep**,避免一次性 Read 整个 `__APP__/app-service.js` 大文件(可能 500KB+)
- 优先消费 `extraction_cache.json` / `app.json` / `app-config.json` 元数据(KB 级)
- 业务 JS 走精准 grep 调用点定位

---

## §1.5 接口接力流程(★解决"AI 不知道按什么顺序消费信息")

### 输入
任何反编译工具产出的接口清单:
- 无影:直接列接口
- tscanplus:`extraction_cache.json` 里的 `Path` 字段
- 手工:`grep -rn '/api/\|/open/\|wx\.request' .` 自建

### 动作链(P1.5 业务建模时执行)

```
Step 1: 接口清单按敏感度排序
  ├─ 高:admin / internal / private / debug / test / staging / v0 / sys / op / manage
  ├─ 中:auth / login / pay / order / user / file / upload / download / share
  └─ 低:public / cdn / static / metric / heartbeat / track / analytics

Step 2: 对每个高敏接口,定位调用方
  ├─ classic: grep -rn '<接口路径>' . 在反编译目录搜索
  └─ toolPlus: mcp__yaklang__ssa_compile{language:"js"} + ssa_query 找数据流

Step 3: 从调用方上下文提取参数模板
  ├─ 字段名(mobile / openid / orderId / ...)
  ├─ 类型(string / int / object)
  └─ 是否加密标记(发现 encrypt/aes/sm4 关键词)

Step 4: 形成 endpoints-prioritized.md 待测清单
  写入工作目录,按敏感度 + 业务节点分组

Step 5: 进入 §2-5 黑盒测试 SOP
```

### 禁止
- ❌ 跳过 §1.5 直接对接口清单一把梭测试(没参数模板瞎打,误报多 + 难复现)
- ❌ 不分敏感度同时测所有接口(浪费精力)

---

## §2 小程序特有的鉴权机制 ★独家

### §2.1 openid 当 user_id → BOLA 主战场

**核心问题**:小程序 openid 是微信用户唯一标识,后端常**直接当 user_id 用**,不做权限校验。

**测试**:
- 抓 2 个账号的请求(账号 A 的 openid_A,账号 B 的 openid_B)
- 用 A 的登录态,把请求里的 `openid=xxx` 改成 `openid_B` 试 → 拿到 B 的数据 = BOLA
- 参数名变种:`open_id` / `openId` / `user_openid` / `wx_openid`

**联动**:[intuition-triggers §A #3 BOLA 两账号交叉](intuition-triggers.md)

### §2.2 wx.login code 复用

**机制**:`wx.login` 返回的 `code` 应该是一次性(5分钟 + 单次使用),换 `openid+session_key`。

**测试**:
- 拿同一个 `code` 多次调用后端的 `/login` 接口
- 后端没校验 code 是否已使用 → 同一 code 反复换 token
- 配合社工:**别人的 code 被你拦截了,你能拿别人的身份**

### §2.3 wx.getPhoneNumber 信任伪造 ★高产 30%+ 中招率

**机制**:`wx.getPhoneNumber` 返回 `encryptedData + iv`,后端用 session_key 解密拿真实手机号。

**漏配**:
- 后端**信任前端传的明文 phone 字段**,不解密 encryptedData → 直接传 `phone=13800138000` 绑定他人
- 后端**没校验 encryptedData 的有效性**(可被伪造)
- 后端**用错 session_key** 解密,得到任意手机号

**测试**:
- 抓获取手机号的接口,**删掉 encryptedData/iv 只留 phone** → 是否成功绑定?
- **改 phone 为他人手机号** → 是否成功?
- **改 encryptedData 为乱码** → 是否报错还是接受?

### §2.4 session_key 泄露

**机制**:`session_key` 是小程序解密敏感数据的钥匙,应该只存后端。

**漏配**:
- session_key **回传到前端**(在某个接口的返回值里)
- 前端 localStorage / vuex / 全局变量里**存 session_key**
- session_key **缓存太久**,过期不更新

**测试**:
- grep 反编译源码 `session_key` / `sessionKey` → 找到使用点
- 抓所有接口返回值找 `session_key` 字段(JSON / Cookie)
- 拿到 session_key → 可解密任意 encryptedData → 绕过 §2.3 防御

### §2.5 unionid 跨端串号

**机制**:同一微信用户在不同小程序里 openid 不同,但 unionid 相同(必须在微信开放平台关联)。

**漏配**:
- 后端**用 unionid 当主账号 ID**,但只有部分接口校验 → 部分接口可串号
- **A 小程序 + B 小程序同一公司 + 不同权限** → 用 A 的 unionid 调 B 的高权接口

**测试**:
- 同一微信号注册多个小程序 → 抓 unionid
- 跨小程序调接口,看是否权限隔离

---

## §3 小程序特有的加密对抗 ★独家

### §3.1 关键词扩展(grep 反编译源码)

```bash
# 加密关键词(超过通用 encrypt/decrypt)
grep -rniE 'encrypt|decrypt|crypto|cipher|aes|sm[234]|hmac|sign|sjcl|kdf|pbkdf|jose' .

# 国密专项
grep -rniE 'sm2|sm3|sm4|gm.{0,10}cipher' .

# 小程序特殊 API
grep -rniE 'wx\.getUserCryptoManager|RequestCipher' .

# 密钥关键词
grep -rniE 'key|secret|token|apikey' . | grep -v node_modules
```

### §3.2 加密可能位置

| 位置 | 检测方法 |
|---|---|
| 主包 JS | grep 加密关键词,有就在 |
| **分包**(subPackages) | 检查 `app.json` subPackages 配置,需要进入分包目录 grep |
| **wasm** | grep `*.wasm` 文件,可能用 WebAssembly 做加密 (难逆) |
| **wx.getUserCryptoManager** | 微信原生加密 API,密钥由微信管理 |
| **服务端下发密钥** | 抓包找有没有接口下发 key / iv (动态密钥) |
| **JSBridge 调原生** | 小程序内嵌 web-view,JS 调原生加密函数 |

### §3.3 横向 5 招(找不到密钥时也能打)

| # | 招式 | 适用场景 |
|---|---|---|
| **1** | **接口版本枚举** (v1/v0/internal) | v2 加密,v1/v0 可能没加密 |
| **2** | **不动加密字段,改其他字段** | 改 userId/orderId 等明文字段 BOLA |
| **3** | **重放(Replay)** | 很多包没 nonce/timestamp,加密包可直接重放 |
| **4** | **下游接口** | 校验接口 / 登录接口 / 拉取列表接口往往参数没加密 |
| **5** | **找到密钥后本地构造** | classic: openssl / pycryptodome,toolPlus: `mcp__yaklang__exec_codec` |

### §3.4 调页面里的加密函数(toolPlus 独家招)

- **classic 版**:HITL — 让用户在小程序客户端 DevTools console 跑加密函数
- **toolPlus 版**:`mcp__chrome__chrome_inject_script` 直接注入 JS 调函数(适用于小程序 H5 模式 / web-view 部分)

---

## §4 微信原生 API 风险 ★独家

### §4.1 wx.web-view 加载远程 URL → 钓鱼 / JSBridge 滥用

**机制**:`<web-view src="https://...">` 在小程序内打开 H5 页面。

**风险**:
- src 拼接用户输入 → 加载攻击者 URL 钓鱼
- web-view 内的 JSBridge 暴露小程序原生能力(`wx.miniProgram.navigateTo`)
- web-view 跨域窃取 token

**测试**:grep `web-view` + 检查 src 是否动态拼接

### §4.2 wx.cloud 云开发

**机制**:微信云开发,后端用云函数 + 云数据库,小程序直连。

**风险**:
- **数据库权限规则错配**(默认允许所有用户读写) → 直接拉全表
- **云函数未鉴权** → 任意人调用敏感云函数
- **环境隔离失败** → 测试环境拿生产数据

**测试**:grep `wx.cloud.callFunction` / `wx.cloud.database` → 列出云函数清单 + 试无鉴权调用

### §4.3 wx.navigateToMiniProgram → 跳转劫持

**机制**:小程序间跳转,可以带参数。

**风险**:
- `appId` 用用户输入 → 跳转到攻击者小程序
- `path` 带 token → token 通过跳转泄露
- `extraData` 含敏感信息

**测试**:grep `navigateToMiniProgram` → 看参数是否过滤

### §4.4 wx.scanCode → 扫码结果信任

**机制**:扫码返回 result 字符串,小程序直接用。

**风险**:
- 扫码结果直接当 URL 打开(类似 Open Redirect)
- 扫码结果直接传后端 → 注入 SQL / XSS
- 扫码二维码内容是攻击者构造(社工)

**测试**:grep `wx.scanCode` → 看 result 是否过滤

### §4.5 web-view 内 JSBridge

**机制**:H5 通过 `wx.miniProgram.*` 调小程序原生 API。

**风险**:
- H5 任意调 `navigateTo` / `postMessage` 跨上下文
- 第三方 SDK 在 web-view 内可越权调原生 API

**测试**:grep `wx.miniProgram.` → 列出暴露的 JSBridge

---

## §5 跨端字段差异 ★独家

### 核心场景
同一个接口在**小程序 / APP / Web** 3 端的请求 / 响应字段**可能不一样**,后端权限校验**可能只覆盖部分端**。

### 实战
- 抓 3 端同一接口的完整请求
- **diff** 字段
- 找**只在某端独有**的字段(可能后端只在该端校验)
- 找**响应里的额外字段**(可能某端返回了更多敏感字段)

### 典型攻击
- 小程序信任的字段 APP 不校验:小程序有 `is_kyc` 隐藏字段,APP 端没传 → APP 端绕过实名
- APP 返回更多字段:APP 调 `/user/profile` 返回 `id_card`,小程序返回过滤后版本 → APP 拉数据
- 字段名大小写差异:`userId` vs `user_id` 后端不同代码路径不同校验

**联动**:[intuition-triggers §A #10 Web / App 字段差异](intuition-triggers.md)

---

## §6 引用回主 skill(通用部分,不重复)

| 测试场景 | 走哪个 |
|---|---|
| 通用 BOLA / 越权 / 未授权 | [api-security.md](api-security.md) |
| 通用业务漏洞测试 | [business-flow-checklist.md](business-flow-checklist.md) |
| 验证码 / 密码重置 / 支付逻辑 | [auth-logic.md](auth-logic.md) |
| 加密 codec 工具 (classic) | [tool-config.md](tool-config.md) |
| 加密 codec 工具 (toolPlus) | [mcp-tools-finder.md](mcp-tools-finder.md) |
| OOB 通道 / 钓鱼接收 | [oob-infrastructure.md](oob-infrastructure.md) |
| 外部资源 HITL | [SKILL.md §1 P3.5](../SKILL.md) |
| 业务建模追问 12 问 | [intuition-triggers.md §B](intuition-triggers.md) |
| SQL / XSS / SSRF 等技术漏洞 | [vuln/*.md](vuln/) |

---

## §7 HITL 触发点

遇到以下情况**必须停下来向用户索取**(不要硬撑):

| 触发条件 | 索取内容 |
|---|---|
| 反编译工具产出格式异常(不在 §0 列表里) | 让用户重新解包或提供产出截图 |
| 加密函数找不到 / 密钥找不到(横向 5 招都失败) | 让用户在小程序 DevTools 跑加密函数,把输入输出贴出来 |
| 抓包失败(证书 / 双向 TLS / 国密 TLS) | 让用户用 Yakit 国密支持 / 或 Burp + 证书安装 |
| 滑块 / 高对抗验证码 | 让用户手动过滑块,提供过后的 token |
| wx 客户端调试需求(只能在微信里调试) | 让用户开发者工具或微信端配合 |
| 真实测试号 / OPSEC 隔离(自己手机号 / 自己邮箱) | 走 [SKILL.md P3.5](../SKILL.md) 协议索取 |
| 反编译产物含真实生产数据 | 让用户确认是否脱敏 / 是否授权范围内测试 |

---

## §8 优先级 + 工作节奏建议

### 高价值场景优先(2 小时内出第一个 finding)
1. **§2.1 openid BOLA**(主战场,30%+ 中招率)
2. **§2.3 wx.getPhoneNumber 信任伪造**(高产)
3. **§3.3 横向 5 招**(如果加密对抗失败立刻横向,不卡死)

### 中价值场景(半天)
4. §2.2 wx.login code 复用
5. §2.4 session_key 泄露
6. §4.1 wx.web-view 钓鱼

### 低优先(项目时间充裕再做)
7. §2.5 unionid 跨端串号
8. §4.2 wx.cloud 云开发(需要后端确实用了 wx.cloud)
9. §4.4 wx.scanCode 扫码信任

---

## 局限性 (诚实说)

- 反编译工具产出**格式千差万别**(tscanplus / wxapp-unpacker / unveilr 等),本文档不绑死格式但具体测试时**需要 AI 灵活适应**
- **加密找不到密钥就是绝症** — §3.3 横向 5 招是当前最好答案,不保证一定打开
- 微信原生 API (wx.*) 风险**依赖业务有没有用**,目标没用 wx.cloud / wx.web-view 就跳过对应章节
- 真正高分逻辑漏洞仍靠 [business-flow-checklist.md](business-flow-checklist.md) + [intuition-triggers.md §B](intuition-triggers.md) 业务建模

---

**版本**: v1.0
**更新日期**: 2026-05-24
**适用场景**: 微信小程序(支付宝 / 抖音 / 百度等小程序原理类似,核心差异在原生 API,可参考)
