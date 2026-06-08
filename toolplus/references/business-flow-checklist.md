---
name: business-flow-checklist
description: 维度旋转:其他文件是"漏洞类型 → 在哪测"视角(auth-logic / api-security / vuln/),本文件是反向索引:"业务节点 → 测哪些漏洞"。 用途:P1.5 业务建模时,识别出目标的所有业务节点,对每个节点对照本表完成测试 + 跑 [intuitio…
category: methodology
---

# 业务节点反向索引 (P1.5 业务建模硬 gate 用)

← 主入口 [../SKILL.md](../SKILL.md) | 配套 [intuition-triggers.md §B](intuition-triggers.md)

> **维度旋转**:其他文件是"**漏洞类型 → 在哪测**"视角(auth-logic / api-security / vuln/*),本文件是反向索引:"**业务节点 → 测哪些漏洞**"。
> **用途**:P1.5 业务建模时,识别出目标的所有业务节点,对每个节点对照本表完成测试 + 跑 [intuition-triggers §B 12 问](intuition-triggers.md)。
> **覆盖度**:本表 10 个核心节点 ~80% SaaS / 电商 / 金融 / 小程序场景。其他垂直行业 (社交 / 教育 / 政企 / SaaS B2B) 等待你提供资料再扩展。

## SRC 状态机记录模板

遇到登录、注册、找回、支付、优惠券、二维码、EDUSRC、若依/Blade、云存储或 APP 入口时, 先记录:

```text
入口信号 -> 可控输入 -> 预期输出 -> 实际输出 -> 下一步转向 -> 关键证据 -> 误判过滤
```

路由规则:

| 入口信号 | 先读 |
|---|---|
| 支付、优惠券、限购、签约、试用、订单关闭、退款、核销、积分商城 | [src-business-logic-state-machine.md](src-business-logic-state-machine.md) |
| 注册、登录、找回密码、验证码主体错位 | [auth-logic.md](auth-logic.md) |
| 高校、证书站、统一认证、教务、后勤、人员选择器、申报 | [edusrc-workflow.md](edusrc-workflow.md) |
| 众测资产、授权边界、SourceMap、SPF/DMARC/DKIM、JSONP/CORS | [recon-workflow.md](recon-workflow.md) |
| 若依、Blade、Nacos、Druid、FineReport、Admin.NET、Swagger、Actuator | [domestic-admin-frameworks.md](domestic-admin-frameworks.md) |
| OSS/COS/S3/MinIO/AK/SK/STS/RAM/CAM | [cloud-security.md](cloud-security.md) |
| 二维码登录、支付、核销、OAuth ticket、scene | [qr-code-workflow.md](qr-code-workflow.md) |
| APP 抓包、Pinning、双向证书、国密、加密参数 | [mobile-app.md](mobile-app.md) |
| 报告前证据和误判过滤 | [src-report-evidence-standards.md](src-report-evidence-standards.md) |

响应差异只作为线索; 高价值结论必须落到最终服务端状态、权益、订单、登录态、对象权限或敏感数据影响。

## 失败流量转向表

false/null、参数 FUZZ 无效、页面可进入但数据空时, 不继续盲测; 先转真实动作包、字段来源和最终服务端状态闭环。
完整横向规则见 [src-failure-pivots.md §通用弱信号转向](src-failure-pivots.md)。

---

## 🔍 Grep 速查

```bash
# 已知业务节点,查应测漏洞
grep -A 20 "## 注册" references/business-flow-checklist.md
grep -A 20 "## 支付下单" references/business-flow-checklist.md

# 已知漏洞类型,反查影响的业务节点
grep "BOLA" references/business-flow-checklist.md
grep "短信轰炸" references/business-flow-checklist.md
```

---

## 业务节点速查表

| 业务节点 | 必查清单 (锚点) | §B 重点问题 |
|---|---|---|
| 注册 | §1 注册 | B3 / B5 / B8 / B9 |
| 登录 | §2 登录 | B1 / B2 / B5 / B9 |
| 找回密码 | §3 找回密码 | B1 / B2 / B7 |
| 支付下单 | §4 支付下单 | B4 / B5 / B8 / B10 / B12 |
| 邀请有礼 | §5 邀请有礼 | B3 / B7 / B12 |
| 实名 / KYC | §6 实名 / KYC | B5 / B6 / B11 |
| 抽奖 | §7 抽奖 | B6 / B9 / B12 |
| 签到打卡 | §8 签到打卡 | B4 / B12 |
| 拼团 / 砍价 | §9 拼团 / 砍价 | B3 / B7 / B12 |
| 充值 / 提现 | §10 充值 / 提现 | B4 / B5 / B8 / B10 |

---

## §1 注册

### 必查清单
| 漏洞 | 锚点 | 测试动作 |
|---|---|---|
| 账号枚举 | [auth-logic.md §1.3](auth-logic.md) | 不同响应区分 用户存在 / 不存在 |
| 默认口令 / 弱口令 | [auth-logic.md §1.4](auth-logic.md) + [weak-password-generation.md](weak-password-generation.md) | admin/123456 等 |
| 短信轰炸 (注册触发) | [api-security.md §速率](api-security.md) + [SKILL.md P3.5](../SKILL.md) | 同一手机号 N 次发送 → **触发 P3.5 索取接收手机号** |
| 邮箱轰炸 (注册触发) | 同上 | 同一邮箱 N 次发送 → **触发 P3.5 索取接收邮箱** |
| 注册逻辑越权 | §8.2 注册接口 | 注册接口直接传 `{"role":"admin","is_vip":true}` |
| 第三方登录绑定混淆 | [vuln/oauth-advanced.md](vuln/oauth-advanced.md) | OAuth 绑定他人账号 |
| 用户名 XSS / SQL | [vuln/xss.md](vuln/xss.md) / [vuln/sqli.md](vuln/sqli.md) | 注册的 nickname / username 后台触发 |

### §B 重点 (P1.5 必跑)
- **B3** 既是甲方又是乙方:邀请自己注册拿邀请奖励?
- **B5** 系统标识冒充:role=admin / user_id=0 注册成功?
- **B8** 字段 null / 类型不对:phone=null 跳过短信验证?
- **B9** 频繁调用:同手机号 1 分钟 N 次注册 → 短信轰炸

---

## §2 登录

### 必查清单
| 漏洞 | 锚点 | 测试动作 |
|---|---|---|
| SQL 注入 / 万能密码 | [auth-logic.md §1.1-1.2](auth-logic.md) | `admin' or '1'='1` |
| 验证码绕过 | [auth-logic.md §3](auth-logic.md) | 回显 / 删除参数 / 万能码 / 复用 / 爆破 |
| 账号枚举 (登录路径) | [auth-logic.md §1.3](auth-logic.md) | 错误消息差异 |
| Session 漏洞 | [auth-logic.md §4](auth-logic.md) | 固定 / 预测 / 并发 / 登出后失效 |
| JWT 漏洞 | [vuln/jwt-advanced.md](vuln/jwt-advanced.md) | alg=none / kid 注入 / jku/x5u 劫持 |
| 短信验证码登录绕过 | [auth-logic.md §3](auth-logic.md) | 短信码 4 位爆破 / 复用 |
| 滑块绕过 | (HITL) | 触发后回 HITL |

### §B 重点
- **B1** 跳过验证步骤:无验证码直接调登录接口?
- **B2** 回退:登录成功后回退到验证步骤,会污染会话吗?
- **B5** 系统标识:username=admin 是否锁定 / 绕过?
- **B9** 频繁调用:无速率限制爆破?

---

## §3 找回密码

### 必查清单
| 漏洞 | 锚点 | 测试动作 |
|---|---|---|
| 步骤跳过 | [auth-logic.md §2](auth-logic.md) | 跳过验证码直接到设置新密码 |
| 手机号 / 邮箱篡改 | [auth-logic.md §2](auth-logic.md) | Step 2 改成他人手机号 |
| Token 可预测 | [auth-logic.md §2](auth-logic.md) | 时间戳 / 自增 ID 当 Token |
| Host Header 注入 | [vuln/host-header.md](vuln/host-header.md) | 改 Host 让重置链接发到攻击者域名 |
| 验证码复用 | [auth-logic.md §3](auth-logic.md) | 多次使用同一验证码 |
| Response 篡改 | (前端绕过) | Step 1 返回 fail,改成 success 继续 Step 2 |

### §B 重点
- **B1** 跳过验证:Step 3 直接调,不走 Step 1/2?
- **B2** 回退:重置成功后回到 Step 1,Token 还能用吗?
- **B7** 影响他人:Step 2 改手机号 → 重置他人密码 (IDOR 致命)

---

## §4 支付下单

### 必查清单
| 漏洞 | 锚点 | 测试动作 |
|---|---|---|
| 金额篡改 (负数 / 0.01 / 极大) | [auth-logic.md §6](auth-logic.md) + [api-security.md](api-security.md) | price=-100 / 0.01 |
| 数量篡改 | 同上 | quantity=-1 / 99999 |
| 并发支付 / 重复扣款 | [vuln/race-condition.md](vuln/race-condition.md) + [intuition-triggers §A #8](intuition-triggers.md) | Burp Intruder 50 并发 |
| 优惠券叠加 | [auth-logic.md §7.1](auth-logic.md) | 多张同时使用 / 满减叠加 |
| 支付回调伪造 | [api-security.md](api-security.md) | 构造 success 回调跳过真实支付 |
| 价格前端化 | (前端信任) | 前端传价格,后端不重算 |
| 订单状态机绕过 | (业务逻辑) | 已发货状态改回未付款退款 |

### §B 重点
- **B4** 时间倒流:优惠到期后改时间戳是否还能用?
- **B5** 系统标识:user_id=admin 下单是否绕过支付?
- **B8** 字段类型:price="0" / price=null 会怎样?
- **B10** 异步回调被人构造:调用方伪造 success 回调
- **B12** 重放:同一订单回调多次 → 多次发货?

---

## §5 邀请有礼

### 必查清单
| 漏洞 | 锚点 | 测试动作 |
|---|---|---|
| 自邀请刷奖励 | [auth-logic.md §7.1](auth-logic.md) | 注册新账号 → 自己邀请自己 |
| 邀请码越权 | [api-security.md](api-security.md) | 改他人邀请码 |
| 重复领奖 | [vuln/race-condition.md](vuln/race-condition.md) | 并发领取 |
| 邀请关系链伪造 | (业务逻辑) | POST 接口直接构造邀请关系 |
| 注销账号后邀请奖励是否回收? | (业务逻辑) | 注销账号 / 拉黑账号是否影响邀请人奖励 |

### §B 重点
- **B3** 自交易:**核心场景**,自己邀请自己 (高产) — 30%+ 中招率
- **B7** 影响他人:伪造邀请关系给目标用户拉黑 / 取消?
- **B12** 重放:领奖接口重放领多次?

---

## §6 实名 / KYC

### 必查清单
| 漏洞 | 锚点 | 测试动作 |
|---|---|---|
| 二次实名占位 | [auth-logic.md §8.1](auth-logic.md) | 用他人身份证占用 ID |
| OCR 绕过 | (前端信任 + 业务) | 上传 PS 身份证 / 改 OCR 结果 |
| 实名信息泄露 | [sensitive-info-exploitation.md](sensitive-info-exploitation.md) | 实名信息返回明文 |
| 实名状态前端化 | (前端信任) | 改前端 is_kyc=true 绕过限制 |

### §B 重点
- **B5** 系统标识:身份证号填 110000000000000000 系统会处理吗?
- **B6** 前端绕过:is_kyc 字段改 true 解锁权限?
- **B11** 导出:管理后台导出实名信息接口越权?

---

## §7 抽奖

### 必查清单
| 漏洞 | 锚点 | 测试动作 |
|---|---|---|
| 概率前端化 | (前端信任) | 前端控制中奖,改返回 success |
| 重放抽奖 | [intuition-triggers §A #8](intuition-triggers.md) | 并发 50 次抽奖 |
| 抽奖次数无限 | [api-security.md](api-security.md) | 接口无次数校验 |
| 奖品 ID 篡改 | (业务逻辑) | 中奖后改奖品 ID 领大奖 |
| 抽奖时间篡改 | (业务逻辑) | 改时间戳到活动期内 |

### §B 重点
- **B6** 前端绕过:概率 / 中奖前端控制
- **B9** 频繁调用:无次数限制刷抽奖
- **B12** 重放:中奖接口重放多次领奖

---

## §8 签到打卡

### 必查清单
| 漏洞 | 锚点 | 测试动作 |
|---|---|---|
| 时间篡改 | (业务逻辑) | 改 client_time 补签历史 |
| 批量补签 | (业务逻辑) | 一次请求补 N 天 |
| 签到奖励翻倍 | (前端 / 业务) | 改奖励数量 |
| 跨天签到 | (时区) | 跨时区 / 改时区领多次 |

### §B 重点
- **B4** 时间倒流:client_time 改昨天补签
- **B12** 重放:同一天签到多次

---

## §9 拼团 / 砍价

### 必查清单
| 漏洞 | 锚点 | 测试动作 |
|---|---|---|
| 虚假人头 | (业务逻辑) | 自己开多账号凑团 |
| 团长退团套利 | (业务逻辑) | 团长退团后是否影响订单 |
| 小号刷砍 | (业务逻辑) | 注册小号给自己砍价 |
| 砍价金额前端化 | (前端信任) | 改前端砍价金额 |
| 拼团状态机 | (业务逻辑) | 团已成功状态改未付款 |

### §B 重点
- **B3** 自交易:**核心场景**,自己凑团 / 自己给自己砍 (高产)
- **B7** 影响他人:伪造帮砍记录到目标
- **B12** 重放:砍价接口重放刷金额

---

## §10 充值 / 提现

### 必查清单
| 漏洞 | 锚点 | 测试动作 |
|---|---|---|
| 提现金额上限绕过 | [auth-logic.md §6.5](auth-logic.md) | 改提现金额超过余额 |
| 银行卡他人绑定 | [api-security.md](api-security.md) | 绑定他人银行卡接收提现 |
| 提现回调伪造 | (业务逻辑) | 失败回调改成功 → 重复发奖 |
| 充值金额篡改 | (业务逻辑) | 充 0.01 到账 100 |
| 提现币种 / 汇率 | (业务逻辑) | 美元提现按人民币结算 |

### §B 重点
- **B4** 时间篡改:汇率窗口时间篡改套利
- **B5** 系统标识:user_id=admin 提现是否走特权通道?
- **B8** 字段类型:amount=null / amount=-100 行为?
- **B10** 回调伪造:支付回调构造 / 提现回调构造

---

## 使用指南

### P1.5 业务建模硬 gate 流程

```
Phase 1 结束 → Phase 2 准入前 强制执行:

1. 输出业务流程图,识别目标的所有业务节点
   (推荐放 assets.md 的 "## 业务建模" 段)

2. 对每个识别出的节点:
   a. 找本文件对应 § 章节,抄"必查清单"到 vulns-trigger.md
   b. 跑 [intuition-triggers §B](intuition-triggers.md) 对应的"重点问题"
   c. 每条结果分类: [HIT_TODO] / [DEFENDED] / [N/A]

3. 全部节点跑完 → 标 [P1.5_DONE] → 准入 P2 参数测试

4. 未识别业务节点 / 未跑必查清单 → 禁止 P2
```

### 优先级建议

不要平摊精力,**优先跑高价值节点的全套**:
- ★★★ 支付下单 / 提现 / 实名 (财产 + 身份)
- ★★ 注册 / 登录 / 找回密码 / 邀请 (账号生命周期)
- ★ 抽奖 / 签到 / 拼团 (营销活动,中低价值)

### 与 [intuition-triggers §A](intuition-triggers.md) 联动

P1.5 §B 追问命中后,进入 P2 测试时还要再跑一遍 §A 现象触发(双层保险):
- §B 找出"该测什么" → 写 vulns-trigger.md
- §A 实测中"看到现象触发动作" → 写 vulns.md

### 与 [SKILL.md P3.5](../SKILL.md) 联动

§B B9 命中速率限制类(短信 / 邮箱轰炸) → 进 P3 利用阶段时**必须先走 P3.5 索取接收资源** (HITL),禁止直接打公共服务。

---

## 局限性 (诚实说)

- 本表 10 节点覆盖 ~80% SaaS / 电商 / 小程序场景
- **不覆盖**:政企 OA / 教育系统 / 工业控制 / IoT / 加密货币 / 在线赌博 等垂直行业 — 这些等你提供资料再扩
- **不覆盖**:接口本身的协议漏洞(SQL / XSS / SSRF 等技术漏洞) — 走 vuln/* 处理
- 业务节点不一定都能识别 — 黑盒看不到的节点(后台审核流程 / 风控决策)无法测,标 [BLACK_BOX]

---

**版本**: v1.0
**更新日期**: 2026-05-24
**适用场景**: SaaS / 电商 / 金融 / 小程序 (其他垂直行业等扩展)
