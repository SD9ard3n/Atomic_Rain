---
name: email-spoofing
description: 范围:目标公司域名的邮件认证三件套 (SPF / DKIM / DMARC) 漏配,导致第三方可伪造该域名发送钓鱼邮件。 价值:钓鱼基础设施漏洞,中高危。配合社工可直接打员工 / 客户。 触发条件:目标有公司域名 + 对外发邮件 (营销 / 通知 / 客服)。 配套:发送 Po…
category: vuln
---

# Email Spoofing (SPF / DKIM / DMARC 漏配)

← 主入口 [../../SKILL.md](../../SKILL.md) | 区别于 [email-header-injection.md](email-header-injection.md) (SMTP CRLF 注入,不是同一类)

> **范围**:目标公司域名的邮件认证三件套 (SPF / DKIM / DMARC) 漏配,导致**第三方可伪造该域名发送钓鱼邮件**。
> **价值**:钓鱼基础设施漏洞,中高危。配合社工可直接打员工 / 客户。
> **触发条件**:目标有公司域名 + 对外发邮件 (营销 / 通知 / 客服)。
> **配套**:发送 PoC 邮件需要 [SKILL.md P3.5](../../SKILL.md) 触发 HITL,索取发送账号 + 接收邮箱。

---

## Decision Card (快速判定)

| 现象 | 判定 | 行动 |
|---|---|---|
| `dig TXT target.com` 无 `v=spf1` 记录 | SPF 缺失 ★高危 | 任意第三方可伪造,直接 swaks PoC |
| `v=spf1 ... +all` 或 `v=spf1 -all` 都没 | SPF 全允许 ★高危 | 同上 |
| `v=spf1 ... ~all` | SPF 软失败 ★中危 | 可能不被拒绝,看 DMARC 配置 |
| `v=spf1 ... -all` | SPF 硬失败 ✅ | 安全,继续看 DKIM/DMARC |
| `dig TXT default._domainkey.target.com` 无记录 | DKIM 缺失 ★中危 | 没签名,容易伪造 |
| DKIM 公钥长度 < 1024 | DKIM 弱密钥 ★中危 | 理论可暴力 |
| `dig TXT _dmarc.target.com` 无记录 | DMARC 缺失 ★高危 | 无策略,SPF/DKIM 失败也接收 |
| `p=none` | DMARC 仅监控 ★中危 | 不拦截,仅报告 |
| `p=quarantine` | DMARC 隔离 ✅ | 失败进垃圾箱 |
| `p=reject` | DMARC 拒绝 ✅ | 安全 |

---

## First-pass Signal (3 分钟出结果)

```bash
# 一键三查
DOMAIN=target.com
echo "=== SPF ==="
dig TXT $DOMAIN +short | grep -i "v=spf1"

echo "=== DMARC ==="
dig TXT _dmarc.$DOMAIN +short

echo "=== DKIM (常见 selector) ==="
for sel in default google selector1 selector2 k1 mail; do
  echo "--- $sel._domainkey.$DOMAIN ---"
  dig TXT $sel._domainkey.$DOMAIN +short
done
```

**判定**:
- 三个都齐 + 都严格 (`-all` + `p=reject` + DKIM ≥ 2048) → ✅ 跳过,记 `[DEFENDED]`
- 任一缺失 / 弱配 → 进入 PoC 阶段

---

## §1 三件套深度解析

### 1.1 SPF (Sender Policy Framework)

**作用**:声明谁能用本域名发邮件 (按 IP 白名单)。

**漏配类型**:
| 配置 | 危险度 | 含义 |
|---|---|---|
| 无 SPF 记录 | ★★★ | 任意 IP 可发送 |
| `v=spf1 +all` | ★★★ | 显式全允许 |
| `v=spf1 -all` 都没结尾 | ★★ | 隐含 `+all` |
| `v=spf1 a mx ~all` | ★ | 软失败,可能进收件箱 |
| `v=spf1 a mx -all` | ✅ | 硬失败 |
| `v=spf1 include:_spf.google.com ~all` | ⚠️ | 看 `~all` 还是 `-all`,以及 include 链是否过宽 |

**SPF 链超长漏洞 (扩展)**:`include:` 超过 10 次 DNS 查询会导致 SPF 校验失败,等同于无 SPF。

### 1.2 DKIM (DomainKeys Identified Mail)

**作用**:邮件签名,证明邮件没被篡改 + 来自授权服务器。

**检测**:`dig TXT <selector>._domainkey.<domain>` (selector 常见: default / google / selector1 / selector2 / k1 / mail / s1024)

**漏配**:
- 无 DKIM 公钥 → 收件方无法校验签名 → 易伪造
- 公钥长度 < 1024 → 理论可暴力推私钥 (2024 后 < 2048 也算弱)
- DKIM `t=y` (测试模式) → 校验失败也接收

### 1.3 DMARC (Domain-based Message Authentication, Reporting & Conformance)

**作用**:声明 SPF/DKIM 失败时该怎么办。

**关键字段**:
| 字段 | 值 | 含义 |
|---|---|---|
| `p=` | none | 不处理 (仅 ruf/rua 报告) |
| `p=` | quarantine | 进垃圾箱 |
| `p=` | reject | 直接拒收 |
| `sp=` | (同 p) | 子域策略,缺失则继承 p |
| `pct=` | 0-100 | 应用策略的邮件比例 (`pct=10` = 90% 不拦) |
| `aspf=` | s/r | SPF 对齐模式 (strict / relaxed) |
| `adkim=` | s/r | DKIM 对齐模式 |

**漏配组合**:
- `p=none` 等于裸奔,只监控不阻断 → ★★★
- `p=quarantine; pct=10` 等于只拦 10%,90% 进收件箱 → ★★
- `sp=` 缺失 → 子域无策略,可用 `sub.target.com` 伪造

---

## §2 工具矩阵

### 2.1 轻量批量 — spf-master / spoofcheck.py

| 工具 | 来源 | 用法 |
|---|---|---|
| **spf-master** | `/path/to/spf-master` | `python spf.py target.com` (依赖 kitterman.com 第三方,**OPSEC 风险**) |
| **spoofcheck.py** | github.com/BishopFox/spoofcheck | `python spoofcheck.py target.com` (本地解析,推荐) |

### 2.2 详查单域 — dig

```bash
# SPF + DMARC + DKIM 一锅端
dig TXT target.com _dmarc.target.com default._domainkey.target.com +short
```

### 2.3 综合 — MXToolbox (HITL 浏览器)

```
https://mxtoolbox.com/SuperTool.aspx?action=mx%3atarget.com
```
图形化看 SPF/DMARC/DKIM/MX 等,适合非渗透人员展示报告。

### 2.4 PoC 发件 — swaks

> **触发 [SKILL.md P3.5](../../SKILL.md)**:索取发送账号 + 接收邮箱,**禁止默认用公共邮箱发**

```bash
# 伪造 admin@target.com 发到攻击者收件箱
swaks --to attacker@your-mail.com \
      --from "admin@target.com" \
      --header "Subject: 内部测试 - SPF/DMARC 验证" \
      --body "本邮件用于验证 target.com 邮件认证配置漏洞" \
      --server smtp.attacker-vps.com:25
```

**OPSEC**:
- 发送服务器用**自己的 VPS** (避免被关联到测试者)
- 接收邮箱用**用户提供的** (P3.5 协议要求)
- 邮件主题 / 内容**明确标注"测试"**,避免被理解为真实钓鱼

---

## §3 与 [email-header-injection.md](email-header-injection.md) 的区别

| 维度 | email-spoofing (本文) | email-header-injection |
|---|---|---|
| 攻击层面 | DNS / SMTP 认证层 | 应用层 (Web 表单调用邮件 API) |
| 攻击者位置 | 任意第三方 (不需要接触目标) | 必须能调用目标的邮件接口 |
| 利用方法 | DNS 查 → swaks PoC | 表单注入 `\r\nBcc:` 等 CRLF |
| 修复方法 | DNS 加严 SPF/DKIM/DMARC | 应用层过滤 CRLF |
| 危害对象 | 收件人 (员工 / 客户) | 任意邮件地址 (BCC / 注入恶意头) |

如果目标有 Web 表单调邮件接口,**两个都测**。

---

## §4 PoC 模板 (报告用)

### 复现步骤

```
1. dig TXT target.com → 显示无 SPF 或 +all
   [截图]

2. dig TXT _dmarc.target.com → 显示 p=none 或缺失
   [截图]

3. swaks 伪造发送 (HITL: 用 P3.5 索取的接收邮箱)
   [完整命令 + 接收截图,脱敏发件人]

4. 邮件成功进入收件箱 (非垃圾箱)
   [截图]
```

### 影响证明

| 等级 | 证明 |
|---|---|
| 低 | 进垃圾箱 |
| 中 | 进收件箱 (但显示警告) |
| 高 | 进收件箱无警告 |
| 严重 | 进收件箱 + 显示官方头像 / Logo (GMAIL / 国内邮箱通常配 BIMI) → 完美钓鱼 |

### 修复建议 (短期 + 长期)

**短期**:
```
SPF:   v=spf1 a mx include:_spf.target.com -all
DMARC: v=DMARC1; p=quarantine; rua=mailto:dmarc@target.com; pct=100
DKIM:  生成 2048 位密钥对,发布 default._domainkey.target.com
```

**长期**:
- 监控 DMARC 报告 (rua) 找伪造源 IP
- 子域策略 `sp=reject` 防伪造子域
- BIMI (品牌指示) 提升合规

---

## §5 触发场景速查

| 场景 | 加分项 |
|---|---|
| 目标是金融 / 政企 / 银行 | 钓鱼员工拿凭证价值极高 |
| 目标客服 / 营销系统 | 钓鱼客户骗钱 |
| SRC 项目 / 红队 | 邮件钓鱼基础设施得分 |

---

## §6 自动化建议 (toolPlus 版可用 MCP 加速)

> Classic 版:走 dig / swaks CLI + HITL (本节)
> toolPlus 版:`chrome_network_request` 调 DoH API 替代 dig — 工具索引见 toolPlus 仓库的 `mcp-tools-finder.md`

---

## 相关参考

- 主入口 → [../../SKILL.md](../../SKILL.md)
- SMTP 应用层注入 → [email-header-injection.md](email-header-injection.md)
- 钓鱼接收端 / OOB 通道 → [../oob-infrastructure.md §10](../oob-infrastructure.md)
- 外部资源 HITL → [SKILL.md §1 P3.5](../../SKILL.md)
- 工具矩阵 → [../tool-config.md](../tool-config.md) (邮件安全工具类)
