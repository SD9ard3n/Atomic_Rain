---
name: tencent-cloud
description: 腾讯云专项 playbook — CAM 凭证体系 / COS 对象存储 / SCF 云函数 / CKafka / TKE 容器服务 / 微信生态联动。聚焦腾讯云独家特性,通用云攻击走 cloud-security.md。
category: technologies
tags: [technology, cloud, tencent, qcloud, cam, cos, scf, china]
---

# 腾讯云 (Tencent Cloud / QCloud) Playbook

> **何时用本文件**: 通过 AK 前缀 (`AKID`) / Endpoint (`*.tencentcloudapi.com`) / COS Bucket (`*.cos.*.myqcloud.com`) 确认目标使用腾讯云后,系统梳理服务面。
> **与 [alibaba-cloud.md](alibaba-cloud.md) 的关系**: 概念高度对称 (RAM↔CAM / OSS↔COS / FC↔SCF / ACK↔TKE),本文件只列腾讯独家差异和需要关注的细节。
> **通用部分**: 走 [cloud-security.md](../cloud-security.md)。

---

## 1. 指纹识别

### 1.1 AK 前缀

| 前缀 | 类型 | 含义 |
| :--- | :--- | :--- |
| `AKID` (4 字符) | 长期 AK SecretId | 主账号 / CAM 子账号 |
| 配对 `SecretKey` | 长期 SK | 32 字符 |
| `q-sign-...` Header | COS 签名 | COS 请求签名标识 |
| `qcs::cam::uin/...:` | CAM 实体 ARN | 类似阿里云 acs |

### 1.2 Endpoint / Bucket 指纹

| 指纹 | 服务 |
| :--- | :--- |
| `*.tencentcloudapi.com` | 腾讯云 OpenAPI |
| `*.cos.ap-*.myqcloud.com` | COS 对象存储 |
| `*.scf.tencentcloudapi.com` | SCF 云函数 |
| `*.ap-guangzhou.tencentcloudapi.com` / `ap-shanghai` / `ap-beijing` | 主 region (广州/上海/北京) |
| `Server: TWS` / `Server: tencent-cos` | 腾讯前端 |
| `X-Cos-Request-Id` 响应头 | COS 标识 |
| `*.cloud.tencent.com` `*.qq.com` | 关联域 |

### 1.3 元数据 Endpoint

```bash
# CVM 元数据 (与 AWS 相同 IP)
http://169.254.0.23/latest/meta-data/    # 注意是 0.23 不是 169.254.169.254
http://metadata.tencentyun.com/latest/meta-data/

# 拿 CAM 角色凭证
http://metadata.tencentyun.com/latest/meta-data/cam/security-credentials/<ROLE_NAME>
# 返回 {TmpSecretId, TmpSecretKey, Token, ExpiredTime, ...}

# 实例信息
http://metadata.tencentyun.com/latest/meta-data/instance-id
http://metadata.tencentyun.com/latest/meta-data/region
```

**与阿里云的差异**: 腾讯云元数据 IP 是 `169.254.0.23`,非阿里云的 `100.100.100.200`,非 AWS 的 `169.254.169.254`。

---

## 2. CAM 权限快速判定

```bash
# 配置 tccli
tccli configure --secretId AKID... --secretKey ... --region ap-guangzhou

# 探权限
tccli cam GetUserAppId      # 拿 AppId + UIN
tccli sts GetCallerIdentity # 类似阿里云 GetCallerIdentity
tccli cam ListAttachedUserPolicies --TargetUin xxx
```

**P3.5 HITL**: 同阿里云,不要直接 List 全部资源。

### CAM 权限优先级

| 策略 | ROI | 验证 |
| :--- | :---: | :--- |
| `QcloudCOSFullAccess` | 🔴 极高 | `tccli cos ListBuckets` |
| `QcloudCamFullAccess` | 🔴 极高 | 可创建后门子账号 |
| `QcloudCVMFullAccess` | 🔴 极高 | `tccli cvm DescribeInstances` |
| `QcloudSCFFullAccess` | 🔴 高 | `tccli scf ListFunctions` |
| `QcloudCDBReadOnlyAccess` | 🟡 中 | `tccli cdb DescribeDBInstances` |
| `QcloudCLSReadOnlyAccess` | 🟡 中 | 日志服务 (含历史 token / 密码) |

---

## 3. 高价值服务

### 3.1 COS 对象存储

#### A. 公开 Bucket 探测

```bash
# COS bucket 格式: <BucketName-APPID>.cos.<region>.myqcloud.com
# APPID 是 10 位数字 (业务唯一)

curl https://target-1234567890.cos.ap-guangzhou.myqcloud.com/
curl https://target-1234567890.cos.ap-shanghai.myqcloud.com/?list-type=2

# 各 region 试探
for r in ap-guangzhou ap-shanghai ap-beijing ap-chengdu ap-hongkong; do
  curl -s -o /dev/null -w "[$r] %{http_code}\n" "https://target-1234567890.cos.$r.myqcloud.com/"
done
```

**关键差异**: COS bucket 名**必须含 APPID** (`-1234567890`),不像 OSS 是纯名字。所以发现 1 个 bucket 就拿到 APPID,后面所有 bucket 都用同一个 APPID 枚举。

#### B. COS 签名版本

腾讯云 COS 用 `q-sign-algorithm` (CV) v3 签名,与 AWS S3 / 阿里云 OSS 不兼容。用 tccli 直接发,不要手算。

#### C. 临时密钥 (STS-like)

腾讯云用 "联合身份临时密钥",对应阿里云 STS。Policy 错配同阿里云。

### 3.2 SCF 云函数

```bash
# 已部署 SCF endpoint (API 网关触发)
https://service-XXXXXXX-1234567890.ap-guangzhou.apigateway.myqcloud.com/PATH

# 拿到 AK 后
tccli scf ListFunctions --region ap-guangzhou
tccli scf GetFunction --FunctionName xxx --Namespace default
# 拉代码 (返回 CosUrl,即下载链接)
tccli scf GetFunction --FunctionName xxx --ShowCode true
```

**SCF 风险**: API 网关 + 函数 + 匿名调用 → 任意调用业务函数。

### 3.3 CDB / TencentDB

- 拿到 CAM `QcloudCDBReadOnlyAccess` → 看实例配置 + 备份策略
- 备份投递到 COS → COS bucket 公开性
- 拿到 AK + SecurityGroup `0.0.0.0/0` + 弱口令 → 数据库直连 (需 HITL)

### 3.4 CLS 日志服务

- `QcloudCLSReadOnlyAccess` → 历史日志可能含明文密码 / Token
- 日志投递到 COS → 看公开性

### 3.5 容器服务 TKE / EKS

- CAM `tke:DescribeClusters` → K8s kubeconfig 暴露 → 接管集群
- TKE 节点 metadata → STS 横向

### 3.6 中间件: CKafka / CMQ / TDMQ

- CKafka 公网接入 + 默认认证 → 消息伪造
- TDMQ (RocketMQ-like) 同阿里云 RocketMQ

### 3.7 微信生态联动

**腾讯云独家优势**: 与微信生态深度集成。

| 联动场景 | 风险 |
| :--- | :--- |
| 微信支付 → 商户回调 | 签名错配 / 不验签 / 金额可控 |
| 微信小程序 → wx.cloud (云开发) | 云开发权限规则错配 (走 [miniapp-workflow.md §4.2](../miniapp-workflow.md)) |
| 微信公众号 → 服务器配置 → Token 验证 | Token 泄露 / 消息伪造 |
| QQ 互联登录 OAuth | 与 OAuth-advanced 同 |

---

## 4. OpenAPI 探测

```bash
# 拿 AppId + UIN
tccli cam GetUserAppId

# 公共信息: 域名备案查 (无 AK 不行)
# Region 列表 (公开)
curl "https://cvm.tencentcloudapi.com/?Action=DescribeRegions&Version=2017-03-12"
```

---

## 5. False Positives / 常见陷阱

| 现象 | 误判 | 真实判断 |
| :--- | :--- | :--- |
| COS bucket 403 | 完全无权限 | 试加 `?versions` / `?delimiter=/` |
| `AKID...` 字符串 | 一定是腾讯 AK? | 长度 36 字符是腾讯,其他云不同 |
| `tccli configure` 成功但调用 401 | AK 假? | 试切 region (有些 API 是 region-specific) |
| SCF 函数报 ResourceNotFound | 不存在? | 检查 Namespace (默认是 `default`) |

---

## 6. Impact 证据

同阿里云,见 [alibaba-cloud.md §7](alibaba-cloud.md)。腾讯特有:
- 微信支付商户号 + API key 泄露 → Critical (可伪造支付/退款)
- 公众号 AppId + AppSecret 泄露 → High (拉取用户 openid 列表)

---

## 7. Pro Tips

- **AppId 优先**: 拿到 COS bucket 名第一动作是提取 APPID (`-1234567890` 后 10 位),后续所有 bucket 用同 APPID 枚举
- **COS 跨区**: 同 APPID 在不同 region 可能有不同 bucket,五大 region 都试 (广州/上海/北京/成都/南京)
- **SCF 反弹**: SCF 默认 Internet egress 开,反弹 shell OK 但要 P3.5 HITL
- **腾讯云 ActionTracker** (类似阿里云 ActionTrail): 默认开启 — 测试要节制
- **WAF**: 腾讯云 WAF (T-Sec) 拦截规则与阿里云不同,经常 multipart/form-data 比 application/json 容易过
- **国密**: 金融业务可能用国密 TLS,需 Yakit 国密版本
- **微信支付回调**: 商户号 + key 泄露后,可构造伪造的支付通知 → 后端不验签就刷单
- **CAM 子账号常见误配**: 给子账号 `QcloudCOSFullAccess` 但 Condition 不限 bucket → 子账号可读所有 COS

---

## 8. 工具升级线

**classic 版**:
- CLI: `tccli` 官方 CLI
- 签名: `tencentcloud-sdk-python` / 手算 v3 签名
- COS scan: `cos-find` 类工具 / 手写 ffuf

**toolPlus 版**:
- `mcp__yaklang__http_fuzzer` sweep COS bucket 命名
- `mcp__yaklang__exec_codec` 处理 v3 签名链 (HMAC-SHA1 + SHA1)
- `mcp__yaklang__brute` 字典爆破 bucket

---

## 9. 相关参考

- 通用云攻击: [cloud-security.md](../cloud-security.md)
- 阿里云对应章节: [alibaba-cloud.md](alibaba-cloud.md)
- SSRF: [vuln/ssrf.md](../vuln/ssrf.md)
- 微信小程序云开发: [miniapp-workflow.md §4.2](../miniapp-workflow.md)
- 敏感信息利用: [sensitive-info-exploitation.md](../sensitive-info-exploitation.md)
