---
name: mobile-app
description: 移动端APP安全测试参考
category: methodology
---

# 移动端APP安全测试参考

## 目录
- [1. 测试环境准备](#1-测试环境准备)
- [2. 证书绑定绕过与流量拦截](#2-证书绑定绕过与流量拦截)
- [3. APK逆向分析](#3-apk逆向分析)
- [4. iOS应用分析](#4-ios应用分析)
- [5. Frida Hook实战](#5-frida-hook实战)
- [6. APP组件安全](#6-app组件安全)
- [7. 本地存储安全](#7-本地存储安全)
- [8. APP API测试](#8-app-api测试)
- [9. 深度检测](#9-深度检测)

---

## 使用纪律

- 先根据目标材料选择路径: APK/IPA 文件、设备抓包、H5/web-view、小程序跳转或后端 API。
- 无移动包时不要加载逆向/Frida 章节; 只有 API 流量时优先转 [api-security.md](api-security.md) 和 [business-flow-checklist.md](business-flow-checklist.md)。
- 环境、抓包、Hook、逆向、组件和本地存储命令速查统一见 [mobile-tool-commands.md](mobile-tool-commands.md); 本文件只保留测试路径、HITL 边界、证据要求和服务端验证。
- 证书绑定/Hook/重签名属于环境动作, 需要用户设备、授权范围和可恢复方案明确后再执行。
- 逆向输出只作为线索; 漏洞确认仍需请求/响应、账号边界、设备状态或后端 API 证据。
- 大于单章节的深挖只在用户提供包体、设备或明确 deep mode 时进行。

---

## 1. 测试环境准备

先确认测试材料、设备可用性、代理链路、是否需要 Root/越狱/Hook 以及是否有可恢复方案。Android / iOS 工具清单和基础命令见 [mobile-tool-commands.md](mobile-tool-commands.md#环境准备)。

HITL 边界: 安装包、真机/模拟器、证书安装、Root/越狱、重签名和 Hook 都需要用户明确授权; 没有设备或包体时转 API / H5 / 小程序路径。

---

## 2. 证书绑定绕过与流量拦截

目标是建立可复现的明文请求链路, 而不是把绕过客户端防护本身作为漏洞。Android / iOS 证书安装、代理设置、SSL Pinning 绕过和 Frida / Objection 命令见 [mobile-tool-commands.md](mobile-tool-commands.md#证书绑定与抓包)。

证据要求: 记录阻碍现象、绕过方式、抓到的原始请求/响应、账号边界和服务端影响; 仅证明能绕过证书绑定不构成有效漏洞。

---

## 3. APK逆向分析

静态分析用于找接口、域名、证书、加密参数、调试开关、云配置、导出组件和本地敏感存储线索。jadx / apktool / MobSF / grep / AndroidManifest 速查见 [mobile-tool-commands.md](mobile-tool-commands.md#apk-逆向)。

评级边界: 逆向发现密钥、接口或配置只是线索; 需要证明密钥可用、接口可越权、配置可造成数据或资产影响。

---

## 4. iOS应用分析

iOS 分析重点是解包/砸壳、类和字符串、ATS、URL Scheme、后台模式、证书校验和接口线索。class-dump / Hopper / IDA / Info.plist 命令见 [mobile-tool-commands.md](mobile-tool-commands.md#ios-分析)。

HITL 边界: 越狱设备、重签名、运行时注入和证书改动必须先确认授权与回滚方式。

---

## 5. Frida Hook实战

Hook 用于还原加密参数、定位客户端校验、辅助抓包和验证服务端是否信任客户端状态。基础 Hook、加密函数 Hook、Root 检测和签名校验绕过脚本见 [mobile-tool-commands.md](mobile-tool-commands.md#frida-hook)。

误判过滤: Hook 改返回值只说明客户端可被篡改; 必须回放真实请求并证明服务端接受越权、篡改或非法状态。

---

## 6. APP组件安全

组件测试关注导出 Activity / Service / Receiver / Provider、Deep Link、Content Provider 数据访问和跨 App 调用链。dumpsys / drozer / Deep Link 命令见 [mobile-tool-commands.md](mobile-tool-commands.md#组件与-deep-link)。

证据要求: 需要证明未授权组件可被外部调用并造成数据读取、状态修改、账号接管、敏感跳转或权限提升。

---

## 7. 本地存储安全

本地存储检查 SharedPreferences、SQLite、备份数据、缓存文件、硬编码密钥和未加密 Token。提取与检查命令见 [mobile-tool-commands.md](mobile-tool-commands.md#本地存储)。

评级边界: 本地可读不等于高危; 需要结合设备前提、攻击者能力、Token 有效性、服务端权限和可批量影响评估。

---

## 8. APP API测试

### 8.0 SRC APP 测试状态机

APP 测试的 SRC 价值通常在服务端接口, 环境绕过只是前置条件:

```text
APP 能运行
-> 能抓包
-> 能解 TLS/Pinning/双向证书/国密
-> 能还原加密参数
-> 服务端 API 测试
```

推进路径:

1. 先记录运行阻碍: 模拟器/root/hook 检测、代理检测、闪退、版本强更。
2. 建立明文流量后, 按登录、注册、找回、列表、详情、上传、支付、消息、个人信息拆接口。
3. 对每个接口做 A/B 账号对照, 优先测 ID 归属、token 绑定、签名是否只防篡改不防越权。
4. 无法抓包时转静态侧: 反编译接口域名、配置、证书、字符串、H5/小程序同接口、历史版本。
5. 还原加密参数后, 回到 [api-security.md](api-security.md)、[auth-logic.md](auth-logic.md) 和 [src-business-logic-state-machine.md](src-business-logic-state-machine.md) 做服务端验证。

误判过滤: 绕过客户端检测、证书绑定或代理检测不是漏洞本身; 拿到接口域名也不是漏洞。最终必须证明服务端数据、权限、业务状态、订单、权益或敏感信息影响。

### 8.1 测试流程

```
1. 抓包: 绕过证书绑定 → Burp/mitmproxy抓取所有请求
2. 分类: 按功能分类 (登录/用户/订单/支付/上传)
3. 测试:
   - 未授权: 不带Token直接调用
   - IDOR: 替换用户ID/订单ID
   - 参数篡改: 金额/数量/状态
   - 逻辑漏洞: 验证码/支付/竞争
   - 重复请求: 支付/提交/领券
```

### 8.2 APP特有测试点

```
- 短信验证码: 在APP上验证,但在Web端使用 (或反之)
- Token过期: 长期有效? 可续期?
- 设备绑定: 多设备登录? 换设备后Token是否失效?
- 推送劫持: 推送消息可伪造?
- 生物识别: 可绕过? 降级到密码?
- APP版本: 旧版本API是否关闭? 降级攻击?
- 数据同步: 修改本地数据 → 同步到服务器?
```

---

## 9. 深度检测

### 9.1 APP漏洞赏金高价值目标

| 漏洞类型 | 影响 | 常见场景 |
|----------|------|----------|
| 证书绑定绕过+API未授权 | 数据泄露 | 未保护的管理API |
| IDOR(订单/用户) | 批量数据泄露 | 用户中心/订单详情 |
| 硬编码AK/SK | 云资源接管 | AWS/阿里云密钥 |
| Deep Link劫持 | 账号接管 | OAuth回调/密码重置 |
| 备份数据泄露 | 凭证泄露 | SQLite中的Token |
| 签名校验绕过 | APP篡改 | 签名检测可绕过 |
| 导出组件 | 数据泄露/提权 | Content Provider |
| 本地加密弱 | 凭证泄露 | AES-ECB/硬编码密钥 |
| APP降级攻击 | 旧漏洞利用 | 版本回退到有漏洞版本 |
| WebView漏洞 | RCE/XSS | addJavascriptInterface |

### 9.2 常用工具速查

常用工具、安装方式和命令速查见 [mobile-tool-commands.md](mobile-tool-commands.md#工具速查)。本文件只保留漏洞路径、证据要求和组合链。

---

## 相关参考与组合链

| 本文件漏洞 | 组合链下一环 | 参考文件 |
|-----------|-------------|---------|
| 证书绑定绕过 | 抓包分析API → 测试API漏洞 | [api-security.md](api-security.md) §API枚举与发现 |
| 硬编码AK/SK | 接管云存储 → 读取/写入敏感文件 | [cloud-security.md](cloud-security.md) §对象存储安全 |
| Deep Link劫持 | OAuth回调劫持 → Token窃取 → 账号接管 | [api-security.md](api-security.md) §OAuth/SSO攻击 |
| 导出ContentProvider | 读取本地Token → 用Token调用API | [api-security.md](api-security.md) §未授权访问 |
| 本地数据库泄露 | 提取密码哈希 → 密码复用攻击 | [auth-logic.md](auth-logic.md) §密码修改逻辑 |
| APK逆向发现API | 测试API接口 → SQL注入/越权 | [vuln/sqli.md](vuln/sqli.md) / [api-security.md](api-security.md) §BOLA |
| Frida绕过签名校验 | 重打包APP → 植入代理 → 全流量分析 | 本文件 §APP API测试 |
| WebView漏洞 | XSS/RCE → 读取本地文件 → 凭证泄露 | [vuln/xss.md](vuln/xss.md) |
