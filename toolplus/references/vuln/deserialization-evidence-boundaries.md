---
name: deserialization-evidence-boundaries
description: 反序列化证据边界与误判过滤横向规则。用于 deserialize / Shiro / Fastjson-Jackson / XStream-Hessian-Dubbo 等反序列化族漏洞的最终定级、HITL 和报告前自检。
category: vuln
tags: [deser, evidence, rating, false-positive]
---

# 反序列化证据边界与误判过滤

用途: 只承接反序列化族漏洞的横向证据、评级边界、HITL 和误判过滤。具体语言、框架、gadget 和 payload 仍回到对应专题文件。

适用入口:

- [deserialize.md](deserialize.md)
- [fastjson-jackson.md](fastjson-jackson.md)
- [shiro.md](shiro.md)
- [xstream-hessian-dubbo.md](xstream-hessian-dubbo.md)

---

## 使用时机

- First-pass 已发现序列化魔数、格式字段、反序列化报错、OOB 命中、稳定延迟或命令回显。
- 准备从 candidate 升级为 confirmed/high/critical。
- 准备写 SRC 报告,需要确认误判过滤、证据闭环和 HITL 最小化验证。

---

## 横向判断表

| 入口信号 | 失败现象 | 转向动作 | 关键证据 | 评级边界 | 误判过滤 |
|---|---|---|---|---|---|
| 魔数 / Base64 / `@type` / `$type` / `O:N` / ViewState | 只有可解码对象,无执行现象 | 做结构化 benign payload 和异常 payload A/B 对照 | 参数位置、格式、A/B 响应差异 | 仅线索或低置信 candidate | 普通 Base64、压缩包、加密 token、客户端状态不等于反序列化 |
| 500 / 解析报错 / ClassNotFound | 无 OOB、无延迟、无回显 | 从格式指纹转到对应语言/框架;只做非破坏探测 | 错误类型、堆栈片段、响应差异、重复性 | candidate,不能直接高危 | WAF、代理、网关、业务校验也会产生 500 |
| URLDNS / OOB 命中 | RCE gadget 失败 | 确认 OOB 通道已授权;切换 gadget 家族或改用延迟探测 | 唯一 token、请求时间、目标请求关联、原始 payload 摘要 | 可证明执行路径;无进一步影响时通常不直接 Critical | 排除扫描器、代理预取、DNS 缓存和第三方误触发 |
| 稳定延迟 | 无回显 | 连续 A/B 复测,控制网络抖动和异步队列 | 多次时延样本、基线请求、payload 请求、时间窗口 | 可作为强执行信号;定级取决于可控影响 | 单次慢响应、队列积压、冷启动不能单独定级 |
| 受控命令回显 | 只证明最小命令执行 | 停止扩大影响;走报告证据流水线 | 请求/响应、最小命令输出、执行主体、脱敏环境信息 | 未授权 RCE 通常 High/Critical | 页面回显、日志拼接、客户端执行不是服务端 RCE |
| 文件写入 / WebShell / 云凭据利用 | 需要高风险动作 | 必须 HITL;只测自有路径、自有对象或只读身份 | 用户授权、最小化动作、写入/读取/权限边界、清理记录 | 影响明确时 Critical 候选 | 不覆盖真实文件、不批量读取、不持久化、不横向扩展 |
| PHAR 上传 / ViewState key / Pickle/YAML 入口 | 缺少 sink、key 或消费链 | 找真实反序列化 sink、有效 key、消费时机 | 上传位置、调用链、key 来源、触发请求 | 缺 sink/key 时只是链路候选 | 上传成功或 key 格式像真不等于可利用 |
| 异步队列 / 缓存 / MQ 消费 | 请求侧无即时响应 | 用 OOB、状态变化或日志侧证据闭环;日志需 HITL | 队列入口、消费时间、OOB/状态证据、账号边界 | 评级取决于消费端权限和最终影响 | 无法关联消费者时不要报 confirmed |

---

## 最小证据包

- 入口: 参数、Cookie、Header、文件、队列消息或 ViewState 的具体位置。
- 格式: 序列化格式、语言/框架判断依据和目标处理路径。
- 控制: benign payload、异常 payload、OOB/延迟/回显 payload 的 A/B 结果。
- 关联: 唯一 token、时间窗口、HTTP flow id、截图或 OOB 记录。
- 影响: 执行主体、权限范围、可访问资源类型、业务或系统影响。
- 边界: 已做和未做的高风险动作,以及 HITL 授权状态。

---

## 评级口径

- 魔数、可解码对象、500、ClassNotFound: 线索或 candidate。
- OOB 命中或稳定延迟: confirmed execution path;通常 High 候选,是否 Critical 看可控影响。
- 受控命令回显: RCE confirmed;未授权且影响生产服务时 High/Critical。
- 文件写入、WebShell、云凭据、批量数据影响: 必须 HITL 最小化验证;证据闭环后 Critical 候选。
- 只有框架版本或公开 CVE 命中: 不足以定级,必须证明目标入口可触发。

---

## HITL 边界

以下动作必须先按 `references/protocols/agent-protocol.md §P3.5` 请求用户确认:

- 使用公共 OOB、临时邮箱、Webhook、监听器或外部文件 URL。
- 写文件、覆盖文件、上传 WebShell、执行系统命令或触发持久化。
- 使用云 AK/SK、STS、RAM/CAM 凭据或访问云资源。
- 下载大文件、读取敏感文件、批量枚举、横向探测或影响第三方资产。

---

## 报告前误判过滤

- 不把编码、压缩、加密 token、ViewState 外观或对象字符串直接当漏洞。
- 不把单次 500、慢响应、空 OOB 记录或扫描器噪声当 confirmed。
- 不把 gadget 不兼容、类缺失、出站被封解释成已 RCE。
- 不把客户端可构造 payload 当服务端已反序列化。
- 不输出真实账号、手机号、身份证、Token、真实云凭据或真实目标内部地址。

---

## 回到专题

| 需要继续做 | 文件 |
|---|---|
| 通用语言格式和 gadget 选择 | [deserialize.md](deserialize.md) |
| Java JSON autoType / Jackson | [fastjson-jackson.md](fastjson-jackson.md) |
| Shiro rememberMe | [shiro.md](shiro.md) |
| XStream / Hessian / Dubbo / RMI | [xstream-hessian-dubbo.md](xstream-hessian-dubbo.md) |
