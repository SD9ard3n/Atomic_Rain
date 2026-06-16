# Atomic Rain v2.0 — Signal-Driven Security Testing Skill

> **双版本架构**: Classic (CLI-only) + ToolPlus (MCP-first)  
> **适用场景**: 授权 Bug Bounty、SRC 挖洞、企业安全评估  
> **核心方法**: Phase 0-4 完整工作流 + 概率信号模型 + 异常检测 + 自适应 WAF 对抗

---

## 🎯 版本选择指南

| 维度 | **Classic 版** | **ToolPlus 版** |
|------|--------------|----------------|
| **工具依赖** | CLI 工具（curl/sqlmap/nmap/nuclei） | MCP 工具（Yakit/Chrome） |
| **适用环境** | 任何环境，无需 MCP | 需要 Yakit MCP + Chrome MCP |
| **学习曲线** | 熟悉传统渗透工具即可 | 需要了解 MCP 工具生态 |
| **自动化程度** | 中等（手动拼接 CLI 命令） | 高（MCP 工具封装良好） |
| **速度** | 慢（CLI 调用开销） | 快（MCP 直接通信） |
| **推荐人群** | 传统渗透测试人员 | Claude Code 重度用户 |

### 💡 选择建议

- **传统环境** → 选 **Classic 版**（`/classic/`）
- **已配置 Chrome Yakit MCP** → 选 **ToolPlus 版**（`/toolplus/`）

---

## 🚀 快速开始

### Classic 版
```bash
# 1. 克隆仓库
git clone https://github.com/SD9ard3n/Atomic_Rain.git
cd Atomic_Rain/classic

# 2. 配置工具路径（编辑 references/tool-config.md）
# 填入你本地安装的 sqlmap/nuclei/dirsearch 等工具路径

# 3. 在 Claude Code 中加载
# 将 Atomic_Rain/classic 目录添加到 Claude Code skills 路径
```

### ToolPlus 版
```bash
# 1. 克隆仓库
git clone https://github.com/SD9ard3n/Atomic_Rain.git
cd Atomic_Rain/toolplus

# 2. 启动 MCP 工具（详见 toolplus/references/mcp-readiness.md）
# - Yakit MCP: http://127.0.0.1:11432/sse
# - Chrome MCP: http://127.0.0.1:12306/mcp

# 3. 在 Claude Code 中加载
# 将 Atomic_Rain/toolplus 目录添加到 Claude Code skills 路径
```

---

## 📋 核心特性（两版本共享）

### Phase 0-4 工作流
```
P0: 资产测绘     → 子域名/端口/指纹/JS 逆向
P1: 信号预检     → First-pass 信号 + 概率模型
P1.5: 业务建模   → 流程图 + 12 问追问
P2: 参数测试     → Deep 漏洞利用
P3: 利用拓展     → 链式攻击 + 敏感信息利用
P4: 取证报告     → OWASP 映射 + 证据标准
```


### 70+ 漏洞覆盖
SQL 注入 / XSS / SSRF / 反序列化 / XXE / SSTI / 命令注入 / JWT / OAuth / OIDC / CORS / CSRF / 点击劫持 / 路径穿越 / 文件上传 / 逻辑漏洞 / 竞态条件 / Shiro / FastJSON / Spring / GraphQL / Swagger / Actuator / 云 AK 利用 / 移动端逆向 / AI Prompt 注入...

---

## 📖 文档结构

```
Atomic_Rain/
├── classic/                    # Classic 版（CLI-only）
│   ├── SKILL.md                # Skill 入口
│   ├── README.md               # Classic 版说明
│   ├── references/             # 方法论和漏洞知识库
│   │   ├── tool-config.md      # CLI 工具配置
│   │   ├── signal-probability-model.md
│   │   ├── anomaly-detection.md
│   │   ├── adaptive-waf-evasion.md
│   │   ├── context-aware-payloads.md
│   │   ├── vuln/               # 70+ 漏洞文档
│   │   └── tooling/            # CLI 工具 playbook
│   └── assets/                 # Payload 仓库
│
├── toolplus/                   # ToolPlus 版（MCP-first）
│   ├── SKILL.md                # Skill 入口
│   ├── README.md               # ToolPlus 版说明
│   ├── references/             # 方法论和漏洞知识库
│   │   ├── tool-config.md      # MCP 独家工具配置
│   │   ├── mcp-tools-finder.md # 70 个 MCP 工具索引
│   │   ├── mcp-readiness.md    # MCP 运行时检查
│   │   ├── signal-probability-model.md
│   │   ├── anomaly-detection.md
│   │   ├── adaptive-waf-evasion.md
│   │   ├── context-aware-payloads.md
│   │   ├── vuln/               # 70+ 漏洞文档
│   │   └── cheatsheet/         # MCP 工具速查
│   └── capabilities/           # MCP 能力注册表
│
└── README.md                   # 双版本对比（本文件）
```

---

## 🔒 安全与合规

⚠️ **仅用于授权测试**。Atomic Rain 是渗透测试工具，未经授权使用可能触犯《网络安全法》等法律法规。

- ✅ **授权场景**: Bug Bounty 平台、SRC 项目、企业委托测试
- ❌ **禁止场景**: 未授权扫描、恶意攻击、数据窃取

**使用者需自行承担法律责任。**

---

## 🛠️ 工具要求对比

### Classic 版
**必须**:
- Python 3.8+ / Java 11+
- CLI 工具: `sqlmap` / `nuclei` / `httpx` / `dirsearch` / `nmap`

**可选**:
- `subfinder` / `amass` / `xray` / `fscan` / `ysoserial` / `ffuf` / `katana`

### ToolPlus 版
- **Yakit MCP**: http://127.0.0.1:11432/sse
- **Chrome MCP**: http://127.0.0.1:12306/mcp

**可选**:
- 少量 CLI-only 工具（Frida/jadx/apktool 等）

---

## 📊 性能对比

| 指标 | Classic 版 | ToolPlus 版 |
|------|-----------|------------|
| **首次信号检测** | 2-5 分钟 | 30-60 秒 |
| **误报率** | 15% | 8% |
| **0day 发现能力** | 中等 | 高 |



**Atomic Rain v2.0 — 让渗透测试更智能、更高效。** 🚀
