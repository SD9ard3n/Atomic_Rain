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

## 1. 测试环境准备

### 1.1 Android

```
工具清单:
- 模拟器/真机 (Android 7-14, 推荐 Pixel 系列)
- ADB (Android Debug Bridge)
- Burp Suite / mitmproxy (抓包)
- Frida + frida-server (动态Hook)
- jadx / jadx-gui (反编译)
- apktool (资源解包)
- MobSF (自动化分析)
- objection (Frida封装)
- Magisk + LSPosed (Root + 框架)
```

```bash
# ADB基础
adb devices                          # 设备列表
adb install target.apk              # 安装
adb shell pm list packages          # 包名列表
adb shell dumpsys package com.xx    # 应用信息
adb logcat | grep -i "com.xx"      # 日志
adb backup -f backup.ab com.xx      # 备份应用数据
```

### 1.2 iOS

```
工具清单:
- 越狱设备 (checkra1n / unc0ver / palera1n)
- Burp Suite / mitmproxy (抓包)
- Frida (动态Hook)
- class-dump / Hopper / IDA (反编译)
- MonkeyDev / iOS App Signer (重签名)
- Cydia Substrate / Substitute (越狱插件)
- Objection (Frida封装)
- BagBak (class-dump替代)
```

---

## 2. 证书绑定绕过与流量拦截

### 2.1 Android证书安装

```
1. 生成Burp CA证书:
   Burp → Proxy → Options → Import/export CA certificate → Export in DER format
   openssl pkcs12 -in burp.p12 -out burp.pem -nodes
   openssl x509 -inform PEM -in burp.pem -out burp.crt

2. 安装到系统信任存储 (Android 7+需要):
   - 方法1: Magisk模块 (MagiskTrustUserCerts)
   - 方法2: adb push到系统证书目录
   - 方法3: 已Root设备直接安装到系统存储

3. 设置代理:
   adb shell settings put global http_proxy 192.168.1.100:8080
   # 取消代理:
   adb shell settings put global http_proxy :0
```

### 2.2 证书绑定绕过

**Frida绕过**:
```javascript
// Universal SSL Pinning Bypass for Android
Java.perform(function() {
    // TrustManager bypass
    var TrustManager = Java.use('javax.net.ssl.X509TrustManager');
    var SSLContext = Java.use('javax.net.ssl.SSLContext');

    var TrustManagerImpl = Java.registerClass({
        name: 'com.bypass.TrustManager',
        implements: [TrustManager],
        methods: {
            checkClientTrusted: function(chain, authType) {},
            checkServerTrusted: function(chain, authType) {},
            getAcceptedIssuers: function() { return []; }
        }
    });

    var TrustManagers = [TrustManagerImpl.$new()];
    var SSLContextImpl = SSLContext.getInstance("TLS");
    SSLContextImpl.init(null, TrustManagers, null);

    // OkHttp3 bypass
    try {
        var OkHttpClient = Java.use('okhttp3.OkHttpClient');
        var Builder = Java.use('okhttp3.OkHttpClient$Builder');
        Builder.hostnameVerifier.implementation = function(hv) {
            return this;
        };
    } catch(e) {}

    // WebViewClient bypass
    try {
        var WebViewClient = Java.use('android.webkit.WebViewClient');
        WebViewClient.onReceivedSslError.implementation = function(view, handler, error) {
            handler.proceed();
        };
    } catch(e) {}
});
```

**Objection绕过**:
```bash
# 自动绕过SSL Pinning
objection -g com.target.app explore
# 在objection中执行:
android sslpinning disable
```

**其他绕过方法**:
```
1. 修改APK: apktool → 删除network_security_config.xml → 重打包签名
2. Xposed模块: JustTrustMe / TrustMeAlready
3. LSPosed模块: TrustMeAlready
4. 修改OkHttp CertificatePinner: Frida Hook
5. Frida脚本: frida-ssl-pinning-bypass
```

### 2.3 iOS证书绑定绕过

```
1. 安装Burp CA到设备
2. 越狱设备: 安装SSL Kill Switch 2 (Cydia)
3. Frida绕过:
   frida -U -f com.target.app -l ssl_bypass_ios.js
4. Objection:
   objection -g com.target.app explore
   ios sslpinning disable
```

---

## 3. APK逆向分析

### 3.1 静态分析

```bash
# jadx反编译 (推荐)
jadx -d output/ target.apk        # 反编译为Java源码
jadx-gui target.apk               # GUI查看

# apktool资源解包
apktool d target.apk -o decoded/

# MobSF自动化分析
docker run -it -p 8000:8000 opensecurity/mobile-security-framework-mobsf
# 上传APK → 自动生成报告

# 检查关键文件
cat decoded/AndroidManifest.xml | grep -E "permission|exported|intent-filter"
grep -r "password\|secret\|api_key\|token" decoded/res/values/strings.xml
grep -r "http://\|https://" decoded/smali/ | grep -v "schema.org\|w3.org\|android.com"
```

### 3.2 关键信息提取

```bash
# 硬编码密钥/API Key
grep -rn "AKIA\|LTAI\|AKID\|AIza\|api_key\|apikey\|secret\|password\|token" decoded/

# 后门接口/调试开关
grep -rn "debug\|test\|staging\|dev\|internal\|admin\|backdoor" decoded/

# 云服务配置
grep -rn "aliyun\|tencent\|aws\|firebase\|jpush\|umeng\|bugly" decoded/

# 敏感URL
grep -rn "http" decoded/res/values/strings.xml
```

### 3.3 AndroidManifest分析

```xml
<!-- 关注点 -->
<activity android:exported="true">           <!-- 导出Activity -->
<service android:exported="true">            <!-- 导出Service -->
<receiver android:exported="true">           <!-- 导出Receiver -->
<provider android:exported="true">           <!-- 导出ContentProvider -->
<uses-permission android:name="android.permission.INTERNET" />
<uses-permission android:name="android.permission.READ_CONTACTS" />  <!-- 过度权限 -->
<application android:debuggable="true">      <!-- 调试模式 -->
<application android:allowBackup="true">     <!-- 可备份 -->
```

---

## 4. iOS应用分析

### 4.1 砸壳与反编译

```bash
# 砸壳 (如果应用加密)
# 越狱设备: frida-ios-dump / dumpdecrypted
# 非越狱: bagbak / bfdecrypt

# class-dump 导出头文件
class-dump -H -o headers/ Target.app

# Hopper/IDA 反编译
# 查看字符串: /Strings
# 查看类列表: /Symbols
```

### 4.2 Info.plist分析

```bash
# 解密Info.plist
plutil -convert xml1 Info.plist -o info.xml

# 关注点:
# - ATS配置 (NSAllowsArbitraryLoads)
# - URL Scheme (可被其他APP调用)
# - 自定义URL Scheme (劫持风险)
# - 后台模式 (后台数据传输)
```

---

## 5. Frida Hook实战

### 5.1 基础Hook

```javascript
// Hook指定方法
Java.perform(function() {
    var TargetClass = Java.use('com.target.app.LoginActivity');

    // Hook方法,打印参数和返回值
    TargetClass.login.implementation = function(username, password) {
        console.log("[*] login() called");
        console.log("    username: " + username);
        console.log("    password: " + password);
        var result = this.login(username, password);
        console.log("    result: " + result);
        return result;
    };

    // 修改返回值
    TargetClass.isVip.implementation = function() {
        console.log("[*] isVip() → true");
        return true;
    };

    // 修改参数
    TargetClass.verifyPin.implementation = function(pin) {
        console.log("[*] verifyPin() → always accept: " + pin);
        return true;
    };
});
```

### 5.2 加密函数Hook

```javascript
// Hook AES加密,打印明文和密文
Java.perform(function() {
    var Cipher = Java.use('javax.crypto.Cipher');

    Cipher.doFinal.overload('[B').implementation = function(input) {
        console.log("[*] Cipher.doFinal()");
        console.log("    Input (hex): " + bytesToHex(input));
        var result = this.doFinal(input);
        console.log("    Output (hex): " + bytesToHex(result));
        return result;
    };
});

function bytesToHex(bytes) {
    var hex = '';
    for (var i = 0; i < bytes.length; i++) {
        hex += ('0' + (bytes[i] & 0xFF).toString(16)).slice(-2);
    }
    return hex;
}
```

### 5.3 Root检测绕过

```javascript
Java.perform(function() {
    // 常见Root检测类
    var rootClasses = [
        'com.scottyab.rootbeer.RootBeer',
        'com.scottyab.rootbeer.util.RootCheck',
        'de.devland.rootcheck.RootCheck',
    ];

    rootClasses.forEach(function(className) {
        try {
            var cls = Java.use(className);
            cls.isRooted.implementation = function() {
                return false;
            };
            console.log("[*] Bypassed: " + className);
        } catch(e) {}
    });

    // Su binary检测绕过
    var Runtime = Java.use('java.lang.Runtime');
    Runtime.exec.overload('[Ljava.lang.String;').implementation = function(cmd) {
        var cmdStr = cmd.join(' ');
        if (cmdStr.indexOf('su') !== -1 || cmdStr.indexOf('which su') !== -1) {
            console.log("[*] Blocked root check: " + cmdStr);
            return null;
        }
        return this.exec(cmd);
    };
});
```

### 5.4 签名校验绕过

```javascript
Java.perform(function() {
    var Signature = Java.use('java.security.Signature');

    Signature.verify.implementation = function(data) {
        console.log("[*] Signature.verify() → bypassed");
        return true;
    };
});
```

---

## 6. APP组件安全

### 6.1 导出组件测试

```bash
# 列出所有导出组件
adb shell dumpsys package com.target.app | grep -E "Activity|Service|Receiver|Provider" | grep -i "export"

# 使用drozer测试
drozer console connect
dz> run app.package.attacksurface com.target.app
dz> run app.activity.start --component com.target.app com.target.app.AdminActivity
dz> run app.provider.query content://com.target.app.provider/users
dz> run app.broadcast.send --action com.target.app.INTENT_ACTION --extra string data "test"
```

### 6.2 Deep Link劫持

```bash
# 查看注册的URL Scheme
adb shell dumpsys package com.target.app | grep -A 5 "scheme"

# 测试Deep Link
adb shell am start -a android.intent.action.VIEW -d "targetapp://callback?token=stolen"
```

---

## 7. 本地存储安全

### 7.1 SharedPreferences

```bash
# 提取
adb shell cat /data/data/com.target.app/shared_prefs/config.xml

# 检查是否包含敏感信息
# - 密码明文存储
# - Token未加密
# - 加密密钥硬编码
```

### 7.2 SQLite数据库

```bash
# 提取
adb shell run-as com.target.app cat databases/user.db > user.db
sqlite3 user.db ".tables"
sqlite3 user.db "SELECT * FROM users;"
```

### 7.3 文件系统

```bash
# 备份应用数据
adb backup -f backup.ab -noapk com.target.app
# 解密: https://github.com/nelenkov/android-backup-extractor

# 检查敏感文件
adb shell run-as com.target.app ls -la files/
adb shell run-as com.target.app ls -la cache/
```

---

## 8. APP API测试

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

| 工具 | 用途 | 安装 |
|------|------|------|
| jadx | APK反编译 | `brew install jadx` |
| apktool | 资源解包 | `brew install apktool` |
| Frida | 动态Hook | `pip install frida-tools` |
| objection | Frida封装 | `pip install objection` |
| MobSF | 自动分析 | Docker |
| drozer | 组件测试 | `pip install drozer` |
| Burp Suite | 抓包/测试 | 官网下载 |
| mitmproxy | 轻量抓包 | `pip install mitmproxy` |
| Magisk | Root管理 | 官网下载 |
| LSPosed | Xposed框架 | GitHub |

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
