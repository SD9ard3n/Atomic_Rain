---
name: mobile-tool-commands
description: Mobile app testing command and script quick reference for Android, iOS, TLS interception, Frida, reverse engineering, components, deep links, and local storage checks.
category: tooling
---

# Mobile Tool Commands

← 主流程 [mobile-app.md](mobile-app.md)

用途: 仅承接移动端环境、抓包、Hook、逆向、组件和本地存储的命令/脚本速查。测试路径、HITL 边界、服务端 API 验证和评级仍以 [mobile-app.md](mobile-app.md) 为准。

## 目录

- [环境准备](#环境准备)
- [证书绑定与抓包](#证书绑定与抓包)
- [APK 逆向](#apk-逆向)
- [iOS 分析](#ios-分析)
- [Frida Hook](#frida-hook)
- [组件与 Deep Link](#组件与-deep-link)
- [本地存储](#本地存储)
- [工具速查](#工具速查)

## 环境准备

### Android 工具清单

```text
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
adb devices
adb install target.apk
adb shell pm list packages
adb shell dumpsys package com.xx
adb logcat | grep -i "com.xx"
adb backup -f backup.ab com.xx
```

### iOS 工具清单

```text
- 越狱设备 (checkra1n / unc0ver / palera1n)
- Burp Suite / mitmproxy (抓包)
- Frida (动态Hook)
- class-dump / Hopper / IDA (反编译)
- MonkeyDev / iOS App Signer (重签名)
- Cydia Substrate / Substitute (越狱插件)
- Objection (Frida封装)
- BagBak (class-dump替代)
```

## 证书绑定与抓包

### Android 证书安装

```text
1. 生成 Burp CA 证书:
   Burp -> Proxy -> Options -> Import/export CA certificate -> Export in DER format
   openssl pkcs12 -in burp.p12 -out burp.pem -nodes
   openssl x509 -inform PEM -in burp.pem -out burp.crt

2. 安装到系统信任存储 (Android 7+):
   - Magisk 模块 (MagiskTrustUserCerts)
   - adb push 到系统证书目录
   - Root 设备直接安装到系统存储

3. 设置代理:
   adb shell settings put global http_proxy 192.168.1.100:8080
   adb shell settings put global http_proxy :0
```

### Android SSL Pinning 绕过

```javascript
Java.perform(function() {
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

    try {
        var Builder = Java.use('okhttp3.OkHttpClient$Builder');
        Builder.hostnameVerifier.implementation = function(hv) {
            return this;
        };
    } catch(e) {}

    try {
        var WebViewClient = Java.use('android.webkit.WebViewClient');
        WebViewClient.onReceivedSslError.implementation = function(view, handler, error) {
            handler.proceed();
        };
    } catch(e) {}
});
```

```bash
objection -g com.target.app explore
android sslpinning disable
```

Other options: patch APK network security config, use JustTrustMe / TrustMeAlready / LSPosed, or hook `CertificatePinner`.

### iOS SSL Pinning 绕过

```bash
frida -U -f com.target.app -l ssl_bypass_ios.js
objection -g com.target.app explore
ios sslpinning disable
```

## APK 逆向

```bash
jadx -d output/ target.apk
jadx-gui target.apk
apktool d target.apk -o decoded/
docker run -it -p 8000:8000 opensecurity/mobile-security-framework-mobsf
cat decoded/AndroidManifest.xml | grep -E "permission|exported|intent-filter"
grep -r "password\|secret\|api_key\|token" decoded/res/values/strings.xml
grep -r "http://\|https://" decoded/smali/ | grep -v "schema.org\|w3.org\|android.com"
```

```bash
grep -rn "AKIA\|LTAI\|AKID\|AIza\|api_key\|apikey\|secret\|password\|token" decoded/
grep -rn "debug\|test\|staging\|dev\|internal\|admin\|backdoor" decoded/
grep -rn "aliyun\|tencent\|aws\|firebase\|jpush\|umeng\|bugly" decoded/
grep -rn "http" decoded/res/values/strings.xml
```

AndroidManifest 关注点:

```xml
<activity android:exported="true">
<service android:exported="true">
<receiver android:exported="true">
<provider android:exported="true">
<uses-permission android:name="android.permission.INTERNET" />
<uses-permission android:name="android.permission.READ_CONTACTS" />
<application android:debuggable="true">
<application android:allowBackup="true">
```

## iOS 分析

```bash
# 砸壳: frida-ios-dump / dumpdecrypted / bagbak / bfdecrypt
class-dump -H -o headers/ Target.app
# Hopper/IDA: 查看 /Strings 和 /Symbols
plutil -convert xml1 Info.plist -o info.xml
```

Info.plist 关注点: ATS 配置、URL Scheme、自定义 URL Scheme、后台模式。

## Frida Hook

### 基础 Hook

```javascript
Java.perform(function() {
    var TargetClass = Java.use('com.target.app.LoginActivity');

    TargetClass.login.implementation = function(username, password) {
        console.log("[*] login() called");
        console.log("    username: " + username);
        console.log("    password: " + password);
        var result = this.login(username, password);
        console.log("    result: " + result);
        return result;
    };

    TargetClass.isVip.implementation = function() {
        console.log("[*] isVip() -> true");
        return true;
    };

    TargetClass.verifyPin.implementation = function(pin) {
        console.log("[*] verifyPin() -> always accept: " + pin);
        return true;
    };
});
```

### 加密函数 Hook

```javascript
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

### Root 检测绕过

```javascript
Java.perform(function() {
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

### 签名校验绕过

```javascript
Java.perform(function() {
    var Signature = Java.use('java.security.Signature');

    Signature.verify.implementation = function(data) {
        console.log("[*] Signature.verify() -> bypassed");
        return true;
    };
});
```

## 组件与 Deep Link

```bash
adb shell dumpsys package com.target.app | grep -E "Activity|Service|Receiver|Provider" | grep -i "export"
drozer console connect
dz> run app.package.attacksurface com.target.app
dz> run app.activity.start --component com.target.app com.target.app.AdminActivity
dz> run app.provider.query content://com.target.app.provider/users
dz> run app.broadcast.send --action com.target.app.INTENT_ACTION --extra string data "test"
adb shell dumpsys package com.target.app | grep -A 5 "scheme"
adb shell am start -a android.intent.action.VIEW -d "targetapp://callback?token=stolen"
```

## 本地存储

```bash
adb shell cat /data/data/com.target.app/shared_prefs/config.xml
adb shell run-as com.target.app cat databases/user.db > user.db
sqlite3 user.db ".tables"
sqlite3 user.db "SELECT * FROM users;"
adb backup -f backup.ab -noapk com.target.app
adb shell run-as com.target.app ls -la files/
adb shell run-as com.target.app ls -la cache/
```

检查点: 明文密码、未加密 Token、硬编码密钥、SQLite 敏感字段、备份数据和缓存文件。

## 工具速查

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
