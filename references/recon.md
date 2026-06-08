# 信息收集与攻击面测绘

## 目录
- [1. 搜索引擎/OSINT搜集](#1-搜索引擎osint搜集)
- [2. 被动信息收集](#2-被动信息收集)
- [3. 存活探测与资产梳理](#3-存活探测与资产梳理)
- [4. 端口扫描与服务识别](#4-端口扫描与服务识别)
- [5. Web应用指纹](#5-web应用指纹)
- [6. 目录与敏感文件枚举](#6-目录与敏感文件枚举)
- [7. JS文件分析](#7-js文件分析)
- [8. 自动化漏洞扫描](#8-自动化漏洞扫描)
- [9. 后端站专用协议](#9-后端站专用协议)
- [10. 攻击面汇总模板](#10-攻击面汇总模板)

---

> **重要**: 前端站与后端站的信息收集流程不同 — 后端站 (纯API/管理面板/无前端页面) 应优先执行 §9 后端站专用协议。
> 判断规则: 有 HTML 页面 + 用户交互 → 前端站 (§1-8); 纯 JSON/API 响应 + 管理面板 → 后端站 (§9)

---

## 1. 搜索引擎/OSINT搜集

> 通过搜索引擎和公开信息源获取目标情报，无需触碰目标系统。

### 1.1 Google Dorks

| 运算符 | 描述 | 示例 |
|--------|------|------|
| `site:` | 指定域名搜索 | `site:example.com` |
| `inurl:` | URL包含关键字 | `inurl:admin_login` |
| `intitle:` | 标题包含关键字 | `intitle:后台登录` |
| `intext:` | 页面内容包含关键字 | `intext:password` |
| `filetype:` | 指定文件类型 | `filetype:pdf` |
| `link:` | 链接到指定站点 | `link:example.com` |
| `cache:` | Google缓存版本 | `cache:example.com` |
| `""` | 完整匹配短语 | `"internal server error"` |
| `-` | 排除关键词 | `site:example.com -www` |
| `\|` | 逻辑或 | `admin \| login \| manage` |

#### 管理后台探测
```
site:target.com intext:管理 | 后台 | 后台管理 | 登陆 | 登录 | 用户名 | 密码 | 系统 | 账号 | login | system
site:target.com inurl:login | inurl:admin | inurl:manage | inurl:manager | inurl:admin_login | inurl:system | inurl:backend | inurl:console
site:target.com intitle:管理后台 | intitle:后台登录 | intitle:系统登录 | intitle:用户登录
```

#### 上传/文件操作
```
site:target.com inurl:file | inurl:upload | inurl:files | inurl:download
```

#### SQL注入页面
```
site:target.com inurl:php?id= | inurl:asp?id= | inurl:jsp?id= | inurl:aspx?id=
site:target.com inurl:?id= | inurl:?page= | inurl:?cat= | inurl:?pid=
```

#### SQL错误暴露
```
site:target.com intext:"sql syntax near" | intext:"syntax error has occurred" | intext:"incorrect syntax near" | intext:"unexpected end of SQL command" | intext:"Warning: mysql_connect()" | intext:"Warning: mysql_query()" | intext:"Warning: pg_connect()"
```

#### phpinfo()
```
site:target.com ext:php intitle:phpinfo "published by the PHP Group"
```

#### 配置文件泄露
```
site:target.com ext:.xml | .conf | .cnf | .reg | .inf | .rdp | .cfg | .txt | .ora | .ini | .env | .yaml | .yml | .properties
```

#### 数据库文件
```
site:target.com ext:.sql | .dbf | .mdb | .db | .sqlite | .sqlite3 | .bak.sql
```

#### 日志文件
```
site:target.com ext:.log | .logs | .error_log | .access_log
```

#### 备份文件
```
site:target.com ext:.bkf | .bkp | .old | .backup | .bak | .swp | .rar | .zip | .7z | .tar.gz | .tgz | .tar | .sql.gz | .dump
```

#### 公开文档
```
site:target.com filetype:.doc | .docx | .xls | .xlsx | .ppt | .pptx | .pdf | .csv | .odt
```

#### 目录遍历
```
site:target.com intitle:index.of "parent directory"
```

#### 邮箱/社工信息
```
site:target.com intext:@target.com | email | 邮箱 | 联系方式
site:target.com intitle:账号 | 密码 | 工号 | 学号 | 身份证 | 手机号
```

#### GitHub源码泄露
```
"target.com" password | api_key | secret | token | access_key
site:github.com "target.com" filename:.env | filename:config.yml | filename:application.yml
site:github.com "target.com" filename:id_rsa | filename:.htpasswd | filename:.npmrc
```

### 2.2 百度/必应/搜狗语法

```
# 百度 (site前不加www)
site:target.com 后台 登录
site:target.com filetype:pdf
site:target.com inurl:admin

# 必应 (国际版收录更全面)
site:target.com intitle:login
site:target.com filetype:pdf "confidential"

# 搜狗 (国内微信内容)
site:weixin.qq.com target.com
```

### 2.3 公开文档元数据提取

```bash
# 下载PDF后提取元数据
exiftool document.pdf | grep -E "Author|Creator|Producer|Company|InternalName"

# 提取内网路径/软件版本
strings document.pdf | grep -E "\\\\[a-zA-Z0-9]|C:\\|/home/|/opt/|version|build"

# 批量提取
for f in *.pdf; do echo "=== $f ==="; exiftool "$f" | head -20; done
```

### 2.4 DNS/WHOIS详细枚举

```bash
# WHOIS
whois target.com

# DNS全记录
dig target.com ANY +noall +answer
dig target.com MX     # 邮件服务器
dig target.com TXT    # SPF/DKIM记录
dig target.com NS     # 域名服务器
dig target.com SOA

# SPF记录泄露云服务商
dig target.com TXT | grep -E "google|amazon|microsoft|aliyun|tencent"

# 区域传送尝试
dig axfr @ns1.target.com target.com

# DNS历史 (绕过CDN找真实IP)
# SecurityTrails: https://securitytrails.com/domain/target.com/history/a
# ViewDNS: https://viewdns.info/iphistory/?domain=target.com
```

### 1.5 招标公告/招聘信息情报

```
# 招标公告暴露技术栈
site:target.com 招标 采购 项目 中标
site:ccgp.gov.cn target.com         # 中国政府采购网
site:bidding.gov.cn target.com      # 全国公共资源交易平台

# 招聘信息暴露技术栈
site:target.com 招聘 岗位 职责 要求 Java | PHP | Python | .NET | Spring
site:51job.com target.com
site:zhaopin.com target.com
site:lagou.com target.com

# 从招聘JD提取：技术栈/框架/中间件/数据库/云服务商
```

### 1.6 学号/工号规律分析

```
# 学校场景
site:target.edu.cn intext:学号 姓名 班级
site:target.edu.cn filetype:pdf 名单 录取
site:target.edu.cn inurl:student | inurl:stu | inurl:xuesheng

# 常见学号规律 (用于构造用户名字典)
# 202401001 → 年份+学院+序号
# 210101001 → 入学年份+专业+序号
# 2022101001 → 入学年份+班级+序号
```

---

## 2. 被动信息收集

> 不触碰目标系统，从公开来源获取情报。

### 2.1 子域名枚举

```bash
# 被动枚举工具
subfinder -d example.com -silent -o subfinder.txt
amass enum -passive -d example.com -o amass.txt
ksubdomain enum -d example.com -o ksubdomain.txt     # 国内速度快

# 证书透明度
curl -s "https://crt.sh/?q=%.example.com&output=json" | jq -r '.[].name_value' | sort -u
curl -s "https://api.certspotter.com/v1/issuances?domain=example.com&include_subdomains=true" | jq -r '.[].dns_names[]' | sort -u

# 合并去重
cat *.txt | sort -u > all_subdomains.txt
```

### 2.2 GitHub信息泄露

```
# GitHub Dorks (在 github.com 搜索)
"example.com" password
"example.com" api_key
"example.com" secret
"example.com" AWS_ACCESS_KEY
"example.com" jdbc:mysql
org:target-org filename:.env
org:target-org filename:wp-config.php
org:target-org filename:id_rsa
org:target-org filename:credentials.json
org:target-org filename:.npmrc
```

### 2.3 网络空间搜索引擎

```
# Fofa (fofa.info)
domain="example.com"
cert="example.com"
body="example.com"
header="X-Powered-By"
protocol="mysql" && port="3306"

# 鹰图 (hunter.qianxin.com)
domain.suffix="example.com"
ip.port="3306"
web.title="管理后台"

# Shodan
hostname:example.com
ssl.cert.subject.cn:example.com
org:"Target Inc"

# Quake (360quake.net)
domain:example.com
service:http
```

### 2.4 历史资产

```bash
# Wayback Machine - 历史URL
curl -s "http://web.archive.org/cdx/search/cdx?url=example.com/*&output=json&fl=original&collapse=urlkey" | jq -r '.[][]' | sort -u > wayback_urls.txt

# DNS历史 - 查找真实IP(绕过CDN)
# SecurityTrails / ViewDNS / DNSDB
```

---

## 3. 存活探测与资产梳理

```bash
# httpx 批量存活检测 + 技术指纹
cat all_subdomains.txt | httpx -silent -tech-detect -status-code -title -cdn -o alive.txt

# 过滤CDN和无效响应
cat alive.txt | grep -v "cdn\|cloudfront\|akamai" > no_cdn.txt

# 提取IP
cat alive.txt | awk '{print $2}' | sort -u > ips.txt
```

---

## 4. 端口扫描与服务识别

### 3.1 分级扫描策略

```bash
# 第一轮: TOP 1000 快速扫描
nmap -sS -T4 --top-ports 1000 -oN nmap_quick.txt TARGET

# 第二轮: 全端口(仅高价值目标)
nmap -sS -p- -T4 -oN nmap_full.txt TARGET

# 第三轮: 服务版本 + 默认脚本
nmap -sV -sC -p PORTS -oN nmap_detail.txt TARGET

# 第四轮: 漏洞脚本
nmap --script=vuln -p PORTS -oN nmap_vuln.txt TARGET

# UDP高危端口
nmap -sU --top-ports 50 -oN nmap_udp.txt TARGET

# 大范围快速扫描
masscan -p80,443,22,8080,3306,6379,1433,3389,6443,2375 CIDR --rate=10000 -oG masscan.txt
```

### 3.2 高价值服务快速枚举

| 端口 | 服务 | 快速检测命令 |
|------|------|-------------|
| 21 | FTP | `nmap --script=ftp-anon,ftp-bounce -p 21 TARGET` |
| 22 | SSH | `nmap --script=ssh2-enum-algos -p 22 TARGET` |
| 80/443 | HTTP | → Phase 4 Web指纹 |
| 389/636 | LDAP | `nmap --script=ldap-rootdse -p 389 TARGET` |
| 1433 | MSSQL | `nmap --script=ms-sql-info,ms-sql-empty-password -p 1433 TARGET` |
| 3306 | MySQL | `nmap --script=mysql-info,mysql-empty-password -p 3306 TARGET` |
| 5432 | PostgreSQL | `nmap --script=pgsql-info -p 5432 TARGET` |
| 6379 | Redis | `redis-cli -h TARGET ping` |
| 9200 | Elasticsearch | `curl http://TARGET:9200/_cat/indices?v` |
| 27017 | MongoDB | `nmap --script=mongodb-info -p 27017 TARGET` |
| 11211 | Memcached | `echo "stats" | nc TARGET 11211` |
| 2375/2376 | Docker API | `curl http://TARGET:2375/v1.24/containers/json` |
| 6443 | K8s API | `curl -k https://TARGET:6443/api/v1/pods` |
| 9090 | Prometheus | `curl http://TARGET:9090/api/v1/targets` |
| 9300 | Elasticsearch | `curl http://TARGET:9300/` |
| 15672 | RabbitMQ | `curl http://TARGET:15672/api/overview` (guest:guest) |

---

## 5. Web应用指纹

```bash
# 技术栈识别
httpx -u https://target.com -tech-detect -status-code -title
whatweb -v https://target.com
wappalyzer https://target.com   # 浏览器插件

# WAF检测
wafw00f https://target.com

# 响应头分析
curl -sI https://target.com | grep -iE "server|x-powered|x-frame|set-cookie|x-aspnet|x-amz"

# 指纹文件探测
for path in .env .git/HEAD .git/config .svn/entries .DS_Store WEB-INF/web.xml \
    backup.sql www.zip web.zip database.sql robots.txt sitemap.xml \
    composer.json package.json phpinfo.php test.php info.php \
    swagger-ui.html swagger.json api-docs graphql playground \
    actuator actuator/env actuator/health \
    server-status server-info .htaccess .htpasswd \
    wp-login.php wp-admin administrator/ user/login; do
    code=$(curl -s -o /dev/null -w "%{http_code}" "https://target.com/$path")
    [ "$code" != "404" ] && echo "$path: $code"
done

# Source Map分析
curl -s "https://target.com/assets/*.map" | head -50
```

---

## 6. 目录与敏感文件枚举

```bash
# gobuster (推荐,递归)
gobuster dir -u https://target.com -w /usr/share/wordlists/dirb/common.txt \
    -t 50 -x php,asp,aspx,jsp,html,json,bak,zip,sql,conf,git \
    -o gobuster.txt --no-error

# ffuf (速度最快)
ffuf -w /usr/share/wordlists/dirb/common.txt -u https://target.com/FUZZ \
    -mc 200,201,301,302,403,500 -t 100 -o ffuf.json

# feroxbuster (多线程递归)
feroxbuster -u https://target.com -w /usr/share/wordlists/dirb/common.txt \
    -t 100 -x php,asp,aspx,jsp,html,json -o ferox.txt

# 参数Fuzzing (发现隐藏参数)
arjun -u https://target.com/api/search
paramspider -u https://target.com

# API端点发现
katana -u https://target.com -d 5 -jc -aff -o katana_urls.txt
```

---

## 7. JS文件分析

```bash
# 收集所有JS文件
katana -u https://target.com -jc -d 3 | grep "\.js$" | sort -u > js_files.txt

# 提取API端点、密钥、内网IP
cat js_files.txt | while read js; do
    curl -s "$js" 2>/dev/null
done | grep -oE '(https?://[^"'\''<> ]+/api/[a-zA-Z0-9/_-]+|/v[0-9]+/[a-zA-Z0-9/_-]+|["\x27][A-Za-z0-9]{32,}["\x27]|[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})' | sort -u > js_findings.txt

# SecretFinder (专门提取密钥)
python3 SecretFinder.py -i target.js -o json

# LinkFinder (提取API端点)
python3 linkfinder.py -i -d https://target.com -o cli
```

---

## 8. 自动化漏洞扫描

```bash
# Nuclei - 全模板扫描(高/严重)
nuclei -l alive.txt -severity critical,high -o nuclei_critical.txt

# Nuclei - 信息泄露
nuclei -l alive.txt -tags exposure,token,misconfig,debug -o nuclei_exposure.txt

# Nuclei - CVE (根据识别的版本)
nuclei -l alive.txt -tags cve -o nuclei_cve.txt

# Nuclei - 默认凭证
nuclei -l alive.txt -tags default-login,default-creds -o nuclei_creds.txt

# Nuclei - 云相关
nuclei -l alive.txt -tags aws,azure,gcp,cloud -o nuclei_cloud.txt

# Nmap 漏洞扫描
nmap --script=vuln -p PORTS TARGET -oN nmap_vuln.txt
```

---

## 9. 后端站专用协议

> **核心原则**: 后端站 (纯 API / 管理面板 / 无前端页面) 的域名几乎总是从前端 JS 泄露的, 所以 **JS 扫描前置**, 而非后置。
> **与前端站的区别**: 前端站走 §1-8 全流程; 后端站走本节专用流程。

### 9.1 判断是否为后端站

```
后端站特征 (满足任一):
- 响应是纯 JSON / XML, 无 HTML 页面
- 管理面板 (只有登录页 + 后台功能)
- 域名含 api / admin / backend / internal / manage
- 无用户交互页面, 只有接口
- 从前端站 JS / 配置中发现的内部域名
```

### 9.2 后端站信息收集流程

```
Phase 0: 来源追溯 (后端域名从哪来的?)
    ├─ 前端 JS 中的 API 请求 → 提取后端域名 + 接口路径
    │   grep -Eo '(https?://[^"'\'' ]+/api/[a-zA-Z0-9/_-]+)' *.js | sort -u
    ├─ 前端 JS 中的 base_url / API_BASE / apiUrl / BASE_URL 配置
    ├─ HTTP 响应头: X-Backend-Server / X-Powered-By / X-Api-Version
    ├─ CORS 头: Access-Control-Allow-Origin 中的域名白名单
    ├─ CSP 头: Content-Security-Policy 中的域名白名单
    └─ 移动端 APP 抓包: APK 中的 API base URL
    ↓
Phase 1: 指纹识别 (最高优先, 直达框架漏洞)
    ├─ Wappalyzer / EHole / P1finger 识别框架
    │   httpx -json -l backend_urls.txt | jq '.tech'
    ├─ 根据指纹直达漏洞文件:
    │   指纹=Shiro      → vuln/shiro.md (550 key 暴力 + 721 Padding Oracle)
    │   指纹=Spring      → vuln/spring-vuln.md (Actuator → heapdump → jolokia→RCE)
    │   指纹=Fastjson    → vuln/fastjson-jackson.md (JdbcRowSetImpl 探测)
    │   指纹=Druid       → vuln/swagger-actuator-druid.md (默认密码 + SQL 监控)
    │   指纹=Swagger     → vuln/swagger-actuator-druid.md (接口文档提取)
    │   指纹=Nacos       → vuln/swagger-actuator-druid.md (默认密码 + 配置读取)
    └─ 指纹识别后, 立即执行对应漏洞文件的 First-pass Payload
    ↓
Phase 2: 接口文档提取
    ├─ Swagger / OpenAPI:
    │   for p in swagger-ui.html v2/api-docs v3/api-docs openapi.json; do
    │     curl -s -o /dev/null -w "%{http_code}" "https://target/$p"
    │   done
    ├─ Actuator (Spring Boot):
    │   for p in actuator env health mappings beans gateway routes heapdump jolokia; do
    │     curl -s "https://target/$p" | head -c 500
    │   done
    ├─ Druid 监控面板:
    │   curl -s https://target/druid/ -u admin:admin
    ├─ JS 中的路由定义:
    │   grep -Eo '(api|/v[0-9]+)/[a-zA-Z0-9/_-]+' *.js | sort -u
    └─ API 路径枚举:
        for v in v1 v2 v3 internal admin; do
          curl -s -o /dev/null -w "%{http_code}" "https://target/api/$v/"
        done
    ↓
Phase 3: 未授权 + 弱口令
    ├─ 接口批量去 Token 测试 (见 api-security.md)
    ├─ 管理面板默认凭证 (见 weak-password-generation.md):
    │   admin/admin / druid/druid / nacos/nacos
    ├─ CAWG 定制化弱口令 (根据 target title/域名/公司名)
    └─ 有限制站: 精简字典 + 间隔执行 (禁止 hydra)
    ↓
Phase 4: 漏洞定向测试 (基于指纹)
    ├─ Spring → Actuator → env(heapdump 提凭据) → jolokia→RCE
    ├─ Shiro → 550 默认 key 暴力 → 721 Padding Oracle → 路径绕过
    ├─ Fastjson → JdbcRowSetImpl 探测 → gadget 利用
    ├─ Druid → 默认密码 → SQL 监控面板 → 信息泄露
    ├─ Nacos → 默认密码 → 配置读取 → AK 泄露
    └─ Swagger → 接口提取 → 批量未授权测试
```

### 9.3 前端站 vs 后端站流程对比

| 步骤 | 前端站 | 后端站 |
|------|--------|--------|
| 1 | 子域名收集 | JS 溯源 (提取后端域名) |
| 2 | 存活探测 | **指纹识别** (最高优先) |
| 3 | 端口扫描 | 接口文档提取 |
| 4 | Web 指纹 | 未授权 + 弱口令 |
| 5 | 目录枚举 | 框架漏洞定向测试 |
| 6 | **JS 分析** (后置) | — |
| 7 | 自动化扫描 | — |

### 9.4 关键提醒

- **后端站 JS 分析前置**: 前端站的 JS 分析在 §7, 但后端站的域名来源就是 JS, 所以 JS 分析是 Phase 0
- **指纹直达漏洞**: 不走通用扫描流程, 指纹=Shiro 就直接去 shiro.md, 不用先跑 nuclei
- **接口文档是金矿**: swagger / actuator / druid 提供的接口信息比目录扫描高效 10 倍
- **弱口令用 CAWG**: 不要只用 admin/admin, 根据目标上下文生成定制化字典

---

## 10. 攻击面汇总模板

```markdown
# 攻击面测绘 - example.com

## 资产清单
| 子域名 | IP | 状态码 | 技术栈 | WAF | 备注 |
|--------|-----|--------|--------|-----|------|
| www.example.com | 1.2.3.4 | 200 | Nginx+PHP | 无 | 主站 |
| api.example.com | 1.2.3.5 | 200 | Spring Boot | 云WAF | API |

## 高优先级攻击面
| 优先级 | 目标 | 类型 | 测试方向 | 理由 |
|--------|------|------|----------|------|
| P0 | /api/v1/user | API | BOLA/IDOR/未授权 | 用户数据接口 |
| P0 | /admin | 后台 | 未授权/弱口令 | 可能无认证 |
| P1 | /upload | 功能 | 文件上传→RCE | 上传功能 |

## 已发现的线索
- [ ] JS文件中发现硬编码AK: AKIAxxxxxxxx
- [ ] /actuator/env 端点可访问 (Spring Boot)
- [ ] 子域名 staging.example.com 无WAF保护
- [ ] Redis 6379端口可未授权访问
```
