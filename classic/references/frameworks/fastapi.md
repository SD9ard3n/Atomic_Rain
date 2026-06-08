---
name: fastapi
description: FastAPI / Starlette 目标栈专项 playbook — Pydantic 校验绕过 / 依赖注入滥用 / SQLAlchemy SQLi / 异步竞态 / OpenAPI 暴露面。Python 现代异步框架。
category: frameworks
tags: [framework, python, fastapi, starlette, async, pydantic]
---

# FastAPI / Starlette Playbook

> **何时用本文件**: Phase 1 指纹确认目标使用 FastAPI / Starlette。
> 与 vuln/ 的关系: 本文件是**目标栈视角** (横向);vuln/ 是漏洞决策卡 (纵向)。

---

## 1. 指纹识别

| 信号 | 含义 |
| :--- | :--- |
| `/docs` / `/redoc` 200 | FastAPI 默认 Swagger UI |
| `/openapi.json` 200 | OpenAPI 3.0 spec 暴露 |
| 报错栈含 `starlette` / `pydantic` | FastAPI 内部栈 |
| `Server: uvicorn` | uvicorn ASGI server |
| `422 Unprocessable Entity` + JSON `{"detail":[{...}]}` | Pydantic 校验错误 |
| WebSocket `/ws/` | starlette WebSocket |

---

## 2. 攻击面地图

### 2.1 OpenAPI / Swagger 暴露

```bash
curl https://target/openapi.json > schema.json
# 含完整 endpoint / 参数 / 类型 / 必填项 / 响应结构
```

OpenAPI JSON 直接给出 BOLA/BFLA 测试目标 + 内部 endpoint。

### 2.2 Pydantic 校验错配

- `Optional` 字段传 None → 后端未处理 None
- 字符串无 `max_length` → 大请求 DoS / SQL 注入位
- `Union[str, int]` → 类型混淆
- 嵌套对象未递归校验
- `Field(...)` 未限范围 → 整数溢出

### 2.3 依赖注入滥用

```python
@app.get("/admin")
def admin(user: User = Depends(get_current_user)):
    if user.role == "admin":   # 只在这里校验
        ...
```

漏洞模式: 依赖只验 token,具体权限校验散在业务 → BFLA 高发。

### 2.4 SQLAlchemy SQLi (raw query)

```python
db.execute(f"SELECT * FROM users WHERE id={user_id}")   # f-string = SQLi
db.execute(text(f"...{name}..."))                       # text() 不安全
```

### 2.5 异步竞态

FastAPI 默认异步,业务未加锁 → race condition 高发(支付 / 转账 / 优惠券 → [vuln/race-condition.md](../vuln/race-condition.md))。

### 2.6 文件上传 (UploadFile)

```python
@app.post("/upload")
async def upload(file: UploadFile = File(...)):
    with open(f"./uploads/{file.filename}", "wb") as f:   # 路径遍历
        f.write(await file.read())
```

### 2.7 模板渲染 SSTI

```python
templates.TemplateResponse(f"{user_input}.html", ...)   # 模板注入
```

走 [vuln/ssti.md](../vuln/ssti.md)。

### 2.8 WebSocket 越权

WebSocket 鉴权常忽略;握手时仅 connect,之后所有消息可控。

---

## 3. 高价值入口

1. **`/openapi.json`** — 拉完整 schema (P0)
2. **`/docs`** — Swagger UI 直接测试 (P0)
3. **Pydantic Optional 字段** — 漏校验 (P0)
4. **依赖注入只在依赖层校验** — BFLA (P0)
5. **WebSocket endpoint** — 无 deep 鉴权 (P1)
6. **UploadFile** — 路径遍历 (P0)

---

## 4. CVE / 历史漏洞

| CVE / 通用名 | 影响 | 备注 |
| :--- | :--- | :--- |
| Starlette path traversal in StaticFiles | LFI | 历史 |
| Pydantic data conversion bugs | 类型混淆 | 业务逻辑 |
| FastAPI CSRF 默认无防护 | CSRF | 默认不带 middleware |
| python-multipart ReDoS | DoS | 上传大文件 |

---

## 5. 系统化 Recon

```bash
# 拉 schema
curl https://target/openapi.json > schema.json
jq '.paths | keys' schema.json

# 找需鉴权 endpoint
jq '.paths | to_entries[] | select(.value | tostring | contains("security")) | .key' schema.json

# 找上传接口
jq '.paths | to_entries[] | select(.value | tostring | contains("multipart/form-data")) | .key' schema.json

# 找 internal/debug 路径
jq '.paths | keys[]' schema.json | grep -iE "internal|debug|admin|test"
```

---

## 6. 利用链优先级

### 6.1 OpenAPI 暴露
1. 拉 schema → 列举所有 endpoint
2. 改 user_id/org_id 测 BOLA
3. admin endpoint 无 token 访问 (BFLA)
4. 传 null 测 Optional

### 6.2 SQLAlchemy raw
1. 找搜索 / 过滤接口 → 拼接 SQLi
2. 走 [vuln/sqli.md](../vuln/sqli.md) sqlmap evidence-gated

### 6.3 上传
1. `filename` 路径遍历 → `../etc/passwd`
2. 后缀 → Python 通常不解析 PHP/JSP
3. 上传到对象存储 → 公开性

---

## 7. False Positives

| 现象 | 真实判断 |
| :--- | :--- |
| `/openapi.json` 404 | 业务侧禁用 | 试 `/api/openapi.json` |
| `/docs` 403 | 加了鉴权 | 试无 cookie / 不同 UA |
| 422 错误带 schema 信息 | Pydantic 泄露内部参数名 | 反向工程 |
| Optional 传 None 200 | 业务侧处理了 | 试其他空值 (`""` `[]` `{}`) |

---

## 8. Impact 证据

| 漏洞 | Impact | 证据 |
| :--- | :--- | :--- |
| OpenAPI + admin endpoint | 攻击面汇总 | schema 列表 |
| BFLA 依赖注入绕过 | 提权 | 1 个 admin 调用证据 |
| UploadFile 路径遍历 | 任意写 | 写到 ./uploads 路径外 |
| Raw SQLi | 全库读 | sqlmap 输出脱敏 |
| WebSocket 无鉴权 | 越权数据 | 1 个 trace 证据 |

---

## 9. Pro Tips

- **永远先拉 `/openapi.json`**: 比任何爬虫都完整
- **FastAPI 默认 CSRF 缺失**: 无 middleware,form-based 风险高
- **`response_model` 字段过滤**: 看 raw response 是否泄露多余字段
- **Form vs JSON 行为差异**: 同 endpoint 接受两种,处理逻辑可能不同
- **国内 SRC 命中**: 字节 / 美团 / 快手 用 FastAPI,暴露面大
- **WebSocket 握手时 token,后续不再校验**: token 拿到后长期有效
- **BackgroundTasks**: 触发任务但 response 不显 → OOB 验证
- **uvicorn workers 多**: in-memory 状态不一致 → 数据竞态

---

## 10. 工具升级线

**classic 版**:
- 拉 schema: `curl /openapi.json | jq`
- BOLA sweep: ffuf 配合 schema 自动生成参数变体
- SQLi: sqlmap (evidence-gated)

**toolPlus 版**:
- `mcp__yaklang__http_fuzzer` 配合 OpenAPI schema 自动 sweep
- `mcp__yaklang__ssa_compile language="python"` + SyntaxFlow 找 raw SQL sink
- `mcp__chrome__chrome_navigate` 用 /docs 直接测试

---

## 11. 相关参考

- 通用 vuln: [../vuln/](../vuln/)
- SQLi: [../vuln/sqli.md](../vuln/sqli.md)
- API 安全 (BOLA/BFLA): [../api-security.md](../api-security.md)
- 上传: [../vuln/upload.md](../vuln/upload.md)
- 路径遍历: [../vuln/path-traversal.md](../vuln/path-traversal.md)
- 竞态: [../vuln/race-condition.md](../vuln/race-condition.md)
- WebSocket: [../vuln/graphql-websocket.md](../vuln/graphql-websocket.md)
- SSTI: [../vuln/ssti.md](../vuln/ssti.md)
