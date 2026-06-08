# SQLi 自动化执行协议 (Decision Card)

> **CWE**: 89 | **ROI**: 极高 (P0)

### [Decision Card: 决策路径]

1. **观察期 (First-pass)**:
   - 发送 `id=1 AND 1=1` vs `id=1 AND 1=2`, 对比响应长度/状态码。
   - IF (5s+ DNS 回调) -> 触发: [OOB-Exfilter Protocol]。
   - IF (500 Error) -> 触发: [Error-based Recheck]。

2. **逻辑确认**:
   - 严禁直接跑 `sqlmap`。必须先确认布尔或时间差异。
   - 记录 `[Ref_Length]` (正常长度) 与 `[Delta_Length]` (注入后长度)。

3. **工具接入 (Evidence-gated)**:
   - 只有确认 `Signal_Detected` 后才调用 sqlmap。
   - 使用 `sqlmap -r req.txt --batch --random-agent`。

---

### [Triage: 失败诊断协议]

- **现象: 200 OK 但无差异**
  - 自检: 该参数是否已在服务端 `cast(int)`?
  - 动作: 尝试 `Arithmetic_Inversion` (如 id=1 -> id=2-1)。
- **现象: 403 Forbidden**
  - 自检: 命中了 WAF。
  - 动作: 挂起 SQLi, 优先 Grep `references/waf-bypass.md`。
- **现象: 500 Error 且无回显**
  - 动作: 切换到 `[Blind-Time]` 模式。

---

### [Level-up: 级联路径]

- **IF (Write Access Granted)**: 强制转向 `references/vuln/upload.md` 寻找 Websink。
- **IF (DBA Privs)**: 执行 `EXEC master..xp_cmdshell` 验证 RCE 潜质。
