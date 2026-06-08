# XSS 自动化执行协议 (Decision Card)

### [Decision Card]
1. **探测信号**: 发送 `"><script>prompt(1)</script>`。
2. **Context 识别**: 
   - IF HTML -> 触发 `<img src=x onerror=...>`。
   - IF Attribute -> 触发 ` autofocus onfocus=...`。
3. **级联挖掘 [Linkable]**:
   - 搜素存储桶路径, 尝试存储型 XSS。
   - 结合认证绕过, 尝试 CSRF-to-XSS 链。

### [Triage]
- **现象: 403 Forbidden** -> WAF 已死盯 `<script>`。
  - 动作: 切换至 JavaScript 编码绕过。
- **现象: 200 但源码被转义** -> 可能是 `htmlspecialchars`。
  - 动作: 寻找非转义上下文 (如 JSON 内部)。
