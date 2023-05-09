# 密钥编码

## 1. ASN.1

### 1.1 ASN.1 的介绍

`ASN.1` 的全称是 `Abstract Syntax Notation dot one`，在后面加上数字 `1`，是为了保持 `ASN` 的开放性，期待未来能够出现 `ASN.2`和 `ASN.3` 等。`ASN.1` 描述了一种对数据进行表示、编码、传输和解码的数据格式。 

### 1.2 ASN.1 语法示例

证书请求包含正在发出请求或为其发出请求的实体的名称等。 该名称是 `X.500` 相对可分辨名称 `(Relative Distinguished Names, RDNs)`。 序列中的每个 `RDN` 都包含一个对象标识符 `(Object Identifier, OID)` 和一个值。 主题名称的 `ASN.1` 语法如下例所示。

```asn.1
---------------------------------------------------------------------
-- Subject name
---------------------------------------------------------------------
Name ::= SEQUENCE OF RelativeDistinguishedName

RelativeDistinguishedName ::= SET OF AttributeTypeValue

AttributeTypeValue ::= SEQUENCE 
{
   type               OBJECT IDENTIFIER,
   value              ANY 
}
```

### 1.3 ASN.1 编码示例

证书注册 `API` 使用可辨别编码规则 `(Distinguished Encoding Rules, DER)` 对前面的主体名称进行编码。 `DER` 要求名称中的每个项都由 `TLV` 三元表示，其中 `T` 包含 `ASN.1` 类型的标记号、`L` 包含长度，`V` 包含关联的值。 以下示例演示如何对主题名称 `TestCN.TestOrg` 进行编码。

```asn.1
1.     30 23            ; SEQUENCE (23 Bytes)
2.     |  |  31 0f            ; SET (f Bytes)
3.     |  |  |  30 0d            ; SEQUENCE (d Bytes)
4.     |  |  |     06 03         ; OBJECT_ID (3 Bytes)
5.     |  |  |     |  55 04 03
6.     |  |  |     |     ; 2.5.4.3 Common Name (CN)
7.     |  |  |     13 06         ; PRINTABLE_STRING (6 Bytes)
8.     |  |  |        54 65 73 74 43 4e                    ; TestCN
9.     |  |  |           ; "TestCN"
10.    |  |  31 10            ; SET (10 Bytes)
11.    |  |     30 0e            ; SEQUENCE (e Bytes)
12.    |  |        06 03         ; OBJECT_ID (3 Bytes)
13.    |  |        |  55 04 0a
14.    |  |        |     ; 2.5.4.10 Organization (O)
15.    |  |        13 07         ; PRINTABLE_STRING (7 Bytes)
16.    |  |           54 65 73 74 4f 72 67                 ; TestOrg
17.    |  |              ; "TestOrg"
```

请注意以下几点：

- 第 1 行：该名称是相对可分辨名称的序列。`SEQUENCE` 类型的标记编号 `0x30`。`TestCN.TestOrg` 的主题名称需要 `35` 个 `(0x23)` 字节。
- 第 2 行：`Common Name`，`TestCN` 是一组 `AttributeTypeValue` 结构。`SET` 的标记号 `0x31`。
- 第 3 行：`AttributeTypeValue` 结构是一个序列。`SEQUENCE` 类型的标记编号 `0x30`。结构需要 `13` 个 `(0xD)` 个字节。
- 第 4 行到 6 行：`Common Name` 的对象标识符 `(OID)` 为 2.5.4.3。`OID` 是三个字节大小的 `OBJECT_ID` 类型。`OBJECT_ID` 类型的标记号 `0x06`。
- 第 7 行到 9 行：`Common Name`，`TestCN` 是一个字符串值。字符串是六字节 `PRINTABLE_STRING` 类型。`PRINTABLE_STRING` 类型的标记编号 `0x13`。