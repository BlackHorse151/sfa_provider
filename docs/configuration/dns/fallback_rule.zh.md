### 结构

```json
{
  "match_all": false,
  "clash_mode": [
    "direct"
  ],
  "geoip": [
    "cn"
  ],
  "ip_cidr": [
    "10.0.0.0/24"
  ],
  "ip_is_private": false,
  "rule_set": [
    "geoip-cn"
  ],
  "invert": false,
  "accept_result": false,
  "server": "local"
}

```

!!! note ""

     当内容只有一项时，可以忽略 JSON 数组 [] 标签

### 字段

!!! note ""

    默认规则使用以下匹配逻辑:  
    `match_all` || `ipcidr` || `geoip` || `rule_set` || `ip_is_private`

    另外，引用的规则集可视为被合并，而不是作为一个单独的规则子项。

`clash_mode` `geoip` `ip_cidr` `ip_is_private` `rule_set` `invert` 详情参阅 [DNS 规则](/configuration/dns/rule).

仅匹配 Rule-Set 中的 IP 类项目。

#### match_all

匹配所有响应。

如果该字段被设置，`invert` 字段将被忽略。

#### accept_result

匹配成功后中止回落并直接返回响应。

#### server

目标 DNS 服务器的标签。

如果该字段被设置，将直接使用该 DNS 服务器返回的结果。
