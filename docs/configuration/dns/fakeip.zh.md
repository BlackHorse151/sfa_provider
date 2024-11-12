# FakeIP

### 结构

```json
{
  "enabled": true,
  "inet4_range": "198.18.0.0/15",
  "inet6_range": "fc00::/18",
  "exclude_rule": {
    "domain": [
      "test.com"
    ],
    "domain_suffix": [
      ".cn"
    ],
    "domain_keyword": [
      "test"
    ],
    "domain_regex": [
      "^stun\\..+"
    ],
    "geosite": [
      "cn"
    ],
    "rule_set": [
      "geoip-cn",
      "geosite-cn"
    ]
  }
}
```

### 字段

`domain` `domain_suffix` `domain_keyword` `domain_regex` `geosite` `rule_set` 详情参阅 [DNS 规则](/configuration/dns/rule).

仅匹配 Rule-Set 中的域名类项目。

#### enabled

启用 FakeIP 服务。

#### inet4_range

用于 FakeIP 的 IPv4 地址范围。

#### inet6_range

用于 FakeIP 的 IPv6 地址范围。

#### exclude_rule

跳过下发 FakeIP 域名规则。
