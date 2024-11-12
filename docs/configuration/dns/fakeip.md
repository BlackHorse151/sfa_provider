# FakeIP

### Structure

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

### Fields

`domain` `domain_suffix` `domain_keyword` `domain_regex` `geosite` `rule_set` see [DNS Rule](/configuration/dns/rule).

Only domain-like items in `rule_set` will be matched.

#### enabled

Enable FakeIP service.

#### inet4_range

IPv4 address range for FakeIP.

#### inet6_address

IPv6 address range for FakeIP.

#### exclude_rule

Match domains those will be skipped when fakeip transport matched in dns rule.
