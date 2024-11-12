### Structure

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
  "rule_set": [
    "geoip-cn"
  ],
  "ip_is_private": false,
  "invert": false,
  "accept_result": false,
  "server": "local"
}

```

!!! note ""

    You can ignore the JSON Array [] tag when the content is only one item

### Fields

!!! note ""

    The rule uses the following matching logic:  
    `match_all` || `ipcidr` || `geoip` || `rule_set` || `ip_is_private`

    Additionally, included rule sets can be considered merged rather than as a single rule sub-item.


`clash_mode` `geoip` `ip_cidr` `ip_is_private` `rule_set` `invert` see [DNS Rule](/configuration/dns/rule).

Only IP-like items in `rule_set` will be matched.

#### match_all

Match all response.

If set, `invert` will be ignored.

#### accept_result

Stop fallback and returns response immediately when its results match the rule.

#### server

Tag of the target dns server.

If set, response will be used which server returns.
