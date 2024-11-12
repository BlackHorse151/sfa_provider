`doh` 入站是一个 DNS 入站，用来响应基于 HTTPS 和 HTTP/3 的 dns 请求。

### 结构

```json
{
  "type": "doh",
  "tag": "doh-in",
  "network": "udp",
  "query_path": "/dns-query",
  "listen": "::",
  "listen_port": 443,
  "udp_fragment": false,
  "tls": {}
}
```

### 字段

#### network

监听的网络协议，`tcp` `udp` 之一。

默认所有。

当监听 TCP 时，将接收 HTTP/2 流量；当监听 UDP 时，将接收 HTTP/3 流量。

当 `tls` 未设置或 `tls.enabled` 设置为 `false` 时，仅接收 HTTP 流量。

#### query_path

接收 DNS 请求的路径。

默认为 `/dns-query`。
