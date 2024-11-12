`doq` 入站是一个 DNS 入站，用来响应基于 QUIC 的 dns 请求。

### 结构

```json
{
  "type": "doq",
  "tag": "doq-in",
  "listen": "::",
  "listen_port": 443,
  "udp_fragment": false,
  "zero_rtt_handshake": false,
  "tls": {}
}
```

### 字段

#### zero_rtt_handshake

在客户端启用 0-RTT QUIC 连接握手
这对性能影响不大，因为协议是完全复用的

!!! warning ""
强烈建议禁用此功能，因为它容易受到重放攻击。
请参阅 [Attack of the clones](https://blog.cloudflare.com/even-faster-connection-establishment-with-quic-0-rtt-resumption/#attack-of-the-clones)
