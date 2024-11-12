`doq` inbound is a dns inbound used to response dns query message over QUIC.

### Structure

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

### Fields

#### zero_rtt_handshake

Enable 0-RTT QUIC connection handshake on the client side  
This is not impacting much on the performance, as the protocol is fully multiplexed

!!! warning ""
Disabling this is highly recommended, as it is vulnerable to replay attacks.
See [Attack of the clones](https://blog.cloudflare.com/even-faster-connection-establishment-with-quic-0-rtt-resumption/#attack-of-the-clones)
