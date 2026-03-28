# DNS failover for EPP connections

When an EPP server hostname resolves to multiple IP addresses, the client should try each one until a connection succeeds. This avoids failures when one IP is unreachable but others are available.

## How it works

1. Resolve the hostname to all its IP addresses using `gethostbynamel()`.
2. Try connecting to each IP in order.
3. Return on the first successful connection.
4. If none succeed, return `false`.

## Details

- The scheme prefix (`ssl://`, `tls://`) is preserved when substituting the IP.
- The SSL `peer_name` is set to the original hostname so TLS certificate verification still works when connecting by IP.
- If DNS resolution fails, the original hostname is passed to `stream_socket_client()` as a fallback.
- If the hostname is already an IP address, it is used directly (no DNS lookup).
