package health

// A minimal SOCKS5 client.
//
// Hand-rolled rather than pulled from a library for one reason that matters here:
// the destination is always sent as a domain name (address type 0x03), never
// resolved locally. Resolving on this side would reintroduce exactly the problem
// the DNS configuration exists to avoid, because a poisoned answer from a
// filtered resolver would be used for a connection the core was supposed to
// route by name.
//
// It also keeps the SOCKS5 support narrow enough to audit. The whole point of
// this file is that it is the code deciding where a probe's bytes go.

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"time"
)

// SOCKS5 constants, named rather than inlined so the wire format below reads as
// the specification it implements.
const (
	socks5Version    = 0x05
	socks5NoAuth     = 0x00
	socks5CmdConnect = 0x01
	socks5CmdUDP     = 0x03

	socks5AddrIPv4   = 0x01
	socks5AddrDomain = 0x03
	socks5AddrIPv6   = 0x04
)

// Socks5Dial opens a proxied TCP connection to host:port through the SOCKS5
// proxy at proxyAddr.
//
// host is passed through unresolved on purpose. See the file comment.
func Socks5Dial(ctx context.Context, proxyAddr, host string, port int, timeout time.Duration) (net.Conn, error) {
	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp", proxyAddr)
	if err != nil {
		return nil, fmt.Errorf("dial proxy %s: %w", proxyAddr, err)
	}
	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		conn.Close()
		return nil, err
	}
	// Clear the handshake deadline once the tunnel is established. The caller's
	// context governs the connection from here on, and leaving a deadline on it
	// would silently kill a long-lived probe partway through.
	if err := conn.SetDeadline(time.Time{}); err != nil {
		conn.Close()
		return nil, err
	}
	if err := socks5Connect(conn, host, port); err != nil {
		conn.Close()
		return nil, err
	}
	return conn, nil
}

// socks5Connect performs greeting and CONNECT on an already-open connection.
func socks5Connect(conn net.Conn, host string, port int) error {
	if err := socks5Greet(conn); err != nil {
		return fmt.Errorf("greeting: %w", err)
	}

	// Build the request. A host that already parses as an IP is sent as such,
	// because some proxies reject a domain request for something that is
	// obviously a literal address.
	req := []byte{socks5Version, socks5CmdConnect, 0x00}
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			req = append(req, socks5AddrIPv4)
			req = append(req, v4...)
		} else {
			req = append(req, socks5AddrIPv6)
			req = append(req, ip.To16()...)
		}
	} else {
		if len(host) > 255 {
			return fmt.Errorf("destination host is %d bytes, over the 255 limit", len(host))
		}
		req = append(req, socks5AddrDomain, byte(len(host)))
		req = append(req, host...)
	}
	req = append(req, byte(port>>8), byte(port))

	if _, err := conn.Write(req); err != nil {
		return fmt.Errorf("write connect: %w", err)
	}
	head := make([]byte, 4)
	if _, err := readFull(conn, head); err != nil {
		return fmt.Errorf("read connect reply: %w", err)
	}
	if head[0] != socks5Version {
		return fmt.Errorf("unexpected version byte %#x in connect reply", head[0])
	}
	if head[1] != 0x00 {
		return fmt.Errorf("proxy refused CONNECT with code %d (%s)", head[1], socks5Reason(head[1]))
	}
	// The bound address is not useful here, but it still has to be consumed or
	// the next read on this connection would return proxy state instead of
	// application data.
	if _, err := readSocks5Addr(conn, head[3]); err != nil {
		return fmt.Errorf("read bound address: %w", err)
	}
	return nil
}

// socks5Reason names a SOCKS5 reply code.
//
// The numeric code alone is not actionable. "code 2" from a proxy reached
// through a censored network almost always means the tunnel's own upstream
// refused, and saying so is the difference between a user retrying the right
// thing and retrying the wrong thing.
func socks5Reason(code byte) string {
	switch code {
	case 0x01:
		return "general failure"
	case 0x02:
		return "connection not allowed by ruleset, or the upstream refused"
	case 0x03:
		return "network unreachable"
	case 0x04:
		return "host unreachable"
	case 0x05:
		return "connection refused"
	case 0x06:
		return "TTL expired"
	case 0x07:
		return "command not supported"
	case 0x08:
		return "address type not supported"
	default:
		return "unassigned code"
	}
}

// readFull is io.ReadFull, named locally so the import list stays short and the
// call sites read as wire-format steps.
func readFull(conn net.Conn, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := conn.Read(buf[total:])
		if err != nil {
			return total, err
		}
		total += n
	}
	return total, nil
}

// Socks5Addr formats a host and port the way the probes expect to report one.
func Socks5Addr(host string, port int) string {
	return net.JoinHostPort(host, strconv.Itoa(port))
}
