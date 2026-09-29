// Package health measures whether a route actually works.
//
// Every check here exists because the corresponding claim is otherwise
// unfalsifiable. "The app says it is connected" is not evidence, and neither is
// "the proxy accepted a connection": Aether deliberately keeps its port closed
// until real data has passed, which is the precedent this package follows.
//
// The IP check is deliberately Cloudflare's trace endpoint, because one
// request answers three separate questions: the exit address, the exit country,
// and whether WARP was involved. Those three are the whole of the routing
// decision, and getting them from one request keeps a probe from needing three
// third-party services to be up at once.
package health

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// TraceURL is Cloudflare's edge trace endpoint.
//
// It answers over the same path the traffic under test takes, which is the
// point: a probe that bypassed the route would be measuring the wrong thing.
const TraceURL = "https://www.cloudflare.com/cdn-cgi/trace"

// Result is the outcome of one probe.
type Result struct {
	// Reachable means a real request completed through the route.
	Reachable bool
	// ExitIP is the address the destination saw.
	ExitIP string
	// ExitISO is the two-letter country the exit was attributed to.
	ExitISO string
	// WARP is "on" or "off" as reported by the edge.
	WARP string
	// Edge is the colo code, which is useful when a route is up but slow.
	Edge string
	// Latency is the time to complete the request.
	Latency time.Duration
	// Err is why the probe failed. A failed probe is a result, not an
	// exception: "this route does not work" is one of the things being
	// measured.
	Err error
}

// String renders a result for the selftest report.
func (r Result) String() string {
	if !r.Reachable {
		return fmt.Sprintf("unreachable (%v)", r.Err)
	}
	parts := []string{fmt.Sprintf("ip=%s", orDash(r.ExitIP)), fmt.Sprintf("loc=%s", orDash(r.ExitISO))}
	if r.WARP != "" {
		parts = append(parts, "warp="+r.WARP)
	}
	if r.Edge != "" {
		parts = append(parts, "edge="+r.Edge)
	}
	parts = append(parts, fmt.Sprintf("%dms", r.Latency.Milliseconds()))
	return strings.Join(parts, " ")
}

// IsLocalExit reports whether the observed exit address is the same one a
// direct, unproxied request would see.
//
// This is the measurement behind the "preserves my real IP" badge. It compares
// against a direct probe rather than inspecting the country's code, because
// the user cares about "is this my address", and because a route can present
// an address that is in the right country and is still not theirs.
func (r Result) IsLocalExit(direct Result) bool {
	if !r.Reachable || !direct.Reachable || r.ExitIP == "" || direct.ExitIP == "" {
		return false
	}
	return r.ExitIP == direct.ExitIP
}

// Probe makes one request to TraceURL through the given SOCKS5 proxy, or
// directly when proxyAddr is empty.
//
// proxyAddr being empty is a first-class case rather than a special one: the
// direct probe is the baseline every other measurement is compared against, and
// if it fails then every "preserves my real IP" answer is vacuously true.
func Probe(ctx context.Context, proxyAddr string, timeout time.Duration) Result {
	start := time.Now()

	transport := &http.Transport{
		DisableKeepAlives: true,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, port, err := splitHostPort(addr)
			if err != nil {
				return nil, err
			}
			if proxyAddr == "" {
				d := net.Dialer{Timeout: timeout}
				return d.DialContext(ctx, network, addr)
			}
			return Socks5Dial(ctx, proxyAddr, host, port, timeout)
		},
	}
	defer transport.CloseIdleConnections()

	reqCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, TraceURL, nil)
	if err != nil {
		return Result{Err: fmt.Errorf("build request: %w", err)}
	}
	req.Header.Set("User-Agent", "ARClient-selftest")

	resp, err := transport.RoundTrip(req)
	if err != nil {
		return Result{Err: fmt.Errorf("request failed: %w", err), Latency: time.Since(start)}
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return Result{Err: fmt.Errorf("status %d", resp.StatusCode), Latency: time.Since(start)}
	}
	// Bounded read: the endpoint is small, and an unbounded read against
	// something that is not the endpoint we think it is would hang the selftest.
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<10))
	if err != nil {
		return Result{Err: fmt.Errorf("read body: %w", err), Latency: time.Since(start)}
	}

	r := Result{Reachable: true, Latency: time.Since(start)}
	for line := range strings.SplitSeq(string(body), "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok {
			continue
		}
		switch k {
		case "ip":
			r.ExitIP = v
		case "loc":
			r.ExitISO = v
		case "warp":
			r.WARP = v
		case "colo":
			r.Edge = v
		}
	}
	if r.ExitIP == "" {
		r.Reachable = false
		r.Err = errors.New("response contained no address; the endpoint's format may have changed")
	}
	return r
}

// UDPAssociateResult reports whether a SOCKS5 proxy will carry UDP.
type UDPAssociateResult struct {
	Supported bool
	// RelayAddr is the address the proxy nominated for UDP datagrams.
	RelayAddr string
	Err       error
}

// ProbeUDPAssociate asks a SOCKS5 proxy to set up a UDP relay.
//
// This is the gate on routing voice through the tunnel. A proxy that answers
// this with an error is telling us its UDP is not available, and the honest
// response is to leave that traffic direct rather than to assume a relay that
// will not carry anything.
func ProbeUDPAssociate(proxyAddr string, timeout time.Duration) UDPAssociateResult {
	conn, err := net.DialTimeout("tcp", proxyAddr, timeout)
	if err != nil {
		return UDPAssociateResult{Err: fmt.Errorf("dial proxy: %w", err)}
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return UDPAssociateResult{Err: err}
	}

	if err := socks5Greet(conn); err != nil {
		return UDPAssociateResult{Err: fmt.Errorf("greeting: %w", err)}
	}
	// CONNECT to 0.0.0.0:0 is the conventional way to ask for a UDP relay
	// without naming a destination; the destination is named per-datagram
	// instead.
	req := []byte{0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0}
	if _, err := conn.Write(req); err != nil {
		return UDPAssociateResult{Err: fmt.Errorf("write associate: %w", err)}
	}
	head := make([]byte, 4)
	if _, err := io.ReadFull(conn, head); err != nil {
		return UDPAssociateResult{Err: fmt.Errorf("read associate reply: %w", err)}
	}
	if head[0] != 0x05 {
		return UDPAssociateResult{Err: fmt.Errorf("unexpected version byte %#x", head[0])}
	}
	if head[1] != 0x00 {
		return UDPAssociateResult{Err: fmt.Errorf("proxy refused UDP ASSOCIATE with code %d", head[1])}
	}

	addr, err := readSocks5Addr(conn, head[3])
	if err != nil {
		return UDPAssociateResult{Err: fmt.Errorf("read bind address: %w", err)}
	}
	// A wildcard bind address means "same host as the control connection", which
	// is what a proxy on loopback returns. Anything else is a routable relay.
	if addr == "0.0.0.0:0" || addr == "[::]:0" {
		host, _, err := splitHostPort(proxyAddr)
		if err != nil {
			return UDPAssociateResult{Err: err}
		}
		addr = net.JoinHostPort(host, "0")
	}
	return UDPAssociateResult{Supported: true, RelayAddr: addr}
}

// UDPEgressResult reports whether UDP leaves this machine at all.
type UDPEgressResult struct {
	Works bool
	RTT   time.Duration
	// Conclusive is false when the probe was inconclusive, which is different
	// from a negative result. A blocked or filtered network and a server that
	// simply did not answer look identical from here.
	Conclusive bool
	Err        error
}

// ProbeUDPEgress sends an NTP request and waits for a reply.
//
// NTP is used as the well-known always-on UDP service rather than something
// bespoke. The result is reported as a signal with an explicit
// conclusive/not-conclusive flag, because a silent server and a filtered
// network are indistinguishable from the outside, and a censorship tool that
// reports that ambiguity as a hard answer will be wrong in both directions.
func ProbeUDPEgress(ctx context.Context, server string, timeout time.Duration) UDPEgressResult {
	start := time.Now()
	conn, err := net.Dial("udp", net.JoinHostPort(server, "123"))
	if err != nil {
		return UDPEgressResult{Err: fmt.Errorf("dial: %w", err)}
	}
	defer conn.Close()

	pkt := make([]byte, 48)
	pkt[0] = 0x1B // LI 0, VN 4, Mode 3 (client)
	deadline := time.Now().Add(timeout)
	if err := conn.SetDeadline(deadline); err != nil {
		return UDPEgressResult{Err: err}
	}
	go func() {
		select {
		case <-ctx.Done():
			conn.Close()
		case <-time.After(timeout):
		}
	}()

	if _, err := conn.Write(pkt); err != nil {
		return UDPEgressResult{Err: fmt.Errorf("write: %w", err)}
	}
	buf := make([]byte, 128)
	n, err := conn.Read(buf)
	if err != nil {
		return UDPEgressResult{Err: fmt.Errorf("no reply within %s", timeout), Conclusive: false}
	}
	if n < 48 {
		return UDPEgressResult{Err: errors.New("short NTP reply"), Conclusive: false}
	}
	return UDPEgressResult{Works: true, RTT: time.Since(start), Conclusive: true}
}

// socks5Greet performs the SOCKS5 method negotiation, selecting "no
// authentication".
//
// Aether's listener has no authentication at all, so a method list is not
// optional framing here; sending a version and method count of one is what
// makes the rest of the handshake legal.
func socks5Greet(conn net.Conn) error {
	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		return err
	}
	reply := make([]byte, 2)
	if _, err := io.ReadFull(conn, reply); err != nil {
		return err
	}
	if reply[0] != 0x05 {
		return fmt.Errorf("unexpected version byte %#x", reply[0])
	}
	if reply[1] != 0x00 {
		return fmt.Errorf("proxy requires authentication method %#x, which ARClient does not configure", reply[1])
	}
	return nil
}

// readSocks5Addr reads a SOCKS5 address and returns it as host:port.
func readSocks5Addr(r io.Reader, atyp byte) (string, error) {
	switch atyp {
	case 0x01: // IPv4
		b := make([]byte, 4)
		if _, err := io.ReadFull(r, b); err != nil {
			return "", err
		}
		p := make([]byte, 2)
		if _, err := io.ReadFull(r, p); err != nil {
			return "", err
		}
		return net.JoinHostPort(net.IP(b).String(), strconv.Itoa(int(binary.BigEndian.Uint16(p)))), nil
	case 0x03: // domain
		n := make([]byte, 1)
		if _, err := io.ReadFull(r, n); err != nil {
			return "", err
		}
		b := make([]byte, n[0])
		if _, err := io.ReadFull(r, b); err != nil {
			return "", err
		}
		p := make([]byte, 2)
		if _, err := io.ReadFull(r, p); err != nil {
			return "", err
		}
		return net.JoinHostPort(string(b), strconv.Itoa(int(binary.BigEndian.Uint16(p)))), nil
	case 0x04: // IPv6
		b := make([]byte, 16)
		if _, err := io.ReadFull(r, b); err != nil {
			return "", err
		}
		p := make([]byte, 2)
		if _, err := io.ReadFull(r, p); err != nil {
			return "", err
		}
		return net.JoinHostPort(net.IP(b).String(), strconv.Itoa(int(binary.BigEndian.Uint16(p)))), nil
	default:
		return "", fmt.Errorf("unknown address type %#x", atyp)
	}
}

func splitHostPort(addr string) (string, int, error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return "", 0, err
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return "", 0, fmt.Errorf("bad port in %q: %w", addr, err)
	}
	return host, port, nil
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
