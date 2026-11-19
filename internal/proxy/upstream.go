// Copyright 2026 The Countersign Authors
// SPDX-License-Identifier: Apache-2.0

// The upstream address policy of 04 §2 step 3 and B2-04/B2-06: every
// upstream dial resolves the host exactly once, refuses loopback,
// link-local, unspecified, multicast, private, unique-local and cluster
// ranges unless the grant opts in with network: cluster, dials the
// checked address itself (a DNS answer can never change between check and
// connect), and records the address that was dialled — never the name.

package proxy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"sync"

	"github.com/countersign/countersign/internal/policy"
)

// errUpstreamBlocked is the typed dial-time denial: the resolved address
// fell inside a range the grant does not admit (UPSTREAM_BLOCKED, 04 §2
// step 3). The result record carries it as error; the client sees 502.
type errUpstreamBlocked struct {
	host string
	ips  []netip.Addr
}

func (e *errUpstreamBlocked) Error() string {
	return fmt.Sprintf("upstream %s resolves to a blocked address range", e.host)
}

// ctxDial carries the per-request context the transport's dial functions
// need: the session (dial budget) and the grant (network opt-in). info,
// when non-nil, receives the dialled address for the result record.
type ctxDialKey struct{}

type ctxDial struct {
	sess  *Session
	grant *policy.Grant
	info  *UpstreamRecord
}

// resolveFunc is the host-to-addresses resolver Config.Resolve installs;
// nil falls back to the build's default (DNS, or the fixture table).
type resolveFunc func(ctx context.Context, host string) ([]netip.Addr, error)

// dialledConn reports the checked address as its remote address so the
// recorded upstream.ip is the address the broker dialled (B2-06) even
// under a fixture dialer whose socket lands on loopback.
type dialledConn struct {
	net.Conn
	addr net.Addr
}

func (c *dialledConn) RemoteAddr() net.Addr { return c.addr }

// resolveOnce resolves host to its address list, once. IP literals return
// themselves (an authority given as a literal is its own resolution).
func (s *Server) resolveOnce(ctx context.Context, host string) ([]netip.Addr, error) {
	if ip, err := netip.ParseAddr(host); err == nil {
		return []netip.Addr{ip.Unmap()}, nil
	}
	res := s.cfg.Resolve
	if res == nil {
		res = resolveHost
	}
	ips, err := res(ctx, host)
	if err != nil {
		return nil, err
	}
	out := make([]netip.Addr, 0, len(ips))
	for _, ip := range ips {
		out = append(out, ip.Unmap())
	}
	return out, nil
}

// upstreamIPOK applies 04 §2 step 3's range policy. Loopback, link-local,
// unspecified and multicast ranges are always refused — even under
// network: cluster, which lifts only the private/unique-local/cluster
// deployment ranges (a cluster grant must not open the metadata path).
func upstreamIPOK(ip netip.Addr, g *policy.Grant) bool {
	ip = ip.Unmap()
	if ip.IsLoopback() || ip.IsUnspecified() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsInterfaceLocalMulticast() {
		return false
	}
	cluster := g != nil && g.Network == "cluster"
	if ip.IsPrivate() || ip.Is6() && isULA(ip) {
		return cluster
	}
	return true
}

// isULA reports whether ip is in fc00::/7 (unique-local).
func isULA(ip netip.Addr) bool {
	return ip.Is6() && !ip.Is4In6() && ip.As16()[0]&0xfe == 0xfc
}

// dialUpstream resolves addr's host once, checks each answer against the
// grant's range policy, and dials the first allowed address — the address
// checked is the address dialled. Blocked resolution yields
// *errUpstreamBlocked; the returned conn reports the dialled address.
func (s *Server) dialUpstream(ctx context.Context, sess *Session, grant *policy.Grant, network, addr string) (net.Conn, UpstreamRecord, error) {
	host, port := splitHostPort(addr)
	ips, err := s.resolveOnce(ctx, host)
	if err != nil {
		return nil, UpstreamRecord{}, err
	}
	var lastErr error
	allowed := false
	for _, ip := range ips {
		if !upstreamIPOK(ip, grant) {
			continue
		}
		allowed = true
		if err := sess.acquireDial(ctx); err != nil {
			return nil, UpstreamRecord{}, err
		}
		c, err := s.dial(ctx, network, net.JoinHostPort(ip.String(), strconv.Itoa(port)))
		sess.releaseDial()
		if err != nil {
			lastErr = err
			continue
		}
		info := UpstreamRecord{IP: ip.String(), Port: port}
		return &dialledConn{Conn: c, addr: &net.TCPAddr{IP: net.ParseIP(ip.String()), Port: port}}, info, nil
	}
	if !allowed && len(ips) > 0 {
		return nil, UpstreamRecord{}, &errUpstreamBlocked{host: host, ips: ips}
	}
	if lastErr != nil {
		return nil, UpstreamRecord{}, lastErr
	}
	return nil, UpstreamRecord{}, fmt.Errorf("upstream %s: no address", host)
}

// dial is the raw socket dialer (Config.DialContext or the build default).
// It always receives the resolved IP:port — never a name (B2-04).
func (s *Server) dial(ctx context.Context, network, addr string) (net.Conn, error) {
	d := s.cfg.DialContext
	if d == nil {
		d = defaultDialContext
	}
	return d(ctx, network, addr)
}

// dialResolved is the transport's DialContext: it resolves and checks the
// URL's host once and dials the checked address.
func (s *Server) dialResolved(ctx context.Context, network, addr string) (net.Conn, UpstreamRecord, error) {
	d, _ := ctx.Value(ctxDialKey{}).(*ctxDial)
	if d == nil || d.sess == nil {
		return nil, UpstreamRecord{}, errors.New("proxy: upstream dial without session context")
	}
	return s.dialUpstream(ctx, d.sess, d.grant, network, addr)
}

// acquireDial takes one of the session's 64 in-flight upstream dial slots
// (04 §2 / M2.5 limits); the wait is bounded by ctx.
func (s *Session) acquireDial(ctx context.Context) error {
	select {
	case s.dialSem <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *Session) releaseDial() { <-s.dialSem }

// acquireConn takes one of the session's 256 concurrent-connection slots.
// Non-blocking: a full session refuses the conn (M2.5 isolation).
func (s *Session) acquireConn() bool {
	select {
	case s.connSem <- struct{}{}:
		return true
	default:
		return false
	}
}

func (s *Session) releaseConn() { <-s.connSem }

// connSlotFor returns the slot release closure for an accepted conn: the
// first admitting session (by table order) with a free slot, else the
// broker-wide unattributed pool. nil means refuse the conn.
func (s *Server) connSlotFor(c net.Conn) *connSlot {
	host, _, err := net.SplitHostPort(c.RemoteAddr().String())
	if err == nil {
		if ip, err := netip.ParseAddr(host); err == nil {
			for _, sess := range s.sessionsByID {
				if !sess.admits(ip) {
					continue
				}
				if sess.acquireConn() {
					var once sync.Once
					return &connSlot{once: func() { once.Do(sess.releaseConn) }}
				}
			}
		}
	}
	// No admitting session with a free slot: charge the unattributed pool
	// so a flood of foreign conns is still bounded.
	select {
	case s.anonSem <- struct{}{}:
		var once sync.Once
		return &connSlot{once: func() { once.Do(func() { <-s.anonSem }) }}
	default:
		return nil
	}
}
