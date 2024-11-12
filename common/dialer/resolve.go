package dialer

import (
	"context"
	"net"
	"net/netip"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-dns"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type ResolveDialer struct {
	addresses      []netip.Addr
	dialer         N.Dialer
	parallel       bool
	router         adapter.Router
	strategy       dns.DomainStrategy
	fallbackDelay  time.Duration
	isDirect       bool
	storeLastIP    bool
	dialPreferIP   netip.Addr
	listenPreferIP netip.Addr
}

func NewResolveDialer(router adapter.Router, dialer N.Dialer, addresses []option.ListenAddress, parallel bool, strategy dns.DomainStrategy, fallbackDelay time.Duration, isDirect bool, storeLastIP bool) *ResolveDialer {
	var addrs []netip.Addr
	addrsMap := make(map[string]struct{})
	if len(addresses) > 0 {
		for _, address := range addresses {
			addr := address.Build()
			if _, exists := addrsMap[addr.String()]; exists {
				continue
			}
			addrs = append(addrs, addr)
			addrsMap[addr.String()] = struct{}{}
		}
	}
	return &ResolveDialer{
		addrs,
		dialer,
		parallel,
		router,
		strategy,
		fallbackDelay,
		isDirect,
		storeLastIP,
		netip.Addr{},
		netip.Addr{},
	}
}

func (d *ResolveDialer) lookup(ctx context.Context, domain string) ([]netip.Addr, error) {
	if d.strategy == dns.DomainStrategyAsIS {
		return d.router.LookupDefault(ctx, domain)
	}
	return d.router.Lookup(ctx, domain, d.strategy)
}

func (d *ResolveDialer) dialContextWithAddr(ctx context.Context, network string, destination M.Socksaddr, addresses []netip.Addr) (net.Conn, netip.Addr, error) {
	if d.parallel {
		return N.DialParallelWithAddr(ctx, d.dialer, network, destination, addresses, d.strategy == dns.DomainStrategyPreferIPv6, d.fallbackDelay)
	}
	return N.DialSerialWithAddr(ctx, d.dialer, network, destination, addresses)
}

func (d *ResolveDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if !destination.IsFqdn() {
		return d.dialer.DialContext(ctx, network, destination)
	}
	ctx, metadata := adapter.ExtendContext(ctx)
	ctx = log.ContextWithOverrideLevel(ctx, log.LevelDebug)
	metadata.Destination = destination
	metadata.Domain = ""
	var addresses []netip.Addr
	var err error
	if !d.isDirect && len(d.addresses) > 0 {
		addresses = d.addresses
	} else if addresses, err = d.lookup(ctx, destination.Fqdn); err != nil {
		return nil, err
	}
	if d.isDirect || !d.storeLastIP {
		if d.parallel {
			return N.DialParallel(ctx, d.dialer, network, destination, addresses, d.strategy == dns.DomainStrategyPreferIPv6, d.fallbackDelay)
		}
		return N.DialSerial(ctx, d.dialer, network, destination, addresses)
	}
	if preferIP := d.dialPreferIP; preferIP.IsValid() {
		if common.Any(addresses, func(addr netip.Addr) bool {
			return addr.String() == preferIP.String()
		}) {
			addresses = common.Filter(addresses, func(addr netip.Addr) bool {
				return addr.String() != preferIP.String()
			})
			if conn, err := d.dialer.DialContext(ctx, network, M.Socksaddr{Addr: preferIP, Port: destination.Port}); err == nil {
				d.dialPreferIP = preferIP
				return conn, nil
			} else if len(addresses) == 0 {
				return nil, err
			}
		}
	}
	conn, addr, err := d.dialContextWithAddr(ctx, network, destination, addresses)
	if err != nil {
		return nil, err
	}
	if addr.IsValid() {
		d.dialPreferIP = addr
	}
	return conn, nil
}

func (d *ResolveDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	if !destination.IsFqdn() {
		return d.dialer.ListenPacket(ctx, destination)
	}
	ctx, metadata := adapter.ExtendContext(ctx)
	ctx = log.ContextWithOverrideLevel(ctx, log.LevelDebug)
	metadata.Destination = destination
	metadata.Domain = ""
	var addresses []netip.Addr
	var err error
	if !d.isDirect && len(d.addresses) > 0 {
		addresses = d.addresses
	} else if addresses, err = d.lookup(ctx, destination.Fqdn); err != nil {
		return nil, err
	}
	if d.isDirect || !d.storeLastIP {
		conn, destinationAddress, err := N.ListenSerial(ctx, d.dialer, destination, addresses)
		if err != nil {
			return nil, err
		}
		return bufio.NewNATPacketConn(bufio.NewPacketConn(conn), M.SocksaddrFrom(destinationAddress, destination.Port), destination), nil
	}
	if preferIP := d.listenPreferIP; preferIP.IsValid() {
		if common.Any(addresses, func(addr netip.Addr) bool {
			return addr.String() == preferIP.String()
		}) {
			addresses = common.Filter(addresses, func(addr netip.Addr) bool {
				return addr.String() != preferIP.String()
			})
			if conn, err := d.dialer.ListenPacket(ctx, M.Socksaddr{Addr: preferIP, Port: destination.Port}); err == nil {
				d.listenPreferIP = preferIP
				return bufio.NewNATPacketConn(bufio.NewPacketConn(conn), M.SocksaddrFrom(preferIP, destination.Port), destination), nil
			} else if len(addresses) == 0 {
				return nil, err
			}
		}
	}
	conn, destinationAddress, err := N.ListenSerial(ctx, d.dialer, destination, addresses)
	if err != nil {
		return nil, err
	}
	d.listenPreferIP = destinationAddress
	return bufio.NewNATPacketConn(bufio.NewPacketConn(conn), M.SocksaddrFrom(destinationAddress, destination.Port), destination), nil
}

func (d *ResolveDialer) Upstream() any {
	return d.dialer
}
