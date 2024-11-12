package dialer

import (
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-dns"
	N "github.com/sagernet/sing/common/network"
)

func New(router adapter.Router, options option.DialerOptions) (N.Dialer, error) {
	return new(router, options, false)
}

func NewDirect(router adapter.Router, options option.DialerOptions) (N.Dialer, error) {
	return new(router, options, true)
}

func new(router adapter.Router, options option.DialerOptions, isDirect bool) (N.Dialer, error) {
	if options.IsWireGuardListener {
		return NewDefault(router, options)
	}
	if router == nil {
		return NewDefault(nil, options)
	}
	var (
		dialer N.Dialer
		err    error
	)
	if options.Detour == "" {
		dialer, err = NewDefault(router, options)
		if err != nil {
			return nil, err
		}
	} else {
		dialer = NewDetour(router, options.Detour)
	}
	domainStrategy := dns.DomainStrategy(options.DomainStrategy)
	if domainStrategy != dns.DomainStrategyAsIS || options.Detour == "" || (!isDirect && len(options.ServerAddresses) > 0) {
		dialer = NewResolveDialer(
			router,
			dialer,
			options.ServerAddresses,
			options.Detour == "" && !options.TCPFastOpen && domainStrategy != dns.DomainStrategyAsIS,
			domainStrategy,
			time.Duration(options.FallbackDelay),
			isDirect,
			options.StoreLastIP)
	}
	return dialer, nil
}
