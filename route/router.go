package route

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"net/url"
	"os"
	"os/user"
	"runtime"
	"strings"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/conntrack"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/common/geoip"
	"github.com/sagernet/sing-box/common/geosite"
	"github.com/sagernet/sing-box/common/process"
	"github.com/sagernet/sing-box/common/sniff"
	"github.com/sagernet/sing-box/common/taskmonitor"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/experimental/libbox/platform"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	O "github.com/sagernet/sing-box/outbound"
	"github.com/sagernet/sing-box/transport/fakeip"
	"github.com/sagernet/sing-dns"
	"github.com/sagernet/sing-mux"
	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing-vmess"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	"github.com/sagernet/sing/common/bufio/deadline"
	"github.com/sagernet/sing/common/control"
	E "github.com/sagernet/sing/common/exceptions"
	F "github.com/sagernet/sing/common/format"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/ntp"
	"github.com/sagernet/sing/common/task"
	"github.com/sagernet/sing/common/uot"
	"github.com/sagernet/sing/common/winpowrprof"
	"github.com/sagernet/sing/service"
	"github.com/sagernet/sing/service/pause"
)

var _ adapter.Router = (*Router)(nil)

type Router struct {
	ctx                                context.Context
	logger                             log.ContextLogger
	dnsLogger                          log.ContextLogger
	overrideLogger                     log.ContextLogger
	inboundByTag                       map[string]adapter.Inbound
	outbounds                          []adapter.Outbound
	outboundByTag                      map[string]adapter.Outbound
	outboundProviders                  []adapter.OutboundProvider
	outboundProviderByTag              map[string]adapter.OutboundProvider
	rules                              []adapter.Rule
	routeRuleByUUID                    map[string]adapter.Rule
	defaultDetour                      string
	defaultOutboundForConnection       adapter.Outbound
	defaultOutboundForPacketConnection adapter.Outbound
	needGeoIPDatabase                  bool
	needGeositeDatabase                bool
	geoIPOptions                       option.GeoIPOptions
	geositeOptions                     option.GeositeOptions
	geoIPReader                        *geoip.Reader
	geositeReader                      *geosite.Reader
	geositeCache                       map[string]adapter.Rule
	needFindProcess                    bool
	stopFindProcess                    bool
	dnsClient                          *dns.Client
	defaultDomainStrategy              dns.DomainStrategy
	dnsRules                           []adapter.DNSRule
	dnsRuleByUUID                      map[string]adapter.DNSRule
	ruleSets                           []adapter.RuleSet
	ruleSetMap                         map[string]adapter.RuleSet
	sniffOverrideRules                 map[string][]adapter.Rule
	defaultTransport                   dns.Transport
	transports                         []dns.Transport
	transportMap                       map[string]dns.Transport
	transportDomainStrategy            map[dns.Transport]dns.DomainStrategy
	dnsReverseMapping                  *DNSReverseMapping
	dnsMappingOverride                 bool
	fakeIPStore                        adapter.FakeIPStore
	interfaceFinder                    *control.DefaultInterfaceFinder
	stopAlwaysResolveUDP               bool
	autoDetectInterface                bool
	defaultInterface                   string
	defaultMark                        uint32
	autoRedirectOutputMark             uint32
	networkMonitor                     tun.NetworkUpdateMonitor
	interfaceMonitor                   tun.DefaultInterfaceMonitor
	packageManager                     tun.PackageManager
	powerListener                      winpowrprof.EventListener
	processSearcher                    process.Searcher
	timeService                        *ntp.Service
	pauseManager                       pause.Manager
	clashServer                        adapter.ClashServer
	v2rayServer                        adapter.V2RayServer
	platformInterface                  platform.Interface
	needWIFIState                      bool
	needPackageManager                 bool
	wifiState                          adapter.WIFIState
	started                            bool
}

func NewRouter(
	ctx context.Context,
	logFactory log.Factory,
	options option.RouteOptions,
	dnsOptions option.DNSOptions,
	ntpOptions option.NTPOptions,
	inbounds []option.Inbound,
	platformInterface platform.Interface,
) (*Router, error) {
	router := &Router{
		ctx:                   ctx,
		logger:                logFactory.NewLogger("router"),
		dnsLogger:             logFactory.NewLogger("dns"),
		overrideLogger:        logFactory.NewLogger("override"),
		outboundByTag:         make(map[string]adapter.Outbound),
		outboundProviderByTag: make(map[string]adapter.OutboundProvider),
		rules:                 make([]adapter.Rule, 0, len(options.Rules)),
		routeRuleByUUID:       make(map[string]adapter.Rule),
		dnsRules:              make([]adapter.DNSRule, 0, len(dnsOptions.Rules)),
		dnsRuleByUUID:         make(map[string]adapter.DNSRule),
		sniffOverrideRules:    make(map[string][]adapter.Rule),
		ruleSetMap:            make(map[string]adapter.RuleSet),
		needGeoIPDatabase:     hasRule(options.Rules, isGeoIPRule) || hasDNSRule(dnsOptions.Rules, isGeoIPDNSRule) || hasDNSFallbackRuleUseGeoIP(dnsOptions.Rules),
		needGeositeDatabase:   hasRule(options.Rules, isGeositeRule) || hasDNSRule(dnsOptions.Rules, isGeositeDNSRule),
		geoIPOptions:          common.PtrValueOrDefault(options.GeoIP),
		geositeOptions:        common.PtrValueOrDefault(options.Geosite),
		geositeCache:          make(map[string]adapter.Rule),
		needFindProcess:       hasRule(options.Rules, isProcessRule) || hasDNSRule(dnsOptions.Rules, isProcessDNSRule) || (options.FindProcess != nil && *options.FindProcess),
		stopFindProcess:       options.FindProcess != nil && !*options.FindProcess,
		defaultDetour:         options.Final,
		defaultDomainStrategy: dns.DomainStrategy(dnsOptions.Strategy),
		interfaceFinder:       control.NewDefaultInterfaceFinder(),
		stopAlwaysResolveUDP:  options.StopAlwaysResolveUDP,
		autoDetectInterface:   options.AutoDetectInterface,
		defaultInterface:      options.DefaultInterface,
		defaultMark:           options.DefaultMark,
		pauseManager:          service.FromContext[pause.Manager](ctx),
		platformInterface:     platformInterface,
		needWIFIState:         hasRule(options.Rules, isWIFIRule) || hasDNSRule(dnsOptions.Rules, isWIFIDNSRule),
		needPackageManager: common.Any(inbounds, func(inbound option.Inbound) bool {
			return len(inbound.TunOptions.IncludePackage) > 0 || len(inbound.TunOptions.ExcludePackage) > 0
		}),
	}
	dialer.ConcurrentDial = options.ConcurrentDial
	if options.KeepAliveInterval != 0 {
		C.TCPKeepAliveInterval = time.Duration(options.KeepAliveInterval)
	}
	var dnsHosts *dns.Hosts
	if len(dnsOptions.Hosts) > 0 {
		var err error
		hostsMap := make(map[string][]string)
		for domain, hosts := range dnsOptions.Hosts {
			hostsMap[domain] = hosts
		}
		dnsHosts, err = dns.NewHosts(hostsMap)
		if err != nil {
			return nil, err
		}
	}
	router.dnsClient = dns.NewClient(dns.ClientOptions{
		DisableCache:     dnsOptions.DNSClientOptions.DisableCache,
		DisableExpire:    dnsOptions.DNSClientOptions.DisableExpire,
		IndependentCache: dnsOptions.DNSClientOptions.IndependentCache,
		LazyCache:        dnsOptions.DNSClientOptions.LazyCache,
		Hosts:            dnsHosts,
		RDRC: func() dns.RDRCStore {
			cacheFile := service.FromContext[adapter.CacheFile](ctx)
			if cacheFile == nil {
				return nil
			}
			if !cacheFile.StoreRDRC() {
				return nil
			}
			return cacheFile
		},
		Logger: router.dnsLogger,
	})
	for i, inboundOptions := range inbounds {
		tag := inboundOptions.Tag
		rules := []adapter.Rule{}
		rawRules := inboundOptions.GetSniffOverrideRules()
		if hasRule(rawRules, isGeoIPRule) {
			router.needGeoIPDatabase = true
		}
		if hasRule(rawRules, isGeositeRule) {
			router.needGeositeDatabase = true
		}
		for j, ruleOptions := range rawRules {
			sniffOverrdideRule, err := NewRule(router, router.logger, ruleOptions, false)
			if err != nil {
				return nil, E.Cause(err, "parse inbound[", i, "] sniff_override_rule[", j, "]")
			}
			rules = append(rules, sniffOverrdideRule)
		}
		router.sniffOverrideRules[tag] = rules
	}
	for i, ruleOptions := range options.Rules {
		routeRule, err := NewRule(router, router.logger, ruleOptions, true)
		if err != nil {
			return nil, E.Cause(err, "parse rule[", i, "]")
		}
		uuid := routeRule.UUID()
		router.rules = append(router.rules, routeRule)
		router.routeRuleByUUID[uuid] = routeRule
	}
	for i, dnsRuleOptions := range dnsOptions.Rules {
		dnsRule, err := NewDNSRule(router, router.logger, dnsRuleOptions, true)
		if err != nil {
			return nil, E.Cause(err, "parse dns rule[", i, "]")
		}
		uuid := dnsRule.UUID()
		router.dnsRules = append(router.dnsRules, dnsRule)
		router.dnsRuleByUUID[uuid] = dnsRule
	}
	for i, ruleSetOptions := range options.RuleSet {
		if _, exists := router.ruleSetMap[ruleSetOptions.Tag]; exists {
			return nil, E.New("duplicate rule-set tag: ", ruleSetOptions.Tag)
		}
		ruleSet, err := NewRuleSet(ctx, router, router.logger, ruleSetOptions)
		if err != nil {
			return nil, E.Cause(err, "parse rule-set[", i, "]")
		}
		router.ruleSets = append(router.ruleSets, ruleSet)
		router.ruleSetMap[ruleSetOptions.Tag] = ruleSet
	}

	transports := make([]dns.Transport, len(dnsOptions.Servers))
	dummyTransportMap := make(map[string]dns.Transport)
	transportMap := make(map[string]dns.Transport)
	transportTags := make([]string, len(dnsOptions.Servers))
	transportTagMap := make(map[string]bool)
	transportDomainStrategy := make(map[dns.Transport]dns.DomainStrategy)
	for i, server := range dnsOptions.Servers {
		var tag string
		if server.Tag != "" {
			tag = server.Tag
		} else {
			tag = F.ToString(i)
		}
		if transportTagMap[tag] {
			return nil, E.New("duplicate dns server tag: ", tag)
		}
		transportTags[i] = tag
		transportTagMap[tag] = true
	}
	ctx = adapter.ContextWithRouter(ctx, router)
	for {
		lastLen := len(dummyTransportMap)
		for i, server := range dnsOptions.Servers {
			tag := transportTags[i]
			if _, exists := dummyTransportMap[tag]; exists {
				continue
			}
			var detour N.Dialer
			if server.Detour == "" {
				detour = dialer.NewRouter(router)
			} else {
				detour = dialer.NewDetour(router, server.Detour)
			}
			if len(server.Address) == 0 {
				return nil, E.New("parse dns server[", tag, "]: missing address")
			}
			detour = dns.NewDefaultDialer(detour, router.dnsClient, time.Duration(server.AddressFallbackDelay))
			var needUpstream bool
			for i, address := range server.Address {
				address = strings.TrimSpace(address)
				switch strings.ToLower(address) {
				case "":
					return nil, E.New("parse dns server[", tag, "].address[", i, "]: empty address")
				case "local", "fakeip":
				default:
					var serverAddress string
					if strings.Contains(address, "://") {
						serverURL, _ := url.Parse(address)
						scheme := serverURL.Scheme
						if common.Contains([]string{"rcode", "dhcp"}, serverURL.Scheme) {
							continue
						}
						if serverURL.Hostname() != "" {
							serverAddress = serverURL.Hostname()
						} else if scheme != "" {
							return nil, E.New("parse dns server[", tag, "].address[", i, "]: missing hostname")
						} else {
							serverAddress = serverURL.Path
						}
					}
					if serverAddress == "" {
						serverAddress = address
					}
					if M.ParseSocksaddr(serverAddress).Addr.IsValid() {
						continue
					}
					serverAddress = router.dnsClient.GetExactDomainFromHosts(ctx, serverAddress, true)
					if addrs := router.dnsClient.GetAddrsFromHosts(ctx, serverAddress, router.defaultDomainStrategy, true); len(addrs) > 0 {
						continue
					}
					needUpstream = true
					break
				}
			}
			if needUpstream {
				if server.AddressResolver == "" {
					return nil, E.New("parse dns server[", tag, "]: missing address_resolver")
				}
				if !transportTagMap[server.AddressResolver] {
					return nil, E.New("parse dns server[", tag, "]: address resolver not found: ", server.AddressResolver)
				}
				if upstream, exists := dummyTransportMap[server.AddressResolver]; exists {
					detour = dns.NewDialerWrapper(detour, router.dnsClient, upstream, dns.DomainStrategy(server.AddressStrategy), time.Duration(server.AddressFallbackDelay))
				} else {
					continue
				}
			}
			var clientSubnet netip.Prefix
			if server.ClientSubnet != nil {
				clientSubnet = server.ClientSubnet.Build()
			} else if dnsOptions.ClientSubnet != nil {
				clientSubnet = dnsOptions.ClientSubnet.Build()
			}
			transport, err := dns.CreateTransport(dns.TransportOptions{
				Context:      ctx,
				Logger:       logFactory.NewLogger(F.ToString("dns/transport[", tag, "]")),
				Name:         tag,
				Dialer:       detour,
				Address:      server.Address,
				ClientSubnet: clientSubnet,
				Insecure:     server.Insecure,
			})
			if err != nil {
				return nil, E.Cause(err, "parse dns server[", tag, "]")
			}
			transports[i] = transport
			dummyTransportMap[tag] = transport
			if server.Tag != "" {
				transportMap[server.Tag] = transport
			}
			strategy := dns.DomainStrategy(server.Strategy)
			if strategy != dns.DomainStrategyAsIS {
				transportDomainStrategy[transport] = strategy
			}
		}
		if len(transports) == len(dummyTransportMap) {
			break
		}
		if lastLen != len(dummyTransportMap) {
			continue
		}
		unresolvedTags := common.MapIndexed(common.FilterIndexed(dnsOptions.Servers, func(index int, server option.DNSServerOptions) bool {
			_, exists := dummyTransportMap[transportTags[index]]
			return !exists
		}), func(index int, server option.DNSServerOptions) string {
			return transportTags[index]
		})
		if len(unresolvedTags) == 0 {
			panic(F.ToString("unexpected unresolved dns servers: ", len(transports), " ", len(dummyTransportMap), " ", len(transportMap)))
		}
		return nil, E.New("found circular reference in dns servers: ", strings.Join(unresolvedTags, " "))
	}
	var defaultTransport dns.Transport
	if dnsOptions.Final != "" {
		defaultTransport = dummyTransportMap[dnsOptions.Final]
		if defaultTransport == nil {
			return nil, E.New("default dns server not found: ", dnsOptions.Final)
		}
	}
	if defaultTransport == nil {
		if len(transports) == 0 {
			transports = append(transports, common.Must1(dns.CreateTransport(dns.TransportOptions{
				Context: ctx,
				Name:    "local",
				Address: []string{"local"},
				Dialer:  common.Must1(dialer.NewDefault(router, option.DialerOptions{})),
			})))
		}
		defaultTransport = transports[0]
	}
	if _, isFakeIP := defaultTransport.(adapter.FakeIPTransport); isFakeIP {
		return nil, E.New("default DNS server cannot be fakeip")
	}
	router.defaultTransport = defaultTransport
	router.transports = transports
	router.transportMap = transportMap
	router.transportDomainStrategy = transportDomainStrategy

	if dnsOptions.ReverseMapping {
		router.dnsReverseMapping = NewDNSReverseMapping()
		router.dnsMappingOverride = dnsOptions.MappingOverride
	}

	if fakeIPOptions := dnsOptions.FakeIP; fakeIPOptions != nil && dnsOptions.FakeIP.Enabled {
		var inet4Range netip.Prefix
		var inet6Range netip.Prefix
		if fakeIPOptions.Inet4Range != nil {
			inet4Range = *fakeIPOptions.Inet4Range
		}
		if fakeIPOptions.Inet6Range != nil {
			inet6Range = *fakeIPOptions.Inet6Range
		}
		excludeRule, err := NewExcludeRule(router, router.logger, fakeIPOptions.ExcludeRule)
		if err != nil {
			return nil, E.Cause(err, "parse fakeip exclude_rule")
		}
		router.fakeIPStore = fakeip.NewStore(ctx, router.logger, inet4Range, inet6Range, excludeRule)
	}

	usePlatformDefaultInterfaceMonitor := platformInterface != nil && platformInterface.UsePlatformDefaultInterfaceMonitor()
	needInterfaceMonitor := options.AutoDetectInterface || common.Any(inbounds, func(inbound option.Inbound) bool {
		return inbound.HTTPOptions.SetSystemProxy || inbound.MixedOptions.SetSystemProxy || inbound.TunOptions.AutoRoute
	})

	if !usePlatformDefaultInterfaceMonitor {
		networkMonitor, err := tun.NewNetworkUpdateMonitor(router.logger)
		if !((err != nil && !needInterfaceMonitor) || errors.Is(err, os.ErrInvalid)) {
			if err != nil {
				return nil, err
			}
			router.networkMonitor = networkMonitor
			networkMonitor.RegisterCallback(func() {
				_ = router.interfaceFinder.Update()
			})
			interfaceMonitor, err := tun.NewDefaultInterfaceMonitor(router.networkMonitor, router.logger, tun.DefaultInterfaceMonitorOptions{
				OverrideAndroidVPN:    options.OverrideAndroidVPN,
				UnderNetworkExtension: platformInterface != nil && platformInterface.UnderNetworkExtension(),
			})
			if err != nil {
				return nil, E.New("auto_detect_interface unsupported on current platform")
			}
			interfaceMonitor.RegisterCallback(router.notifyNetworkUpdate)
			router.interfaceMonitor = interfaceMonitor
		}
	} else {
		interfaceMonitor := platformInterface.CreateDefaultInterfaceMonitor(router.logger)
		interfaceMonitor.RegisterCallback(router.notifyNetworkUpdate)
		router.interfaceMonitor = interfaceMonitor
	}

	if ntpOptions.Enabled {
		ntpDialer, err := dialer.New(router, ntpOptions.DialerOptions)
		if err != nil {
			return nil, E.Cause(err, "create NTP service")
		}
		timeService := ntp.NewService(ntp.Options{
			Context:       ctx,
			Dialer:        ntpDialer,
			Logger:        logFactory.NewLogger("ntp"),
			Server:        ntpOptions.ServerOptions.Build(),
			Interval:      time.Duration(ntpOptions.Interval),
			WriteToSystem: ntpOptions.WriteToSystem,
		})
		service.MustRegister[ntp.TimeService](ctx, timeService)
		router.timeService = timeService
	}
	return router, nil
}

func (r *Router) Initialize(inbounds []adapter.Inbound, outboundProviders []adapter.OutboundProvider, outbounds []adapter.Outbound) error {
	inboundByTag := make(map[string]adapter.Inbound)
	for _, inbound := range inbounds {
		inboundByTag[inbound.Tag()] = inbound
	}
	outboundProviderByTag := make(map[string]adapter.OutboundProvider)
	for _, provider := range outboundProviders {
		outboundProviderByTag[provider.Tag()] = provider
	}
	outboundByTag := make(map[string]adapter.Outbound)
	for _, detour := range outbounds {
		outboundByTag[detour.Tag()] = detour
	}
	var defaultOutboundForConnection adapter.Outbound
	var defaultOutboundForPacketConnection adapter.Outbound
	if r.defaultDetour != "" {
		detour, loaded := outboundByTag[r.defaultDetour]
		if !loaded {
			return E.New("default detour not found: ", r.defaultDetour)
		}
		if common.Contains(detour.Network(), N.NetworkTCP) {
			defaultOutboundForConnection = detour
		}
		if common.Contains(detour.Network(), N.NetworkUDP) {
			defaultOutboundForPacketConnection = detour
		}
	}
	if defaultOutboundForConnection == nil {
		for _, detour := range outbounds {
			if detour.Tag() == "OUTBOUNDLESS" {
				continue
			}
			if common.Contains(detour.Network(), N.NetworkTCP) {
				defaultOutboundForConnection = detour
				break
			}
		}
		if defaultOutboundForConnection == nil {
			defaultOutboundForConnection = outboundByTag["OUTBOUNDLESS"]
		}
	}
	if defaultOutboundForPacketConnection == nil {
		for _, detour := range outbounds {
			if detour.Tag() == "OUTBOUNDLESS" {
				continue
			}
			if common.Contains(detour.Network(), N.NetworkUDP) {
				defaultOutboundForPacketConnection = detour
				break
			}
		}
		if defaultOutboundForPacketConnection == nil {
			defaultOutboundForPacketConnection = outboundByTag["OUTBOUNDLESS"]
		}
	}
	r.inboundByTag = inboundByTag
	r.outbounds = outbounds
	r.defaultOutboundForConnection = defaultOutboundForConnection
	r.defaultOutboundForPacketConnection = defaultOutboundForPacketConnection
	r.outboundByTag = outboundByTag
	r.outboundProviderByTag = outboundProviderByTag
	r.outboundProviders = outboundProviders
	for i, rule := range r.rules {
		if _, loaded := outboundByTag[rule.Outbound()]; !loaded {
			return E.New("outbound not found for rule[", i, "]: ", rule.Outbound())
		}
	}
	return nil
}

func (r *Router) Outbounds() []adapter.Outbound {
	if !r.started {
		return nil
	}
	return r.outbounds
}

func (r *Router) OutboundProviders() []adapter.OutboundProvider {
	return r.outboundProviders
}

func (r *Router) OutboundProvider(tag string) (adapter.OutboundProvider, bool) {
	provider, loaded := r.outboundProviderByTag[tag]
	return provider, loaded
}

func (r *Router) PreStart() error {
	monitor := taskmonitor.New(r.logger, C.StartTimeout)
	if r.interfaceMonitor != nil {
		monitor.Start("initialize interface monitor")
		err := r.interfaceMonitor.Start()
		monitor.Finish()
		if err != nil {
			return err
		}
	}
	if r.networkMonitor != nil {
		monitor.Start("initialize network monitor")
		err := r.networkMonitor.Start()
		monitor.Finish()
		if err != nil {
			return err
		}
	}
	if r.fakeIPStore != nil {
		monitor.Start("initialize fakeip store")
		err := r.fakeIPStore.Start()
		monitor.Finish()
		if err != nil {
			return err
		}
	}
	return nil
}

func (r *Router) Start() error {
	monitor := taskmonitor.New(r.logger, C.StartTimeout)
	if r.needGeoIPDatabase {
		monitor.Start("initialize geoip database")
		err := r.prepareGeoIPDatabase()
		monitor.Finish()
		if err != nil {
			return err
		}
	}
	if r.needGeositeDatabase {
		monitor.Start("initialize geosite database")
		err := r.prepareGeositeDatabase()
		monitor.Finish()
		if err != nil {
			return err
		}
	}
	if r.needGeositeDatabase {
		for _, rule := range r.rules {
			err := rule.UpdateGeosite()
			if err != nil {
				r.logger.Error("failed to initialize geosite: ", err)
			}
		}
		for _, rule := range r.dnsRules {
			err := rule.UpdateGeosite()
			if err != nil {
				r.logger.Error("failed to initialize geosite: ", err)
			}
		}
		for _, rules := range r.sniffOverrideRules {
			for _, rule := range rules {
				err := rule.UpdateGeosite()
				if err != nil {
					r.logger.Error("failed to initialize geosite: ", err)
				}
			}
		}
		err := common.Close(r.geositeReader)
		if err != nil {
			return err
		}
		r.geositeCache = nil
		r.geositeReader = nil
	}

	if runtime.GOOS == "windows" {
		powerListener, err := winpowrprof.NewEventListener(r.notifyWindowsPowerEvent)
		if err == nil {
			r.powerListener = powerListener
		} else {
			r.logger.Warn("initialize power listener: ", err)
		}
	}

	if r.powerListener != nil {
		monitor.Start("start power listener")
		err := r.powerListener.Start()
		monitor.Finish()
		if err != nil {
			return E.Cause(err, "start power listener")
		}
	}

	monitor.Start("initialize DNS client")
	r.dnsClient.Start()
	monitor.Finish()

	if !r.stopFindProcess && r.needFindProcess && C.IsAndroid && r.platformInterface == nil {
		monitor.Start("initialize package manager")
		packageManager, err := tun.NewPackageManager(tun.PackageManagerOptions{
			Callback: r,
			Logger:   r.logger,
		})
		monitor.Finish()
		if err != nil {
			return E.Cause(err, "create package manager")
		}
		if r.needPackageManager {
			monitor.Start("start package manager")
			err = packageManager.Start()
			monitor.Finish()
			if err != nil {
				r.logger.ErrorContext(r.ctx, E.Cause(err, "start package manager"))
				packageManager = nil
			}
		}
		r.packageManager = packageManager
	}

	for i, rule := range r.dnsRules {
		monitor.Start("initialize DNS rule[", i, "]")
		err := rule.Start()
		monitor.Finish()
		if err != nil {
			return E.Cause(err, "initialize DNS rule[", i, "]")
		}
	}
	for in, rules := range r.sniffOverrideRules {
		for i, rule := range rules {
			monitor.Start("initialize inbound[", in, "] sniff_overrride_rule[", i, "]")
			err := rule.Start()
			monitor.Finish()
			if err != nil {
				return E.Cause(err, "initialize inbound[", in, "] sniff_overrride_rule[", i, "]")
			}
		}
	}
	for i, transport := range r.transports {
		monitor.Start("initialize DNS transport[", i, "]")
		err := transport.Start()
		monitor.Finish()
		if err != nil {
			return E.Cause(err, "initialize DNS server[", i, "]")
		}
	}
	if r.timeService != nil {
		monitor.Start("initialize time service")
		err := r.timeService.Start()
		monitor.Finish()
		if err != nil {
			return E.Cause(err, "initialize time service")
		}
	}
	return nil
}

func (r *Router) Close() error {
	monitor := taskmonitor.New(r.logger, C.StopTimeout)
	var err error
	for i, rule := range r.rules {
		monitor.Start("close rule[", i, "]")
		err = E.Append(err, rule.Close(), func(err error) error {
			return E.Cause(err, "close rule[", i, "]")
		})
		monitor.Finish()
	}
	for i, rule := range r.dnsRules {
		monitor.Start("close dns rule[", i, "]")
		err = E.Append(err, rule.Close(), func(err error) error {
			return E.Cause(err, "close dns rule[", i, "]")
		})
		monitor.Finish()
	}
	for i, transport := range r.transports {
		monitor.Start("close dns transport[", i, "]")
		err = E.Append(err, transport.Close(), func(err error) error {
			return E.Cause(err, "close dns transport[", i, "]")
		})
		monitor.Finish()
	}
	if r.geoIPReader != nil {
		monitor.Start("close geoip reader")
		err = E.Append(err, r.geoIPReader.Close(), func(err error) error {
			return E.Cause(err, "close geoip reader")
		})
		monitor.Finish()
	}
	if r.interfaceMonitor != nil {
		monitor.Start("close interface monitor")
		err = E.Append(err, r.interfaceMonitor.Close(), func(err error) error {
			return E.Cause(err, "close interface monitor")
		})
		monitor.Finish()
	}
	if r.networkMonitor != nil {
		monitor.Start("close network monitor")
		err = E.Append(err, r.networkMonitor.Close(), func(err error) error {
			return E.Cause(err, "close network monitor")
		})
		monitor.Finish()
	}
	if r.packageManager != nil {
		monitor.Start("close package manager")
		err = E.Append(err, r.packageManager.Close(), func(err error) error {
			return E.Cause(err, "close package manager")
		})
		monitor.Finish()
	}
	if r.powerListener != nil {
		monitor.Start("close power listener")
		err = E.Append(err, r.powerListener.Close(), func(err error) error {
			return E.Cause(err, "close power listener")
		})
		monitor.Finish()
	}
	if r.timeService != nil {
		monitor.Start("close time service")
		err = E.Append(err, r.timeService.Close(), func(err error) error {
			return E.Cause(err, "close time service")
		})
		monitor.Finish()
	}
	if r.fakeIPStore != nil {
		monitor.Start("close fakeip store")
		err = E.Append(err, r.fakeIPStore.Close(), func(err error) error {
			return E.Cause(err, "close fakeip store")
		})
		monitor.Finish()
	}
	return err
}

func (r *Router) PostStart() error {
	monitor := taskmonitor.New(r.logger, C.StopTimeout)
	if len(r.ruleSets) > 0 {
		monitor.Start("initialize rule-set")
		ruleSetStartContext := NewRuleSetStartContext()
		var ruleSetStartGroup task.Group
		for i, ruleSet := range r.ruleSets {
			ruleSetInPlace := ruleSet
			ruleSetStartGroup.Append0(func(ctx context.Context) error {
				err := ruleSetInPlace.StartContext(ctx, ruleSetStartContext)
				if err != nil {
					return E.Cause(err, "initialize rule-set[", i, "]")
				}
				return nil
			})
		}
		ruleSetStartGroup.Concurrency(5)
		ruleSetStartGroup.FastFail()
		err := ruleSetStartGroup.Run(r.ctx)
		monitor.Finish()
		if err != nil {
			return err
		}
		ruleSetStartContext.Close()
	}
	needFindProcess := r.needFindProcess
	needWIFIState := r.needWIFIState
	for _, ruleSet := range r.ruleSets {
		metadata := ruleSet.Metadata()
		if metadata.ContainsProcessRule {
			needFindProcess = true
		}
		if metadata.ContainsWIFIRule {
			needWIFIState = true
		}
	}
	if !r.stopFindProcess && C.IsAndroid && r.platformInterface == nil && !r.needPackageManager {
		if needFindProcess {
			monitor.Start("start package manager")
			err := r.packageManager.Start()
			monitor.Finish()
			if err != nil {
				r.packageManager = nil
				r.logger.ErrorContext(r.ctx, E.Cause(err, "start package manager"))
			}
		} else {
			r.packageManager = nil
		}
	}
	if !r.stopFindProcess && needFindProcess {
		if r.platformInterface != nil {
			r.processSearcher = r.platformInterface
		} else {
			monitor.Start("initialize process searcher")
			searcher, err := process.NewSearcher(process.Config{
				Logger:         r.logger,
				PackageManager: r.packageManager,
			})
			monitor.Finish()
			if err != nil {
				if err != os.ErrInvalid {
					r.logger.Warn(E.Cause(err, "create process searcher"))
				}
			} else {
				r.processSearcher = searcher
			}
		}
	}
	if needWIFIState && r.platformInterface != nil {
		monitor.Start("initialize WIFI state")
		r.needWIFIState = true
		r.interfaceMonitor.RegisterCallback(func(_ int) {
			r.updateWIFIState()
		})
		r.updateWIFIState()
		monitor.Finish()
	}
	for i, rule := range r.rules {
		monitor.Start("initialize rule[", i, "]")
		err := rule.Start()
		monitor.Finish()
		if err != nil {
			return E.Cause(err, "initialize rule[", i, "]")
		}
	}
	for _, ruleSet := range r.ruleSets {
		monitor.Start("post start rule_set[", ruleSet.Name(), "]")
		err := ruleSet.PostStart()
		monitor.Finish()
		if err != nil {
			return E.Cause(err, "post start rule_set[", ruleSet.Name(), "]")
		}
	}
	r.started = true
	return nil
}

func (r *Router) Cleanup() error {
	for _, ruleSet := range r.ruleSetMap {
		ruleSet.Cleanup()
	}
	runtime.GC()
	return nil
}

func (r *Router) Outbound(tag string) (adapter.Outbound, bool) {
	outbound, loaded := r.outboundByTag[tag]
	return outbound, loaded
}

func (r *Router) OutboundWithProvider(tag string) (adapter.Outbound, bool) {
	outbound, loaded := r.outboundByTag[tag]
	if loaded {
		return outbound, loaded
	}
	for _, provider := range r.outboundProviders {
		outbound, loaded = provider.Outbound(tag)
		if loaded {
			return outbound, loaded
		}
	}
	return nil, false
}

func (r *Router) OutboundsWithProvider() []adapter.Outbound {
	outbounds := []adapter.Outbound{}
	outbounds = append(outbounds, r.outbounds...)
	for _, provider := range r.outboundProviders {
		myOutbounds := provider.Outbounds()
		outbounds = append(outbounds, myOutbounds...)
	}
	return outbounds
}

func (r *Router) DefaultOutbound(network string) (adapter.Outbound, error) {
	if network == N.NetworkTCP {
		if r.defaultOutboundForConnection == nil {
			return nil, E.New("missing default outbound for TCP connections")
		}
		return r.defaultOutboundForConnection, nil
	} else {
		if r.defaultOutboundForPacketConnection == nil {
			return nil, E.New("missing default outbound for UDP connections")
		}
		return r.defaultOutboundForPacketConnection, nil
	}
}

func (r *Router) FakeIPStore() adapter.FakeIPStore {
	return r.fakeIPStore
}

func (r *Router) RuleSets() []adapter.RuleSet {
	return r.ruleSets
}

func (r *Router) RuleSet(tag string) (adapter.RuleSet, bool) {
	ruleSet, loaded := r.ruleSetMap[tag]
	return ruleSet, loaded
}

func (r *Router) NeedWIFIState() bool {
	return r.needWIFIState
}

func (r *Router) RouteConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext) error {
	if r.pauseManager.IsDevicePaused() {
		return E.New("reject connection to ", metadata.Destination, " while device paused")
	}

	if metadata.InboundDetour != "" {
		if metadata.LastInbound == metadata.InboundDetour {
			return E.New("routing loop on detour: ", metadata.InboundDetour)
		}
		detour := r.inboundByTag[metadata.InboundDetour]
		if detour == nil {
			return E.New("inbound detour not found: ", metadata.InboundDetour)
		}
		injectable, isInjectable := detour.(adapter.InjectableInbound)
		if !isInjectable {
			return E.New("inbound detour is not injectable: ", metadata.InboundDetour)
		}
		if !common.Contains(injectable.Network(), N.NetworkTCP) {
			return E.New("inject: TCP unsupported")
		}
		metadata.LastInbound = metadata.Inbound
		metadata.Inbound = metadata.InboundDetour
		metadata.InboundDetour = ""
		err := injectable.NewConnection(ctx, conn, metadata)
		if err != nil {
			return E.Cause(err, "inject ", detour.Tag())
		}
		return nil
	}
	conntrack.KillerCheck()
	metadata.Network = N.NetworkTCP
	switch metadata.Destination.Fqdn {
	case mux.Destination.Fqdn:
		return E.New("global multiplex is deprecated since sing-box v1.7.0, enable multiplex in inbound options instead.")
	case vmess.MuxDestination.Fqdn:
		return E.New("global multiplex (v2ray legacy) not supported since sing-box v1.7.0.")
	case uot.MagicAddress:
		return E.New("global UoT not supported since sing-box v1.7.0.")
	case uot.LegacyMagicAddress:
		return E.New("global UoT (legacy) not supported since sing-box v1.7.0.")
	}

	if r.fakeIPStore != nil && r.fakeIPStore.Contains(metadata.Destination.Addr) {
		domain, loaded := r.fakeIPStore.Lookup(metadata.Destination.Addr)
		if !loaded {
			return E.New("missing fakeip context")
		}
		metadata.OriginDestination = metadata.Destination
		metadata.Destination = M.Socksaddr{
			Fqdn: domain,
			Port: metadata.Destination.Port,
		}
		metadata.DNSMode = C.DNSModeFakeIP
		r.logger.DebugContext(ctx, "found fakeip domain: ", domain)
		r.logger.DebugContext(ctx, "connection destination is overridden as ", domain, ":", metadata.Destination.Port)
	}

	if r.dnsReverseMapping != nil {
		domain, loaded := r.dnsReverseMapping.Query(metadata.Destination.Addr)
		if loaded {
			metadata.Domain = domain
			metadata.DNSMode = C.DNSModeRedirHost
			r.logger.DebugContext(ctx, "found reserve mapped domain: ", domain)
			if !metadata.Destination.IsFqdn() && r.dnsMappingOverride {
				metadata.OriginDestination = metadata.Destination
				metadata.Destination = M.Socksaddr{
					Fqdn: domain,
					Port: metadata.Destination.Port,
				}
				metadata.DNSMode = C.DNSModeRedirHost
				r.logger.DebugContext(ctx, "connection destination is overridden as ", domain, ":", metadata.Destination.Port)
			}
		}
	}

	if deadline.NeedAdditionalReadDeadline(conn) {
		conn = deadline.NewConn(conn)
	}

	if metadata.InboundOptions.SniffEnabled {
		buffer := buf.NewPacket()
		err := sniff.PeekStream(
			ctx,
			&metadata,
			conn,
			buffer,
			time.Duration(metadata.InboundOptions.SniffTimeout),
			sniff.StreamDomainNameQuery,
			sniff.TLSClientHello,
			sniff.HTTPHost,
			sniff.BitTorrent,
		)
		if err == nil {
			if metadata.SniffHost != "" {
				r.logger.DebugContext(ctx, "sniffed protocol: ", metadata.Protocol, ", domain: ", metadata.SniffHost)
			} else {
				r.logger.DebugContext(ctx, "sniffed protocol: ", metadata.Protocol)
			}
			if !metadata.Destination.IsFqdn() && metadata.InboundOptions.SniffOverrideDestination && M.IsDomainName(metadata.SniffHost) && r.matchSniffOverride(ctx, &metadata) {
				metadata.OriginDestination = metadata.Destination
				metadata.Destination = M.Socksaddr{
					Fqdn: metadata.SniffHost,
					Port: metadata.Destination.Port,
				}
				r.logger.DebugContext(ctx, "connection destination is overridden as ", metadata.SniffHost, ":", metadata.Destination.Port)
			}
		}
		if !buffer.IsEmpty() {
			conn = bufio.NewCachedConn(conn, buffer)
		} else {
			buffer.Release()
		}
	}

	if metadata.Destination.IsFqdn() {
		metadata.Destination.Fqdn = r.dnsClient.GetExactDomainFromHosts(ctx, metadata.Destination.Fqdn, false)
		inboundStrategy := dns.DomainStrategy(metadata.InboundOptions.DomainStrategy)
		strategy := inboundStrategy
		if strategy == dns.DomainStrategyAsIS {
			strategy = r.defaultDomainStrategy
		}
		if responseAddrs := r.dnsClient.GetAddrsFromHosts(ctx, metadata.Destination.Fqdn, strategy, false); len(responseAddrs) > 0 {
			metadata.DestinationAddresses = responseAddrs
		} else if inboundStrategy != dns.DomainStrategyAsIS {
			addresses, err := r.lookup(adapter.WithContext(ctx, &metadata), metadata.Destination.Fqdn, dns.DomainStrategy(metadata.InboundOptions.DomainStrategy))
			if err != nil {
				return err
			}
			metadata.DestinationAddresses = addresses
			r.dnsLogger.DebugContext(ctx, "resolved [", strings.Join(F.MapToString(metadata.DestinationAddresses), " "), "]")
		}
	} else if metadata.Destination.IsIPv4() {
		metadata.IPVersion = 4
	} else if metadata.Destination.IsIPv6() {
		metadata.IPVersion = 6
	}
	ctx, matchedRule, detour, err := r.match(ctx, &metadata, r.defaultOutboundForConnection)
	if err != nil {
		return err
	}
	if !common.Contains(detour.Network(), N.NetworkTCP) {
		return E.New("missing supported outbound, closing connection")
	}
	if r.clashServer != nil {
		trackerConn, tracker := r.clashServer.RoutedConnection(ctx, conn, metadata, matchedRule)
		defer tracker.Leave()
		conn = trackerConn
	}
	if r.v2rayServer != nil {
		if statsService := r.v2rayServer.StatsService(); statsService != nil {
			conn = statsService.RoutedConnection(metadata.Inbound, detour.Tag(), metadata.User, conn)
		}
	}
	return detour.NewConnection(ctx, conn, metadata)
}

func (r *Router) RoutePacketConnection(ctx context.Context, conn N.PacketConn, metadata adapter.InboundContext) error {
	if r.pauseManager.IsDevicePaused() {
		return E.New("reject packet connection to ", metadata.Destination, " while device paused")
	}
	if metadata.InboundDetour != "" {
		if metadata.LastInbound == metadata.InboundDetour {
			return E.New("routing loop on detour: ", metadata.InboundDetour)
		}
		detour := r.inboundByTag[metadata.InboundDetour]
		if detour == nil {
			return E.New("inbound detour not found: ", metadata.InboundDetour)
		}
		injectable, isInjectable := detour.(adapter.InjectableInbound)
		if !isInjectable {
			return E.New("inbound detour is not injectable: ", metadata.InboundDetour)
		}
		if !common.Contains(injectable.Network(), N.NetworkUDP) {
			return E.New("inject: UDP unsupported")
		}
		metadata.LastInbound = metadata.Inbound
		metadata.Inbound = metadata.InboundDetour
		metadata.InboundDetour = ""
		err := injectable.NewPacketConnection(ctx, conn, metadata)
		if err != nil {
			return E.Cause(err, "inject ", detour.Tag())
		}
		return nil
	}
	conntrack.KillerCheck()
	metadata.Network = N.NetworkUDP

	var destOverride bool

	if r.fakeIPStore != nil && r.fakeIPStore.Contains(metadata.Destination.Addr) {
		domain, loaded := r.fakeIPStore.Lookup(metadata.Destination.Addr)
		if !loaded {
			return E.New("missing fakeip context")
		}
		metadata.OriginDestination = metadata.Destination
		metadata.Destination = M.Socksaddr{
			Fqdn: domain,
			Port: metadata.Destination.Port,
		}
		metadata.DNSMode = C.DNSModeFakeIP
		destOverride = true
		r.logger.DebugContext(ctx, "found fakeip domain: ", domain)
		r.logger.DebugContext(ctx, "packet destination is overridden as ", domain, ":", metadata.Destination.Port)
	}

	if r.dnsReverseMapping != nil {
		domain, loaded := r.dnsReverseMapping.Query(metadata.Destination.Addr)
		if loaded {
			metadata.DNSMode = C.DNSModeRedirHost
			r.logger.DebugContext(ctx, "found reserve mapped domain: ", domain)
			metadata.Domain = domain
			if !metadata.Destination.IsFqdn() && r.dnsMappingOverride {
				metadata.OriginDestination = metadata.Destination
				metadata.Destination = M.Socksaddr{
					Fqdn: domain,
					Port: metadata.Destination.Port,
				}
				metadata.DNSMode = C.DNSModeRedirHost
				r.logger.DebugContext(ctx, "packet destination is overridden as ", domain, ":", metadata.Destination.Port)
				destOverride = true
			}
		}
	}

	// Currently we don't have deadline usages for UDP connections
	/*if deadline.NeedAdditionalReadDeadline(conn) {
		conn = deadline.NewPacketConn(bufio.NewNetPacketConn(conn))
	}*/

	if metadata.InboundOptions.SniffEnabled || metadata.Destination.Addr.IsUnspecified() {
		var bufferList []*buf.Buffer
		for {
			buffer := buf.NewPacket()
			destination, err := conn.ReadPacket(buffer)
			if err != nil {
				buffer.Release()
				return err
			}
			if metadata.Destination.Addr.IsUnspecified() {
				metadata.Destination = destination
			}
			if metadata.InboundOptions.SniffEnabled {
				if len(bufferList) > 0 {
					err = sniff.PeekPacket(
						ctx,
						&metadata,
						buffer.Bytes(),
						sniff.QUICClientHello,
					)
				} else {
					err = sniff.PeekPacket(
						ctx,
						&metadata,
						buffer.Bytes(),
						sniff.DomainNameQuery,
						sniff.QUICClientHello,
						sniff.STUNMessage,
						sniff.UTP,
						sniff.UDPTracker,
						sniff.DTLSRecord,
					)
				}
				if E.IsMulti(err, sniff.ErrClientHelloFragmented) && len(bufferList) == 0 {
					bufferList = append(bufferList, buffer)
					r.logger.DebugContext(ctx, "attempt to sniff fragmented QUIC client hello")
					continue
				}
				if metadata.Protocol != "" {
					if metadata.SniffHost != "" && metadata.Client != "" {
						r.logger.DebugContext(ctx, "sniffed packet protocol: ", metadata.Protocol, ", domain: ", metadata.SniffHost, ", client: ", metadata.Client)
					} else if metadata.SniffHost != "" {
						r.logger.DebugContext(ctx, "sniffed packet protocol: ", metadata.Protocol, ", domain: ", metadata.SniffHost)
					} else if metadata.Client != "" {
						r.logger.DebugContext(ctx, "sniffed packet protocol: ", metadata.Protocol, ", client: ", metadata.Client)
					} else {
						r.logger.DebugContext(ctx, "sniffed packet protocol: ", metadata.Protocol)
					}
					if !metadata.Destination.IsFqdn() && metadata.InboundOptions.SniffOverrideDestination && M.IsDomainName(metadata.SniffHost) && r.matchSniffOverride(ctx, &metadata) {
						metadata.OriginDestination = metadata.Destination
						metadata.Destination = M.Socksaddr{
							Fqdn: metadata.SniffHost,
							Port: metadata.Destination.Port,
						}
						destOverride = true
						r.logger.DebugContext(ctx, "connection destination is overridden as ", metadata.SniffHost, ":", metadata.Destination.Port)
					}
				}
			}
			conn = bufio.NewCachedPacketConn(conn, buffer, destination)
			for _, cachedBuffer := range common.Reverse(bufferList) {
				conn = bufio.NewCachedPacketConn(conn, cachedBuffer, destination)
			}
			break
		}
	}
	if metadata.Destination.IsFqdn() {
		metadata.Destination.Fqdn = r.dnsClient.GetExactDomainFromHosts(ctx, metadata.Destination.Fqdn, false)
		inboundStrategy := dns.DomainStrategy(metadata.InboundOptions.DomainStrategy)
		strategy := inboundStrategy
		if strategy == dns.DomainStrategyAsIS {
			strategy = r.defaultDomainStrategy
		}
		if responseAddrs := r.dnsClient.GetAddrsFromHosts(ctx, metadata.Destination.Fqdn, strategy, false); len(responseAddrs) > 0 {
			metadata.DestinationAddresses = responseAddrs
		} else if inboundStrategy != dns.DomainStrategyAsIS {
			addresses, err := r.lookup(adapter.WithContext(ctx, &metadata), metadata.Destination.Fqdn, dns.DomainStrategy(metadata.InboundOptions.DomainStrategy))
			if err != nil {
				return err
			}
			metadata.DestinationAddresses = addresses
			r.dnsLogger.DebugContext(ctx, "resolved [", strings.Join(F.MapToString(metadata.DestinationAddresses), " "), "]")
		}
	} else if metadata.Destination.IsIPv4() {
		metadata.IPVersion = 4
	} else if metadata.Destination.IsIPv6() {
		metadata.IPVersion = 6
	}
	ctx, matchedRule, detour, err := r.match(ctx, &metadata, r.defaultOutboundForPacketConnection)
	if err != nil {
		return err
	}
	if !common.Contains(detour.Network(), N.NetworkUDP) {
		return E.New("missing supported outbound, closing packet connection")
	}
	if r.clashServer != nil {
		trackerConn, tracker := r.clashServer.RoutedPacketConnection(ctx, conn, metadata, matchedRule)
		defer tracker.Leave()
		conn = trackerConn
	}
	if r.v2rayServer != nil {
		if statsService := r.v2rayServer.StatsService(); statsService != nil {
			conn = statsService.RoutedPacketConnection(metadata.Inbound, detour.Tag(), metadata.User, conn)
		}
	}
	if destOverride {
		conn = bufio.NewNATPacketConn(bufio.NewNetPacketConn(conn), metadata.OriginDestination, metadata.Destination)
	}
	if r.mustResolve(detour, &metadata) {
		addresses, err := r.LookupDefault(adapter.WithContext(ctx, &metadata), metadata.Destination.Fqdn)
		if err != nil {
			return err
		}
		metadata.DestinationAddresses = addresses
		r.dnsLogger.DebugContext(ctx, "resolved [", strings.Join(F.MapToString(metadata.DestinationAddresses), " "), "]")
	}
	return detour.NewPacketConnection(ctx, conn, metadata)
}

func (r *Router) mustResolve(detour adapter.Outbound, metadata *adapter.InboundContext) bool {
	if metadata.IsResolved {
		return false
	}
	if r.stopAlwaysResolveUDP {
		return false
	}
	if !metadata.Destination.IsFqdn() {
		return false
	}
	if len(metadata.DestinationAddresses) > 0 {
		return false
	}
	tag := O.RealOutboundTag(detour, N.NetworkUDP)
	outbound, _ := r.OutboundWithProvider(tag)
	switch outbound.Type() {
	case C.TypeBlock, C.TypeDNS:
		return false
	}
	return true
}

func (r *Router) match(ctx context.Context, metadata *adapter.InboundContext, defaultOutbound adapter.Outbound) (context.Context, adapter.Rule, adapter.Outbound, error) {
	matchRule, matchOutbound := r.match0(ctx, metadata, defaultOutbound)
	if contextOutbound, loaded := O.TagFromContext(ctx); loaded {
		if contextOutbound == matchOutbound.Tag() {
			return nil, nil, nil, E.New("connection loopback in outbound/", matchOutbound.Type(), "[", matchOutbound.Tag(), "]")
		}
	}
	ctx = O.ContextWithTag(ctx, matchOutbound.Tag())
	return ctx, matchRule, matchOutbound, nil
}

func (r *Router) match0(ctx context.Context, metadata *adapter.InboundContext, defaultOutbound adapter.Outbound) (adapter.Rule, adapter.Outbound) {
	if r.processSearcher != nil {
		var originDestination netip.AddrPort
		if metadata.OriginDestination.IsValid() {
			originDestination = metadata.OriginDestination.AddrPort()
		} else if metadata.Destination.IsIP() {
			originDestination = metadata.Destination.AddrPort()
		}
		processInfo, err := process.FindProcessInfo(r.processSearcher, ctx, metadata.Network, metadata.Source.AddrPort(), originDestination)
		if err != nil {
			r.logger.InfoContext(ctx, "failed to search process: ", err)
		} else {
			if processInfo.ProcessPath != "" {
				r.logger.InfoContext(ctx, "found process path: ", processInfo.ProcessPath)
			} else if processInfo.PackageName != "" {
				r.logger.InfoContext(ctx, "found package name: ", processInfo.PackageName)
			} else if processInfo.UserId != -1 {
				if /*needUserName &&*/ true {
					osUser, _ := user.LookupId(F.ToString(processInfo.UserId))
					if osUser != nil {
						processInfo.User = osUser.Username
					}
				}
				if processInfo.User != "" {
					r.logger.InfoContext(ctx, "found user: ", processInfo.User)
				} else {
					r.logger.InfoContext(ctx, "found user id: ", processInfo.UserId)
				}
			}
			metadata.ProcessInfo = processInfo
		}
	}
	resolveStatus := -1
	if metadata.Destination.IsFqdn() && len(metadata.DestinationAddresses) == 0 {
		resolveStatus = 0
	}
	var outbound adapter.Outbound
	defer func() {
		if resolveStatus == 1 && !r.mustUseIP(outbound, metadata) {
			metadata.DestinationAddresses = []netip.Addr{}
		}
	}()
	for i, rule := range r.rules {
		if rule.Disabled() {
			continue
		}
		metadata.ResetRuleCache()
		if !rule.SkipResolve() && resolveStatus == 0 && rule.ContainsDestinationIPCIDRRule() {
			addresses, err := r.lookupDefault(adapter.WithContext(ctx, metadata), metadata.Destination.Fqdn)
			resolveStatus = 2
			if err == nil {
				resolveStatus = 1
				metadata.IsResolved = true
				metadata.DestinationAddresses = addresses
			}
			metadata.ResetRuleCache()
		}
		if rule.Match(metadata) {
			detour := rule.Outbound()
			r.logger.DebugContext(ctx, "match[", i, "] ", rule.String(), " => ", detour)
			var loaded bool
			if outbound, loaded = r.Outbound(detour); loaded {
				return rule, outbound
			}
			r.logger.ErrorContext(ctx, "outbound not found: ", detour)
		}
	}
	outbound = defaultOutbound
	return nil, outbound
}

func (r *Router) mustUseIP(outbound adapter.Outbound, metadata *adapter.InboundContext) bool {
	network := metadata.Network
	tag := O.RealOutboundTag(outbound, network)
	detour, _ := r.OutboundWithProvider(tag)
	if d, ok := detour.(adapter.OutboundUseIP); ok {
		return d.UseIP()
	}
	if network == N.NetworkTCP {
		return false
	}
	if r.stopAlwaysResolveUDP {
		return false
	}
	switch detour.Type() {
	case C.TypeBlock, C.TypeDNS:
		return false
	}
	return true
}

func (r *Router) InterfaceFinder() control.InterfaceFinder {
	return r.interfaceFinder
}

func (r *Router) UpdateInterfaces() error {
	if r.platformInterface == nil || !r.platformInterface.UsePlatformInterfaceGetter() {
		return r.interfaceFinder.Update()
	} else {
		interfaces, err := r.platformInterface.Interfaces()
		if err != nil {
			return err
		}
		r.interfaceFinder.UpdateInterfaces(interfaces)
		return nil
	}
}

func (r *Router) AutoDetectInterface() bool {
	return r.autoDetectInterface
}

func (r *Router) AutoDetectInterfaceFunc() control.Func {
	if r.platformInterface != nil && r.platformInterface.UsePlatformAutoDetectInterfaceControl() {
		return r.platformInterface.AutoDetectInterfaceControl()
	} else {
		if r.interfaceMonitor == nil {
			return nil
		}
		return control.BindToInterfaceFunc(r.InterfaceFinder(), func(network string, address string) (interfaceName string, interfaceIndex int, err error) {
			remoteAddr := M.ParseSocksaddr(address).Addr
			if C.IsLinux {
				interfaceName, interfaceIndex = r.InterfaceMonitor().DefaultInterface(remoteAddr)
				if interfaceIndex == -1 {
					err = tun.ErrNoRoute
				}
			} else {
				interfaceIndex = r.InterfaceMonitor().DefaultInterfaceIndex(remoteAddr)
				if interfaceIndex == -1 {
					err = tun.ErrNoRoute
				}
			}
			return
		})
	}
}

func (r *Router) RegisterAutoRedirectOutputMark(mark uint32) error {
	if r.autoRedirectOutputMark > 0 {
		return E.New("only one auto-redirect can be configured")
	}
	r.autoRedirectOutputMark = mark
	return nil
}

func (r *Router) AutoRedirectOutputMark() uint32 {
	return r.autoRedirectOutputMark
}

func (r *Router) DefaultInterface() string {
	return r.defaultInterface
}

func (r *Router) DefaultMark() uint32 {
	return r.defaultMark
}

func (r *Router) Rules() []adapter.Rule {
	return r.rules
}

func (r *Router) Rule(uuid string) (adapter.Rule, bool) {
	rule, exists := r.routeRuleByUUID[uuid]
	return rule, exists
}

func (r *Router) DNSRules() []adapter.DNSRule {
	return r.dnsRules
}

func (r *Router) DNSRule(uuid string) (adapter.DNSRule, bool) {
	rule, exists := r.dnsRuleByUUID[uuid]
	return rule, exists
}

func (r *Router) DefaultDNSServer() string {
	return r.defaultTransport.Name()
}

func (r *Router) WIFIState() adapter.WIFIState {
	return r.wifiState
}

func (r *Router) NetworkMonitor() tun.NetworkUpdateMonitor {
	return r.networkMonitor
}

func (r *Router) InterfaceMonitor() tun.DefaultInterfaceMonitor {
	return r.interfaceMonitor
}

func (r *Router) PackageManager() tun.PackageManager {
	return r.packageManager
}

func (r *Router) ClashServer() adapter.ClashServer {
	return r.clashServer
}

func (r *Router) SetClashServer(server adapter.ClashServer) {
	r.clashServer = server
}

func (r *Router) V2RayServer() adapter.V2RayServer {
	return r.v2rayServer
}

func (r *Router) SetV2RayServer(server adapter.V2RayServer) {
	r.v2rayServer = server
}

func (r *Router) OnPackagesUpdated(packages int, sharedUsers int) {
	r.logger.Info("updated packages list: ", packages, " packages, ", sharedUsers, " shared users")
}

func (r *Router) NewError(ctx context.Context, err error) {
	common.Close(err)
	if E.IsClosedOrCanceled(err) {
		r.logger.DebugContext(ctx, "connection closed: ", err)
		return
	}
	r.logger.ErrorContext(ctx, err)
}

func (r *Router) notifyNetworkUpdate(event int) {
	if event == tun.EventNoRoute {
		r.pauseManager.NetworkPause()
		r.logger.Error("missing default interface")
	} else {
		r.pauseManager.NetworkWake()
		if C.IsAndroid && r.platformInterface == nil {
			var vpnStatus string
			if r.interfaceMonitor.AndroidVPNEnabled() {
				vpnStatus = "enabled"
			} else {
				vpnStatus = "disabled"
			}
			r.logger.Info("updated default interface ", r.interfaceMonitor.DefaultInterfaceName(netip.IPv4Unspecified()), ", index ", r.interfaceMonitor.DefaultInterfaceIndex(netip.IPv4Unspecified()), ", vpn ", vpnStatus)
		} else {
			r.logger.Info("updated default interface ", r.interfaceMonitor.DefaultInterfaceName(netip.IPv4Unspecified()), ", index ", r.interfaceMonitor.DefaultInterfaceIndex(netip.IPv4Unspecified()))
		}
	}

	if !r.started {
		return
	}

	_ = r.ResetNetwork()
}

func (r *Router) ResetNetwork() error {
	conntrack.Close()

	for _, provider := range r.outboundProviders {
		listener, isListener := provider.(adapter.InterfaceUpdateListener)
		if isListener {
			listener.InterfaceUpdated()
		}
	}

	for _, outbound := range r.outbounds {
		listener, isListener := outbound.(adapter.InterfaceUpdateListener)
		if isListener {
			listener.InterfaceUpdated()
		}
	}

	for _, transport := range r.transports {
		transport.Reset()
	}

	runtime.GC()
	return nil
}

func (r *Router) updateWIFIState() {
	if r.platformInterface == nil {
		return
	}
	state := r.platformInterface.ReadWIFIState()
	if state != r.wifiState {
		r.wifiState = state
		if state.SSID == "" && state.BSSID == "" {
			r.logger.Info("updated WIFI state: disconnected")
		} else {
			r.logger.Info("updated WIFI state: SSID=", state.SSID, ", BSSID=", state.BSSID)
		}
	}
}

func (r *Router) notifyWindowsPowerEvent(event int) {
	switch event {
	case winpowrprof.EVENT_SUSPEND:
		r.pauseManager.DevicePause()
		_ = r.ResetNetwork()
	case winpowrprof.EVENT_RESUME:
		if !r.pauseManager.IsDevicePaused() {
			return
		}
		fallthrough
	case winpowrprof.EVENT_RESUME_AUTOMATIC:
		r.pauseManager.DeviceWake()
		_ = r.ResetNetwork()
	}
}