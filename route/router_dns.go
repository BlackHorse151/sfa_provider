package route

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-dns"
	"github.com/sagernet/sing/common/cache"
	E "github.com/sagernet/sing/common/exceptions"
	F "github.com/sagernet/sing/common/format"
	M "github.com/sagernet/sing/common/metadata"

	mDNS "github.com/miekg/dns"
)

type DNSReverseMapping struct {
	cache *cache.LruCache[netip.Addr, string]
}

func NewDNSReverseMapping() *DNSReverseMapping {
	return &DNSReverseMapping{
		cache: cache.New[netip.Addr, string](),
	}
}

func (m *DNSReverseMapping) Save(address netip.Addr, domain string, ttl int) {
	m.cache.StoreWithExpire(address, domain, time.Now().Add(time.Duration(ttl)*time.Second))
}

func (m *DNSReverseMapping) Query(address netip.Addr) (string, bool) {
	domain, loaded := m.cache.Load(address)
	return domain, loaded
}

func (r *Router) matchDNS(ctx context.Context, allowFakeIP bool, index int, isAddressQuery bool) (context.Context, dns.Transport, dns.DomainStrategy, adapter.DNSRule, int, bool) {
	metadata := adapter.ContextFrom(ctx)
	if metadata == nil {
		panic("no context")
	}
	if index < len(r.dnsRules) {
		dnsRules := r.dnsRules
		if index != -1 {
			dnsRules = dnsRules[index+1:]
		}
		for currentRuleIndex, rule := range dnsRules {
			if rule.WithAddressLimit() && !isAddressQuery {
				continue
			}
			metadata.ResetRuleCache()
			if rule.Match(metadata) {
				detour := rule.Outbound()
				transport, loaded := r.transportMap[detour]
				if !loaded {
					r.dnsLogger.ErrorContext(ctx, "transport not found: ", detour)
					continue
				}
				fakeIPTransport, isFakeIP := transport.(adapter.FakeIPTransport)
				if isFakeIP && (!allowFakeIP || (fakeIPTransport.Store() != nil && fakeIPTransport.Store().ExcludeRule() != nil && fakeIPTransport.Store().ExcludeRule().Match(&adapter.InboundContext{Domain: metadata.Domain, FakeIPFilter: true}))) {
					continue
				}
				ruleIndex := currentRuleIndex
				if index != -1 {
					ruleIndex += index + 1
				}
				r.dnsLogger.DebugContext(ctx, "match[", ruleIndex, "] ", rule.String(), " => ", detour)
				if isFakeIP {
					ctx = dns.ContextWithDisableCache(ctx, true)
					ctx = dns.ContextWithRewriteTTL(ctx, 1)
				}
				if rule.DisableCache() {
					ctx = dns.ContextWithDisableCache(ctx, true)
				}
				if rewriteTTL := rule.RewriteTTL(); rewriteTTL != nil {
					ctx = dns.ContextWithRewriteTTL(ctx, *rewriteTTL)
				}
				if clientSubnet := rule.ClientSubnet(); clientSubnet != nil {
					ctx = dns.ContextWithClientSubnet(ctx, *clientSubnet)
				}
				if domainStrategy, dsLoaded := r.transportDomainStrategy[transport]; dsLoaded {
					return ctx, transport, domainStrategy, rule, ruleIndex, isFakeIP
				} else {
					return ctx, transport, r.defaultDomainStrategy, rule, ruleIndex, isFakeIP
				}
			}
		}
	}
	if domainStrategy, dsLoaded := r.transportDomainStrategy[r.defaultTransport]; dsLoaded {
		return ctx, r.defaultTransport, domainStrategy, nil, -1, false
	} else {
		return ctx, r.defaultTransport, r.defaultDomainStrategy, nil, -1, false
	}
}

func (r *Router) matchFallbackRules(ctx context.Context, domain string, addrs []netip.Addr, rules []adapter.FallbackRule, allowFakeIP bool) (context.Context, dns.Transport, dns.DomainStrategy, adapter.FallbackRule, bool) {
	metadata := &adapter.InboundContext{DestinationAddresses: addrs, DnsFallBack: true}
	for _, rule := range rules {
		metadata.ResetRuleCache()
		if rule.Match(metadata) {
			if rule.AcceptResult() {
				break
			}
			var (
				transport dns.Transport
				loaded    bool
				isFakeIP  bool
			)
			detour := rule.Outbound()
			if detour != "" {
				transport, loaded = r.transportMap[detour]
				if !loaded {
					r.dnsLogger.ErrorContext(ctx, "transport not found: ", detour)
					continue
				}
				var fakeIPTransport adapter.FakeIPTransport
				fakeIPTransport, isFakeIP = transport.(adapter.FakeIPTransport)
				if isFakeIP && (!allowFakeIP || (fakeIPTransport.Store() != nil && fakeIPTransport.Store().ExcludeRule() != nil && fakeIPTransport.Store().ExcludeRule().Match(&adapter.InboundContext{Domain: domain, FakeIPFilter: true}))) {
					continue
				}
			}
			r.dnsLogger.DebugContext(ctx, "match fallback_rule: ", rule.String())
			if isFakeIP {
				ctx = dns.ContextWithDisableCache(ctx, true)
				ctx = dns.ContextWithRewriteTTL(ctx, 1)
			}
			if rule.DisableCache() {
				ctx = dns.ContextWithDisableCache(ctx, true)
			}
			if rewriteTTL := rule.RewriteTTL(); rewriteTTL != nil {
				ctx = dns.ContextWithRewriteTTL(ctx, *rewriteTTL)
			}
			if clientSubnet := rule.ClientSubnet(); clientSubnet != nil {
				ctx = dns.ContextWithClientSubnet(ctx, *clientSubnet)
			}
			if detour == "" {
				return ctx, nil, dns.DomainStrategyAsIS, rule, false
			} else if domainStrategy, dsLoaded := r.transportDomainStrategy[transport]; dsLoaded {
				return ctx, transport, domainStrategy, rule, isFakeIP
			} else {
				return ctx, transport, r.defaultDomainStrategy, rule, isFakeIP
			}
		}
	}
	return ctx, nil, dns.DomainStrategyAsIS, nil, false
}

func createUpdateCacheContext(ctx context.Context) context.Context {
	result := log.ContextWithNewID(context.Background())
	return adapter.WithContext(result, adapter.ContextFrom(ctx))
}

func (r *Router) Exchange(ctx context.Context, message *mDNS.Msg) (*mDNS.Msg, error) {
	var rawFqdn string
	if len(message.Question) > 0 {
		rawFqdn = message.Question[0].Name
		r.dnsLogger.DebugContext(ctx, "exchange ", formatQuestion(message.Question[0].String()))
	}
	var (
		response *mDNS.Msg
		records  []mDNS.RR
		cached   bool
		isFakeIP bool
		err      error
	)
	if response, records = r.dnsClient.SearchCNAMEHosts(ctx, message); response != nil {
		return response, nil
	}
	defer func() {
		if err != nil || isFakeIP || r.dnsReverseMapping == nil || len(message.Question) == 0 || response == nil || len(response.Answer) == 0 {
			return
		}
		for _, answer := range response.Answer {
			domain := rawFqdn
			switch record := answer.(type) {
			case *mDNS.A:
				if domain == "" {
					domain = record.Hdr.Name
				}
				r.dnsReverseMapping.Save(M.AddrFromIP(record.A), fqdnToDomain(domain), int(record.Hdr.Ttl))
			case *mDNS.AAAA:
				if domain == "" {
					domain = record.Hdr.Name
				}
				r.dnsReverseMapping.Save(M.AddrFromIP(record.AAAA), fqdnToDomain(domain), int(record.Hdr.Ttl))
			}
		}
	}()
	if len(records) > 0 {
		defer func() {
			if err != nil || len(message.Question) == 0 {
				return
			}
			message.Question[0].Name = rawFqdn
			if response == nil {
				return
			}
			response.Answer = append(records, response.Answer...)
		}()
	}
	if response = r.dnsClient.SearchIPHosts(ctx, message, r.defaultDomainStrategy); response != nil {
		return response, nil
	}
	var needUpdate bool
	if response, cached, needUpdate = r.dnsClient.ExchangeCache(ctx, message); cached {
		if needUpdate {
			go r.exchangeFunc(createUpdateCacheContext(ctx), message, true)
		}
		return response, nil
	}
	response, isFakeIP, err = r.exchangeFunc(ctx, message, false)
	return response, err
}

func (r *Router) exchangeFunc(ctx context.Context, message *mDNS.Msg, isCacheUpdate bool) (*mDNS.Msg, bool, error) {
	if isCacheUpdate && len(message.Question) > 0 {
		r.dnsLogger.DebugContext(ctx, "update ", formatQuestion(message.Question[0].String()), " exchange cache")
	}
	var (
		response  *mDNS.Msg
		transport dns.Transport
		metadata  *adapter.InboundContext
		isFakeIP  bool
		err       error
	)
	ctx, metadata = adapter.ExtendContext(ctx)
	metadata.Destination = M.Socksaddr{}
	if len(message.Question) > 0 {
		metadata.QueryType = message.Question[0].Qtype
		switch metadata.QueryType {
		case mDNS.TypeA:
			metadata.IPVersion = 4
		case mDNS.TypeAAAA:
			metadata.IPVersion = 6
		}
		metadata.Domain = fqdnToDomain(message.Question[0].Name)
	}
	var (
		strategy  dns.DomainStrategy
		rule      adapter.DNSRule
		ruleIndex int
	)
	ruleIndex = -1
	for {
		var (
			dnsCtx       context.Context
			addressLimit bool
		)
		isAddressQuery := isAddressQuery(message)
		dnsCtx, transport, strategy, rule, ruleIndex, isFakeIP = r.matchDNS(ctx, true, ruleIndex, isAddressQuery)
		dnsCtx = adapter.OverrideContext(dnsCtx)
		if rule != nil && rule.WithAddressLimit() {
			addressLimit = true
			response, err = r.dnsClient.ExchangeWithResponseCheck(dnsCtx, transport, message, strategy, isCacheUpdate, func(response *mDNS.Msg) bool {
				addresses, addrErr := dns.MessageToAddresses(response)
				if addrErr != nil {
					return false
				}
				metadata.DestinationAddresses = addresses
				return rule.MatchAddressLimit(metadata)
			})
		} else {
			addressLimit = false
			response, err = r.dnsClient.Exchange(dnsCtx, transport, message, strategy, isCacheUpdate)
		}
		var rejected bool
		if err != nil {
			if errors.Is(err, dns.ErrResponseRejectedCached) {
				rejected = true
				r.dnsLogger.DebugContext(ctx, E.Cause(err, "response rejected for ", formatQuestion(message.Question[0].String())), " (cached)")
			} else if errors.Is(err, dns.ErrResponseRejected) {
				rejected = true
				r.dnsLogger.DebugContext(ctx, E.Cause(err, "response rejected for ", formatQuestion(message.Question[0].String())))
			} else if len(message.Question) > 0 {
				r.dnsLogger.ErrorContext(ctx, E.Cause(err, "exchange failed for ", formatQuestion(message.Question[0].String())))
			} else {
				r.dnsLogger.ErrorContext(ctx, E.Cause(err, "exchange failed for <empty query>"))
			}
		}
		if rule == nil || !isAddressQuery || isFakeIP {
			break
		}
		if _, isRcode := transport.(*dns.RCodeTransport); isRcode {
			break
		}
		if addressLimit && rejected {
			continue
		}
		if err != nil || response == nil {
			break
		}
		addrs, _ := dns.MessageToAddresses(response)
		if response.Rcode != mDNS.RcodeSuccess || len(addrs) == 0 {
			if rule.AllowFallthrough() {
				continue
			}
			break
		}
		fbRules := rule.FallbackRules()
		if len(fbRules) == 0 {
			break
		}
		var fallbackRule adapter.FallbackRule
		dnsCtx, transport, strategy, fallbackRule, isFakeIP = r.matchFallbackRules(ctx, metadata.Domain, addrs, fbRules, true)
		dnsCtx = adapter.OverrideContext(dnsCtx)
		if fallbackRule == nil {
			break
		}
		if transport == nil {
			continue
		}
		response, err = r.dnsClient.Exchange(dnsCtx, transport, message, strategy, isCacheUpdate)
		if isFakeIP {
			break
		}
		if _, isRcode := transport.(*dns.RCodeTransport); isRcode {
			break
		}
		if err == nil {
			break
		}
		if len(message.Question) > 0 {
			r.dnsLogger.ErrorContext(ctx, E.Cause(err, "exchange failed for ", formatQuestion(message.Question[0].String())))
		} else {
			r.dnsLogger.ErrorContext(ctx, E.Cause(err, "exchange failed for <empty query>"))
		}
		break
	}
	if err != nil {
		return nil, false, err
	}
	return response, isFakeIP, nil
}

func (r *Router) Lookup(ctx context.Context, domain string, strategy dns.DomainStrategy) ([]netip.Addr, error) {
	domain = r.dnsClient.GetExactDomainFromHosts(ctx, domain, false)
	if responseAddrs := r.dnsClient.GetAddrsFromHosts(ctx, domain, strategy, false); len(responseAddrs) > 0 {
		return responseAddrs, nil
	}
	return r.lookup(ctx, domain, strategy)
}

func (r *Router) LookupDefault(ctx context.Context, domain string) ([]netip.Addr, error) {
	return r.Lookup(ctx, domain, dns.DomainStrategyAsIS)
}

func (r *Router) lookup(ctx context.Context, domain string, strategy dns.DomainStrategy) ([]netip.Addr, error) {
	if responseAddrs, cached, needUpdate := r.dnsClient.LookupCache(ctx, domain, strategy); cached {
		if needUpdate {
			go r.lookupFunc(createUpdateCacheContext(ctx), domain, strategy, true)
		}
		return responseAddrs, nil
	}
	return r.lookupFunc(ctx, domain, strategy, false)
}

func (r *Router) lookupFunc(ctx context.Context, domain string, strategy dns.DomainStrategy, isCacheUpdate bool) ([]netip.Addr, error) {
	if !isCacheUpdate {
		r.dnsLogger.DebugContext(ctx, "lookup domain ", domain)
	} else {
		r.dnsLogger.DebugContext(ctx, "update domain ", domain, " lookup cache")
	}
	ctx, metadata := adapter.ExtendContext(ctx)
	metadata.Destination = M.Socksaddr{}
	metadata.Domain = domain
	var (
		transport         dns.Transport
		transportStrategy dns.DomainStrategy
		rule              adapter.DNSRule
		ruleIndex         int
		responseAddrs     []netip.Addr
		err               error
	)
	ruleIndex = -1
	for {
		var (
			dnsCtx       context.Context
			addressLimit bool
			lookupErr    error
		)
		dnsCtx, transport, transportStrategy, rule, ruleIndex, _ = r.matchDNS(ctx, false, ruleIndex, true)
		dnsCtx = adapter.OverrideContext(dnsCtx)
		if strategy == dns.DomainStrategyAsIS {
			strategy = transportStrategy
		}
		if rule != nil && rule.WithAddressLimit() {
			addressLimit = true
			responseAddrs, err = r.dnsClient.LookupWithResponseCheck(dnsCtx, transport, domain, strategy, isCacheUpdate, func(responseAddrs []netip.Addr) bool {
				metadata.DestinationAddresses = responseAddrs
				return rule.MatchAddressLimit(metadata)
			})
		} else {
			addressLimit = false
			responseAddrs, err = r.dnsClient.Lookup(dnsCtx, transport, domain, strategy, isCacheUpdate)
		}
		lookupErr = err
		var rejected bool
		if err != nil {
			if errors.Is(err, dns.ErrResponseRejectedCached) {
				rejected = true
				r.dnsLogger.DebugContext(ctx, "response rejected for ", domain, " (cached)")
			} else if errors.Is(err, dns.ErrResponseRejected) {
				rejected = true
				r.dnsLogger.DebugContext(ctx, "response rejected for ", domain)
			} else {
				r.dnsLogger.ErrorContext(ctx, E.Cause(err, "lookup failed for ", domain))
			}
		} else if len(responseAddrs) == 0 {
			r.dnsLogger.ErrorContext(ctx, "lookup failed for ", domain, ": empty result")
			err = dns.RCodeNameError
		} else {
			r.dnsLogger.InfoContext(ctx, "lookup succeed for ", domain, ": ", strings.Join(F.MapToString(responseAddrs), " "))
		}
		if rule == nil {
			break
		}
		if _, isRcode := transport.(*dns.RCodeTransport); isRcode {
			break
		}
		if addressLimit && rejected {
			continue
		}
		if lookupErr == nil && len(responseAddrs) == 0 && rule.AllowFallthrough() {
			continue
		}
		if err != nil {
			break
		}
		fbRules := rule.FallbackRules()
		if len(fbRules) == 0 {
			break
		}
		var fallbackRule adapter.FallbackRule
		dnsCtx, transport, strategy, fallbackRule, _ = r.matchFallbackRules(ctx, metadata.Domain, responseAddrs, fbRules, false)
		dnsCtx = adapter.OverrideContext(dnsCtx)
		if fallbackRule == nil {
			break
		}
		if transport == nil {
			continue
		}
		responseAddrs, err = r.dnsClient.Lookup(dnsCtx, transport, domain, strategy, isCacheUpdate)
		if err != nil {
			r.dnsLogger.ErrorContext(ctx, E.Cause(err, "lookup failed for ", domain))
		} else if len(responseAddrs) == 0 {
			r.dnsLogger.ErrorContext(ctx, "lookup failed for ", domain, ": empty result")
			err = dns.RCodeNameError
		} else {
			r.dnsLogger.InfoContext(ctx, "lookup succeed for ", domain, ": ", strings.Join(F.MapToString(responseAddrs), " "))
		}
		break
	}
	if err == nil {
		r.dnsLogger.InfoContext(ctx, "finally lookup succeed for ", domain, ": ", strings.Join(F.MapToString(responseAddrs), " "))
	}
	return responseAddrs, err
}

func (r *Router) lookupDefault(ctx context.Context, domain string) ([]netip.Addr, error) {
	return r.lookup(ctx, domain, dns.DomainStrategyAsIS)
}

func (r *Router) ClearDNSCache() {
	r.dnsClient.ClearCache()
	if r.platformInterface != nil {
		r.platformInterface.ClearDNSCache()
	}
}

func isAddressQuery(message *mDNS.Msg) bool {
	for _, question := range message.Question {
		if question.Qtype == mDNS.TypeA || question.Qtype == mDNS.TypeAAAA || question.Qtype == mDNS.TypeHTTPS {
			return true
		}
	}
	return false
}

func fqdnToDomain(fqdn string) string {
	if mDNS.IsFqdn(fqdn) {
		return fqdn[:len(fqdn)-1]
	}
	return fqdn
}

func formatQuestion(string string) string {
	if strings.HasPrefix(string, ";") {
		string = string[1:]
	}
	string = strings.ReplaceAll(string, "\t", " ")
	for strings.Contains(string, "  ") {
		string = strings.ReplaceAll(string, "  ", " ")
	}
	return string
}
