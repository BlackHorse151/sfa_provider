package option

import "net/netip"

type DNSOptions struct {
	Servers         []DNSServerOptions          `json:"servers,omitempty"`
	Rules           []DNSRule                   `json:"rules,omitempty"`
	Final           string                      `json:"final,omitempty"`
	ReverseMapping  bool                        `json:"reverse_mapping,omitempty"`
	MappingOverride bool                        `json:"mapping_override,omitempty"`
	Hosts           map[string]Listable[string] `json:"hosts,omitempty"`
	FakeIP          *DNSFakeIPOptions           `json:"fakeip,omitempty"`
	DNSClientOptions
}

type DNSServerOptions struct {
	Tag                  string           `json:"tag,omitempty"`
	Address              Listable[string] `json:"address"`
	AddressResolver      string           `json:"address_resolver,omitempty"`
	AddressStrategy      DomainStrategy   `json:"address_strategy,omitempty"`
	AddressFallbackDelay Duration         `json:"address_fallback_delay,omitempty"`
	Strategy             DomainStrategy   `json:"strategy,omitempty"`
	Detour               string           `json:"detour,omitempty"`
	ClientSubnet         *AddrPrefix      `json:"client_subnet,omitempty"`
	Insecure             bool             `json:"insecure,omitempty"`
}

type DNSClientOptions struct {
	Strategy         DomainStrategy `json:"strategy,omitempty"`
	DisableCache     bool           `json:"disable_cache,omitempty"`
	DisableExpire    bool           `json:"disable_expire,omitempty"`
	IndependentCache bool           `json:"independent_cache,omitempty"`
	LazyCache        bool           `json:"lazy_cache,omitempty"`
	ClientSubnet     *AddrPrefix    `json:"client_subnet,omitempty"`
}

type ExcludeRule struct {
	Domain        Listable[string] `json:"domain,omitempty"`
	DomainSuffix  Listable[string] `json:"domain_suffix,omitempty"`
	DomainKeyword Listable[string] `json:"domain_keyword,omitempty"`
	DomainRegex   Listable[string] `json:"domain_regex,omitempty"`
	Geosite       Listable[string] `json:"geosite,omitempty"`
	RuleSet       Listable[string] `json:"rule_set,omitempty"`
}

type DNSFakeIPOptions struct {
	Enabled     bool          `json:"enabled,omitempty"`
	Inet4Range  *netip.Prefix `json:"inet4_range,omitempty"`
	Inet6Range  *netip.Prefix `json:"inet6_range,omitempty"`
	ExcludeRule ExcludeRule   `json:"exclude_rule,omitempty"`
}

type DoHInboundOptions struct {
	Network     NetworkList    `json:"network,omitempty"`
	Listen      *ListenAddress `json:"listen,omitempty"`
	ListenPort  uint16         `json:"listen_port,omitempty"`
	QueryPath   string         `json:"query_path,omitempty"`
	UDPFragment *bool          `json:"udp_fragment,omitempty"`
	InboundTLSOptionsContainer
}

type DoQInboundOptions struct {
	Listen           *ListenAddress `json:"listen,omitempty"`
	ListenPort       uint16         `json:"listen_port,omitempty"`
	ZeroRTTHandshake bool           `json:"zero_rtt_handshake,omitempty"`
	UDPFragment      *bool          `json:"udp_fragment,omitempty"`
	InboundTLSOptionsContainer
}
