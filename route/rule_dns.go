package route

import (
	"net/netip"
	"strings"

	"github.com/gofrs/uuid/v5"
	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	F "github.com/sagernet/sing/common/format"
	"github.com/sagernet/sing/common/logger"
)

var _ adapter.ExcludeRule = (*ExcludeRule)(nil)

type ExcludeRule struct {
	items []RuleItem
}

func (r *ExcludeRule) Match(metadata *adapter.InboundContext) bool {
	return common.Any(r.items, func(item RuleItem) bool {
		return item.Match(metadata)
	})
}

func (r *ExcludeRule) String() string {
	return strings.Join(F.MapToString(r.items), " ")
}

func (r *ExcludeRule) Start() error {
	for _, item := range r.items {
		err := common.Start(item)
		if err != nil {
			return err
		}
	}
	return nil
}

func (r *ExcludeRule) Close() error {
	for _, item := range r.items {
		err := common.Close(item)
		if err != nil {
			return err
		}
	}
	return nil
}

func NewExcludeRule(router adapter.Router, logger logger.ContextLogger, excludeRuleOptions option.ExcludeRule) (adapter.ExcludeRule, error) {
	var items []RuleItem
	if len(excludeRuleOptions.Domain) > 0 || len(excludeRuleOptions.DomainSuffix) > 0 {
		item := NewDomainItem(excludeRuleOptions.Domain, excludeRuleOptions.DomainSuffix)
		items = append(items, item)
	}
	if len(excludeRuleOptions.DomainKeyword) > 0 {
		item := NewDomainKeywordItem(excludeRuleOptions.DomainKeyword)
		items = append(items, item)
	}
	if len(excludeRuleOptions.DomainRegex) > 0 {
		item, err := NewDomainRegexItem(excludeRuleOptions.DomainRegex)
		if err != nil {
			return nil, E.Cause(err, "domain_regex")
		}
		items = append(items, item)
	}
	if len(excludeRuleOptions.Geosite) > 0 {
		item := NewGeositeItem(router, logger, excludeRuleOptions.Geosite)
		items = append(items, item)
	}
	if len(excludeRuleOptions.RuleSet) > 0 {
		item := NewRuleSetItem(router, excludeRuleOptions.RuleSet, false, false)
		items = append(items, item)
	}
	if len(items) == 0 {
		return nil, nil
	}
	return &ExcludeRule{items}, nil
}

var _ adapter.FallbackRule = (*FallbackRule)(nil)

type FallbackRule struct {
	acceptResult            bool
	matchAll                bool
	items                   []RuleItem
	destinationAddressItems []RuleItem
	allItems                []RuleItem
	invert                  bool
	server                  string
	disableCache            bool
	rewriteTTL              *uint32
	clientSubnet            *netip.Prefix
}

func (r *FallbackRule) String() string {
	result := func() string {
		if r.matchAll {
			return "match_all"
		}
		result := strings.Join(F.MapToString(r.allItems), " ")
		if r.invert {
			return "!(" + result + ")"
		}
		if len(r.allItems) > 1 {
			return "[" + result + "]"
		}
		return result
	}()
	if r.server != "" {
		result = result + "=>" + r.server
	}
	return result
}

func (r *FallbackRule) Start() error {
	for _, item := range r.allItems {
		err := common.Start(item)
		if err != nil {
			return err
		}
	}
	return nil
}

func (r *FallbackRule) Match(metadata *adapter.InboundContext) bool {
	if r.matchAll {
		return true
	}
	for _, item := range r.items {
		if !item.Match(metadata) {
			return r.invert
		}
	}
	for _, item := range r.destinationAddressItems {
		if item.Match(metadata) {
			return !r.invert
		}
	}
	return r.invert
}

func (r *FallbackRule) AcceptResult() bool {
	return r.acceptResult
}

func (r *FallbackRule) Outbound() string {
	return r.server
}

func (r *FallbackRule) DisableCache() bool {
	return r.disableCache
}

func (r *FallbackRule) RewriteTTL() *uint32 {
	return r.rewriteTTL
}

func (r *FallbackRule) ClientSubnet() *netip.Prefix {
	return r.clientSubnet
}

func NewFallbackRules(router adapter.Router, logger log.ContextLogger, fbOptions []option.FallBackRule) ([]adapter.FallbackRule, error) {
	var fallbackRules []adapter.FallbackRule
	for i, options := range fbOptions {
		if !options.IsValid() {
			return nil, E.New("fallback_rule[", i, "] missing conditions")
		}
		var items, destinationAddressItems, allItems []RuleItem
		if len(options.ClashMode) > 0 {
			item := NewClashModeItem(router, options.ClashMode)
			items = append(items, item)
			allItems = append(allItems, item)
		}
		if len(options.IPCIDR) > 0 {
			item, err := NewIPCIDRItem(false, options.IPCIDR)
			if err != nil {
				return nil, E.Cause(err, "ipcidr")
			}
			destinationAddressItems = append(destinationAddressItems, item)
			allItems = append(allItems, item)
		}
		if options.IPIsPrivate {
			item := NewIPIsPrivateItem(false)
			destinationAddressItems = append(destinationAddressItems, item)
			allItems = append(allItems, item)
		}
		if len(options.GeoIP) > 0 {
			item := NewGeoIPItem(router, logger, false, options.GeoIP)
			destinationAddressItems = append(destinationAddressItems, item)
			allItems = append(allItems, item)
		}
		if len(options.RuleSet) > 0 {
			item := NewRuleSetItem(router, options.RuleSet, false, false)
			destinationAddressItems = append(destinationAddressItems, item)
			allItems = append(allItems, item)
		}
		fallbackRules = append(fallbackRules, &FallbackRule{
			options.AcceptResult,
			options.MatchAll,
			items,
			destinationAddressItems,
			allItems,
			options.Invert,
			options.Server,
			options.DisableCache,
			options.RewriteTTL,
			(*netip.Prefix)(options.ClientSubnet),
		})
	}
	return fallbackRules, nil
}

type abstractDNSRule struct {
	fallbackRules    []adapter.FallbackRule
	allowFallthrough bool
	disableCache     bool
	rewriteTTL       *uint32
	clientSubnet     *netip.Prefix
}

func (r *abstractDNSRule) AllowFallthrough() bool {
	return r.allowFallthrough
}

func (r *abstractDNSRule) DisableCache() bool {
	return r.disableCache
}

func (r *abstractDNSRule) RewriteTTL() *uint32 {
	return r.rewriteTTL
}

func (r *abstractDNSRule) ClientSubnet() *netip.Prefix {
	return r.clientSubnet
}

func (r *abstractDNSRule) FallbackRules() []adapter.FallbackRule {
	return r.fallbackRules
}

func (r *abstractDNSRule) FallbackString() string {
	if len(r.fallbackRules) == 0 {
		return ""
	}
	if len(r.fallbackRules) == 1 {
		return " fallback_rule=" + r.fallbackRules[0].String()
	}
	result := strings.Join(common.Map(r.fallbackRules, func(it adapter.FallbackRule) string {
		return it.String()
	}), " ")
	return " fallback_rules=[" + result + "]"
}

func (r *abstractDNSRule) Start() error {
	if len(r.fallbackRules) > 0 {
		for _, rule := range r.fallbackRules {
			err := rule.Start()
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func NewDNSRule(router adapter.Router, logger log.ContextLogger, options option.DNSRule, checkServer bool) (adapter.DNSRule, error) {
	fallbackRules, err := NewFallbackRules(router, logger, options.FallBackRules)
	if err != nil {
		return nil, err
	}
	switch options.Type {
	case "", C.RuleTypeDefault:
		if len(options.FallBackRules) == 0 && !options.DefaultOptions.IsValid() {
			return nil, E.New("missing conditions")
		}
		if options.DefaultOptions.Server == "" && checkServer {
			return nil, E.New("missing server field")
		}
		return NewDefaultDNSRule(router, logger, options.DefaultOptions, fallbackRules)
	case C.RuleTypeLogical:
		if !options.LogicalOptions.IsValid() {
			return nil, E.New("missing conditions")
		}
		if options.LogicalOptions.Server == "" && checkServer {
			return nil, E.New("missing server field")
		}
		return NewLogicalDNSRule(router, logger, options.LogicalOptions, fallbackRules)
	default:
		return nil, E.New("unknown rule type: ", options.Type)
	}
}

var _ adapter.DNSRule = (*DefaultDNSRule)(nil)

type DefaultDNSRule struct {
	abstractDefaultRule
	abstractDNSRule
}

func NewDefaultDNSRule(router adapter.Router, logger log.ContextLogger, options option.DefaultDNSRule, fallbackRules []adapter.FallbackRule) (*DefaultDNSRule, error) {
	id, _ := uuid.NewV4()
	rule := &DefaultDNSRule{
		abstractDefaultRule: abstractDefaultRule{
			abstractRule: abstractRule{
				uuid:     id.String(),
				tag:      options.Tag,
				invert:   options.Invert,
				outbound: options.Server,
			},
		},
		abstractDNSRule: abstractDNSRule{
			fallbackRules,
			options.AllowFallthrough,
			options.DisableCache,
			options.RewriteTTL,
			(*netip.Prefix)(options.ClientSubnet),
		},
	}
	if len(options.Inbound) > 0 {
		item := NewInboundRule(options.Inbound)
		rule.items = append(rule.items, item)
		rule.allItems = append(rule.allItems, item)
	}
	if options.IPVersion > 0 {
		switch options.IPVersion {
		case 4, 6:
			item := NewIPVersionItem(options.IPVersion == 6)
			rule.items = append(rule.items, item)
			rule.allItems = append(rule.allItems, item)
		default:
			return nil, E.New("invalid ip version: ", options.IPVersion)
		}
	}
	if len(options.QueryType) > 0 {
		item := NewQueryTypeItem(options.QueryType)
		rule.items = append(rule.items, item)
		rule.allItems = append(rule.allItems, item)
	}
	if len(options.Network) > 0 {
		item := NewNetworkItem(options.Network)
		rule.items = append(rule.items, item)
		rule.allItems = append(rule.allItems, item)
	}
	if len(options.AuthUser) > 0 {
		item := NewAuthUserItem(options.AuthUser)
		rule.items = append(rule.items, item)
		rule.allItems = append(rule.allItems, item)
	}
	if len(options.Protocol) > 0 {
		item := NewProtocolItem(options.Protocol)
		rule.items = append(rule.items, item)
		rule.allItems = append(rule.allItems, item)
	}
	if len(options.Domain) > 0 || len(options.DomainSuffix) > 0 {
		item := NewDomainItem(options.Domain, options.DomainSuffix)
		rule.destinationAddressItems = append(rule.destinationAddressItems, item)
		rule.allItems = append(rule.allItems, item)
	}
	if len(options.DomainKeyword) > 0 {
		item := NewDomainKeywordItem(options.DomainKeyword)
		rule.destinationAddressItems = append(rule.destinationAddressItems, item)
		rule.allItems = append(rule.allItems, item)
	}
	if len(options.DomainRegex) > 0 {
		item, err := NewDomainRegexItem(options.DomainRegex)
		if err != nil {
			return nil, E.Cause(err, "domain_regex")
		}
		rule.destinationAddressItems = append(rule.destinationAddressItems, item)
		rule.allItems = append(rule.allItems, item)
	}
	if len(options.Geosite) > 0 {
		item := NewGeositeItem(router, logger, options.Geosite)
		rule.destinationAddressItems = append(rule.destinationAddressItems, item)
		rule.allItems = append(rule.allItems, item)
	}
	if len(options.SourceGeoIP) > 0 {
		item := NewGeoIPItem(router, logger, true, options.SourceGeoIP)
		rule.sourceAddressItems = append(rule.sourceAddressItems, item)
		rule.allItems = append(rule.allItems, item)
	}
	if len(options.GeoIP) > 0 {
		item := NewGeoIPItem(router, logger, false, options.GeoIP)
		rule.destinationIPCIDRItems = append(rule.destinationIPCIDRItems, item)
		rule.allItems = append(rule.allItems, item)
	}
	if len(options.SourceIPCIDR) > 0 {
		item, err := NewIPCIDRItem(true, options.SourceIPCIDR)
		if err != nil {
			return nil, E.Cause(err, "source_ip_cidr")
		}
		rule.sourceAddressItems = append(rule.sourceAddressItems, item)
		rule.allItems = append(rule.allItems, item)
	}
	if len(options.IPCIDR) > 0 {
		item, err := NewIPCIDRItem(false, options.IPCIDR)
		if err != nil {
			return nil, E.Cause(err, "ip_cidr")
		}
		rule.destinationIPCIDRItems = append(rule.destinationIPCIDRItems, item)
		rule.allItems = append(rule.allItems, item)
	}
	if options.SourceIPIsPrivate {
		item := NewIPIsPrivateItem(true)
		rule.sourceAddressItems = append(rule.sourceAddressItems, item)
		rule.allItems = append(rule.allItems, item)
	}
	if options.IPIsPrivate {
		item := NewIPIsPrivateItem(false)
		rule.destinationIPCIDRItems = append(rule.destinationIPCIDRItems, item)
		rule.allItems = append(rule.allItems, item)
	}
	if len(options.SourcePort) > 0 {
		item := NewPortItem(true, options.SourcePort)
		rule.sourcePortItems = append(rule.sourcePortItems, item)
		rule.allItems = append(rule.allItems, item)
	}
	if len(options.SourcePortRange) > 0 {
		item, err := NewPortRangeItem(true, options.SourcePortRange)
		if err != nil {
			return nil, E.Cause(err, "source_port_range")
		}
		rule.sourcePortItems = append(rule.sourcePortItems, item)
		rule.allItems = append(rule.allItems, item)
	}
	if len(options.Port) > 0 {
		item := NewPortItem(false, options.Port)
		rule.destinationPortItems = append(rule.destinationPortItems, item)
		rule.allItems = append(rule.allItems, item)
	}
	if len(options.PortRange) > 0 {
		item, err := NewPortRangeItem(false, options.PortRange)
		if err != nil {
			return nil, E.Cause(err, "port_range")
		}
		rule.destinationPortItems = append(rule.destinationPortItems, item)
		rule.allItems = append(rule.allItems, item)
	}
	if len(options.ProcessName) > 0 {
		item := NewProcessItem(options.ProcessName)
		rule.items = append(rule.items, item)
		rule.allItems = append(rule.allItems, item)
	}
	if len(options.ProcessPath) > 0 {
		item := NewProcessPathItem(options.ProcessPath)
		rule.items = append(rule.items, item)
		rule.allItems = append(rule.allItems, item)
	}
	if len(options.PackageName) > 0 {
		item := NewPackageNameItem(options.PackageName)
		rule.items = append(rule.items, item)
		rule.allItems = append(rule.allItems, item)
	}
	if len(options.User) > 0 {
		item := NewUserItem(options.User)
		rule.items = append(rule.items, item)
		rule.allItems = append(rule.allItems, item)
	}
	if len(options.UserID) > 0 {
		item := NewUserIDItem(options.UserID)
		rule.items = append(rule.items, item)
		rule.allItems = append(rule.allItems, item)
	}
	if len(options.Outbound) > 0 {
		item := NewOutboundRule(options.Outbound)
		rule.items = append(rule.items, item)
		rule.allItems = append(rule.allItems, item)
	}
	if len(options.ClashMode) > 0 {
		item := NewClashModeItem(router, options.ClashMode)
		rule.items = append(rule.items, item)
		rule.allItems = append(rule.allItems, item)
	}
	if len(options.WIFISSID) > 0 {
		item := NewWIFISSIDItem(router, options.WIFISSID)
		rule.items = append(rule.items, item)
		rule.allItems = append(rule.allItems, item)
	}
	if len(options.WIFIBSSID) > 0 {
		item := NewWIFIBSSIDItem(router, options.WIFIBSSID)
		rule.items = append(rule.items, item)
		rule.allItems = append(rule.allItems, item)
	}
	if len(options.RuleSet) > 0 {
		item := NewRuleSetItem(router, options.RuleSet, options.RuleSetIPCIDRMatchSource, options.RuleSetIPCIDRAcceptEmpty)
		rule.items = append(rule.items, item)
		rule.ruleSetItems = append(rule.ruleSetItems, item)
		rule.allItems = append(rule.allItems, item)
	}
	return rule, nil
}

func (r *DefaultDNSRule) String() string {
	return r.abstractDefaultRule.String() + r.abstractDNSRule.FallbackString()
}

func (r *DefaultDNSRule) Start() error {
	if err := r.abstractDefaultRule.Start(); err != nil {
		return err
	}
	if len(r.fallbackRules) == 0 {
		return nil
	}
	for _, rule := range r.fallbackRules {
		if err := rule.Start(); err != nil {
			return err
		}
	}
	return nil
}

func (r *DefaultDNSRule) WithAddressLimit() bool {
	if len(r.destinationIPCIDRItems) > 0 {
		return true
	}
	for _, rawRule := range r.items {
		ruleSet, isRuleSet := rawRule.(*RuleSetItem)
		if !isRuleSet {
			continue
		}
		if ruleSet.ContainsDestinationIPCIDRRule() {
			return true
		}
	}
	return false
}

func (r *DefaultDNSRule) Match(metadata *adapter.InboundContext) bool {
	metadata.IgnoreDestinationIPCIDRMatch = true
	defer func() {
		metadata.IgnoreDestinationIPCIDRMatch = false
	}()
	return r.abstractDefaultRule.Match(metadata)
}

func (r *DefaultDNSRule) MatchAddressLimit(metadata *adapter.InboundContext) bool {
	return r.abstractDefaultRule.Match(metadata)
}

var _ adapter.DNSRule = (*LogicalDNSRule)(nil)

type LogicalDNSRule struct {
	abstractLogicalRule
	abstractDNSRule
}

func NewLogicalDNSRule(router adapter.Router, logger log.ContextLogger, options option.LogicalDNSRule, fallbackRules []adapter.FallbackRule) (*LogicalDNSRule, error) {
	id, _ := uuid.NewV4()
	r := &LogicalDNSRule{
		abstractLogicalRule: abstractLogicalRule{
			abstractRule: abstractRule{
				uuid:     id.String(),
				tag:      options.Tag,
				invert:   options.Invert,
				outbound: options.Server,
			},
			rules: make([]adapter.HeadlessRule, len(options.Rules)),
		},
		abstractDNSRule: abstractDNSRule{
			fallbackRules,
			options.AllowFallthrough,
			options.DisableCache,
			options.RewriteTTL,
			(*netip.Prefix)(options.ClientSubnet),
		},
	}
	switch options.Mode {
	case C.LogicalTypeAnd:
		r.mode = C.LogicalTypeAnd
	case C.LogicalTypeOr:
		r.mode = C.LogicalTypeOr
	default:
		return nil, E.New("unknown logical mode: ", options.Mode)
	}
	for i, subRule := range options.Rules {
		rule, err := NewDNSRule(router, logger, subRule, false)
		if err != nil {
			return nil, E.Cause(err, "sub rule[", i, "]")
		}
		r.rules[i] = rule
	}
	return r, nil
}

func (r *LogicalDNSRule) String() string {
	return r.abstractLogicalRule.String() + r.abstractDNSRule.FallbackString()
}

func (r *LogicalDNSRule) Start() error {
	if err := r.abstractLogicalRule.Start(); err != nil {
		return err
	}
	if len(r.fallbackRules) == 0 {
		return nil
	}
	for _, rule := range r.fallbackRules {
		if err := rule.Start(); err != nil {
			return err
		}
	}
	return nil
}

func (r *LogicalDNSRule) WithAddressLimit() bool {
	for _, rawRule := range r.rules {
		switch rule := rawRule.(type) {
		case *DefaultDNSRule:
			if rule.WithAddressLimit() {
				return true
			}
		case *LogicalDNSRule:
			if rule.WithAddressLimit() {
				return true
			}
		}
	}
	return false
}

func (r *LogicalDNSRule) Match(metadata *adapter.InboundContext) bool {
	if r.mode == C.LogicalTypeAnd {
		return common.All(r.rules, func(it adapter.HeadlessRule) bool {
			metadata.ResetRuleCache()
			return it.(adapter.DNSRule).Match(metadata)
		}) != r.invert
	} else {
		return common.Any(r.rules, func(it adapter.HeadlessRule) bool {
			metadata.ResetRuleCache()
			return it.(adapter.DNSRule).Match(metadata)
		}) != r.invert
	}
}

func (r *LogicalDNSRule) MatchAddressLimit(metadata *adapter.InboundContext) bool {
	if r.mode == C.LogicalTypeAnd {
		return common.All(r.rules, func(it adapter.HeadlessRule) bool {
			metadata.ResetRuleCache()
			return it.(adapter.DNSRule).MatchAddressLimit(metadata)
		}) != r.invert
	} else {
		return common.Any(r.rules, func(it adapter.HeadlessRule) bool {
			metadata.ResetRuleCache()
			return it.(adapter.DNSRule).MatchAddressLimit(metadata)
		}) != r.invert
	}
}
