package route

import (
	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
)

var _ RuleItem = (*FakeIPItem)(nil)

type FakeIPItem struct{}

func NewFakeIPItem() *FakeIPItem {
	return &FakeIPItem{}
}

func (r *FakeIPItem) Match(metadata *adapter.InboundContext) bool {
	return metadata.DNSMode == C.DNSModeFakeIP
}

func (r *FakeIPItem) String() string {
	return "fake_ip=true"
}
