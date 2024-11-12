package constant

import "time"

var TCPKeepAliveInterval = 75 * time.Second

const (
	TCPKeepAliveInitial        = 10 * time.Minute
	TCPConnectTimeout          = 5 * time.Second
	TCPTimeout                 = 15 * time.Second
	ReadPayloadTimeout         = 300 * time.Millisecond
	DNSTimeout                 = 10 * time.Second
	QUICTimeout                = 30 * time.Second
	STUNTimeout                = 15 * time.Second
	UDPTimeout                 = 5 * time.Minute
	DefaultDonloadInterval     = 1 * time.Hour
	DefaultURLTestInterval     = 3 * time.Minute
	DefaultURLTestIdleTimeout  = 30 * time.Minute
	StartTimeout               = 10 * time.Second
	StopTimeout                = 5 * time.Second
	FatalStopTimeout           = 10 * time.Second
	FakeIPMetadataSaveInterval = 10 * time.Second
)