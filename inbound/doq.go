package inbound

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"runtime"

	mDNS "github.com/miekg/dns"
	"github.com/sagernet/quic-go"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/tls"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	qtls "github.com/sagernet/sing-quic"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/control"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

var _ adapter.Inbound = (*DnsOverQUIC)(nil)

type DnsOverQUIC struct {
	protocol         string
	ctx              context.Context
	router           adapter.Router
	logger           log.ContextLogger
	tag              string
	listen           M.Socksaddr
	udpFragment      *bool
	zeroRTTHandshake bool
	tlsConfig        tls.ServerConfig
	quicConfig       *quic.Config
	listener         io.Closer
}

func NewDoQ(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.DoQInboundOptions) (*DnsOverQUIC, error) {
	if options.TLS == nil {
		return nil, E.New("doq inbound must over tls server")
	}
	if len(options.TLS.ALPN) == 0 {
		options.TLS.ALPN = []string{"doq", "doq-i11"}
	}
	tlsConfig, err := tls.NewServer(ctx, logger, common.PtrValueOrDefault(options.TLS))
	if err != nil {
		return nil, err
	}
	if options.ListenPort == 0 {
		options.ListenPort = 443
	}
	quicConfig := &quic.Config{
		DisablePathMTUDiscovery: !(runtime.GOOS == "windows" || runtime.GOOS == "linux" || runtime.GOOS == "android" || runtime.GOOS == "darwin"),
		EnableDatagrams:         true,
		Allow0RTT:               options.ZeroRTTHandshake,
		MaxIncomingStreams:      1 << 60,
		MaxIncomingUniStreams:   1 << 60,
	}
	listen := M.SocksaddrFrom(options.Listen.Build(), options.ListenPort)
	return &DnsOverQUIC{
		protocol:         C.TypeDoQ,
		ctx:              ctx,
		router:           router,
		logger:           logger,
		tag:              tag,
		listen:           listen,
		udpFragment:      options.UDPFragment,
		zeroRTTHandshake: options.ZeroRTTHandshake,
		tlsConfig:        tlsConfig,
		quicConfig:       quicConfig,
	}, nil
}

func (d *DnsOverQUIC) Tag() string {
	return d.tag
}

func (d *DnsOverQUIC) Type() string {
	return d.protocol
}

func (d *DnsOverQUIC) Start() error {
	err := d.tlsConfig.Start()
	if err != nil {
		return E.Cause(err, "create TLS config")
	}
	conn, err := d.listenUDP()
	if err != nil {
		return E.Cause(err, "create UDP listener")
	}
	d.logger.InfoContext(d.ctx, "DNS-Over-QUIC server listening at ", d.listen.String())
	if !d.quicConfig.Allow0RTT {
		listener, err := qtls.Listen(conn, d.tlsConfig, d.quicConfig)
		if err != nil {
			return E.Cause(err, "create QUIC listener")
		}
		d.listener = listener
		go func() {
			for {
				connection, hErr := listener.Accept(d.ctx)
				if hErr != nil {
					if E.IsClosedOrCanceled(hErr) || errors.Is(hErr, quic.ErrServerClosed) {
						d.logger.DebugContext(d.ctx, E.Cause(hErr, "QUIC listener closed"))
					} else {
						d.logger.ErrorContext(d.ctx, E.Cause(hErr, "QUIC listener closed"))
					}
					return
				}
				go d.handleConnection(connection)
			}
		}()
	} else {
		listener, err := qtls.ListenEarly(conn, d.tlsConfig, d.quicConfig)
		if err != nil {
			return E.Cause(err, "create early QUIC listener")
		}
		d.listener = listener
		go func() {
			for {
				var connection quic.Connection
				connection, hErr := listener.Accept(d.ctx)
				if hErr != nil {
					if E.IsClosedOrCanceled(hErr) || errors.Is(hErr, quic.ErrServerClosed) {
						d.logger.DebugContext(d.ctx, E.Cause(hErr, "early QUIC listener closed"))
					} else {
						d.logger.ErrorContext(d.ctx, E.Cause(hErr, "early QUIC listener closed"))
					}
					return
				}
				go d.handleConnection(connection)
			}
		}()
	}
	return nil
}

func (d *DnsOverQUIC) Close() error {
	return common.Close(
		d.tlsConfig,
		d.listener,
	)
}

func (d *DnsOverQUIC) listenUDP() (net.PacketConn, error) {
	var lc net.ListenConfig
	var udpFragment bool
	if d.udpFragment != nil {
		udpFragment = *d.udpFragment
	} else {
		udpFragment = true
	}
	if !udpFragment {
		lc.Control = control.Append(lc.Control, control.DisableUDPFragment())
	}
	udpConn, err := lc.ListenPacket(d.ctx, M.NetworkFromNetAddr(N.NetworkUDP, d.listen.Addr), d.listen.String())
	if err != nil {
		return nil, err
	}
	return udpConn, err
}

func (d *DnsOverQUIC) handleConnection(conn quic.Connection) {
	for {
		stream, err := conn.AcceptStream(d.ctx)
		if err != nil {
			if neterr, ok := err.(net.Error); ok && neterr.Timeout() {
				continue
			}
			break
		}
		ctx := log.ContextWithNewID(d.ctx)
		ctx, metadata := adapter.AppendContext(ctx)
		metadata.Inbound = d.tag
		metadata.InboundType = C.TypeDoQ
		metadata.Source = M.SocksaddrFromNet(conn.RemoteAddr())
		go handleStream(ctx, d.router, d.logger, stream)
	}
}

func handleStream(ctx context.Context, router adapter.Router, logger log.ContextLogger, stream quic.Stream) {
	defer stream.Close()
	var length uint16
	if err := binary.Read(stream, binary.BigEndian, &length); err != nil {
		logger.DebugContext(ctx, E.Cause(err, "parse stream length"))
		return
	}
	rawQuery := make([]byte, length)
	if _, err := io.ReadFull(stream, rawQuery); err != nil {
		logger.DebugContext(ctx, E.Cause(err, "read stream"))
		return
	}
	if len(rawQuery) < 12 {
		return
	}
	var message mDNS.Msg
	if err := message.Unpack(rawQuery); err != nil {
		logger.DebugContext(ctx, E.Cause(err, "unpack query message"))
		return
	}
	if message.Id != 0 {
		logger.DebugContext(ctx, E.New("invalid message id"))
		stream.CancelRead(0x3)
		stream.CancelWrite(0x3)
		return
	}
	response, err := router.Exchange(ctx, &message)
	if err != nil {
		logger.DebugContext(ctx, E.Cause(err, "exchange query"))
		return
	}
	responseBuffer := buf.NewPacket()
	defer responseBuffer.Release()
	responseBuffer.Resize(2, 0)
	n, err := response.PackBuffer(responseBuffer.FreeBytes())
	if err != nil {
		logger.DebugContext(ctx, E.Cause(err, "pack response"))
		return
	}
	responseBuffer.Truncate(len(n))
	binary.BigEndian.PutUint16(responseBuffer.ExtendHeader(2), uint16(len(n)))
	_, err = stream.Write(responseBuffer.Bytes())
	if err != nil {
		logger.DebugContext(ctx, E.Cause(err, "write strem"))
		return
	}
}
