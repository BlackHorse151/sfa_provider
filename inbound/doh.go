package inbound

import (
	"context"
	"encoding/base64"
	"errors"
	"io"
	"math"
	"net"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/render"
	mDNS "github.com/miekg/dns"
	"github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/http3"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/tls"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/experimental/clashapi"
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

var _ adapter.Inbound = (*DnsOverHTTP)(nil)

type DnsOverHTTP struct {
	protocol    string
	ctx         context.Context
	network     []string
	logger      log.ContextLogger
	tag         string
	listen      M.Socksaddr
	udpFragment *bool
	httpServer  *http.Server
	http3Server *http3.Server
	tlsConfig   tls.ServerConfig
}

func NewDoH(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.DoHInboundOptions) (*DnsOverHTTP, error) {
	networks := options.Network.Build()
	overTLS := options.TLS != nil && options.TLS.Enabled
	if len(networks) == 1 && networks[0] == N.NetworkUDP && !overTLS {
		return nil, E.New("doh inbound with udp only must over tls server")
	}
	if options.ListenPort == 0 {
		options.ListenPort = 80
		if overTLS {
			options.ListenPort = 443
		}
	}
	listen := M.SocksaddrFrom(options.Listen.Build(), options.ListenPort)
	queryPath := options.QueryPath
	if queryPath == "" {
		queryPath = "/dns-query"
	} else if !strings.HasPrefix(queryPath, "/") {
		queryPath = "/" + queryPath
	}
	chiRouter := chi.NewRouter()
	chiRouter.Group(func(r chi.Router) {
		r.Use(middleware.RealIP)
		r.Mount(queryPath, queryRouter(logger, router, tag))
	})
	httpServer := &http.Server{
		Addr:    listen.String(),
		Handler: chiRouter,
	}
	doh := DnsOverHTTP{
		protocol:   C.TypeDoH,
		network:    networks,
		ctx:        ctx,
		logger:     logger,
		tag:        tag,
		listen:     listen,
		httpServer: httpServer,
	}
	if !overTLS {
		return &doh, nil
	}
	if len(options.TLS.ALPN) == 0 {
		if common.Contains(networks, N.NetworkTCP) {
			options.TLS.ALPN = append(options.TLS.ALPN, "h2")
		}
		if common.Contains(networks, N.NetworkUDP) {
			options.TLS.ALPN = append(options.TLS.ALPN, "h3")
		}
	}
	tlsConfig, err := tls.NewServer(ctx, logger, common.PtrValueOrDefault(options.TLS))
	if err != nil {
		return nil, err
	}
	doh.tlsConfig = tlsConfig
	if common.Contains(networks, N.NetworkUDP) {
		doh.udpFragment = options.UDPFragment
		stdTLSConfig, err := tlsConfig.Config()
		if err != nil {
			return nil, E.Cause(err, "build stdTLSConfig")
		}
		doh.http3Server = &http3.Server{
			Addr:      listen.String(),
			Handler:   chiRouter,
			TLSConfig: stdTLSConfig,
		}
	}
	return &doh, nil
}

func (d *DnsOverHTTP) Tag() string {
	return d.tag
}

func (d *DnsOverHTTP) Type() string {
	return d.protocol
}

func (d *DnsOverHTTP) Start() error {
	if d.tlsConfig == nil {
		listener, err := net.Listen("tcp", d.listen.String())
		if err != nil {
			return E.Cause(err, "create TCP listener")
		}
		d.logger.InfoContext(d.ctx, "DNS-Over-HTTP/1.1 server listening at ", listener.Addr())
		go func() {
			err := d.httpServer.Serve(listener)
			if err != nil && !errors.Is(err, http.ErrServerClosed) {
				d.logger.ErrorContext(d.ctx, "DNS-Over-HTTP/1.1 serve error: ", err)
			}
		}()
		return nil
	}
	err := d.tlsConfig.Start()
	if err != nil {
		return E.Cause(err, "create TLS config")
	}
	for _, network := range d.network {
		switch network {
		case N.NetworkTCP:
			listener, err := tls.NewListener(d.ctx, d.listen.String(), d.tlsConfig)
			if err != nil {
				return E.Cause(err, "create TLS listener")
			}
			d.logger.InfoContext(d.ctx, "DNS-Over-HTTP/2 server listening at ", listener.Addr())
			go func() {
				err := d.httpServer.Serve(listener)
				if err != nil && !errors.Is(err, http.ErrServerClosed) {
					d.logger.ErrorContext(d.ctx, "DNS-Over-HTTP/2 server serve error: ", err)
				}
			}()
		case N.NetworkUDP:
			err := qtls.ConfigureHTTP3(d.tlsConfig)
			if err != nil {
				return E.Cause(err, "create QUIC TLS config")
			}
			conn, err := d.listenUDP()
			if err != nil {
				return E.Cause(err, "create UDP listener")
			}
			listener, err := qtls.ListenEarly(conn, d.tlsConfig, &quic.Config{
				MaxIncomingStreams: 1 << 60,
				Allow0RTT:          true,
			})
			if err != nil {
				conn.Close()
				return E.Cause(err, "create early QUIC listener")
			}
			d.logger.InfoContext(d.ctx, "DNS-Over-HTTP/3 server listening at ", d.listen.String())
			go func() {
				err := d.http3Server.ServeListener(listener)
				if err != nil && !errors.Is(err, http.ErrServerClosed) {
					d.logger.ErrorContext(d.ctx, "DNS-Over-HTTP/3 server serve error: ", err)
				}
			}()
		}
	}
	return nil
}

func (d *DnsOverHTTP) Close() error {
	return common.Close(
		common.PtrOrNil(d.httpServer),
		common.PtrOrNil(d.http3Server),
	)
}

func (d *DnsOverHTTP) listenUDP() (net.PacketConn, error) {
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

func queryRouter(logger log.ContextLogger, router adapter.Router, tag string) http.Handler {
	r := chi.NewRouter()
	r.Use(middleware.RealIP)
	r.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := log.ContextWithNewID(r.Context())
			logger.InfoContext(ctx, "receive a new http ", strings.ToLower(r.Method), " request on inbound/doh[", tag, "]")
			ctx, metadata := adapter.AppendContext(ctx)
			metadata.Inbound = tag
			metadata.InboundType = C.TypeDoH
			metadata.Source = M.ParseSocksaddr(r.RemoteAddr)
			next.ServeHTTP(w, r.Clone(ctx))
		})
	})
	r.Head("/", func(w http.ResponseWriter, r *http.Request) {
		render.Status(r, http.StatusBadRequest)
		render.JSON(w, r, &clashapi.HTTPError{Message: "Unsupported http method"})
	})
	r.Get("/", getMethodQueryResult(logger, router))
	r.Post("/", postMethodQueryResult(logger, router))
	r.MethodNotAllowed(func(w http.ResponseWriter, r *http.Request) {
		render.Status(r, http.StatusNotImplemented)
		render.JSON(w, r, clashapi.HTTPError{Message: "Not implemented"})
	})
	return r
}

func handleDNSMessage(ctx context.Context, logger log.ContextLogger, router adapter.Router, query []byte, w http.ResponseWriter, r *http.Request) {
	var message mDNS.Msg
	err := message.Unpack(query)
	if err != nil {
		err = E.Cause(err, "unpack query message")
		logger.DebugContext(ctx, err)
		render.Status(r, http.StatusBadRequest)
		render.JSON(w, r, clashapi.HTTPError{Message: err.Error()})
		return
	}
	response, err := router.Exchange(ctx, &message)
	if err != nil {
		err = E.Cause(err, "exchange query")
		logger.DebugContext(ctx, err)
		render.Status(r, http.StatusBadRequest)
		render.JSON(w, r, clashapi.HTTPError{Message: err.Error()})
		return
	}
	responseBuffer := buf.NewPacket()
	defer responseBuffer.Release()
	responseBuffer.Resize(2, 0)
	n, err := response.PackBuffer(responseBuffer.FreeBytes())
	if err != nil {
		err = E.Cause(err, "pack buffer")
		logger.DebugContext(ctx, err)
		render.Status(r, http.StatusBadRequest)
		render.JSON(w, r, clashapi.HTTPError{Message: err.Error()})
		return
	}
	responseBuffer.Truncate(len(n))
	render.Status(r, http.StatusOK)
	w.Header().Set("Content-Type", "application/dns-message")
	w.Header().Set("Content-Length", strconv.Itoa(responseBuffer.Len()))
	if len(response.Answer) > 0 {
		maxAge := math.MaxInt
		for _, answer := range response.Answer {
			ttl := int(answer.Header().Ttl)
			if ttl < maxAge {
				maxAge = ttl
			}
		}
		w.Header().Set("Cache-Control", "max-age="+strconv.Itoa(maxAge))
	}
	_, err = w.Write(responseBuffer.Bytes())
	if err != nil {
		err = E.Cause(err, "write response")
		logger.DebugContext(ctx, E.Cause(err, "write response"))
		render.Status(r, http.StatusInternalServerError)
		render.JSON(w, r, clashapi.HTTPError{Message: err.Error()})
		return
	}

}

func getMethodQueryResult(logger log.ContextLogger, router adapter.Router) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		query := r.URL.Query()
		msg := query.Get("dns")
		if msg == "" {
			logger.DebugContext(ctx, "missing query message")
			render.Status(r, http.StatusBadRequest)
			render.JSON(w, r, &clashapi.HTTPError{Message: "Missing query message"})
			return
		}
		rawQuery, err := base64.RawURLEncoding.DecodeString(msg)
		if err != nil {
			err = E.Cause(err, "decode query message")
			logger.DebugContext(ctx, err)
			render.Status(r, http.StatusBadRequest)
			render.JSON(w, r, clashapi.HTTPError{Message: err.Error()})
			return
		}
		handleDNSMessage(ctx, logger, router, rawQuery, w, r)
	}
}

func postMethodQueryResult(logger log.ContextLogger, router adapter.Router) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		contentType := r.Header.Get("Content-Type")
		if contentType != "application/dns-message" {
			logger.DebugContext(ctx, "unsupported media type")
			render.Status(r, http.StatusUnsupportedMediaType)
			render.JSON(w, r, clashapi.HTTPError{Message: "Unsupported media type"})
			return
		}
		rawQuery, err := io.ReadAll(r.Body)
		if err != nil {
			err = E.Cause(err, "read body")
			logger.DebugContext(ctx, err)
			render.Status(r, http.StatusBadRequest)
			render.JSON(w, r, clashapi.HTTPError{Message: err.Error()})
			return
		}
		handleDNSMessage(ctx, logger, router, rawQuery, w, r)
	}
}
