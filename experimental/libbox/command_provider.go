package libbox

import (
	"bufio"
	"encoding/binary"
	"io"
	"net"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/urltest"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/varbin"
	"github.com/sagernet/sing/service"
)

type OutboundProvider struct {
	Tag        string
	Type       string
	IsExpand   bool
	ItemList   []*OutboundProviderItem
}

func (g *OutboundProvider) GetItems() OutboundProviderItemIterator {
	return newIterator(g.ItemList)
}

type OutboundProviderIterator interface {
	Next() *OutboundProvider
	HasNext() bool
}

type OutboundProviderItem struct {
	Tag          string
	Type         string
	URLTestTime  int64
	URLTestDelay int32
}

type OutboundProviderItemIterator interface {
	Next() *OutboundProviderItem
	HasNext() bool
}

func (c *CommandClient) handleProviderConn(conn net.Conn) {
	defer conn.Close()

	for {
		providers, err := readGroups(conn)
		if err != nil {
			c.handler.Disconnected(err.Error())
			return
		}
		c.handler.WriteGroups(providers)
	}
}

func (s *CommandServer) handleProviderConn(conn net.Conn) error {
	var interval int64
	err := binary.Read(conn, binary.BigEndian, &interval)
	if err != nil {
		return E.Cause(err, "read interval")
	}
	ticker := time.NewTicker(time.Duration(interval))
	defer ticker.Stop()
	ctx := connKeepAlive(conn)
	writer := bufio.NewWriter(conn)
	for {
		service := s.service
		if service != nil {
			err = writeProviders(writer, service)
			if err != nil {
				return err
			}
		} else {
			err = binary.Write(writer, binary.BigEndian, uint16(0))
			if err != nil {
				return err
			}
		}
		err = writer.Flush()
		if err != nil {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-s.urlTestUpdate:
		}
	}
}

func readProviders(reader io.Reader) (OutboundProviderIterator, error) {
	providers, err := varbin.ReadValue[[]*OutboundProvider](reader, binary.BigEndian)
	if err != nil {
		return nil, err
	}
	return newIterator(providers), nil
}

func writeProviders(writer io.Writer, boxService *BoxService) error {
	historyStorage := service.PtrFromContext[urltest.HistoryStorage](boxService.ctx)
	cacheFile := service.FromContext[adapter.CacheFile](boxService.ctx)
	outbounds := boxService.instance.Router().OutboundProviders()
	var iProviders []adapter.OutboundProvider
	for _, it := range outbounds {
		if provider, isProvider := it.(adapter.OutboundProvider); isProvider {
			iProviders = append(iProviders, provider)
		}
	}
	var providers []OutboundProvider
	for _, iProvider := range iProviders {
		var provider OutboundProvider
		provider.Tag = iProvider.Tag()
		provider.Type = iProvider.Type()
		if cacheFile != nil {
			if isExpand, loaded := cacheFile.LoadProviderExpand(provider.Tag); loaded {
				provider.IsExpand = isExpand
			}
		}

		for _, outbound := range iProvider.Outbounds() {
			var item OutboundProviderItem
			item.Tag = outbound.Tag()
			item.Type = outbound.Type()
			if history := historyStorage.LoadURLTestHistory(outbound.Tag()); history != nil {
				item.URLTestTime = history.Time.Unix()
				item.URLTestDelay = int32(history.Delay)
			}
			provider.ItemList = append(provider.ItemList, &item)
		}
		providers = append(providers, provider)
	}
	return varbin.Write(writer, binary.BigEndian, providers)
}

func (c *CommandClient) SetProviderExpand(providerTag string, isExpand bool) error {
	conn, err := c.directConnect()
	if err != nil {
		return err
	}
	defer conn.Close()
	err = binary.Write(conn, binary.BigEndian, uint8(CommandProviderExpand))
	if err != nil {
		return err
	}
	err = varbin.Write(conn, binary.BigEndian, providerTag)
	if err != nil {
		return err
	}
	err = binary.Write(conn, binary.BigEndian, isExpand)
	if err != nil {
		return err
	}
	return readError(conn)
}

func (s *CommandServer) handleSetProviderExpand(conn net.Conn) error {
	providerTag, err := varbin.ReadValue[string](conn, binary.BigEndian)
	if err != nil {
		return err
	}
	var isExpand bool
	err = binary.Read(conn, binary.BigEndian, &isExpand)
	if err != nil {
		return err
	}
	serviceNow := s.service
	if serviceNow == nil {
		return writeError(conn, E.New("service not ready"))
	}
	cacheFile := service.FromContext[adapter.CacheFile](serviceNow.ctx)
	if cacheFile != nil {
		err = cacheFile.StoreProviderExpand(providerTag, isExpand)
		if err != nil {
			return writeError(conn, err)
		}
	}
	return writeError(conn, nil)
}
