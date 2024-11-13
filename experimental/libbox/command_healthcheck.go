package libbox

import (
	"encoding/binary"
	"net"

	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/varbin"
)

func (c *CommandClient) HealthCheck(providerTag string) error {
	conn, err := c.directConnect()
	if err != nil {
		return err
	}
	defer conn.Close()
	err = binary.Write(conn, binary.BigEndian, uint8(CommandHealthCheck))
	if err != nil {
		return err
	}
	err = varbin.Write(conn, binary.BigEndian, providerTag)
	if err != nil {
		return err
	}
	return readError(conn)
}

func (s *CommandServer) handleHealthCheck(conn net.Conn) error {
	defer conn.Close()
	providerTag, err := varbin.ReadValue[string](conn, binary.BigEndian)
	if err != nil {
		return err
	}
	service := s.service
	if service == nil {
		return nil
	}
	outboundProvider, isLoaded := service.instance.Router().OutboundProvider(providerTag)
	if !isLoaded {
		return writeError(conn, E.New("outbound provider not found: ", providerTag))
	}
	go outboundProvider.CheckOutbounds(true)
	return writeError(conn, nil)
}