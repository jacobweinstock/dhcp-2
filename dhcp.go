package dhcp

import (
	"context"
	"net"

	"github.com/go-logr/logr"
	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/insomniacslk/dhcp/dhcpv4/server4"
	"github.com/jacobweinstock/dhcp/backend/tink"
	"golang.org/x/sync/errgroup"
	"inet.af/netaddr"
)

type BackendReader interface {
	// Read from a backend and return DHCP headers and options based on the mac address.
	Read(context.Context, net.HardwareAddr) ([]dhcpv4.Modifier, error)
}

type Server struct {
	ctx        context.Context
	Log        logr.Logger
	ListenAddr netaddr.IPPort
	Backend    BackendReader
}

// New returns a proxy DHCP server for the Handler.
func (s *Server) ListenAndServe(ctx context.Context) error {
	// for broadcast traffic we need to listen on all IPs
	conn := &net.UDPAddr{
		IP:   net.ParseIP("0.0.0.0"),
		Port: s.ListenAddr.UDPAddr().Port,
	}
	s.Backend = &tink.Conn{}

	// server4.NewServer() will isolate listening to the specific interface.
	srv, err := server4.NewServer(getInterfaceByIP(s.ListenAddr.IP().String()), conn, s.handleFunc)
	if err != nil {
		return err
	}

	g, ctx := errgroup.WithContext(ctx)
	g.Go(func() error {
		return srv.Serve()
	})

	<-ctx.Done()

	return srv.Close()
}

func (s *Server) handleFunc(conn net.PacketConn, peer net.Addr, m *dhcpv4.DHCPv4) {
	var reply *dhcpv4.DHCPv4
	switch mt := m.MessageType(); mt {
	case dhcpv4.MessageTypeDiscover:
		reply = s.handleDiscover(s.ctx, m)
	case dhcpv4.MessageTypeRequest:
		reply = s.handleRequest(s.ctx, m)
	case dhcpv4.MessageTypeRelease:
		s.handleRelease(s.ctx, m)
		return
	default:
		s.Log.Info("received unknown message type", "type", mt)
	}
	s.Log.Info(reply.Summary())
	if _, err := conn.WriteTo(reply.ToBytes(), peer); err != nil {
		s.Log.Error(err, "failed to send DHCP")
	}
}

func (s *Server) handleDiscover(ctx context.Context, m *dhcpv4.DHCPv4) *dhcpv4.DHCPv4 {
	s.Log.Info("received discover, sending offer")
	mods, err := s.Backend.Read(ctx, m.ClientHWAddr)
	if err != nil {
		return nil
	}
	mods = append(mods, dhcpv4.WithMessageType(dhcpv4.MessageTypeOffer))
	reply, err := dhcpv4.NewReplyFromRequest(m, mods...)
	if err != nil {
		return nil
	}
	return reply
}

func (s *Server) handleRequest(ctx context.Context, m *dhcpv4.DHCPv4) *dhcpv4.DHCPv4 {
	s.Log.Info("received request, sending ack")
	mods, err := s.Backend.Read(ctx, m.ClientHWAddr)
	if err != nil {
		return nil
	}
	mods = append(mods, dhcpv4.WithMessageType(dhcpv4.MessageTypeAck))
	reply, err := dhcpv4.NewReplyFromRequest(m, mods...)
	if err != nil {
		return nil
	}
	return reply
}

func (s *Server) handleRelease(ctx context.Context, m *dhcpv4.DHCPv4) {
	s.Log.Info("received release, no response required")
}

// getInterfaceByIP returns the interface with the given IP address or an empty string.
func getInterfaceByIP(ip string) string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return ""
	}
	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok {
				if ipnet.IP.String() == ip {
					return iface.Name
				}
			}
		}
	}
	return ""
}
