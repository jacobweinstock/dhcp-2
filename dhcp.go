package dhcp

import (
	"context"
	"net"
	"net/url"
	"reflect"

	"github.com/go-logr/logr"
	"github.com/imdario/mergo"
	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/insomniacslk/dhcp/dhcpv4/server4"
	"github.com/jacobweinstock/dhcp/backend/tink"
	"github.com/jacobweinstock/dhcp/data"
	"golang.org/x/sync/errgroup"
	"inet.af/netaddr"
)

type BackendReader interface {
	// Read from a backend and return DHCP headers and options based on the mac address.
	Read(context.Context, net.HardwareAddr) (*data.Dhcp, *data.Netboot, error)
}

type Server struct {
	ctx context.Context
	Log logr.Logger

	// ListenAddr is the address to listen on for DHCP requests.
	ListenAddr netaddr.IPPort

	// IPAddr is the IP address to use in DHCP requests.
	// Option 54 and maybe sname DHCP header.
	IPAddr netaddr.IP

	// iPXE binary server IP:Port serving via TFTP.
	IPXEBinServerTFTP netaddr.IPPort

	// IPXEBinServerHTTP is the URL to the IPXE binary server serving via HTTP(s).
	IPXEBinServerHTTP *url.URL

	// IPXEScriptURL is the URL to the IPXE script to use.
	IPXEScriptURL *url.URL

	// NetbootEnabled is whether to enable sending netboot DHCP options.
	NetbootEnabled bool

	UserClass UserClass

	Backend BackendReader
}

func DefaultIP() netaddr.IP {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return netaddr.IPv4(0, 0, 0, 0)
	}
	for _, addr := range addrs {
		ip, ok := addr.(*net.IPNet)
		if !ok {
			continue
		}
		v4 := ip.IP.To4()
		if v4 == nil || !v4.IsGlobalUnicast() {
			continue
		}

		i, err := netaddr.ParseIP(v4.String())
		if err != nil {
			return netaddr.IPv4(0, 0, 0, 0)
		}
		return i
	}
	return netaddr.IPv4(0, 0, 0, 0)
}

// New returns a proxy DHCP server for the Handler.
func (s *Server) ListenAndServe(ctx context.Context) error {
	defaults := &Server{
		Log:        logr.Discard(),
		ListenAddr: netaddr.IPPortFrom(netaddr.IPv4(0, 0, 0, 0), 67),
		IPAddr:     DefaultIP(),
	}

	err := mergo.Merge(s, defaults, mergo.WithTransformers(s))
	if err != nil {
		return err
	}
	// for broadcast traffic we need to listen on all IPs
	conn := &net.UDPAddr{
		IP:   net.ParseIP("0.0.0.0"),
		Port: s.ListenAddr.UDPAddr().Port,
	}
	/*
		s.Backend = &tink.Conn{
			Log: s.Log,
		}
	*/

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

func (s *Server) Serve(ctx context.Context, conn net.PacketConn) error {
	s.Backend = &tink.Conn{
		Log: s.Log,
	}

	// server4.NewServer() will isolate listening to the specific interface.
	srv, err := server4.NewServer("", nil, s.handleFunc, server4.WithConn(conn))
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
	default:
		s.Log.Info("received unknown message type", "type", mt)
	}
	if reply != nil {
		s.Log.Info("summary", "summary", reply.Summary())
		if _, err := conn.WriteTo(reply.ToBytes(), peer); err != nil {
			s.Log.Error(err, "failed to send DHCP")
		}
	}
}

func (s *Server) handleDiscover(ctx context.Context, m *dhcpv4.DHCPv4) *dhcpv4.DHCPv4 {
	s.Log.Info("received discover packet")
	d, n, err := s.Backend.Read(ctx, m.ClientHWAddr)
	if err != nil {
		s.Log.Info("not sending DHCP OFFER", "mac", m.ClientHWAddr, "error", err)
		return nil
	}
	mods := []dhcpv4.Modifier{
		dhcpv4.WithMessageType(dhcpv4.MessageTypeOffer),
		dhcpv4.WithGeneric(dhcpv4.OptionServerIdentifier, s.ListenAddr.UDPAddr().IP),
		dhcpv4.WithServerIP(s.IPAddr.IPAddr().IP),
	}
	mods = append(mods, s.setDHCPOpts(ctx, m, d)...)
	if s.NetbootEnabled {
		mods = append(mods, s.setNetworkBootOpts(ctx, m, n))
	}
	reply, err := dhcpv4.NewReplyFromRequest(m, mods...)
	if err != nil {
		return nil
	}
	s.Log.Info("sending offer packet")
	return reply
}

func (s *Server) handleRequest(ctx context.Context, m *dhcpv4.DHCPv4) *dhcpv4.DHCPv4 {
	s.Log.Info("received request packet")
	d, n, err := s.Backend.Read(ctx, m.ClientHWAddr)
	if err != nil {
		s.Log.Info("not sending DHCP ACK", "mac", m.ClientHWAddr, "error", err)
		return nil
	}
	mods := []dhcpv4.Modifier{
		dhcpv4.WithMessageType(dhcpv4.MessageTypeAck),
		dhcpv4.WithGeneric(dhcpv4.OptionServerIdentifier, s.ListenAddr.UDPAddr().IP),
		dhcpv4.WithServerIP(s.IPAddr.IPAddr().IP),
	}
	mods = append(mods, s.setDHCPOpts(ctx, m, d)...)
	if s.NetbootEnabled {
		mods = append(mods, s.setNetworkBootOpts(ctx, m, n))
	}
	reply, err := dhcpv4.NewReplyFromRequest(m, mods...)
	if err != nil {
		return nil
	}
	s.Log.Info("sending ack packet")
	return reply
}

func (s *Server) handleRelease(_ context.Context, _ *dhcpv4.DHCPv4) {
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

// Transformer for merging the netaddr.IPPort and logr.Logger structs.
func (s *Server) Transformer(typ reflect.Type) func(dst, src reflect.Value) error {
	switch typ {
	case reflect.TypeOf(logr.Logger{}):
		return func(dst, src reflect.Value) error {
			if dst.CanSet() {
				isZero := dst.MethodByName("GetSink")
				result := isZero.Call(nil)
				if result[0].IsNil() {
					dst.Set(src)
				}
			}
			return nil
		}
	case reflect.TypeOf(netaddr.IPPort{}):
		return func(dst, src reflect.Value) error {
			if dst.CanSet() {
				isZero := dst.MethodByName("IsZero")
				result := isZero.Call([]reflect.Value{})
				if result[0].Bool() {
					dst.Set(src)
				}
			}
			return nil
		}
	}
	return nil
}
