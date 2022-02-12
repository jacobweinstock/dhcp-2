package dhcp

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"path/filepath"
	"strings"

	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/insomniacslk/dhcp/iana"
	"github.com/jacobweinstock/dhcp/data"
	"inet.af/netaddr"
)

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
	/*
		prl := m.ParameterRequestList()
		list := map[uint8]string{}
		for _, o := range prl {
			list[o.Code()] = o.String()
		}
		s.Log.Info("DEBUGGING", "option 55", list)
	*/
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
	mods = append(mods, s.setDHCPOpts(ctx, d)...)
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
	mods = append(mods, s.setDHCPOpts(ctx, d)...)
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

func (s *Server) setDHCPOpts(_ context.Context, d *data.Dhcp) []dhcpv4.Modifier {
	// need to handle option 82

	mods := []dhcpv4.Modifier{
		dhcpv4.WithDNS(d.NameServers...),
		dhcpv4.WithDomainSearchList(d.DomainSearch...),
		dhcpv4.WithOption(dhcpv4.OptNTPServers(d.NTPServers...)),
		dhcpv4.WithGeneric(dhcpv4.OptionBroadcastAddress, d.BroadcastAddress.IPAddr().IP),
		dhcpv4.WithGeneric(dhcpv4.OptionDomainName, []byte(d.DomainName)),
		dhcpv4.WithGeneric(dhcpv4.OptionHostName, []byte(d.Hostname)),
		dhcpv4.WithNetmask(d.SubnetMask),
		dhcpv4.WithRouter(d.DefaultGateway.IPAddr().IP),
		dhcpv4.WithLeaseTime(d.LeaseTime),
		dhcpv4.WithYourIP(d.IPAddress.IPAddr().IP),
	}

	return mods
}

// setNetworkBootOpts purpose is to sets 2 or 3 values. 2 DHCP headers, option 43 and optionally 1 DHCP option (60).
// DHCP Headers (https://datatracker.ietf.org/doc/html/rfc2131#section-2)
// 'siaddr': IP address of next bootstrap server. represented below as `.ServerIPAddr`.
// 'file': Client boot file name. represented below as `.BootFileName`.
// DHCP option
// option 60: Class Identifier. https://www.rfc-editor.org/rfc/rfc2132.html#section-9.13
// option 60 is set if the client's option 60 (Class Identifier) starts with HTTPClient.
//
// info neeeded:
// - ipport for tftp ipxe binary
// - ipport for http ipxe binary
// - url for ipxe script
// - user class (defaults to "Tinkerbell").
func (s *Server) setNetworkBootOpts(_ context.Context, m *dhcpv4.DHCPv4, n *data.Netboot) func(d *dhcpv4.DHCPv4) {
	// m is the received DHCPv4 packet.
	// d is the reply packet we are building.
	withNetboot := func(d *dhcpv4.DHCPv4) {
		d.BootFileName = "/netboot-not-allowed"
		d.ServerIPAddr = net.IPv4(0, 0, 0, 0)

		// echo back opt 60
		if val := m.Options.Get(dhcpv4.OptionClassIdentifier); val != nil {
			if strings.HasPrefix(string(val), string(httpClient)) {
				d.UpdateOption(dhcpv4.OptGeneric(dhcpv4.OptionClassIdentifier, []byte(httpClient)))
			}
		}
		if n.AllowPxe {
			uClass := UserClass(string(m.GetOneOption(dhcpv4.OptionUserClassInformation))) // userClass returns the user class, option 77.
			opt60 := ""                                                                    // client type, option 60, normally pxeClient or httpClient.
			if strings.HasPrefix(string(m.GetOneOption(dhcpv4.OptionClassIdentifier)), string(httpClient)) {
				opt60 = string(httpClient)
			}
			mac := m.ClientHWAddr
			a := arch(m)
			bin, found := ArchToBootFile[a]
			if !found {
				s.Log.Error(fmt.Errorf("unable to find bootfile for arch"), "arch", a)
				return
			}
			// do we need to set d.ServerIPAddr? testing against virtualbox and proxmox showed that it was not needed.
			d.BootFileName, d.ServerIPAddr = s.bootfileAndNextServer(mac, uClass, opt60, bin, s.IPXEBinServerTFTP, s.IPXEBinServerHTTP, s.IPXEScriptURL)
			pxe := dhcpv4.Options{
				// PXE Boot Server Discovery Control - bypass, just boot from filename.
				6: []byte{8}, // or []byte{8}
			}
			d.UpdateOption(dhcpv4.OptGeneric(dhcpv4.OptionVendorSpecificInformation, pxe.ToBytes()))
		}
	}

	return withNetboot
}

func (s *Server) bootfileAndNextServer(mac net.HardwareAddr, uClass UserClass, opt60, bin string, tftp netaddr.IPPort, ipxe, iscript *url.URL) (string, net.IP) {
	var nextServer net.IP
	var bootfile string
	// If a machine is in an ipxe boot loop, it is likely to be that we arent matching on IPXE or Tinkerbell.
	// if the "iPXE" user class is found it means we arent in our custom version of ipxe, but because of the option 43 we're setting we need to give a full tftp url from which to boot.
	switch { // order matters here.
	case uClass == Tinkerbell, (s.UserClass != "" && uClass == s.UserClass): // this case gets us out of an ipxe boot loop.
		bootfile = iscript.String() // "https://boot.netboot.xyz" // fmt.Sprintf("%s/%s/%s", ipxe, mac.String(), iscript)
	case clientType(opt60) == httpClient: // Check the client type from option 60.
		bootfile = fmt.Sprintf("%s/%s/%s", ipxe, mac.String(), bin)
		nextServer = net.ParseIP(ipxe.Host) // check if net.IP is nil
	case uClass == IPXE:
		bootfile = fmt.Sprintf("tftp://%v/%v/%v", tftp.String(), mac.String(), bin)
		nextServer = tftp.UDPAddr().IP
	default:
		bootfile = filepath.Join(mac.String(), bin)
		nextServer = tftp.UDPAddr().IP
	}
	s.Log.Info("DEBUGGING", "bootfile", bootfile, "nextServer", nextServer)
	return bootfile, nextServer
}

func arch(d *dhcpv4.DHCPv4) iana.Arch {
	// get option 93 ; arch
	fwt := d.ClientArch()
	if len(fwt) == 0 {
		return iana.Arch(255) // unknown arch
	}
	// TODO(jacobweinstock): handle unknown arch, better?
	var archKnown bool
	var a iana.Arch
	for _, elem := range fwt {
		if !strings.Contains(elem.String(), "unknown") {
			archKnown = true
			// Basic architecture identification, based purely on
			// the PXE architecture option.
			// https://www.iana.org/assignments/dhcpv6-parameters/dhcpv6-parameters.xhtml#processor-architecture
			a = elem
			break
		}
	}
	if !archKnown {
		return iana.Arch(255) // unknown arch
	}

	return a
}
