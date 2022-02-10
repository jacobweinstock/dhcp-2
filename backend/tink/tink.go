package tink

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"net/url"
	"path/filepath"
	"strings"

	"github.com/go-logr/logr"
	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/insomniacslk/dhcp/iana"
	"inet.af/netaddr"
)

var tr = TinkRecord{
	ID: "12345",
	Network: TinkNetwork{
		Interfaces: []TinkIntf{
			{
				Dhcp: TinkDhcp{
					MacAddress:     "08:00:27:29:4E:67",
					IPAddress:      "192.168.2.152",
					SubnetMask:     "255.255.255.0",
					DefaultGateway: "192.168.2.1",
					NameServers: []string{
						"8.8.8.8",
						"1.1.1.1",
					},
					Hostname:         "pxe-test",
					DomainName:       "weinstocklabs.com",
					BroadcastAddress: "192.168.2.255",
					NTPServers: []string{
						"132.163.96.2",
						"132.163.96.3",
					},
					LeaseTime: 3600,
					DomainSearch: []string{
						"weinstocklabs.com",
					},
				},
				Netboot: TinkNetboot{
					AllowPxe:      true,
					IpxeScriptURL: "",
				},
			},
		},
	},
}

type Conn struct {
	NetbootDisabled bool
	ServerIP        netaddr.IPPort
	ServerCertURL   string
	UserClass       UserClass
	Log             logr.Logger
}

func (c *Conn) Read(ctx context.Context, mac net.HardwareAddr, m *dhcpv4.DHCPv4) ([]dhcpv4.Modifier, error) {
	var mods []dhcpv4.Modifier
	// get tink data here, translate it, then pass it into setDHCPOpts and setNetworkBootOpts
	var t TinkIntf
	var found bool
	// check if we have a record for this mac
	for _, i := range tr.Network.Interfaces {
		ma, err := net.ParseMAC(i.Dhcp.MacAddress)
		if err != nil {
			fmt.Println(err, "failed to parse mac address")
			continue
		}
		if bytes.Equal(ma, mac) {
			// found a record for this mac
			t.Dhcp = i.Dhcp
			t.Netboot = i.Netboot
			found = true
			break
		}
	}
	if !found {
		return nil, fmt.Errorf("no record found for mac %s", mac.String())
	}
	r, err := t.translate()
	if err != nil {
		return nil, err
	}
	mods = append(mods, c.setDHCPOpts(ctx, m, r.Dhcp)...)
	if !c.NetbootDisabled {
		mods = append(mods, c.setNetworkBootOpts(ctx, m, r.Netboot))
	}

	return mods, nil
}

func (t TinkIntf) translate() (*Intf, error) {
	d := Dhcp{}
	n := Netboot{}

	// mac address
	ma, err := net.ParseMAC(t.Dhcp.MacAddress)
	if err != nil {
		return nil, fmt.Errorf("failed to parse mac address from Tink record: %w", err)
	}
	d.MacAddress = ma

	// ip address
	ip, err := netaddr.ParseIP(t.Dhcp.IPAddress)
	if err != nil {
		return nil, fmt.Errorf("failed to parse ip address from Tink record: %w", err)
	}
	d.IPAddress = ip

	// subnet mask
	sm, err := netaddr.ParseIP(t.Dhcp.SubnetMask)
	if err != nil {
		return nil, fmt.Errorf("failed to parse subnet mask from Tink record: %w", err)
	}
	d.SubnetMask = sm.IPAddr().IP.DefaultMask()

	// default gateway
	dg, err := netaddr.ParseIP(t.Dhcp.DefaultGateway)
	if err != nil {
		return nil, fmt.Errorf("failed to parse default gateway from Tink record: %w", err)
	}
	d.DefaultGateway = dg

	// name servers
	for _, s := range t.Dhcp.NameServers {
		ip := net.ParseIP(s)
		if ip == nil {
			fmt.Println("failed to parse name server", s)
			break
		}
		d.NameServers = append(d.NameServers, ip)
	}

	// hostname
	d.Hostname = t.Dhcp.Hostname

	// domain name
	d.DomainName = t.Dhcp.DomainName

	// broadcast address
	ba, err := netaddr.ParseIP(t.Dhcp.BroadcastAddress)
	if err != nil {
		return nil, fmt.Errorf("failed to parse broadcast address from Tink record: %w", err)
	}
	d.BroadcastAddress = ba

	// ntp servers
	for _, s := range t.Dhcp.NTPServers {
		ip := net.ParseIP(s)
		if ip == nil {
			fmt.Println("failed to parse ntp server", s)
			break
		}
		d.NTPServers = append(d.NTPServers, ip)
	}

	// lease time
	// validation?
	d.LeaseTime = uint32(t.Dhcp.LeaseTime)

	// domain search
	d.DomainSearch = t.Dhcp.DomainSearch

	n.AllowPxe = t.Netboot.AllowPxe
	n.IpxeScriptURL = t.Netboot.IpxeScriptURL

	return &Intf{Dhcp: d, Netboot: n}, nil
}

func (c *Conn) setDHCPOpts(ctx context.Context, m *dhcpv4.DHCPv4, d Dhcp) []dhcpv4.Modifier {
	// need to handle option 82

	var mods []dhcpv4.Modifier
	mods = append(mods,
		dhcpv4.WithDNS(d.NameServers...),
		dhcpv4.WithDomainSearchList(d.DomainSearch...),
		dhcpv4.WithGeneric(dhcpv4.OptionNTPServers, dhcpv4.OptNTPServers(d.NTPServers...).Value.ToBytes()),
		dhcpv4.WithGeneric(dhcpv4.OptionBroadcastAddress, d.BroadcastAddress.IPAddr().IP),
		dhcpv4.WithGeneric(dhcpv4.OptionDomainName, []byte(d.DomainName)),
		dhcpv4.WithGeneric(dhcpv4.OptionHostName, []byte(d.Hostname)),
		dhcpv4.WithNetmask(d.SubnetMask),
		dhcpv4.WithRouter(d.DefaultGateway.IPAddr().IP),
		dhcpv4.WithLeaseTime(d.LeaseTime),
		dhcpv4.WithServerIP(net.IP{192, 168, 2, 225}),
		dhcpv4.WithYourIP(d.IPAddress.IPAddr().IP),
		dhcpv4.WithGeneric(dhcpv4.OptionServerIdentifier, net.IP{192, 168, 2, 225}),
	)

	return mods
}

// setNetworkBootOpts purpose is to sets 2 or 3 values. 2 DHCP headers and optionally 1 DHCP option (60).
// DHCP Headers (https://datatracker.ietf.org/doc/html/rfc2131#section-2)
// 'siaddr': IP address of next bootstrap server.
// 'file': Client boot file name.
// DHCP option
// option 60: Class Identifier. https://www.rfc-editor.org/rfc/rfc2132.html#section-9.13
// option 60 is set if the client's option 60 (Class Identifier) starts with HTTPClient.
//
// info neeeded:
// - ipport for tftp ipxe binary
// - ipport for http ipxe binary
// - url for ipxe script
// - user class (defaults to "Tinkerbell")
func (c *Conn) setNetworkBootOpts(ctx context.Context, m *dhcpv4.DHCPv4, n Netboot) func(d *dhcpv4.DHCPv4) {
	// m is the received DHCPv4 packet.
	// d is the reply packet we are building.
	withNetboot := func(d *dhcpv4.DHCPv4) {
		a := arch(m)
		bin, found := ArchToBootFile[a]
		if !found {
			c.Log.Error(fmt.Errorf("unable to find bootfile for arch"), "arch", a)
			return
		}
		u := &url.URL{
			Scheme: "http",
			Host:   "192.168.2.225:8080",
		} // needs to come from the data returned from Tink server.
		d.BootFileName = "/netboot-not-allowed"
		if n.AllowPxe { // this should probably be the first thing checked?
			uClass := UserClass(string(m.GetOneOption(dhcpv4.OptionUserClassInformation))) // userClass returns the user class, option 77.
			opt60 := ""                                                                    // client type, option 60, normally pxeClient or httpClient.
			if strings.HasPrefix(string(m.GetOneOption(dhcpv4.OptionClassIdentifier)), string(httpClient)) {
				opt60 = string(httpClient)
			}
			mac := m.ClientHWAddr
			d.BootFileName = c.bootfileName(mac, uClass, opt60, bin, netaddr.IPPortFrom(netaddr.IPv4(192, 168, 2, 225), 69), u, "") // netaddr.IPPort{}, u, "auto.ipxe" need to come from the data returned from Tink server.
		}
		d.ServerIPAddr = net.IPv4(192, 168, 2, 225) //net.ParseIP(u.String()) //net.IPv4(192, 168, 1, 225) // this needs to come from the data returned from Tink server?
		pxe := dhcpv4.Options{
			// PXE Boot Server Discovery Control - bypass, just boot from filename.
			6: []byte{8}, // or []byte{8}
		}
		d.UpdateOption(dhcpv4.OptGeneric(dhcpv4.OptionVendorSpecificInformation, pxe.ToBytes()))
		// echo back opt 60
		if val := m.Options.Get(dhcpv4.OptionClassIdentifier); val != nil {
			if strings.HasPrefix(string(val), string(httpClient)) {
				d.UpdateOption(dhcpv4.OptGeneric(dhcpv4.OptionClassIdentifier, []byte(httpClient)))
			}
		}
	}

	return withNetboot
}

func (c *Conn) bootfileName(mac net.HardwareAddr, uClass UserClass, opt60, bin string, tftp netaddr.IPPort, ipxe *url.URL, iscript string) string {
	var bootfile string
	// If a machine is in an ipxe boot loop, it is likely to be that we arent matching on IPXE or Tinkerbell.
	// if the "iPXE" user class is found it means we arent in our custom version of ipxe, but because of the option 43 we're setting we need to give a full tftp url from which to boot.
	switch { // order matters here.
	case uClass == Tinkerbell, (c.UserClass != "" && uClass == c.UserClass): // this case gets us out of an ipxe boot loop.
		bootfile = "https://boot.netboot.xyz" // fmt.Sprintf("%s/%s/%s", ipxe, mac.String(), iscript)
	case clientType(opt60) == httpClient: // Check the client type from option 60.
		bootfile = fmt.Sprintf("%s/%s/%s", ipxe, mac.String(), bin)
	case uClass == IPXE:
		u := &url.URL{
			Scheme: "tftp",
			Host:   tftp.String(),
			Path:   fmt.Sprintf("%v/%v", mac.String(), bin),
		}
		bootfile = u.String()
	default:
		bootfile = filepath.Join(mac.String(), bin)
	}

	return bootfile
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
