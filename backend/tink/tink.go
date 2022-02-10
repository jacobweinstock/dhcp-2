package tink

import (
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

type Conn struct {
	NetbootDisabled bool
	ServerIP        netaddr.IPPort
	ServerCertURL   string
	UserClass       UserClass
	Log             logr.Logger
}

func (c *Conn) Read(ctx context.Context, mac net.HardwareAddr, m *dhcpv4.DHCPv4) ([]dhcpv4.Modifier, error) {
	var withNetboot func(m *dhcpv4.DHCPv4)
	if !c.NetbootDisabled {
		withNetboot = c.setNetworkBootOpts(ctx, m, true) // true needs to come from the data returned from Tink server.
	}
	mods := []dhcpv4.Modifier{
		dhcpv4.WithDNS(net.IP{8, 8, 8, 8}),
		dhcpv4.WithNetmask(net.IPMask{255, 255, 255, 0}),
		dhcpv4.WithRouter(net.IP{192, 168, 2, 1}),
		dhcpv4.WithLeaseTime(3600),
		dhcpv4.WithServerIP(net.IP{192, 168, 2, 225}),
		dhcpv4.WithYourIP(net.IP{192, 168, 2, 152}),
		dhcpv4.WithGeneric(dhcpv4.OptionServerIdentifier, net.IP{192, 168, 1, 225}),

		// netboot options
		withNetboot,
	}

	return mods, nil
}

func (c *Conn) setNetworkBootOpts(ctx context.Context, m *dhcpv4.DHCPv4, pxeAllowed bool) func(d *dhcpv4.DHCPv4) {
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
		if pxeAllowed {
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
