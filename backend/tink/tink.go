package tink

import (
	"context"
	"net"

	"github.com/insomniacslk/dhcp/dhcpv4"
	"inet.af/netaddr"
)

type Conn struct {
	NetbootDisabled bool
	ServerIP        netaddr.IPPort
	ServerCertURL   string
}

func (c *Conn) Read(ctx context.Context, mac net.HardwareAddr) ([]dhcpv4.Modifier, error) {
	var withNetboot func(d *dhcpv4.DHCPv4)
	if !c.NetbootDisabled {
		pxe := dhcpv4.Options{
			// PXE Boot Server Discovery Control - bypass, just boot from filename.
			6: []byte{8}, // or []byte{8}
		}
		withNetboot = func(d *dhcpv4.DHCPv4) {
			d.BootFileName = "undionly.kpxe"
			d.ServerIPAddr = net.IPv4(192, 168, 1, 225)
			d.UpdateOption(dhcpv4.OptGeneric(dhcpv4.OptionVendorSpecificInformation, pxe.ToBytes()))
		}

	}

	mods := []dhcpv4.Modifier{
		dhcpv4.WithDNS(net.IP{8, 8, 8, 8}),
		dhcpv4.WithNetmask(net.IPMask{255, 255, 255, 0}),
		dhcpv4.WithRouter(net.IP{192, 168, 1, 1}),
		dhcpv4.WithLeaseTime(3600),
		dhcpv4.WithServerIP(net.IP{192, 168, 1, 225}),
		dhcpv4.WithYourIP(net.IP{192, 168, 1, 152}),
		dhcpv4.WithGeneric(dhcpv4.OptionServerIdentifier, net.IP{192, 168, 1, 225}),

		// netboot options
		withNetboot,
	}
	return mods, nil
}
