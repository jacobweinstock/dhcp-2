package tink

import (
	"context"
	"net"

	"github.com/insomniacslk/dhcp/dhcpv4"
	"inet.af/netaddr"
)

type Conn struct {
	IP      netaddr.IPPort
	CertURL string
}

func (c *Conn) Read(ctx context.Context, mac net.HardwareAddr) ([]dhcpv4.Modifier, error) {
	withNetboot := func(d *dhcpv4.DHCPv4) {
		d.BootFileName = "undionly.kpxe"
		d.ServerIPAddr = net.IPv4(192, 168, 2, 225)
	}
	pxe := dhcpv4.Options{
		// PXE Boot Server Discovery Control - bypass, just boot from filename.
		6: []byte{8}, // or []byte{8}
	}
	mods := []dhcpv4.Modifier{
		dhcpv4.WithDNS(net.IP{8, 8, 8, 8}),
		dhcpv4.WithNetmask(net.IPMask{255, 255, 255, 0}),
		dhcpv4.WithRouter(net.IP{192, 168, 2, 1}),
		dhcpv4.WithLeaseTime(3600),
		dhcpv4.WithServerIP(net.IP{192, 168, 2, 225}),
		dhcpv4.WithYourIP(net.IP{192, 168, 2, 152}),
		dhcpv4.WithGeneric(dhcpv4.OptionServerIdentifier, net.IP{192, 168, 2, 225}),

		// netboot options
		withNetboot,
		dhcpv4.WithGeneric(dhcpv4.OptionVendorSpecificInformation, pxe.ToBytes()),
	}
	return mods, nil
}
