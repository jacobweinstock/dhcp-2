package data

import (
	"net"

	"inet.af/netaddr"
)

type Dhcp struct {
	MacAddress       net.HardwareAddr // chaddr DHCP header.
	IPAddress        netaddr.IP       // yiaddr DHCP header.
	SubnetMask       net.IPMask       // DHCP option 1.
	DefaultGateway   netaddr.IP       // DHCP option 3.
	NameServers      []net.IP         // DHCP option 6.
	Hostname         string           // DHCP option 12.
	DomainName       string           // DHCP option 15.
	BroadcastAddress netaddr.IP       // DHCP option 28.
	NTPServers       []net.IP         // DHCP option 42.
	LeaseTime        uint32           // DHCP option 51.
	DomainSearch     []string         // DHCP option 119.
}

type Netboot struct {
	AllowPxe      bool   // If true, the client will be provided netboot options in the DHCP offer/ack.
	IpxeScriptURL string // Overrides default value of that is passed into DHCP on startup.
}
