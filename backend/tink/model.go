package tink

import (
	"net"

	"inet.af/netaddr"
)

type TinkRecord struct {
	ID      string      `json:"id"`
	Network TinkNetwork `json:"network"`
}

type TinkDhcp struct {
	MacAddress       string   `json:"mac_address"`       // chaddr DHCP header.
	IPAddress        string   `json:"ip_address"`        // yiaddr DHCP header.
	SubnetMask       string   `json:"subnet_mask"`       // DHCP option 1.
	DefaultGateway   string   `json:"default_gateway"`   // DHCP option 3.
	NameServers      []string `json:"name_servers"`      // DHCP option 6.
	Hostname         string   `json:"hostname"`          // DHCP option 12.
	DomainName       string   `json:"domain_name"`       // DHCP option 15.
	BroadcastAddress string   `json:"broadcast_address"` // DHCP option 28.
	NTPServers       []string `json:"ntp_servers"`       // DHCP option 42.
	LeaseTime        int      `json:"lease_time"`        // DHCP option 51.
	DomainSearch     []string `json:"domain_search"`     // DHCP option 119.
}

type TinkNetboot struct {
	AllowPxe      bool   `json:"allow_pxe"`       // If true, the client will be provided netboot options in the DHCP offer/ack.
	IpxeScriptURL string `json:"ipxe_script_url"` // Overrides default value of that is passed into DHCP on startup.
}

type TinkIntf struct {
	Dhcp    TinkDhcp    `json:"dhcp"`
	Netboot TinkNetboot `json:"netboot"`
}

type TinkNetwork struct {
	Interfaces []TinkIntf `json:"interfaces"`
}

type Record struct {
	ID      string
	Network Network
}

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

type Intf struct {
	Dhcp    Dhcp
	Netboot Netboot
}

type Network struct {
	Interfaces []Intf
}
