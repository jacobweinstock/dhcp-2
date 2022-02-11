package tink

import (
	"bytes"
	"context"
	"fmt"
	"net"

	"github.com/go-logr/logr"
	"github.com/jacobweinstock/dhcp/data"
	"inet.af/netaddr"
)

type Record struct {
	ID      string  `json:"id"`
	Network Network `json:"network"`
}

type Dhcp struct {
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

type Netboot struct {
	AllowPxe      bool   `json:"allow_pxe"`       // If true, the client will be provided netboot options in the DHCP offer/ack.
	IpxeScriptURL string `json:"ipxe_script_url"` // Overrides default value of that is passed into DHCP on startup.
}

type Intf struct {
	Dhcp    Dhcp    `json:"dhcp"`
	Netboot Netboot `json:"netboot"`
}

type Network struct {
	Interfaces []Intf `json:"interfaces"`
}

var tr = Record{
	ID: "12345",
	Network: Network{
		Interfaces: []Intf{
			{
				Dhcp: Dhcp{
					MacAddress:     "08:00:27:29:4E:67",
					IPAddress:      "192.168.2.152",
					SubnetMask:     "255.255.255.0",
					DefaultGateway: "192.168.2.1",
					NameServers: []string{
						"8.8.8.8",
						"1.1.1.1",
					},
					Hostname:         "pxe-virtualbox",
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
				Netboot: Netboot{
					AllowPxe:      true,
					IpxeScriptURL: "",
				},
			},
			{
				Dhcp: Dhcp{
					MacAddress:     "86:96:b0:6e:ca:36",
					IPAddress:      "192.168.2.153",
					SubnetMask:     "255.255.255.0",
					DefaultGateway: "192.168.2.1",
					NameServers: []string{
						"8.8.8.8",
						"1.1.1.1",
					},
					Hostname:         "pxe-proxmox",
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
				Netboot: Netboot{
					AllowPxe:      true,
					IpxeScriptURL: "",
				},
			},
			{
				Dhcp: Dhcp{
					MacAddress:     "b4:96:91:6f:33:d0",
					IPAddress:      "192.168.56.15",
					SubnetMask:     "255.255.255.0",
					DefaultGateway: "192.168.56.4",
					NameServers: []string{
						"8.8.8.8",
						"1.1.1.1",
					},
					Hostname:         "dhcp-testing",
					BroadcastAddress: "192.168.56.255",
					NTPServers: []string{
						"132.163.96.2",
						"132.163.96.3",
					},
					LeaseTime: 3600,
					DomainSearch: []string{
						"weinstocklabs.com",
					},
				},
				Netboot: Netboot{
					AllowPxe:      true,
					IpxeScriptURL: "",
				},
			},
		},
	},
}

type Conn struct {
	ServerIP      netaddr.IPPort
	ServerCertURL string
	Log           logr.Logger
}

func (c *Conn) Read(_ context.Context, mac net.HardwareAddr) (*data.Dhcp, *data.Netboot, error) {
	// get tink data here, translate it, then pass it into setDHCPOpts and setNetworkBootOpts
	var t Intf
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
		return nil, nil, fmt.Errorf("no record found for mac %s", mac.String())
	}
	return t.translate()
}

func (t Intf) translate() (*data.Dhcp, *data.Netboot, error) {
	// TODO(jacobweinstock): add len validations to all options that take strings or a string slice?
	d := &data.Dhcp{}
	n := &data.Netboot{}

	// mac address
	ma, err := net.ParseMAC(t.Dhcp.MacAddress)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse mac address from Tink record: %w", err)
	}
	d.MacAddress = ma

	// ip address
	ip, err := netaddr.ParseIP(t.Dhcp.IPAddress)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse ip address from Tink record: %w", err)
	}
	d.IPAddress = ip

	// subnet mask
	sm, err := netaddr.ParseIP(t.Dhcp.SubnetMask)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse subnet mask from Tink record: %w", err)
	}
	d.SubnetMask = sm.IPAddr().IP.DefaultMask()

	// default gateway
	dg, err := netaddr.ParseIP(t.Dhcp.DefaultGateway)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse default gateway from Tink record: %w", err)
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
		return nil, nil, fmt.Errorf("failed to parse broadcast address from Tink record: %w", err)
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
	// TODO(jacobweinstock): write some validations. > 0, etc.
	d.LeaseTime = uint32(t.Dhcp.LeaseTime)

	// domain search
	d.DomainSearch = t.Dhcp.DomainSearch

	n.AllowPxe = t.Netboot.AllowPxe
	n.IpxeScriptURL = t.Netboot.IpxeScriptURL

	return d, n, nil
}
