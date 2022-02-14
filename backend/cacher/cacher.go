package cacher

import (
	"context"
	"encoding/json"
	"fmt"
	"net"

	"github.com/go-logr/logr"
	"github.com/jacobweinstock/dhcp/data"
	"github.com/packethost/cacher/client"
	"github.com/packethost/cacher/protos/cacher"
	"inet.af/netaddr"
)

type Conn struct {
	Facility      string
	Client        client.CacherClient
	UseTLS        string
	CertURL       string
	GRPCAuthority string
	DNSServers    []string
	LeaseTime     uint32
	data          DiscoveryCacher
	Log           logr.Logger
}

func (c *Conn) Read(ctx context.Context, mac net.HardwareAddr) (*data.Dhcp, *data.Netboot, error) {
	hw, err := c.Client.ByMAC(ctx, &cacher.GetRequest{
		MAC: mac.String(),
	})
	if err != nil {
		return nil, nil, err
	}
	b := []byte(hw.JSON)
	d := &DiscoveryCacher{}
	if err := json.Unmarshal(b, &d); err != nil {
		return nil, nil, fmt.Errorf("error unmarshaling cacher data: %w", err)
	}

	return c.translate()
}

func (c *Conn) translate() (*data.Dhcp, *data.Netboot, error) {
	d := new(data.Dhcp)
	n := new(data.Netboot)

	d.MacAddress = c.data.mac

	// ip address
	ip, err := netaddr.ParseIP(c.data.GetIP(c.data.MAC()).Address.String())
	if err != nil {
		return nil, nil, fmt.Errorf("error parsing IP from cacher data: %w", err)
	}
	d.IPAddress = ip

	// subnet mask
	d.SubnetMask = c.data.GetIP(c.data.MAC()).Netmask.DefaultMask()

	// default gateway
	dg, err := netaddr.ParseIP(c.data.GetIP(c.data.MAC()).Gateway.String())
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse default gateway from cacher data: %w", err)
	}
	d.DefaultGateway = dg

	// name servers
	for _, ns := range c.DNSServers {
		n := net.ParseIP(ns)
		if n == nil {
			c.Log.Info("skipping invalid DNS server", "server", ns)
			continue
		}
		d.NameServers = append(d.NameServers, net.ParseIP(ns))
	}

	// hostname
	d.Hostname = c.data.instance().Hostname

	// domain name

	// broadcast address

	// ntp servers

	// lease time
	d.LeaseTime = c.LeaseTime

	// domain search

	// netboot options
	n.AllowNetboot = c.data.AllowPXE
	n.IpxeScriptURL = c.data.instance().IPXEScriptURL

	return d, n, nil
}

// DiscoveryCacher presents the structure for old data model.
type DiscoveryCacher struct {
	*HardwareCacher
	mac net.HardwareAddr
}

// HardwareCacher represents the old hardware data model for backward compatibility.
type HardwareCacher struct {
	ID    string        `json:"id"`
	Name  string        `json:"name"`
	State HardwareState `json:"state"`

	BondingMode       BondingMode     `json:"bonding_mode"`
	NetworkPorts      []Port          `json:"network_ports"`
	Manufacturer      Manufacturer    `json:"manufacturer"`
	PlanSlug          string          `json:"plan_slug"`
	PlanVersionSlug   string          `json:"plan_version_slug"`
	Arch              string          `json:"arch"`
	FacilityCode      string          `json:"facility_code"`
	IPMI              IP              `json:"management"`
	IPs               []IP            `json:"ip_addresses"`
	PreinstallOS      OperatingSystem `json:"preinstalled_operating_system_version"`
	PrivateSubnets    []string        `json:"private_subnets,omitempty"`
	UEFI              bool            `json:"efi_boot"`
	AllowPXE          bool            `json:"allow_pxe"`
	AllowWorkflow     bool            `json:"allow_workflow"`
	ServicesVersion   ServicesVersion `json:"services"`
	Instance          *Instance       `json:"instance"`
	ProvisionerEngine string          `json:"provisioner_engine"`
	Traceparent       string          `json:"traceparent"`
}

// HardwareState is the hardware state (e.g. provisioning).
type HardwareState string

// BondingMode is the hardware bonding mode.
type BondingMode int

// Port represents a network port.
type Port struct {
	ID   string   `json:"id"`
	Type PortType `json:"type"`
	Name string   `json:"name"`
	Data struct {
		MAC  *MACAddr `json:"mac"`
		Bond string   `json:"bond"`
	} `json:"data"`
}

// PortType is type for a network port.
type PortType string

// Manufacturer holds data for hardware manufacturer.
type Manufacturer struct {
	ID   string `json:"id"`
	Slug string `json:"slug"`
}

// IP represents IP address for a hardware.
type IP struct {
	Address    net.IP `json:"address"`
	Netmask    net.IP `json:"netmask"`
	Gateway    net.IP `json:"gateway"`
	Family     int    `json:"address_family"`
	Public     bool   `json:"public"`
	Management bool   `json:"management"`
}

// OperatingSystem holds details for the operating system.
type OperatingSystem struct {
	Slug          string         `json:"slug"`
	Distro        string         `json:"distro"`
	Version       string         `json:"version"`
	ImageTag      string         `json:"image_tag"`
	OsSlug        string         `json:"os_slug"`
	Installer     string         `json:"installer,omitempty"`
	InstallerData *InstallerData `json:"installer_data,omitempty"`
}

// InstallerData holds a number of fields that may be used by an installer.
type InstallerData struct {
	Chain  string `json:"chain,omitempty"`
	Script string `json:"script,omitempty"`
}

type ServicesVersion struct {
	OSIE string `json:"osie"`
}

// Instance models the instance data as returned by the API.
type Instance struct {
	ID       string        `json:"id"`
	State    InstanceState `json:"state"`
	Hostname string        `json:"hostname"`
	AllowPXE bool          `json:"allow_pxe"`
	Rescue   bool          `json:"rescue"`

	OS              *OperatingSystem `json:"operating_system"`
	OSV             *OperatingSystem `json:"operating_system_version"`
	AlwaysPXE       bool             `json:"always_pxe,omitempty"`
	IPXEScriptURL   string           `json:"ipxe_script_url,omitempty"`
	IPs             []IP             `json:"ip_addresses"`
	UserData        string           `json:"userdata,omitempty"`
	servicesVersion ServicesVersion  // nolint: structcheck, unused // oh cacher cant wait for you to be gone

	// Same as PasswordHash
	// Duplicated here, because CryptedRootPassword is in cacher/legacy mode
	// which is soon to go away as Tinkerbell/PasswordHash is the future
	CryptedRootPassword string `json:"crypted_root_password,omitempty"`
	// Only returned in the first 24 hours of a provision
	PasswordHash string `json:"password_hash,omitempty"`

	Tags []string `json:"tags,omitempty"`
	// Project
	SSHKeys []string `json:"ssh_keys,omitempty"`
	// CustomData
	NetworkReady bool `json:"network_ready,omitempty"`
	// BootDriveHint defines what the VMware installer should pass as the argument to "--firstdisk=".
	BootDriveHint string `json:"boot_drive_hint,omitempty"`
}

// InstanceState represents the state of an instance (e.g. active).
type InstanceState string

// NetConfig returns the network configuration that corresponds to the interface whose MAC address is mac.
func (d DiscoveryCacher) GetIP(mac net.HardwareAddr) IP {
	ip := d.InstanceIP(mac.String())
	if ip != nil {
		return *ip
	}
	ip = d.ManagementIP(mac.String())
	if ip != nil {
		return *ip
	}
	ip = d.HardwareIP(mac.String())
	if ip != nil {
		return *ip
	}
	ip = d.DiscoveredIP(mac.String())
	if ip != nil {
		return *ip
	}

	return IP{}
}

// InstanceIP returns the IP configuration that should be Offered to the instance if there is one; if it's prov/deprov'ing, it's the hardware IP.
func (d DiscoveryCacher) InstanceIP(mac string) *IP {
	if d.Instance() == nil || d.Instance().ID == "" || !d.MacIsType(mac, "data") || d.PrimaryDataMAC().HardwareAddr().String() != mac {
		return nil
	}
	if ip := d.Instance().FindIP(managementPublicIPv4IP); ip != nil {
		return ip
	}
	if ip := d.Instance().FindIP(managementPrivateIPv4IP); ip != nil {
		return ip
	}
	if d.Instance().State == "provisioning" || d.Instance().State == "deprovisioning" {
		ip := d.hardwareIP()
		if ip != nil {
			return ip
		}
	}

	return nil
}

// HardwareIP returns the IP configuration that should be offered to the hardware if there is no instance.
func (d DiscoveryCacher) HardwareIP(mac string) *IP {
	if !d.MacIsType(mac, "data") {
		return nil
	}
	if d.PrimaryDataMAC().HardwareAddr().String() != mac {
		return nil
	}

	return d.hardwareIP()
}

// hardwareIP returns the IP configuration that should be offered to the hardware (not exported).
func (d DiscoveryCacher) hardwareIP() *IP { // nolint:revive // oh cacher cant wait for you to be gone
	h := d.Hardware()
	for _, ip := range h.HardwareIPs() {
		if ip.Family != 4 {
			continue
		}
		if ip.Public {
			continue
		}

		return &ip
	}

	return nil
}

// ManagementIP returns the IP configuration that should be Offered to the BMC, if the MAC is a BMC MAC.
func (d DiscoveryCacher) ManagementIP(mac string) *IP {
	if d.MacIsType(mac, "ipmi") && d.Name != "" {
		return &d.IPMI
	}

	return nil
}

// DiscoveredIP returns the IP configuration that should be offered to a newly discovered BMC, if the MAC is a BMC MAC.
func (d DiscoveryCacher) DiscoveredIP(mac string) *IP {
	if d.MacIsType(mac, "ipmi") && d.Name == "" {
		return &d.IPMI
	}

	return nil
}

func (d DiscoveryCacher) Instance() *Instance {
	return d.HardwareCacher.Instance
}

func (d DiscoveryCacher) MacIsType(mac string, portType string) bool {
	for _, port := range d.NetworkPorts {
		if port.MAC().String() != mac {
			continue
		}

		return string(port.Type) == portType
	}

	return false
}

// MAC returns the physical hardware address, nil otherwise.
func (p *Port) MAC() net.HardwareAddr {
	if p.Data.MAC != nil && *p.Data.MAC != ZeroMAC {
		return p.Data.MAC.HardwareAddr()
	}

	return nil
}

func (d DiscoveryCacher) MAC() net.HardwareAddr {
	if d.mac == nil {
		mac := d.PrimaryDataMAC()

		return mac.HardwareAddr()
	}

	return d.mac
}

// PrimaryDataMAC returns the mac associated with eth0, or as a fallback the lowest numbered non-bmc MAC address.
func (d DiscoveryCacher) PrimaryDataMAC() MACAddr {
	mac := OnesMAC
	for _, port := range d.NetworkPorts {
		if port.Type != "data" {
			continue
		}
		if port.Name == "eth0" {
			mac = *port.Data.MAC

			break
		}
		if port.MAC().String() < mac.String() {
			mac = *port.Data.MAC
		}
	}

	if mac.IsOnes() {
		return ZeroMAC
	}

	return mac
}

// FindIP returns IP for an instance, nil otherwise.
func (i *Instance) FindIP(pred func(IP) bool) *IP {
	for _, ip := range i.IPs {
		if pred(ip) {
			return &ip
		}
	}

	return nil
}

func managementPublicIPv4IP(ip IP) bool {
	return ip.Public && ip.Management && ip.Family == 4
}

func managementPrivateIPv4IP(ip IP) bool {
	return !ip.Public && ip.Management && ip.Family == 4
}

func (d DiscoveryCacher) Hardware() Hardware {
	var h Hardware = d.HardwareCacher

	return h
}

type HardwareID string

// Hardware interface holds primary hardware methods.
type Hardware interface {
	HardwareAllowPXE(mac net.HardwareAddr) bool
	HardwareAllowWorkflow(mac net.HardwareAddr) bool
	HardwareArch(mac net.HardwareAddr) string
	HardwareBondingMode() BondingMode
	HardwareFacilityCode() string
	HardwareID() HardwareID
	HardwareIPs() []IP
	Interfaces() []Port // TODO: to be updated
	HardwareManufacturer() string
	HardwareProvisioner() string
	HardwarePlanSlug() string
	HardwarePlanVersionSlug() string
	HardwareState() HardwareState
	HardwareOSIEVersion() string
	HardwareUEFI(mac net.HardwareAddr) bool
	OSIEBaseURL(mac net.HardwareAddr) string
	KernelPath(mac net.HardwareAddr) string
	InitrdPath(mac net.HardwareAddr) string
	OperatingSystem() *OperatingSystem
	GetTraceparent() string
}

func (h HardwareCacher) Interfaces() []Port {
	ports := make([]Port, 0, len(h.NetworkPorts)-1)
	for _, p := range h.NetworkPorts {
		if p.Type == "ipmi" {
			continue
		}
		ports = append(ports, p)
	}
	if len(ports) == 0 {
		return nil
	}

	return ports
}

func (h HardwareCacher) HardwareAllowPXE(_ net.HardwareAddr) bool {
	return h.AllowPXE
}

func (h HardwareCacher) HardwareAllowWorkflow(_ net.HardwareAddr) bool {
	return h.AllowWorkflow
}

func (h HardwareCacher) HardwareArch(_ net.HardwareAddr) string {
	return h.Arch
}

func (h HardwareCacher) HardwareBondingMode() BondingMode {
	return h.BondingMode
}

func (h HardwareCacher) HardwareFacilityCode() string {
	return h.FacilityCode
}

func (h HardwareCacher) HardwareID() HardwareID {
	return HardwareID(h.ID)
}

func (h HardwareCacher) HardwareIPs() []IP {
	return h.IPs
}

func (h HardwareCacher) HardwareIPMI() IP {
	return h.IPMI
}

func (h HardwareCacher) HardwareManufacturer() string {
	return h.Manufacturer.Slug
}

func (h HardwareCacher) HardwareProvisioner() string {
	return h.ProvisionerEngine
}

func (h HardwareCacher) HardwarePlanSlug() string {
	return h.PlanSlug
}

func (h HardwareCacher) HardwarePlanVersionSlug() string {
	return h.PlanVersionSlug
}

func (h HardwareCacher) HardwareOSIEVersion() string {
	return h.ServicesVersion.OSIE
}

func (h HardwareCacher) HardwareState() HardwareState {
	return h.State
}

func (h HardwareCacher) HardwareUEFI(_ net.HardwareAddr) bool {
	return h.UEFI
}

// dummy method for tink data model transition.
func (h HardwareCacher) OSIEBaseURL(_ net.HardwareAddr) string {
	return ""
}

// dummy method for tink data model transition.
func (h HardwareCacher) KernelPath(_ net.HardwareAddr) string {
	return ""
}

// dummy method for tink data model transition.
func (h HardwareCacher) InitrdPath(_ net.HardwareAddr) string {
	return ""
}

func (h *HardwareCacher) OperatingSystem() *OperatingSystem {
	i := h.instance()
	if i.OSV == (*OperatingSystem)(nil) {
		i.OSV = &OperatingSystem{}
	}

	return i.OSV
}

func (h *HardwareCacher) instance() *Instance {
	if h.Instance == nil {
		h.Instance = &Instance{}
	}

	return h.Instance
}

func (h HardwareCacher) GetTraceparent() string {
	return h.Traceparent
}
