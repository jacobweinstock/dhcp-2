package file

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"

	"github.com/fsnotify/fsnotify"
	"github.com/ghodss/yaml"
	"github.com/go-logr/logr"
	"github.com/jacobweinstock/dhcp/data"
	"inet.af/netaddr"
)

type Conn struct {
	DataMu   sync.RWMutex
	Data     []byte
	FilePath string
	Watcher  *fsnotify.Watcher
	Log      logr.Logger
}

func NewFile(f string, l logr.Logger) (*Conn, error) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, err
	}
	if err := watcher.Add(f); err != nil {
		return nil, err
	}

	d, err := readfile(f)
	if err != nil {
		return nil, err
	}

	return &Conn{
		FilePath: f,
		Data:     d,
		Watcher:  watcher,
		Log:      l,
	}, nil
}

func (c *Conn) Read(_ context.Context, mac net.HardwareAddr) (*data.Dhcp, *data.Netboot, error) {
	// get data from file, translate it, then pass it into setDHCPOpts and setNetworkBootOpts
	c.DataMu.RLock()
	d := c.Data
	c.DataMu.RUnlock()
	r := make(map[string]dhcp)
	if err := yaml.Unmarshal(d, &r); err != nil {
		return nil, nil, fmt.Errorf("failed to marshal data: %w", err)
	}
	for k, v := range r {
		if strings.EqualFold(k, mac.String()) {
			// found a record for this mac address
			v.MacAddress = mac
			return translate(v)
		}
	}

	return nil, nil, fmt.Errorf("no record found for mac %s", mac.String())
}

func translate(r dhcp) (*data.Dhcp, *data.Netboot, error) {
	d := new(data.Dhcp)
	n := new(data.Netboot)

	d.MacAddress = r.MacAddress
	// ip address
	ip, err := netaddr.ParseIP(r.IPAddress)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse ip address from Tink record: %w", err)
	}
	d.IPAddress = ip

	// subnet mask
	sm, err := netaddr.ParseIP(r.SubnetMask)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse subnet mask from Tink record: %w", err)
	}
	d.SubnetMask = sm.IPAddr().IP.DefaultMask()

	// default gateway
	dg, err := netaddr.ParseIP(r.DefaultGateway)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse default gateway from Tink record: %w", err)
	}
	d.DefaultGateway = dg

	// name servers
	for _, s := range r.NameServers {
		ip := net.ParseIP(s)
		if ip == nil {
			fmt.Println("failed to parse name server", s)
			break
		}
		d.NameServers = append(d.NameServers, ip)
	}

	// hostname
	d.Hostname = r.Hostname

	// domain name
	d.DomainName = r.DomainName

	// broadcast address
	ba, err := netaddr.ParseIP(r.BroadcastAddress)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse broadcast address from Tink record: %w", err)
	}
	d.BroadcastAddress = ba

	// ntp servers
	for _, s := range r.NtpServers {
		ip := net.ParseIP(s)
		if ip == nil {
			fmt.Println("failed to parse ntp server", s)
			break
		}
		d.NTPServers = append(d.NTPServers, ip)
	}

	// lease time
	// TODO(jacobweinstock): write some validations. > 0, etc.
	d.LeaseTime = uint32(r.LeaseTime)

	// domain search
	d.DomainSearch = r.DomainSearch

	n.AllowPxe = r.Netboot.AllowPxe
	n.IpxeScriptURL = r.Netboot.IpxeScriptURL

	return d, n, nil
}

type netboot struct {
	AllowPxe      bool   `yaml:"allowPxe"`      // If true, the client will be provided netboot options in the DHCP offer/ack.
	IpxeScriptURL string `yaml:"ipxeScriptUrl"` // Overrides default value of that is passed into DHCP on startup.
}

type dhcp struct {
	MacAddress       net.HardwareAddr // The MAC address of the client.
	IPAddress        string           `yaml:"ipAddress"`        // yiaddr DHCP header.
	SubnetMask       string           `yaml:"subnetMask"`       // DHCP option 1.
	DefaultGateway   string           `yaml:"defaultGateway"`   // DHCP option 3.
	NameServers      []string         `yaml:"nameServers"`      // DHCP option 6.
	Hostname         string           `yaml:"hostname"`         // DHCP option 12.
	DomainName       string           `yaml:"domainName"`       // DHCP option 15.
	BroadcastAddress string           `yaml:"broadcastAddress"` // DHCP option 28.
	NtpServers       []string         `yaml:"ntpServers"`       // DHCP option 42.
	LeaseTime        int              `yaml:"leaseRime"`        // DHCP option 51.
	DomainSearch     []string         `yaml:"domainSearch"`     // DHCP option 119.
	Netboot          netboot          `yaml:"netboot"`
}

func readfile(filePath string) ([]byte, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	d, err := io.ReadAll(f)
	if err != nil {
		return nil, fmt.Errorf("failed to read data from file: %w", err)
	}
	return d, nil
}

func (c *Conn) StartWatcher() {
	for {
		select {
		case event, ok := <-c.Watcher.Events:
			if !ok {
				continue
			}
			if event.Op&fsnotify.Write == fsnotify.Write {
				c.Log.Info("file changed, updating cache")
				c.DataMu.Lock()
				d, err := readfile(c.FilePath)
				if err != nil {
					c.DataMu.Unlock()
					c.Log.Error(err, "failed to read file", "file", c.FilePath)
					break
				}
				c.Data = d
				c.DataMu.Unlock()
			}
		case err, ok := <-c.Watcher.Errors:
			if !ok {
				continue
			}
			c.Log.Info("error watching file: %v", err)
		}
	}
}
