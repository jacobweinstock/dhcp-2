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
	"go.opentelemetry.io/otel/trace"
	"inet.af/netaddr"
)

// UserClass is DHCP option 77 (https://www.rfc-editor.org/rfc/rfc3004.html).
type UserClass string

// clientType is from DHCP option 60. Normally on PXEClient or HTTPClient.
type clientType string

const (
	httpClient clientType = "HTTPClient"
)

// known user-class types. must correspond to DHCP option 77 - User-Class
// https://www.rfc-editor.org/rfc/rfc3004.html
const (
	// If the client has had iPXE burned into its ROM (or is a VM
	// that uses iPXE as the PXE "ROM"), special handling is
	// needed because in this mode the client is using iPXE native
	// drivers and chainloading to a UNDI stack won't work.
	IPXE UserClass = "iPXE"
	// If the client identifies as "Tinkerbell", we've already
	// chainloaded this client to the full-featured copy of iPXE
	// we supply. We have to distinguish this case so we don't
	// loop on the chainload step.
	Tinkerbell UserClass = "Tinkerbell"
)

// ArchToBootFile maps supported hardware PXE architectures types to iPXE binary files.
var ArchToBootFile = map[iana.Arch]string{
	iana.INTEL_X86PC:       "undionly.kpxe",
	iana.NEC_PC98:          "undionly.kpxe",
	iana.EFI_ITANIUM:       "undionly.kpxe",
	iana.DEC_ALPHA:         "undionly.kpxe",
	iana.ARC_X86:           "undionly.kpxe",
	iana.INTEL_LEAN_CLIENT: "undionly.kpxe",
	iana.EFI_IA32:          "ipxe.efi",
	iana.EFI_X86_64:        "ipxe.efi",
	iana.EFI_XSCALE:        "ipxe.efi",
	iana.EFI_BC:            "ipxe.efi",
	iana.EFI_ARM32:         "snp.efi",
	iana.EFI_ARM64:         "snp.efi",
	iana.EFI_X86_HTTP:      "ipxe.efi",
	iana.EFI_X86_64_HTTP:   "ipxe.efi",
	iana.EFI_ARM32_HTTP:    "snp.efi",
	iana.EFI_ARM64_HTTP:    "snp.efi",
	iana.Arch(41):          "snp.efi", // arm rpiboot: https://www.iana.org/assignments/dhcpv6-parameters/dhcpv6-parameters.xhtml#processor-architecture
}

func (c clientType) String() string {
	return string(c)
}

func (c UserClass) String() string {
	return string(c)
}

// setDHCPOpts takes a client dhcp packet and data (typically from a backend) and creates a slice of DHCP packet modifiers.
// m is the DHCP request from a client. d is the data to use to create the DHCP packet modifiers.
// This is most likely the place where we would have any business logic for determining DHCP option setting.
func (s *Server) setDHCPOpts(_ context.Context, clientPkt *dhcpv4.DHCPv4, d *data.Dhcp) []dhcpv4.Modifier {
	// need to handle option 82

	prl := clientPkt.ParameterRequestList()
	list := map[uint8]string{}
	for _, o := range prl {
		list[o.Code()] = o.String()
	}
	s.Log.Info("DEBUGGING", "option 55", list)

	var mods []dhcpv4.Modifier
	mods = append(mods,
		dhcpv4.WithDNS(d.NameServers...),
		dhcpv4.WithDomainSearchList(d.DomainSearch...),
		dhcpv4.WithOption(dhcpv4.OptNTPServers(d.NTPServers...)),
		dhcpv4.WithGeneric(dhcpv4.OptionBroadcastAddress, d.BroadcastAddress.IPAddr().IP),
		dhcpv4.WithGeneric(dhcpv4.OptionDomainName, []byte(d.DomainName)),
		dhcpv4.WithGeneric(dhcpv4.OptionHostName, []byte(d.Hostname)),
		dhcpv4.WithNetmask(d.SubnetMask),
		dhcpv4.WithRouter(d.DefaultGateway.IPAddr().IP), // this seems to be the gateway ip not WithGatewayIP()
		dhcpv4.WithGatewayIP(d.DefaultGateway.IPAddr().IP),
		dhcpv4.WithLeaseTime(d.LeaseTime),
		dhcpv4.WithYourIP(d.IPAddress.IPAddr().IP),
	)

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
func (s *Server) setNetworkBootOpts(ctx context.Context, m *dhcpv4.DHCPv4, n *data.Netboot) func(d *dhcpv4.DHCPv4) {
	// m is the received DHCPv4 packet.
	// d is the reply packet we are building.
	withNetboot := func(d *dhcpv4.DHCPv4) {
		d.BootFileName = "/netboot-not-allowed"
		d.ServerIPAddr = net.IPv4(0, 0, 0, 0)

		// echo back opt 60 if its an httpClient
		if val := m.Options.Get(dhcpv4.OptionClassIdentifier); val != nil {
			if strings.HasPrefix(string(val), string(httpClient)) {
				d.UpdateOption(dhcpv4.OptGeneric(dhcpv4.OptionClassIdentifier, []byte(httpClient)))
			}
		}
		if n.AllowNetboot {
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
				6:  []byte{8}, // or []byte{8}
				69: binaryTpFromContext(ctx),
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
		bootfile = "didnt get one"
		if iscript != nil {
			bootfile = iscript.String()
		}
		// "https://boot.netboot.xyz" // fmt.Sprintf("%s/%s/%s", ipxe, mac.String(), iscript)
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

// binaryTpFromContext extracts the binary trace id, span id, and trace flags
// from the running span in ctx and returns a 26 byte []byte with the traceparent
// encoded and ready to pass in opt43
// see test/test-boots.sh for how to decode tp with busybox udhcpc & cut(1).
func binaryTpFromContext(ctx context.Context) []byte {
	sc := trace.SpanContextFromContext(ctx)
	tpBytes := make([]byte, 0, 26)

	// the otel spec says 16 bytes for trace id and 8 for spans are good enough
	// for everyone copy them into a []byte that we can deliver over option43
	tid := [16]byte(sc.TraceID()) // type TraceID [16]byte
	sid := [8]byte(sc.SpanID())   // type SpanID [8]byte

	tpBytes = append(tpBytes, 0x00)      // traceparent version
	tpBytes = append(tpBytes, tid[:]...) // trace id
	tpBytes = append(tpBytes, sid[:]...) // span id
	if sc.IsSampled() {
		tpBytes = append(tpBytes, 0x01) // trace flags
	} else {
		tpBytes = append(tpBytes, 0x00)
	}

	return tpBytes
}
