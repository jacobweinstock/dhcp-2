package cacher

import (
	"context"
	"net"
	"os"

	"github.com/jacobweinstock/dhcp/data"
	"github.com/packethost/cacher/client"
)

type Conn struct {
	Facility      string
	UseTLS        string
	CertURL       string
	GRPCAuthority string
}

func (c *Conn) Read(_ context.Context, mac net.HardwareAddr) (*data.Dhcp, *data.Netboot, error) {
	os.Setenv("CACHER_USE_TLS", c.UseTLS)
	os.Setenv("CACHER_CERT_URL", c.CertURL)
	os.Setenv("CACHER_GRPC_AUTHORITY", c.GRPCAuthority)
	conn, err := client.New(c.Facility)
	if err != nil {
		return nil, nil, err
	}
	defer conn.Close()

	conn

	return nil, nil, nil
}
