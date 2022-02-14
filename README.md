[![Test and Build](https://github.com/jacobweinstock/dhcp/actions/workflows/ci.yaml/badge.svg)](https://github.com/jacobweinstock/dhcp/actions/workflows/ci.yaml)
[![codecov](https://codecov.io/gh/jacobweinstock/dhcp/branch/main/graph/badge.svg)](https://codecov.io/gh/jacobweinstock/dhcp)
[![Go Report Card](https://goreportcard.com/badge/github.com/jacobweinstock/dhcp)](https://goreportcard.com/report/github.com/jacobweinstock/dhcp)
[![Go Reference](https://pkg.go.dev/badge/github.com/jacobweinstock/dhcp.svg)](https://pkg.go.dev/github.com/jacobweinstock/dhcp)

# dhcp

DHCP is a dhcp server backed by Tink server. All IP addresses are served as DHCP reservations. There are no leases.

## Definitions

**DHCP Reservation:**
A fixed IP address that is reserved for a specific client.

**DHCP Lease:**
An IP address, that can potentially change, that is assigned to a client by the DHCP server.
The IP is typically pulled from a pool or subnet of available IP addresses.
