# dhcp

DHCP is a dhcp server backed by Tink server. All IP addresses are served as DHCP reservations. There are no leases.

## Definitions

**DHCP Reservation:**
A fixed IP address that is reserved for a specific client.

**DHCP Lease:**
An IP address, that can potentially change, that is assigned to a client by the DHCP server.
The IP is typically pulled from a pool or subnet of available IP addresses.
