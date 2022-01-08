package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/go-logr/stdr"
	"github.com/jacobweinstock/dhcp"
	"inet.af/netaddr"
)

func main() {
	ctx, done := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGHUP, syscall.SIGTERM)
	defer done()
	l := stdr.NewWithOptions(log.New(os.Stderr, "", log.LstdFlags), stdr.Options{LogCaller: stdr.All})

	s := dhcp.Server{Log: l, ListenAddr: netaddr.IPPortFrom(netaddr.IPv4(192, 168, 2, 225), 67)}
	l.Info("starting server", "addr", s.ListenAddr)
	l.Error(s.ListenAndServe(ctx), "done")
	l.Info("done")
}
