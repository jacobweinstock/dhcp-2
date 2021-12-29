package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	logrusr "github.com/bombsimon/logrusr/v2"
	log_prefixed "github.com/chappjc/logrus-prefix"
	"github.com/coredhcp/coredhcp/handler"
	"github.com/coredhcp/coredhcp/plugins"
	"github.com/go-logr/logr"
	"github.com/go-logr/stdr"
	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/jacobweinstock/dhcp"
	"github.com/sirupsen/logrus"
)

func main() {
	ctx, done := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGHUP, syscall.SIGTERM)
	defer done()
	l := stdr.NewWithOptions(log.New(os.Stderr, "", log.LstdFlags), stdr.Options{LogCaller: stdr.All})
	logrusLog := logrus.New()
	logrusLog.SetFormatter(&log_prefixed.TextFormatter{
		FullTimestamp: true,
		ForceColors:   true,
	})
	l = logrusr.New(logrusLog)
	s := &dhcp.Server{Log: l}
	if err := s.ListenAndServe(ctx, &mock{log: l}); err != nil {
		fmt.Printf("ListenAndServe() error = %v, type: %T", err, err)
	}
}

type mock struct {
	log logr.Logger
}

func (m *mock) Name(ctx context.Context) string {
	return "mock"
}

func (m *mock) Args(ctx context.Context) []string {
	return []string{}
}

func (m *mock) Handle(ctx context.Context) *plugins.Plugin {
	return m.mockPlugin()
}

func (m *mock) mockPlugin() *plugins.Plugin {
	setup4 := func(args ...string) (handler.Handler4, error) {
		m.log.Info("debugging", "keys", args)
		return m.mockHandler4, nil
	}
	name := m.Name(context.Background())
	m.log.Info(name)
	return &plugins.Plugin{Name: name, Setup4: setup4}
}

func (m *mock) mockHandler4(req, resp *dhcpv4.DHCPv4) (*dhcpv4.DHCPv4, bool) {
	m.log.Info("received DHCPv4 packet", "summary", req.Summary())
	// return the unmodified response, and false. This means that the next
	// plugin in the chain will be called, and the unmodified response packet
	// will be used as its input.
	return resp, false
}
