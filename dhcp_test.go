package dhcp

import (
	"context"
	"log"
	"os"
	"testing"
	"time"

	logrusr "github.com/bombsimon/logrusr/v2"
	"github.com/coredhcp/coredhcp/handler"
	"github.com/coredhcp/coredhcp/plugins"
	"github.com/go-logr/logr"
	"github.com/go-logr/stdr"
	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/sirupsen/logrus"
	log_prefixed "github.com/chappjc/logrus-prefix"
)

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

func TestListenAndServe(t *testing.T) {
	/*
		tests := []struct {
			name    string
			wantErr bool
		}{
			// TODO: Add test cases.
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				if err := ListenAndServe(); (err != nil) != tt.wantErr {
					t.Errorf("ListenAndServe() error = %v, wantErr %v", err, tt.wantErr)
				}
			})
		}
	*/
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()
	l := stdr.NewWithOptions(log.New(os.Stderr, "", log.LstdFlags), stdr.Options{LogCaller: stdr.All})
	logrusLog := logrus.New()
	logrusLog.SetFormatter(&log_prefixed.TextFormatter{
		FullTimestamp: true,
		ForceColors: true,
	})
	l = logrusr.New(logrusLog)
	s := &Server{Log: l}
	if err := s.ListenAndServe(ctx, &mock{log: l}); err != nil {
		t.Fatalf("ListenAndServe() error = %v, type: %T", err, err)
	}
	t.Fail()
}
