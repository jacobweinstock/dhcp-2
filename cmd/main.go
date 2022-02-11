package main

import (
	"context"
	"net/url"
	"os"
	"os/signal"
	"syscall"

	"github.com/go-logr/logr"
	"github.com/go-logr/zerologr"
	"github.com/jacobweinstock/dhcp"
	"github.com/rs/zerolog"
	"inet.af/netaddr"
)

func main() {
	ctx, done := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGHUP, syscall.SIGTERM)
	defer done()
	// l := stdr.NewWithOptions(log.New(os.Stderr, "", log.LstdFlags), stdr.Options{LogCaller: stdr.All})
	l := defaultLogger("debug")
	l = l.WithName("github.com/tinkerbell/dhcp")

	s := dhcp.Server{
		Log:               l,
		ListenAddr:        netaddr.IPPortFrom(netaddr.IPv4(192, 168, 2, 225), 67),
		IPAddr:            netaddr.IPv4(192, 168, 2, 225),
		IPXEBinServerTFTP: netaddr.IPPortFrom(netaddr.IPv4(192, 168, 2, 225), 69),
		IPXEBinServerHTTP: &url.URL{Scheme: "http", Host: "192.168.2.225:8080"},
		IPXEScriptURL:     &url.URL{Scheme: "https", Host: "boot.netboot.xyz"},
	}
	l.Info("starting server", "addr", s.ListenAddr)
	l.Error(s.ListenAndServe(ctx), "done")
	l.Info("done")
}

// defaultLogger is a zerolog logr implementation.
func defaultLogger(level string) logr.Logger {
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnixMs
	zerologr.NameFieldName = "logger"
	zerologr.NameSeparator = "/"

	zl := zerolog.New(os.Stdout)
	zl = zl.With().Caller().Timestamp().Logger()
	var l zerolog.Level
	switch level {
	case "debug":
		l = zerolog.DebugLevel
	default:
		l = zerolog.InfoLevel
	}
	zl = zl.Level(l)

	return zerologr.New(&zl)
}
