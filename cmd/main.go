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
	"github.com/jacobweinstock/dhcp/backend/cacher"
	"github.com/jacobweinstock/dhcp/backend/file"
	"github.com/jacobweinstock/dhcp/backend/tink"
	"github.com/packethost/cacher/client"
	"github.com/rs/zerolog"
	"inet.af/netaddr"
)

func main() {
	ctx, done := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGHUP, syscall.SIGTERM)
	defer done()
	l := defaultLogger("debug")
	l = l.WithName("github.com/tinkerbell/dhcp")

	b, err := BackendFile(l, "./example/dhcp.yaml")
	// b, err := BackendTink(l)
	if err != nil {
		panic(err)
	}
	s := dhcp.Server{
		Log:               l,
		Listener:        netaddr.IPPortFrom(netaddr.IPv4(192, 168, 2, 225), 67),
		IPAddr:            netaddr.IPv4(192, 168, 2, 225),
		IPXEBinServerTFTP: netaddr.IPPortFrom(netaddr.IPv4(192, 168, 1, 34), 69),
		IPXEBinServerHTTP: &url.URL{Scheme: "http", Host: "192.168.1.34:8080"},
		IPXEScriptURL:     &url.URL{Scheme: "https", Host: "boot.netboot.xyz"},
		NetbootEnabled:    true,
		Backend:           b,
	}
	l.Info("starting server", "addr", s.Listener)
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

func BackendCacher(l logr.Logger, useTLS string, certURL string, grpcAuthority string, f string) (dhcp.BackendReader, error) { // nolint: deadcode // this is just an example file
	os.Setenv("CACHER_USE_TLS", useTLS)
	os.Setenv("CACHER_CERT_URL", certURL)
	os.Setenv("CACHER_GRPC_AUTHORITY", grpcAuthority)
	cli, err := client.New(f)
	if err != nil {
		return nil, err
	}
	c := &cacher.Conn{
		Log:    l,
		Client: cli,
	}
	return c, nil
	// defer cli.Conn.Close()
}

func BackendTink(l logr.Logger) (dhcp.BackendReader, error) { // nolint: unparam // this is just an example file
	return &tink.Conn{
		Log: l,
	}, nil
}

func BackendFile(l logr.Logger, f string) (dhcp.BackendReader, error) { // nolint: deadcode // this is just an example file
	fb, err := file.NewFile(f, l)
	if err != nil {
		return nil, err
	}
	go fb.StartWatcher()
	return fb, nil
}
