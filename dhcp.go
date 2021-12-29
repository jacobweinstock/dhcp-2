package dhcp

import (
	"context"
	"fmt"
	"net"
	"reflect"

	"github.com/coredhcp/coredhcp/config"
	"github.com/coredhcp/coredhcp/plugins"
	"github.com/coredhcp/coredhcp/server"
	"github.com/go-logr/logr"
	"github.com/imdario/mergo"
)

type Server struct {
	Log  logr.Logger
	Addr net.UDPAddr
}

type Handler interface {
	Name(context.Context) string
	Args(context.Context) []string
	Handle(context.Context) *plugins.Plugin
}

func (s *Server) ListenAndServe(ctx context.Context, h Handler) error {
	defaults := Server{
		Log:  logr.Discard(),
		Addr: net.UDPAddr{Port: 67},
	}

	err := mergo.Merge(s, defaults, mergo.WithTransformers(s))
	if err != nil {
		return err
	}

	l := s.Log
	l.Info("debugging", "name", h.Name(ctx))
	if err := plugins.RegisterPlugin(h.Handle(ctx)); err != nil {
		return fmt.Errorf("error registering plugin: %w", err)
	}

	cfg := &config.Config{
		Server4: &config.ServerConfig{
			Addresses: []net.UDPAddr{
				s.Addr,
			},
			Plugins: []config.PluginConfig{
				{Name: h.Name(ctx), Args: h.Args(ctx)},
			},
		},
	}
	// start server
	srv, err := server.Start(cfg)
	if err != nil {
		return err
	}

	<-ctx.Done()
	srv.Close()
	l.Info("shutting down")
	return nil
}

// Transformer for merging the logr.Logger struct.
// Can be extended for other types by adding cases.
func (*Server) Transformer(typ reflect.Type) func(dst, src reflect.Value) error {
	switch typ {
	case reflect.TypeOf(logr.Logger{}):
		return func(dst, src reflect.Value) error {
			if dst.CanSet() {
				getSink := dst.MethodByName("GetSink")
				result := getSink.Call(nil)
				if result[0].IsNil() {
					dst.Set(src)
				}
			}
			return nil
		}
	}
	return nil
}
