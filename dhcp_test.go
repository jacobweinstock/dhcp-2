package dhcp

import (
	"context"
	"net"
	"sync"
	"testing"

	"github.com/google/go-cmp/cmp"
	"inet.af/netaddr"
)

func TestListenAndServe(t *testing.T) {
	tests := map[string]struct {
		wantErr error
	}{
		"success": {
			wantErr: nil,
		},
		/*"fail": {
			wantErr: &net.OpError{
				Op:   "listen",
				Net:  "udp",
				Addr: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 69},
				Err:  fmt.Errorf("bind: permission denied"),
			},
		},*/
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			got := &Server{}
			ctx, cn := context.WithCancel(context.Background())

			var err error
			var wg sync.WaitGroup
			wg.Add(1)
			go func() {
				err = got.ListenAndServe(ctx)

				wg.Done()
			}()
			cn()
			wg.Wait()

			switch {
			case tt.wantErr == nil && err != nil:
				t.Errorf("expected nil error, got: %T (%[1]v)", err)
			case tt.wantErr != nil && err == nil:
				t.Errorf("expected error, got: nil")
			case tt.wantErr != nil && err != nil:
				if diff := cmp.Diff(err.Error(), tt.wantErr.Error()); diff != "" {
					t.Fatal(diff)
				}
			}
		})
	}
}

func TestServe(t *testing.T) {
	tests := map[string]struct {
		wantErr    error
		wantUDPErr bool
	}{
		"success": {
			wantErr: nil,
		},
		/*"fail udp listener": {
			wantErr:    fmt.Errorf("udp conn must not be nil"),
			wantUDPErr: true,
		},*/
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			got := &Server{}
			ctx, cn := context.WithCancel(context.Background())

			var uconn net.PacketConn
			var err error
			if !tt.wantUDPErr {
				a, err := net.ResolveUDPAddr("udp", "0.0.0.0:0")
				if err != nil {
					t.Fatal(err)
				}
				uconn, err = net.ListenUDP("udp", a)
				if err != nil {
					t.Fatal(err)
				}
			}

			var wg sync.WaitGroup
			wg.Add(1)
			go func() {
				err = got.Serve(ctx, uconn)
				wg.Done()
			}()
			cn()
			wg.Wait()

			switch {
			case tt.wantErr == nil && err != nil:
				t.Errorf("expected nil error, got: %T", err)
			case tt.wantErr != nil && err == nil:
				t.Errorf("expected error, got: nil")
			case tt.wantErr != nil && err != nil:
				if diff := cmp.Diff(err.Error(), tt.wantErr.Error()); diff != "" {
					t.Fatal(diff)
				}
			}
		})
	}
}

func TestDefaultIP(t *testing.T) {
	tests := map[string]struct {
		want netaddr.IP
	}{
		"success": {netaddr.IPv4(0, 0, 0, 0)},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			got := defaultIP()
			if got.Compare(tt.want) == 0 {
				t.Fatalf("defaultIP() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGetInterfaceByIP(t *testing.T) {
	tests := map[string]struct {
		ip     string
		wantIF []string
	}{
		"success": {
			ip:     "127.0.0.1",
			wantIF: []string{"lo0", "lo"},
		},
		"not found": {
			ip:     "1.1.1.1",
			wantIF: []string{""},
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			var diffs []string
			for _, want := range tt.wantIF {
				if diff := cmp.Diff(getInterfaceByIP(tt.ip), want); diff != "" {
					diffs = append(diffs, diff)
				}
			}
			if len(diffs) == len(tt.wantIF) {
				t.Fatalf("%v", diffs)
			}
		})
	}
}
