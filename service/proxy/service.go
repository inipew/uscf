package proxy

import (
	"context"

	"github.com/HynoR/uscf/config"
	"github.com/HynoR/uscf/service/socks"
	"github.com/HynoR/uscf/service/tunnel"
)

// Service coordinates the SOCKS proxy and MASQUE tunnel.
type Service struct {
	Tunnel tunnel.Manager
}

// New creates a Service with the given tunnel manager.
func New(m tunnel.Manager) *Service {
	return &Service{Tunnel: m}
}

// Run initializes and starts the MASQUE tunnel and SOCKS proxy.
func (s *Service) Run(ctx context.Context, cfg *config.Config) error {
	tlsCfg, err := tunnel.PrepareTLSConfig(cfg)
	if err != nil {
		return err
	}

	endpoint, locals, dnsAddrs, err := tunnel.PrepareNetworkConfig(cfg)
	if err != nil {
		return err
	}

	connTimeout, idleTimeout := tunnel.TimeoutSettings(cfg)
	dev, netTun, err := tunnel.CreateTun(locals, dnsAddrs, cfg)
	if err != nil {
		return err
	}
	defer dev.Close()

	tunnel.StartTunnel(ctx, s.Tunnel, tlsCfg, endpoint, cfg, dev)
	return socks.Run(ctx, cfg, netTun, connTimeout, idleTimeout)
}
