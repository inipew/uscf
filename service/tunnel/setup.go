package tunnel

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/netip"
	"time"

	"github.com/HynoR/uscf/api"
	"github.com/HynoR/uscf/config"
	"github.com/HynoR/uscf/internal"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

// PrepareTLSConfig creates a TLS configuration for the MASQUE tunnel.
func PrepareTLSConfig(cfg *config.Config) (*tls.Config, error) {
	privKey, err := cfg.GetEcPrivateKey()
	if err != nil {
		return nil, fmt.Errorf("failed to get private key: %w", err)
	}

	peerPubKey, err := cfg.GetEcEndpointPublicKey()
	if err != nil {
		return nil, fmt.Errorf("failed to get public key: %w", err)
	}

	cert, err := internal.GenerateCert(privKey, &privKey.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to generate cert: %w", err)
	}

	tlsConfig, err := api.PrepareTlsConfig(privKey, peerPubKey, cert, cfg.Tunnel.SNIAddress)
	if err != nil {
		return nil, fmt.Errorf("failed to prepare TLS config: %w", err)
	}
	return tlsConfig, nil
}

// PrepareNetworkConfig returns tunnel endpoint and address configuration.
func PrepareNetworkConfig(cfg *config.Config) (*net.UDPAddr, []netip.Addr, []netip.Addr, error) {
	var endpoint *net.UDPAddr
	if cfg.Tunnel.UseIPv6 {
		endpoint = &net.UDPAddr{IP: net.ParseIP(cfg.EndpointV6), Port: cfg.Tunnel.ConnectPort}
	} else {
		endpoint = &net.UDPAddr{IP: net.ParseIP(cfg.EndpointV4), Port: cfg.Tunnel.ConnectPort}
	}

	var locals []netip.Addr
	if !cfg.Tunnel.NoTunnelIPv4 {
		v4, err := netip.ParseAddr(cfg.IPv4)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("failed to parse IPv4 address: %w", err)
		}
		locals = append(locals, v4)
	}
	if !cfg.Tunnel.NoTunnelIPv6 {
		v6, err := netip.ParseAddr(cfg.IPv6)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("failed to parse IPv6 address: %w", err)
		}
		locals = append(locals, v6)
	}

	var dnsAddrs []netip.Addr
	for _, dns := range cfg.Tunnel.DNS {
		addr, err := netip.ParseAddr(dns)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("failed to parse DNS server: %w", err)
		}
		dnsAddrs = append(dnsAddrs, addr)
	}

	return endpoint, locals, dnsAddrs, nil
}

// TimeoutSettings returns the connection and idle timeout values.
func TimeoutSettings(cfg *config.Config) (time.Duration, time.Duration) {
	conn := cfg.Tunnel.ConnectionTimeout.Duration()
	idle := cfg.Tunnel.IdleTimeout.Duration()
	if conn == 0 {
		conn = 30 * time.Second
	}
	if idle == 0 {
		idle = 5 * time.Minute
	}
	return conn, idle
}

// CreateTun sets up the virtual network interface for the tunnel.
func CreateTun(local, dns []netip.Addr, cfg *config.Config) (tun.Device, *netstack.Net, error) {
	if cfg.Tunnel.MTU != 1280 {
		log.Println("Warning: MTU is not the default 1280. Packet loss may occur")
	}
	dev, netTun, err := netstack.CreateNetTUN(local, dns, cfg.Tunnel.MTU)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create virtual TUN device: %w", err)
	}
	return dev, netTun, nil
}

// StartTunnel launches the MASQUE tunnel in a background goroutine.
func StartTunnel(ctx context.Context, m Manager, tlsCfg *tls.Config, endpoint *net.UDPAddr, cfg *config.Config, dev tun.Device) {
	conf := api.ConnectionConfig{
		TLSConfig:         tlsCfg,
		KeepAlivePeriod:   cfg.Tunnel.KeepalivePeriod.Duration(),
		InitialPacketSize: cfg.Tunnel.InitialPacketSize,
		Endpoint:          endpoint,
		MTU:               cfg.Tunnel.MTU,
		MaxPacketRate:     8192,
		MaxBurst:          1024,
		ReconnectStrategy: &api.ExponentialBackoff{
			InitialDelay: cfg.Tunnel.ReconnectDelay.Duration(),
			MaxDelay:     5 * time.Minute,
			Factor:       2.0,
		},
	}
	go m.MaintainTunnel(ctx, conf, api.NewNetstackAdapter(dev))
}
