package socks

import (
	"context"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/HynoR/uscf/api"
	"github.com/HynoR/uscf/config"
	"github.com/HynoR/uscf/internal/logger"
	"github.com/HynoR/uscf/models"
	"github.com/HynoR/uscf/service/tunnel"
	"github.com/things-go/go-socks5"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

// Run starts a SOCKS5 server using the provided tunnel network stack.
func Run(ctx context.Context, cfg *config.Config, tunNet *netstack.Net, connectionTimeout, idleTimeout time.Duration) error {
	dnsTimeoutSec := int(cfg.Tunnel.DNSTimeout.Duration().Seconds())
	resolver := api.NewCachingDNSResolver("", dnsTimeoutSec)

	tlsCfg, err := tunnel.PrepareTLSConfig(cfg)
	if err != nil {
		return err
	}

	endpoint, locals, dnsAddrs, err := tunnel.PrepareNetworkConfig(cfg)
	if err != nil {
		return err
	}

	dialFunc := func(netTun *netstack.Net) func(ctx context.Context, network, addr string) (net.Conn, error) {
		return func(ctx context.Context, network, addr string) (net.Conn, error) {
			dctx, cancel := context.WithTimeout(ctx, connectionTimeout)
			defer cancel()

			conn, err := netTun.DialContext(dctx, network, addr)
			if err != nil {
				return nil, err
			}
			return &models.TimeoutConn{Conn: conn, IdleTimeout: idleTimeout}, nil
		}
	}

	var server *socks5.Server
	if !cfg.Tunnel.PerClient {
		server = createServer(cfg.Socks.Username, cfg.Socks.Password, dialFunc(tunNet), resolver)
	}
	bindAddr := net.JoinHostPort(cfg.Socks.BindAddress, cfg.Socks.Port)
	logger.Logger.Infof("SOCKS proxy listening on %s", bindAddr)

	l, err := net.Listen("tcp", bindAddr)
	if err != nil {
		return fmt.Errorf("failed to start SOCKS proxy: %w", err)
	}

	go func() {
		<-ctx.Done()
		l.Close()
	}()

	for {
		conn, err := l.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			logger.Logger.Warnf("Failed to accept connection: %v", err)
			continue
		}

		if cfg.Tunnel.PerClient {
			dev, netTun, err := tunnel.CreateTun(locals, dnsAddrs, cfg)
			if err != nil {
				logger.Logger.Warnf("Failed to create tun device: %v", err)
				conn.Close()
				continue
			}

			cctx, cancel := context.WithCancel(ctx)
			tunnel.StartTunnel(cctx, tunnel.DefaultManager{}, tlsCfg, endpoint, cfg, dev)
			svr := createServer(cfg.Socks.Username, cfg.Socks.Password, dialFunc(netTun), resolver)

			go func(c net.Conn, cancel context.CancelFunc, dev tun.Device) {
				timeoutConn := &models.TimeoutConn{Conn: c, IdleTimeout: idleTimeout}
				svr.ServeConn(timeoutConn)
				cancel()
				dev.Close()
			}(conn, cancel, dev)
			continue
		}

		timeoutConn := &models.TimeoutConn{Conn: conn, IdleTimeout: idleTimeout}
		go server.ServeConn(timeoutConn)
	}
}

func createServer(username, password string, dial func(ctx context.Context, network, addr string) (net.Conn, error), resolver socks5.NameResolver) *socks5.Server {
	buf := api.NewNetBuffer(32 * 1024)
	if buf == nil {
		logger.Logger.Error("Failed to create buffer")
		return nil
	}

	opts := []socks5.Option{
		socks5.WithLogger(socks5.NewLogger(log.New(logger.Logger.Writer(), "socks5: ", log.LstdFlags))),
		socks5.WithDial(dial),
		socks5.WithResolver(resolver),
		socks5.WithBufferPool(buf),
	}
	if username != "" && password != "" {
		opts = append(opts, socks5.WithAuthMethods([]socks5.Authenticator{
			socks5.UserPassAuthenticator{Credentials: socks5.StaticCredentials{username: password}},
		}))
	}
	return socks5.NewServer(opts...)
}
