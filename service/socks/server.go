package socks

import (
       "context"
       "fmt"
       "log"
       "net"
       "time"

       "github.com/HynoR/uscf/api"
       "github.com/HynoR/uscf/config"
       "github.com/HynoR/uscf/models"
       "github.com/HynoR/uscf/internal/logger"
       "github.com/things-go/go-socks5"
       "golang.zx2c4.com/wireguard/tun/netstack"
)

// Run starts a SOCKS5 server using the provided tunnel network stack.
func Run(cfg *config.Config, tunNet *netstack.Net, connectionTimeout, idleTimeout time.Duration) error {
	dnsTimeoutSec := int(cfg.Tunnel.DNSTimeout.Duration().Seconds())
	resolver := api.NewCachingDNSResolver("", dnsTimeoutSec)

	dialFunc := func(ctx context.Context, network, addr string) (net.Conn, error) {
		dctx, cancel := context.WithTimeout(ctx, connectionTimeout)
		defer cancel()

		conn, err := tunNet.DialContext(dctx, network, addr)
		if err != nil {
			return nil, err
		}
		return &models.TimeoutConn{Conn: conn, IdleTimeout: idleTimeout}, nil
	}

	server := createServer(cfg.Socks.Username, cfg.Socks.Password, dialFunc, resolver)
	bindAddr := net.JoinHostPort(cfg.Socks.BindAddress, cfg.Socks.Port)
       logger.Logger.Infof("SOCKS proxy listening on %s", bindAddr)

	l, err := net.Listen("tcp", bindAddr)
	if err != nil {
		return fmt.Errorf("failed to start SOCKS proxy: %w", err)
	}

	for {
		conn, err := l.Accept()
		if err != nil {
                       logger.Logger.Warnf("Failed to accept connection: %v", err)
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
