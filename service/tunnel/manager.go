package tunnel

import (
	"context"
	"github.com/HynoR/uscf/api"
)

// Manager abstracts the tunnel maintenance logic so it can be easily mocked.
type Manager interface {
	MaintainTunnel(ctx context.Context, cfg api.ConnectionConfig, dev api.TunnelDevice)
}

// DefaultManager uses api.MaintainTunnel for production.
type DefaultManager struct{}

// MaintainTunnel implements Manager by delegating to api.MaintainTunnel.
func (DefaultManager) MaintainTunnel(ctx context.Context, cfg api.ConnectionConfig, dev api.TunnelDevice) {
	api.MaintainTunnel(ctx, cfg, dev)
}
