package models

import (
	"net"
	"time"
)

// 超时管理的连接包装器
type TimeoutConn struct {
	net.Conn
	IdleTimeout time.Duration
}

func (c *TimeoutConn) Read(b []byte) (int, error) {
	if c.IdleTimeout > 0 {
		err := c.Conn.SetReadDeadline(time.Now().Add(c.IdleTimeout))
		if err != nil {
			return 0, err
		}
	}
	return c.Conn.Read(b)
}

func (c *TimeoutConn) Write(b []byte) (int, error) {
	if c.IdleTimeout > 0 {
		err := c.Conn.SetWriteDeadline(time.Now().Add(c.IdleTimeout))
		if err != nil {
			return 0, err
		}
	}
	return c.Conn.Write(b)
}
