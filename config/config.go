package config

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"time"
)

// Duration wraps time.Duration to allow human-readable JSON values.
type Duration time.Duration

// UnmarshalJSON parses either a string duration like "30s" or a number of nanoseconds.
func (d *Duration) UnmarshalJSON(b []byte) error {
	if len(b) == 0 {
		*d = 0
		return nil
	}
	if b[0] == '"' {
		var s string
		if err := json.Unmarshal(b, &s); err != nil {
			return err
		}
		dur, err := time.ParseDuration(s)
		if err != nil {
			return err
		}
		*d = Duration(dur)
		return nil
	}
	var n int64
	if err := json.Unmarshal(b, &n); err != nil {
		return err
	}
	*d = Duration(time.Duration(n))
	return nil
}

// MarshalJSON writes the duration as a human-readable string.
func (d Duration) MarshalJSON() ([]byte, error) {
	return json.Marshal(time.Duration(d).String())
}

// Duration converts the custom type back to time.Duration.
func (d Duration) Duration() time.Duration {
	return time.Duration(d)
}

// Config represents the application configuration structure, containing essential details such as keys, endpoints, and access tokens.
type Config struct {
	// 连接信息
	PrivateKey     string `json:"private_key"`      // Base64-encoded ECDSA private key
	EndpointV4     string `json:"endpoint_v4"`      // IPv4 address of the endpoint
	EndpointV6     string `json:"endpoint_v6"`      // IPv6 address of the endpoint
	EndpointPubKey string `json:"endpoint_pub_key"` // PEM-encoded ECDSA public key of the endpoint to verify against
	License        string `json:"license"`          // Application license key
	ID             string `json:"id"`               // Device unique identifier
	AccessToken    string `json:"access_token"`     // Authentication token for API access
	IPv4           string `json:"ipv4"`             // Assigned IPv4 address
	IPv6           string `json:"ipv6"`             // Assigned IPv6 address

	// SOCKS代理配置
	Socks SocksConfig `json:"socks"` // SOCKS5代理相关配置

	// 隧道配置
	Tunnel TunnelConfig `json:"tunnel"` // MASQUE隧道相关配置

	// 日志配置
	Logging LoggingConfig `json:"logging"` // 日志相关配置

	// 注册信息
	Registration RegistrationInfo `json:"registration"` // 注册相关信息
}

// SocksConfig 包含SOCKS5代理相关的配置，仅涉及代理服务器本身
type SocksConfig struct {
	BindAddress string `json:"bind_address"` // 代理绑定的地址
	Port        string `json:"port"`         // 代理监听的端口
	Username    string `json:"username"`     // 代理认证的用户名
	Password    string `json:"password"`     // 代理认证的密码
}

// TunnelConfig 包含MASQUE隧道相关配置
type TunnelConfig struct {
	ConnectPort       int      `json:"connect_port"`        // MASQUE连接使用的端口
	DNS               []string `json:"dns"`                 // 在隧道内使用的DNS服务器
	DNSTimeout        Duration `json:"dns_timeout"`         // DNS查询超时时间
	UseIPv6           bool     `json:"use_ipv6"`            // 是否使用IPv6进行MASQUE连接
	NoTunnelIPv4      bool     `json:"no_tunnel_ipv4"`      // 是否在隧道内禁用IPv4
	NoTunnelIPv6      bool     `json:"no_tunnel_ipv6"`      // 是否在隧道内禁用IPv6
	SNIAddress        string   `json:"sni_address"`         // MASQUE连接使用的SNI地址
	KeepalivePeriod   Duration `json:"keepalive_period"`    // 连接心跳周期
	MTU               int      `json:"mtu"`                 // 隧道MTU
	InitialPacketSize uint16   `json:"initial_packet_size"` // 初始包大小
	ReconnectDelay    Duration `json:"reconnect_delay"`     // 重连延迟
	ConnectionTimeout Duration `json:"connection_timeout"`  // 建立连接超时
	IdleTimeout       Duration `json:"idle_timeout"`        // 空闲连接超时
	PerClient         bool     `json:"per_client"`          // 是否为每个SOCKS客户端创建独立隧道
}

// LoggingConfig contains configuration related to logging output.
type LoggingConfig struct {
	// OutputPath specifies the file path to write logs to. If empty, logs are written to stdout.
	OutputPath string `json:"output_path"`
	// Level defines the minimum log level (debug, info, warn, error).
	Level string `json:"level"`
}

// RegistrationInfo 包含注册相关的信息
type RegistrationInfo struct {
	DeviceName string `json:"device_name"` // 注册的设备名称
}

// AppConfig holds the global application configuration.
var AppConfig Config

// ConfigLoaded indicates whether the configuration has been successfully loaded.
var ConfigLoaded bool

// LoadConfig loads the application configuration from a JSON file.
//
// Parameters:
//   - configPath: string - The path to the configuration JSON file.
//
// Returns:
//   - error: An error if the configuration file cannot be loaded or parsed.
func LoadConfig(configPath string) error {
	file, err := os.Open(configPath)
	if err != nil {
		return fmt.Errorf("failed to open config file: %v", err)
	}
	defer file.Close()

	decoder := json.NewDecoder(file)
	if err := decoder.Decode(&AppConfig); err != nil {
		return fmt.Errorf("failed to decode config file: %v", err)
	}

	// 如果配置项为空，设置为默认值
	if AppConfig.Socks.Port == "" && AppConfig.Socks.BindAddress == "" {
		AppConfig.Socks = GetDefaultSocksConfig()
	}
	if AppConfig.Tunnel.ConnectPort == 0 && len(AppConfig.Tunnel.DNS) == 0 {
		AppConfig.Tunnel = GetDefaultTunnelConfig()
	}
	if AppConfig.Logging.OutputPath == "" {
		AppConfig.Logging.OutputPath = GetDefaultLoggingConfig().OutputPath
	}
	if AppConfig.Logging.Level == "" {
		AppConfig.Logging.Level = GetDefaultLoggingConfig().Level
	}

	ConfigLoaded = true

	return nil
}

// GetDefaultSocksConfig 返回默认的SOCKS代理配置
func GetDefaultSocksConfig() SocksConfig {
	return SocksConfig{
		BindAddress: "127.0.0.1",
		Port:        "1080",
		Username:    "",
		Password:    "",
	}
}

// GetDefaultTunnelConfig 返回默认的MASQUE隧道配置
func GetDefaultTunnelConfig() TunnelConfig {
	return TunnelConfig{
		ConnectPort:       443,
		DNS:               []string{"1.1.1.1", "8.8.8.8"},
		DNSTimeout:        Duration(2 * time.Second),
		UseIPv6:           false,
		NoTunnelIPv4:      false,
		NoTunnelIPv6:      false,
		SNIAddress:        "",
		KeepalivePeriod:   Duration(30 * time.Second),
		MTU:               1280,
		InitialPacketSize: 1242,
		ReconnectDelay:    Duration(1 * time.Second),
		ConnectionTimeout: Duration(30 * time.Second),
		IdleTimeout:       Duration(5 * time.Minute),
		PerClient:         false,
	}
}

// GetDefaultLoggingConfig returns the default logging configuration.
func GetDefaultLoggingConfig() LoggingConfig {
	return LoggingConfig{OutputPath: "", Level: "info"}
}

// SaveConfig writes the current application configuration to a prettified JSON file.
//
// Parameters:
//   - configPath: string - The path to save the configuration JSON file.
//
// Returns:
//   - error: An error if the configuration file cannot be written.
func (*Config) SaveConfig(configPath string) error {
	file, err := os.Create(configPath)
	if err != nil {
		return fmt.Errorf("failed to create config file: %v", err)
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(AppConfig); err != nil {
		return fmt.Errorf("failed to encode config file: %v", err)
	}

	return nil
}

// InitNewConfig initializes a new configuration with default values.
//
// Parameters:
//   - privateKey: string - Base64-encoded ECDSA private key.
//   - endpointV4: string - IPv4 address of the endpoint.
//   - endpointV6: string - IPv6 address of the endpoint.
//   - endpointPubKey: string - PEM-encoded ECDSA public key of the endpoint.
//   - license: string - Application license key.
//   - id: string - Device unique identifier.
//   - accessToken: string - Authentication token for API access.
//   - ipv4: string - Assigned IPv4 address.
//   - ipv6: string - Assigned IPv6 address.
//   - deviceName: string - Name of the device (for registration info).
//
// Returns:
//   - The newly initialized Config.
func InitNewConfig(
	privateKey, endpointV4, endpointV6, endpointPubKey,
	license, id, accessToken, ipv4, ipv6, deviceName string,
) Config {
	return Config{
		PrivateKey:     privateKey,
		EndpointV4:     endpointV4,
		EndpointV6:     endpointV6,
		EndpointPubKey: endpointPubKey,
		License:        license,
		ID:             id,
		AccessToken:    accessToken,
		IPv4:           ipv4,
		IPv6:           ipv6,
		Socks:          GetDefaultSocksConfig(),
		Tunnel:         GetDefaultTunnelConfig(),
		Logging:        GetDefaultLoggingConfig(),
		Registration: RegistrationInfo{
			DeviceName: deviceName,
		},
	}
}

// GetEcPrivateKey retrieves the ECDSA private key from the stored Base64-encoded string.
//
// Returns:
//   - *ecdsa.PrivateKey: The parsed ECDSA private key.
//   - error: An error if decoding or parsing the private key fails.
func (*Config) GetEcPrivateKey() (*ecdsa.PrivateKey, error) {
	privKeyB64, err := base64.StdEncoding.DecodeString(AppConfig.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decode private key: %v", err)
	}

	privKey, err := x509.ParseECPrivateKey(privKeyB64)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %v", err)
	}

	return privKey, nil
}

// GetEcEndpointPublicKey retrieves the ECDSA public key from the stored PEM-encoded string.
//
// Returns:
//   - *ecdsa.PublicKey: The parsed ECDSA public key.
//   - error: An error if decoding or parsing the public key fails.
func (*Config) GetEcEndpointPublicKey() (*ecdsa.PublicKey, error) {
	endpointPubKeyB64, _ := pem.Decode([]byte(AppConfig.EndpointPubKey))
	if endpointPubKeyB64 == nil {
		return nil, fmt.Errorf("failed to decode endpoint public key")
	}

	pubKey, err := x509.ParsePKIXPublicKey(endpointPubKeyB64.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %v", err)
	}

	ecPubKey, ok := pubKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("failed to assert public key as ECDSA")
	}

	return ecPubKey, nil
}
