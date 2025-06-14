package cmd

import (
	"context"
	"encoding/base64"
	"fmt"
	"log"

	"github.com/HynoR/uscf/api"
	"github.com/HynoR/uscf/config"
	"github.com/HynoR/uscf/internal"
	proxysvc "github.com/HynoR/uscf/service/proxy"
	"github.com/HynoR/uscf/service/tunnel"
	"github.com/spf13/cobra"
)

// proxyCmd 命令，结合 socks 和 register 的功能
var proxyCmd = &cobra.Command{
	Use:   "proxy",
	Short: "One-command solution to run SOCKS5 proxy with auto-registration",
	Long:  "Automatically registers if no config exists, then runs a dual-stack SOCKS5 proxy with optional authentication.",
	Run:   runProxyCmd,
}

func init() {
	// 初始化 proxy 命令的参数

	// 只保留必要的注册相关参数，其他参数已转移到配置文件
	proxyCmd.Flags().String("locale", internal.DefaultLocale, "Locale for registration")
	proxyCmd.Flags().String("model", internal.DefaultModel, "Model for registration")
	proxyCmd.Flags().String("name", "", "Device name for registration")
	proxyCmd.Flags().Bool("accept-tos", true, "Automatically accept Cloudflare TOS")
	proxyCmd.Flags().String("jwt", "", "Team token for registration")

	// 添加重置SOCKS5配置的标志
	proxyCmd.Flags().Bool("reset-config", false, "Reset SOCKS5 configuration to default values")

	// 添加SOCKS5代理配置的命令行参数
	proxyCmd.Flags().StringP("bind-address", "b", "", "Bind address for SOCKS5 proxy (overrides config file)")
	proxyCmd.Flags().StringP("port", "p", "", "Port for SOCKS5 proxy (overrides config file)")
	proxyCmd.Flags().StringP("username", "u", "", "Username for SOCKS5 proxy authentication (overrides config file)")
	proxyCmd.Flags().StringP("password", "w", "", "Password for SOCKS5 proxy authentication (overrides config file)")

	// 添加提示，说明SOCKS配置已移至配置文件，但可通过命令行参数覆盖
	proxyCmd.Long += "\n\nNote: All SOCKS proxy settings are primarily managed through the config file, but can be overridden with command-line flags."

	// 把 proxyCmd 注册到根命令
	rootCmd.AddCommand(proxyCmd)
}

// runProxyCmd 是 proxyCmd 的执行逻辑
func runProxyCmd(cmd *cobra.Command, args []string) {
	// 0. 获取配置文件路径
	configPath, err := cmd.Flags().GetString("config")
	if err != nil {
		cmd.Printf("Failed to get config path: %v\n", err)
		return
	}
	if configPath == "" {
		configPath = "config.json"
	}

	// 检查是否需要重置SOCKS5配置
	resetConfig, _ := cmd.Flags().GetBool("reset-config")

	// 1. 如有需要，进行自动注册
	if !config.ConfigLoaded {
		if err := handleRegistration(cmd, configPath); err != nil {
			cmd.Printf("%v\n", err)
			return
		}

		// 更新一些需要从内部常量获取的配置值
		config.AppConfig.Tunnel.SNIAddress = internal.ConnectSNI

		// 保存更新后的配置
		if err := config.AppConfig.SaveConfig(configPath); err != nil {
			log.Printf("Warning: Failed to save updated config: %v", err)
		}
	} else if resetConfig {
		// 如果已加载配置且指定了reset-config标志，则重置SOCKS5配置
		log.Println("Resetting SOCKS5 configuration to default values...")

		// 保存当前的SNI地址，因为它取决于内部常量
		sniAddress := config.AppConfig.Tunnel.SNIAddress

		// 重置为默认配置
		config.AppConfig.Socks = config.GetDefaultSocksConfig()
		config.AppConfig.Tunnel = config.GetDefaultTunnelConfig()

		// 恢复SNI地址
		config.AppConfig.Tunnel.SNIAddress = sniAddress

		// 保存更新后的配置
		if err := config.AppConfig.SaveConfig(configPath); err != nil {
			log.Printf("Warning: Failed to save reset config: %v", err)
			cmd.Printf("Failed to save reset configuration: %v\n", err)
			return
		}
		log.Printf("SOCKS5 configuration has been reset to default values in %s", configPath)
	}

	// 检查并应用命令行参数覆盖配置文件的值
	configChanged := false

	// 检查绑定地址
	if bindAddress, _ := cmd.Flags().GetString("bind-address"); bindAddress != "" {
		log.Printf("Overriding bind address from command line: %s", bindAddress)
		config.AppConfig.Socks.BindAddress = bindAddress
		configChanged = true
	}

	// 检查端口
	if port, _ := cmd.Flags().GetString("port"); port != "" {
		log.Printf("Overriding port from command line: %s", port)
		config.AppConfig.Socks.Port = port
		configChanged = true
	}

	// 检查用户名
	if username, _ := cmd.Flags().GetString("username"); username != "" {
		log.Printf("Overriding username from command line")
		config.AppConfig.Socks.Username = username
		configChanged = true
	}

	// 检查密码
	if password, _ := cmd.Flags().GetString("password"); password != "" {
		log.Printf("Overriding password from command line")
		config.AppConfig.Socks.Password = password
		configChanged = true
	}

	// 如果配置有变更，保存到配置文件
	if configChanged {
		log.Printf("Saving updated configuration to %s", configPath)
		if err := config.AppConfig.SaveConfig(configPath); err != nil {
			log.Printf("Warning: Failed to save updated config: %v", err)
		}
	}

	// 2. 启动 SOCKS5 代理
	svc := proxysvc.New(tunnel.DefaultManager{})
	if err := svc.Run(context.Background(), &config.AppConfig); err != nil {
		cmd.Printf("%v\n", err)
		return
	}
}

// handleRegistration 处理自动注册流程
func handleRegistration(cmd *cobra.Command, configPath string) error {
	log.Println("Config not loaded. Starting automatic registration...")

	// 获取注册参数
	deviceName, _ := cmd.Flags().GetString("name")
	locale, _ := cmd.Flags().GetString("locale")
	model, _ := cmd.Flags().GetString("model")
	acceptTos, _ := cmd.Flags().GetBool("accept-tos")
	jwt, _ := cmd.Flags().GetString("jwt")

	log.Printf("Registering with locale %s and model %s", locale, model)

	// 注册账户
	accountData, err := api.Register(model, locale, jwt, acceptTos)
	if err != nil {
		return fmt.Errorf("Failed to register: %v", err)
	}

	// 生成密钥对
	privKey, pubKey, err := internal.GenerateEcKeyPair()
	if err != nil {
		return fmt.Errorf("Failed to generate key pair: %v", err)
	}

	log.Printf("Enrolling device key...")

	// 注册设备密钥
	updatedAccountData, apiErr, err := api.EnrollKey(accountData, pubKey, deviceName)
	if err != nil {
		if apiErr != nil {
			return fmt.Errorf("Failed to enroll key: %v (API errors: %s)", err, apiErr.ErrorsAsString("; "))
		}
		return fmt.Errorf("Failed to enroll key: %v", err)
	}

	log.Printf("Registration successful. Saving config...")

	// 保存配置，使用InitNewConfig创建带有默认值的配置
	config.AppConfig = config.InitNewConfig(
		base64.StdEncoding.EncodeToString(privKey),
		// TODO: proper endpoint parsing in utils
		// strip :0
		updatedAccountData.Config.Peers[0].Endpoint.V4[:len(updatedAccountData.Config.Peers[0].Endpoint.V4)-2],
		// strip [ from beginning and ]:0 from end
		updatedAccountData.Config.Peers[0].Endpoint.V6[1:len(updatedAccountData.Config.Peers[0].Endpoint.V6)-3],
		updatedAccountData.Config.Peers[0].PublicKey,
		updatedAccountData.Account.License,
		updatedAccountData.ID,
		accountData.Token,
		updatedAccountData.Config.Interface.Addresses.V4,
		updatedAccountData.Config.Interface.Addresses.V6,
		deviceName,
	)

	err = config.AppConfig.SaveConfig(configPath)
	if err != nil {
		return fmt.Errorf("Failed to save config: %v", err)
	}

	log.Printf("Config saved to %s", configPath)

	// 标记配置已加载
	config.ConfigLoaded = true
	return nil
}
