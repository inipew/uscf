package cmd

import (
       "github.com/HynoR/uscf/config"
       "github.com/HynoR/uscf/internal/logger"
       "github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "usque",
	Short: "Usque Warp CLI",
	Long:  "An unofficial Cloudflare Warp CLI that uses the MASQUE protocol and exposes the tunnel as various different services.",
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
               configPath, err := cmd.Flags().GetString("config")
               if err != nil {
                       logger.Logger.Fatalf("Failed to get config path: %v", err)
               }

		if configPath != "" {
			if err := config.LoadConfig(configPath); err != nil {
                               logger.Logger.Infof("Config file not found: %v", err)
                               logger.Logger.Info("You may only use the register command to generate one.")
                       }
               }

		// Initialize logging after config is loaded
               if err := logger.Init(config.AppConfig.Logging.OutputPath, config.AppConfig.Logging.Level); err != nil {
                       logger.Logger.Errorf("Failed to init logger: %v", err)
               }
	},
}

func Execute() error {
	return rootCmd.Execute()
}

func init() {
	rootCmd.PersistentFlags().StringP("config", "c", "config.json", "config file (default is config.json)")
}
