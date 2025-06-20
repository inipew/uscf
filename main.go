package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/HynoR/uscf/cmd"
	"github.com/HynoR/uscf/internal/logger"
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	defer logger.Close()

	if err := cmd.ExecuteContext(ctx); err != nil {
		fmt.Println("Error:", err)
		os.Exit(1)
	}
}
