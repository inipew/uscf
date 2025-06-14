package main

import (
	"fmt"
	"os"

	"github.com/HynoR/uscf/cmd"
	"github.com/HynoR/uscf/internal/logger"
)

func main() {
	defer logger.Close()
	if err := cmd.Execute(); err != nil {
		fmt.Println("Error:", err)
		os.Exit(1)
	}
}
