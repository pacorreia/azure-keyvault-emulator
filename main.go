package main

import (
	"context"
	"log"
	"os/signal"
	"syscall"

	"github.com/pacorreia/azure-keyvault-emulator/internal/server"
	"github.com/pacorreia/azure-keyvault-emulator/internal/store"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := server.Run(ctx, store.New()); err != nil {
		log.Fatal(err)
	}
}
