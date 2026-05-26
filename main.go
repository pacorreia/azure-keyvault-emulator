package main

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/pacorreia/azure-keyvault-emulator/internal/server"
	"github.com/pacorreia/azure-keyvault-emulator/internal/store"
	"github.com/pacorreia/azure-keyvault-emulator/internal/store/sqlstore"
)

var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	log.Printf("starting azure-keyvault-emulator version=%s commit=%s date=%s", version, commit, date)

	s, err := openStore()
	if err != nil {
		log.Fatal(err)
	}
	defer func() {
		if err := s.Close(); err != nil {
			log.Printf("store close: %v", err)
		}
	}()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := server.Run(ctx, s); err != nil {
		log.Fatal(err)
	}
}

func openStore() (store.Storer, error) {
	backend := strings.ToLower(strings.TrimSpace(os.Getenv("STORE_BACKEND")))
	switch backend {
	case "", "memory":
		return store.New(), nil
	case "sqlite":
		return openSQLStore("sqlite", envOrDefault("STORE_DSN", "keyvault.db"), sqlstore.FlavorSQLite)
	case "postgres", "postgresql":
		dsn, err := requiredEnv("STORE_DSN")
		if err != nil {
			return nil, err
		}
		return openSQLStore("postgres", dsn, sqlstore.FlavorPostgres)
	case "mssql", "sqlserver":
		dsn, err := requiredEnv("STORE_DSN")
		if err != nil {
			return nil, err
		}
		return openSQLStore("sqlserver", dsn, sqlstore.FlavorMSSQL)
	default:
		return nil, fmt.Errorf("unsupported STORE_BACKEND %q", backend)
	}
}

func openSQLStore(driverName, dsn string, flavor sqlstore.DBFlavor) (store.Storer, error) {
	db, err := sql.Open(driverName, dsn)
	if err != nil {
		return nil, err
	}
	if err := db.Ping(); err != nil {
		_ = db.Close()
		return nil, err
	}
	s, err := sqlstore.NewSQLStore(db, flavor)
	if err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

func envOrDefault(key, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		return value
	}
	return fallback
}

func requiredEnv(key string) (string, error) {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return "", fmt.Errorf("%s is required", key)
	}
	return value, nil
}
