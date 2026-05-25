package main

import (
	"context"
	"database/sql"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	_ "github.com/lib/pq"

	"simple-config-service/internal/app"
	"simple-config-service/internal/config"
	"simple-config-service/internal/httpapi"
	"simple-config-service/internal/store"
	"simple-config-service/pkg/configcrypto"
)

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

	cfg, err := config.Load(".env")
	if err != nil {
		logger.Error("load config", "error", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	db, err := sql.Open("postgres", cfg.PostgresURL())
	if err != nil {
		logger.Error("connect postgres", "error", err)
		os.Exit(1)
	}
	defer db.Close()

	if err := db.PingContext(ctx); err != nil {
		logger.Error("ping postgres", "error", err)
		os.Exit(1)
	}

	if err := store.RunMigrations(ctx, db); err != nil {
		logger.Error("run migrations", "error", err)
		os.Exit(1)
	}

	serviceKey, err := configcrypto.LoadOrCreateRSAKeyPair(cfg.ServicePrivateKeyPath, cfg.ServicePublicKeyPath)
	if err != nil {
		logger.Error("load service rsa key pair", "error", err)
		os.Exit(1)
	}
	logger.Info("service rsa key ready", "public_key", cfg.ServicePublicKeyPath)

	st := store.New(db)
	svc, err := app.New(cfg, st, logger, serviceKey)
	if err != nil {
		logger.Error("create app", "error", err)
		os.Exit(1)
	}

	publicServer := &http.Server{
		Addr:              cfg.PublicListenAddr,
		Handler:           httpapi.NewPublicHandler(svc),
		ReadHeaderTimeout: 5 * time.Second,
	}
	internalServer := &http.Server{
		Addr:              cfg.InternalListenAddr,
		Handler:           httpapi.NewInternalHandler(svc),
		ReadHeaderTimeout: 5 * time.Second,
	}

	errCh := make(chan error, 2)
	go serveHTTP(publicServer, "public", logger, errCh)
	go serveHTTP(internalServer, "internal", logger, errCh)

	select {
	case <-ctx.Done():
		logger.Info("shutdown requested")
	case err := <-errCh:
		logger.Error("server stopped", "error", err)
		stop()
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := publicServer.Shutdown(shutdownCtx); err != nil {
		logger.Error("shutdown public server", "error", err)
	}
	if err := internalServer.Shutdown(shutdownCtx); err != nil {
		logger.Error("shutdown internal server", "error", err)
	}
}

func serveHTTP(server *http.Server, name string, logger *slog.Logger, errCh chan<- error) {
	logger.Info("server listening", "name", name, "addr", server.Addr)
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		errCh <- err
	}
}
