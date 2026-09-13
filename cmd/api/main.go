package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/devSparta/bubu-task-tracker/internal/config"
	"github.com/devSparta/bubu-task-tracker/internal/httpapi/health"
	"github.com/devSparta/bubu-task-tracker/internal/platform/postgres"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	slog.SetDefault(logger)

	if err := run(); err != nil {
		slog.Error("application stopped", "error", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.Load()

	if err != nil {
		return fmt.Errorf("load configuration: %w", err)
	}

	//Signal context
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	//Pool opening
	ctxPool, cancelPool := context.WithTimeout(ctx, time.Second*5)

	pool, err := postgres.Open(ctxPool, cfg.DatabaseURL)
	cancelPool()

	if err != nil {
		return fmt.Errorf("open PostgreSQL: %w", err)
	}

	defer pool.Close()
	slog.Info("connected to PostgreSQL")

	//Health Handler creation
	healthHandler := health.New(pool)

	//mux
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health/live", healthHandler.Live)
	mux.HandleFunc("GET /health/ready", healthHandler.Ready)

	server := &http.Server{
		Addr:              cfg.HTTPAddr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	slog.Info(
		"starting HTTP server",
		"address", server.Addr,
	)

	errs := make(chan error, 1)

	go func() {
		errs <- server.ListenAndServe()
	}()

	select {
	case err := <-errs:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			return fmt.Errorf("run HTTP server: %w", err)
		}

	case <-ctx.Done():
		slog.Info("server is shutting down")
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)

		err := server.Shutdown(shutdownCtx)
		shutdownCancel()

		if err != nil {
			return fmt.Errorf("shut down HTTP server: %w", err)
		}

		slog.Info("server stopped")
	}

	return nil
}
