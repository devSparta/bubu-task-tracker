package main

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
	"fmt"

	"github.com/devSparta/bubu-task-tracker/internal/config"
	"github.com/devSparta/bubu-task-tracker/internal/platform/postgres"
)

type healthResponse struct {
	Status string `json:"status"`
}

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

	//Pool creation
	ctxPool, cancelPool := context.WithTimeout(ctx, time.Second*5)

	pool, err := postgres.Open(ctxPool, cfg.DatabaseURL)
	cancelPool()

	if err != nil {
		return fmt.Errorf("open PostgreSQL: %w", err)
	}

	defer pool.Close()
	slog.Info("connected to PostgreSQL")

	mux := http.NewServeMux()
	mux.HandleFunc("GET /health/live", liveHandler)

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

func liveHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set(
		"Content-Type",
		"application/json; charset=utf-8",
	)
	w.WriteHeader(http.StatusOK)

	response := healthResponse{
		Status: "OK",
	}

	if err := json.NewEncoder(w).Encode(response); err != nil {
		slog.Error("failed to encode response", "error", err)
	}
}
