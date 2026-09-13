package health

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"time"
)

type Pinger interface {
	Ping(ctx context.Context) error
}

type Handler struct {
	db Pinger
}

type response struct {
	Status string `json:"status"`
}

func New(db Pinger) *Handler {
	return &Handler{
		db: db,
	}
}

func (h *Handler) Live(w http.ResponseWriter, r *http.Request) {
	w.Header().Set(
		"Content-Type",
		"application/json; charset=utf-8",
	)

	resp := response{
		Status: "ok",
	}

	if err := json.NewEncoder(w).Encode(resp); err != nil {
		slog.Error("failed to encode health response", "error", err)
	}
}

func (h *Handler) Ready(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()

	w.Header().Set(
		"Content-Type",
		"application/json; charset=utf-8",
	)

	if err := h.db.Ping(ctx); err != nil {
		slog.Warn("database readiness check failed", "error", err)
		w.WriteHeader(http.StatusServiceUnavailable)

		resp := response{
			Status: "not_ready",
		}

		if err := json.NewEncoder(w).Encode(resp); err != nil {
			slog.Error("failed to encode readiness response", "error", err)
		}

		return
	}

	resp := response{
		Status: "ready",
	}

	if err := json.NewEncoder(w).Encode(resp); err != nil {
		slog.Error("failed to encode READY response", "error", err)
	}
}
