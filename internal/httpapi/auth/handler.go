package auth

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"time"

	authapp "github.com/devSparta/bubu-task-tracker/internal/application/auth"
	"github.com/devSparta/bubu-task-tracker/internal/domain/user"
)

type registerRequest struct {
	Email       string `json:"email"`
	DisplayName string `json:"display_name"`
	Password    string `json:"password"`
}

type registerResponse struct {
	ID            string    `json:"id"`
	Email         string    `json:"email"`
	DisplayName   string    `json:"display_name"`
	EmailVerified bool      `json:"email_verified"`
	CreatedAt     time.Time `json:"created_at"`
}

type problemResponse struct {
	Type   string `json:"type"`
	Title  string `json:"title"`
	Status int    `json:"status"`
	Code   string `json:"code"`
	Detail string `json:"detail"`
}

type RegistrationService interface {
	Register(ctx context.Context, input authapp.RegisterInput) (user.User, error)
}

type Handler struct {
	service RegistrationService
}

func NewHandler(service RegistrationService) *Handler {
	return &Handler{
		service: service,
	}
}

func (h *Handler) Register(w http.ResponseWriter, r *http.Request) {
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))

	if err != nil || mediaType != "application/json" {
		writeProblem(w, http.StatusUnsupportedMediaType, "UNSUPPORTED_MEDIA_TYPE", "Content-Type must be application/json.")
		return
	}

	const maxRegisterRequestBodyBytes = 64 << 10
	reader := http.MaxBytesReader(w, r.Body, maxRegisterRequestBodyBytes)
	defer reader.Close()

	decoder := json.NewDecoder(reader)
	decoder.DisallowUnknownFields()

	var req registerRequest
	var errorMaxBytes *http.MaxBytesError

	if err := decoder.Decode(&req); err != nil {
		if errors.As(err, &errorMaxBytes) {
			writeProblem(w, http.StatusRequestEntityTooLarge, "REQUEST_BODY_TOO_LARGE", "Request body exceeds the maximum allowed size.")
			return
		}

		writeProblem(w, http.StatusBadRequest, "INVALID_REQUEST_BODY", "Request body must contain a single valid JSON object with no unknown fields.")
		return
	}

	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		if errors.As(err, &errorMaxBytes) {
			writeProblem(w, http.StatusRequestEntityTooLarge, "REQUEST_BODY_TOO_LARGE", "Request body exceeds the maximum allowed size.")
			return
		}

		writeProblem(w, http.StatusBadRequest, "INVALID_REQUEST_BODY", "Request body must contain a single valid JSON object with no unknown fields.")
		return
	}

	input := authapp.RegisterInput{
		Email:       req.Email,
		DisplayName: req.DisplayName,
		Password:    req.Password,
	}

	createdUser, err := h.service.Register(r.Context(), input)
	var validationErr *authapp.ValidationError

	if err != nil {
		if errors.As(err, &validationErr) {
			writeProblem(w, http.StatusUnprocessableEntity, "VALIDATION_FAILED", validationErr.Error())
			return
		}

		if errors.Is(err, authapp.ErrEmailAlreadyExists) {
			writeProblem(w, http.StatusConflict, "EMAIL_ALREADY_REGISTERED", "An account with this email already exists.")
			return
		}

		slog.Error("error registering user", "error", err)
		writeProblem(w, http.StatusInternalServerError, "INTERNAL_ERROR", "An unexpected error occurred.")
		return
	}

	regResp := registerResponse{
		ID:            createdUser.ID.String(),
		Email:         createdUser.Email,
		DisplayName:   createdUser.DisplayName,
		EmailVerified: createdUser.EmailVerifiedAt != nil,
		CreatedAt:     createdUser.CreatedAt,
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")

	w.WriteHeader(http.StatusCreated)

	if err := json.NewEncoder(w).Encode(regResp); err != nil {
		slog.Error("failed to encode registration response", "error", err)
		return
	}
}

func writeProblem(
	w http.ResponseWriter,
	status int,
	code string,
	detail string,
) {
	w.Header().Set("Content-Type", "application/problem+json; charset=utf-8")
	w.WriteHeader(status)

	resp := problemResponse{
		Type:   "about:blank",
		Title:  http.StatusText(status),
		Status: status,
		Code:   code,
		Detail: detail,
	}

	if err := json.NewEncoder(w).Encode(resp); err != nil {
		slog.Error("failed to encode problem response", "error", err)
	}
}
